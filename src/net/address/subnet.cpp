// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/address/subnet.h"
#include "core/logging.h"

#include <algorithm>
#include <charconv>
#include <cstring>

namespace net {

// ===================================================================
// Internal helpers
// ===================================================================

namespace {

/// Returns the maximum meaningful prefix length for a given network type.
uint16_t max_prefix_for_network(Network net) noexcept {
    switch (net) {
        case Network::IPV4:  return 32;
        case Network::IPV6:  return 128;
        case Network::TORV3: return 256; // 32 bytes * 8
        case Network::I2P:   return 256;
        case Network::CJDNS: return 128;
        default:             return 0;
    }
}

/// Compare two byte arrays under a given prefix mask (in bits).
/// Returns true if they match within the first `prefix_bits` bits.
bool match_prefix(const uint8_t* a, const uint8_t* b,
                  size_t total_bytes, uint8_t prefix_bits) noexcept {
    uint8_t full_bytes = prefix_bits / 8;
    uint8_t remaining_bits = prefix_bits % 8;

    // Compare full bytes.
    if (full_bytes > 0 && full_bytes <= total_bytes) {
        if (std::memcmp(a, b, full_bytes) != 0) {
            return false;
        }
    }

    // Compare remaining bits in the next byte.
    if (remaining_bits > 0 && full_bytes < total_bytes) {
        uint8_t mask = static_cast<uint8_t>(0xFF << (8 - remaining_bits));
        if ((a[full_bytes] & mask) != (b[full_bytes] & mask)) {
            return false;
        }
    }

    return true;
}

/// Returns the byte count used by a network type for address data.
size_t addr_byte_count(Network net) noexcept {
    switch (net) {
        case Network::IPV4:  return 4;
        case Network::IPV6:  return 16;
        case Network::TORV3: return 32;
        case Network::I2P:   return 32;
        case Network::CJDNS: return 16;
        default:             return 32;
    }
}

}  // anonymous namespace

// ===================================================================
// Subnet construction
// ===================================================================

Subnet::Subnet() noexcept : network_addr_(), prefix_bits_(0) {}

Subnet::Subnet(NetAddress network_addr, uint8_t prefix_bits) noexcept
    : network_addr_(std::move(network_addr)), prefix_bits_(prefix_bits) {
    // Clamp to maximum for the network type.
    uint8_t max_bits = max_prefix_for_network(network_addr_.get_network());
    if (prefix_bits_ > max_bits) {
        prefix_bits_ = max_bits;
    }
    apply_mask();
}

core::Result<Subnet> Subnet::from_string(std::string_view str) {
    if (str.empty()) {
        return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                           "empty subnet string");
    }

    // Strip whitespace.
    while (!str.empty() && (str.front() == ' ' || str.front() == '\t')) {
        str.remove_prefix(1);
    }
    while (!str.empty() && (str.back() == ' ' || str.back() == '\t')) {
        str.remove_suffix(1);
    }

    // Find the '/' separator.
    auto slash_pos = str.find('/');
    std::string_view addr_part;
    uint8_t prefix = 0;
    bool has_prefix = false;

    if (slash_pos != std::string_view::npos) {
        addr_part = str.substr(0, slash_pos);
        auto prefix_str = str.substr(slash_pos + 1);
        if (prefix_str.empty()) {
            return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                               "missing prefix length after '/'");
        }
        uint32_t parsed = 0;
        auto [ptr, ec] = std::from_chars(
            prefix_str.data(), prefix_str.data() + prefix_str.size(), parsed);
        if (ec != std::errc{} || ptr != prefix_str.data() + prefix_str.size()) {
            return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                               "invalid prefix length: " + std::string(prefix_str));
        }
        if (parsed > 255) {
            return core::Error(core::ErrorCode::VALIDATION_RANGE,
                               "prefix length exceeds maximum: " + std::string(prefix_str));
        }
        prefix = static_cast<uint8_t>(parsed);
        has_prefix = true;
    } else {
        addr_part = str;
    }

    // Parse the address portion.
    auto addr_result = NetAddress::from_string(addr_part);
    if (!addr_result.ok()) {
        return core::Error(addr_result.error().code(),
                           "invalid subnet address: " + addr_result.error().message());
    }

    NetAddress addr = std::move(addr_result).value();

    if (!has_prefix) {
        // Default to single-host prefix.
        prefix = max_prefix_for_network(addr.get_network());
    }

    // Validate prefix range.
    uint8_t max_bits = max_prefix_for_network(addr.get_network());
    if (prefix > max_bits) {
        return core::Error(core::ErrorCode::VALIDATION_RANGE,
                           "prefix length " + std::to_string(prefix) +
                           " exceeds maximum " + std::to_string(max_bits) +
                           " for " + std::string(network_name(addr.get_network())));
    }

    return Subnet(std::move(addr), prefix);
}

// ===================================================================
// Subnet queries
// ===================================================================

// ===================================================================
// Factory: single-host subnet
// ===================================================================

Subnet Subnet::from_address(const NetAddress& addr) {
    uint8_t max_bits = max_prefix_for_network(addr.get_network());
    return Subnet(addr, max_bits);
}

// ===================================================================
// Subnet queries
// ===================================================================

bool Subnet::contains(const NetAddress& addr) const noexcept {
    // Must be the same network type.
    if (addr.get_network() != network_addr_.get_network()) {
        return false;
    }

    auto subnet_bytes = network_addr_.get_addr_bytes();
    auto addr_bytes = addr.get_addr_bytes();
    size_t byte_count = addr_byte_count(addr.get_network());

    if (subnet_bytes.size() < byte_count || addr_bytes.size() < byte_count) {
        return false;
    }

    return match_prefix(subnet_bytes.data(), addr_bytes.data(),
                        byte_count, prefix_bits_);
}

bool Subnet::contains_subnet(const Subnet& other) const noexcept {
    // A subnet A contains another subnet B if:
    //   1) They are the same network type
    //   2) A's prefix length <= B's prefix length (A is wider or equal)
    //   3) B's network address falls within A

    if (network_addr_.get_network() != other.network_addr_.get_network()) {
        return false;
    }

    if (prefix_bits_ > other.prefix_bits_) {
        return false; // Cannot contain a wider subnet.
    }

    // Check if the other subnet's base address falls within this subnet.
    return contains(other.network_addr_);
}

std::string Subnet::to_string() const {
    return network_addr_.to_string() + "/" + std::to_string(prefix_bits_);
}

bool Subnet::is_valid() const noexcept {
    // A subnet is valid if it has a valid base address or a meaningful prefix.
    // A /0 prefix (matching everything) with a valid address is still valid.
    return network_addr_.is_valid() || prefix_bits_ > 0;
}

bool Subnet::is_single_host() const noexcept {
    return prefix_bits_ == max_prefix_for_network(network_addr_.get_network());
}

Network Subnet::network_type() const noexcept {
    return network_addr_.get_network();
}

uint64_t Subnet::host_count() const noexcept {
    uint8_t max_bits = max_prefix_for_network(network_addr_.get_network());
    uint8_t host_bits = max_bits - prefix_bits_;

    // If the host portion exceeds 64 bits, cap at UINT64_MAX.
    if (host_bits >= 64) {
        return UINT64_MAX;
    }
    if (host_bits == 0) {
        return 1;
    }

    return uint64_t{1} << host_bits;
}

const NetAddress& Subnet::network_addr() const noexcept {
    return network_addr_;
}

uint8_t Subnet::prefix_bits() const noexcept {
    return prefix_bits_;
}

// ===================================================================
// Internal masking
// ===================================================================

void Subnet::apply_mask() noexcept {
    // The stored network_addr_ is used for prefix comparisons in contains(),
    // which dynamically masks to prefix_bits_ bits.  We do not modify the
    // internal representation here because NetAddress does not expose a
    // mutable byte interface.
    //
    // As a result, to_string() may display host bits that are technically
    // outside the prefix.  This is cosmetic and does not affect correctness
    // of contains() or contains_subnet() operations.
    //
    // If a canonicalized display is needed, callers can reconstruct the
    // subnet from the masked bytes themselves.
}

}  // namespace net
