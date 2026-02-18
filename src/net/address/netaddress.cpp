// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/address/netaddress.h"
#include "core/logging.h"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <functional>
#include <sstream>
#include <stdexcept>

namespace net {

// ===================================================================
// Network name mapping
// ===================================================================

std::string_view network_name(Network net) noexcept {
    switch (net) {
        case Network::IPV4:     return "IPv4";
        case Network::IPV6:     return "IPv6";
        case Network::TORV3:    return "TORv3";
        case Network::I2P:      return "I2P";
        case Network::CJDNS:    return "CJDNS";
        case Network::INTERNAL: return "Internal";
        default:                return "Unknown";
    }
}

// ===================================================================
// Internal helpers
// ===================================================================

namespace {

/// Parse a dotted-quad IPv4 string into a host-order uint32_t.
/// Returns false on any parse failure.
bool parse_ipv4(std::string_view str, uint32_t& out) {
    uint32_t result = 0;
    int octet_count = 0;

    size_t pos = 0;
    while (pos <= str.size() && octet_count < 4) {
        // Find the next dot or end-of-string.
        size_t dot = str.find('.', pos);
        if (dot == std::string_view::npos) {
            dot = str.size();
        }

        std::string_view part = str.substr(pos, dot - pos);
        if (part.empty() || part.size() > 3) {
            return false;
        }

        // Reject leading zeros (e.g. "01.02.03.04").
        if (part.size() > 1 && part[0] == '0') {
            return false;
        }

        uint32_t val = 0;
        auto [ptr, ec] = std::from_chars(part.data(), part.data() + part.size(), val);
        if (ec != std::errc{} || ptr != part.data() + part.size()) {
            return false;
        }
        if (val > 255) {
            return false;
        }

        result = (result << 8) | val;
        ++octet_count;
        pos = dot + 1;
    }

    if (octet_count != 4) {
        return false;
    }
    // Make sure there is nothing trailing.
    if (pos - 1 != str.size()) {
        return false;
    }

    out = result;
    return true;
}

/// Parse a hex nibble character.  Returns -1 on failure.
int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

/// Parse an IPv6 address string into 16 bytes (network order).
/// Supports "::" shorthand but NOT zone IDs, embedded IPv4, etc.
bool parse_ipv6(std::string_view str, uint8_t out[16]) {
    std::memset(out, 0, 16);

    // Strip surrounding brackets if present.
    if (str.size() >= 2 && str.front() == '[' && str.back() == ']') {
        str = str.substr(1, str.size() - 2);
    }

    if (str.empty()) {
        return false;
    }

    // Split into groups.  We need to handle "::" expansion.
    // Strategy: parse left-side groups and right-side groups separately.
    uint16_t left[8] = {};
    uint16_t right[8] = {};
    int left_count = 0;
    int right_count = 0;
    bool has_double_colon = false;

    // Find "::" position.
    auto dc_pos = str.find("::");
    std::string_view left_part;
    std::string_view right_part;

    if (dc_pos != std::string_view::npos) {
        has_double_colon = true;
        left_part = str.substr(0, dc_pos);
        right_part = str.substr(dc_pos + 2);
    } else {
        left_part = str;
    }

    // Parse a colon-separated group list.
    auto parse_groups = [](std::string_view s, uint16_t* groups, int& count) -> bool {
        count = 0;
        if (s.empty()) return true;

        size_t pos = 0;
        while (pos <= s.size() && count < 8) {
            size_t colon = s.find(':', pos);
            if (colon == std::string_view::npos) colon = s.size();
            std::string_view group = s.substr(pos, colon - pos);
            if (group.empty() || group.size() > 4) return false;

            uint16_t val = 0;
            for (char c : group) {
                int n = hex_nibble(c);
                if (n < 0) return false;
                val = static_cast<uint16_t>((val << 4) | n);
            }
            groups[count++] = val;
            pos = colon + 1;
        }
        // Check no trailing content.
        return pos - 1 == s.size() || s.empty();
    };

    if (!parse_groups(left_part, left, left_count)) return false;
    if (has_double_colon) {
        if (!parse_groups(right_part, right, right_count)) return false;
    }

    int total = left_count + right_count;
    if (has_double_colon) {
        if (total > 8) return false;
    } else {
        if (total != 8) return false;
    }

    // Fill output: left groups at the beginning, right groups at the end.
    for (int i = 0; i < left_count; ++i) {
        out[i * 2]     = static_cast<uint8_t>(left[i] >> 8);
        out[i * 2 + 1] = static_cast<uint8_t>(left[i] & 0xFF);
    }
    // Right groups fill from the end.
    int right_start = 8 - right_count;
    for (int i = 0; i < right_count; ++i) {
        int idx = right_start + i;
        out[idx * 2]     = static_cast<uint8_t>(right[i] >> 8);
        out[idx * 2 + 1] = static_cast<uint8_t>(right[i] & 0xFF);
    }

    return true;
}

/// Check if 16 bytes represent an IPv4-mapped IPv6 address (::ffff:x.x.x.x).
bool is_ipv4_mapped_ipv6(const uint8_t bytes[16]) {
    static constexpr uint8_t prefix[12] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF
    };
    return std::memcmp(bytes, prefix, 12) == 0;
}

}  // anonymous namespace

// ===================================================================
// NetAddress construction
// ===================================================================

NetAddress::NetAddress() noexcept
    : network_(Network::IPV4), addr_bytes_{}, prefix_len_(0) {}

NetAddress NetAddress::make(Network net, std::span<const uint8_t> bytes, uint8_t prefix) {
    NetAddress addr;
    addr.network_ = net;
    addr.prefix_len_ = prefix;
    addr.addr_bytes_.fill(0);
    size_t copy_len = std::min(bytes.size(), addr.addr_bytes_.size());
    std::memcpy(addr.addr_bytes_.data(), bytes.data(), copy_len);
    return addr;
}

NetAddress NetAddress::from_ipv4(uint32_t ip) noexcept {
    uint8_t bytes[4];
    bytes[0] = static_cast<uint8_t>((ip >> 24) & 0xFF);
    bytes[1] = static_cast<uint8_t>((ip >> 16) & 0xFF);
    bytes[2] = static_cast<uint8_t>((ip >> 8) & 0xFF);
    bytes[3] = static_cast<uint8_t>(ip & 0xFF);
    return make(Network::IPV4, std::span<const uint8_t>(bytes, 4), 32);
}

NetAddress NetAddress::from_ipv6(std::span<const uint8_t, 16> ip) noexcept {
    // Check for IPv4-mapped IPv6 and store as plain IPv4.
    if (is_ipv4_mapped_ipv6(ip.data())) {
        uint32_t ipv4 = (static_cast<uint32_t>(ip[12]) << 24)
                       | (static_cast<uint32_t>(ip[13]) << 16)
                       | (static_cast<uint32_t>(ip[14]) << 8)
                       | static_cast<uint32_t>(ip[15]);
        return from_ipv4(ipv4);
    }
    return make(Network::IPV6, std::span<const uint8_t>(ip.data(), 16), 128);
}

core::Result<NetAddress> NetAddress::from_string(std::string_view str) {
    if (str.empty()) {
        return core::Error(core::ErrorCode::PARSE_BAD_FORMAT, "empty address string");
    }

    // Strip whitespace.
    while (!str.empty() && (str.front() == ' ' || str.front() == '\t')) {
        str.remove_prefix(1);
    }
    while (!str.empty() && (str.back() == ' ' || str.back() == '\t')) {
        str.remove_suffix(1);
    }

    // Try IPv4 first.
    uint32_t ipv4 = 0;
    if (parse_ipv4(str, ipv4)) {
        return from_ipv4(ipv4);
    }

    // Try IPv6 (with or without brackets).
    uint8_t ipv6_bytes[16];
    if (parse_ipv6(str, ipv6_bytes)) {
        std::array<uint8_t, 16> arr;
        std::memcpy(arr.data(), ipv6_bytes, 16);
        return from_ipv6(std::span<const uint8_t, 16>(arr));
    }

    // Check for TORv3 .onion address (56 char base32 + ".onion").
    if (str.size() > 6) {
        auto suffix = str.substr(str.size() - 6);
        if (suffix == ".onion" || suffix == ".ONION") {
            auto host = str.substr(0, str.size() - 6);
            if (host.size() == 56) {
                // Store the raw onion hostname bytes (ASCII) in addr_bytes.
                // TORv3 addresses are 56 base32 characters encoding 35 bytes.
                NetAddress addr;
                addr.network_ = Network::TORV3;
                addr.prefix_len_ = 0;
                addr.addr_bytes_.fill(0);
                size_t copy_len = std::min(host.size(), size_t{32});
                std::memcpy(addr.addr_bytes_.data(), host.data(), copy_len);
                return addr;
            }
            return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                               "invalid TORv3 onion address length");
        }
    }

    return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                       "unrecognized address format: " + std::string(str));
}

// ===================================================================
// NetAddress queries
// ===================================================================

bool NetAddress::is_ipv4() const noexcept { return network_ == Network::IPV4; }
bool NetAddress::is_ipv6() const noexcept { return network_ == Network::IPV6; }
bool NetAddress::is_tor() const noexcept { return network_ == Network::TORV3; }
bool NetAddress::is_i2p() const noexcept { return network_ == Network::I2P; }
bool NetAddress::is_cjdns() const noexcept { return network_ == Network::CJDNS; }
bool NetAddress::is_internal() const noexcept { return network_ == Network::INTERNAL; }

bool NetAddress::is_rfc1918() const noexcept {
    if (!is_ipv4()) return false;
    uint8_t a = addr_bytes_[0];
    uint8_t b = addr_bytes_[1];
    // 10.0.0.0/8
    if (a == 10) return true;
    // 172.16.0.0/12
    if (a == 172 && (b >= 16 && b <= 31)) return true;
    // 192.168.0.0/16
    if (a == 192 && b == 168) return true;
    return false;
}

bool NetAddress::is_rfc3927() const noexcept {
    if (!is_ipv4()) return false;
    // 169.254.0.0/16 (link-local)
    return addr_bytes_[0] == 169 && addr_bytes_[1] == 254;
}

bool NetAddress::is_rfc4193() const noexcept {
    if (!is_ipv6()) return false;
    // fc00::/7  -->  first byte & 0xFE == 0xFC
    return (addr_bytes_[0] & 0xFE) == 0xFC;
}

bool NetAddress::is_rfc4862() const noexcept {
    if (!is_ipv6()) return false;
    // fe80::/10
    return addr_bytes_[0] == 0xFE && (addr_bytes_[1] & 0xC0) == 0x80;
}

bool NetAddress::is_rfc6598() const noexcept {
    if (!is_ipv4()) return false;
    // 100.64.0.0/10 (carrier-grade NAT)
    return addr_bytes_[0] == 100 && (addr_bytes_[1] & 0xC0) == 64;
}

bool NetAddress::is_multicast() const noexcept {
    if (is_ipv4()) {
        // 224.0.0.0/4
        return (addr_bytes_[0] & 0xF0) == 224;
    }
    if (is_ipv6()) {
        // ff00::/8
        return addr_bytes_[0] == 0xFF;
    }
    return false;
}

bool NetAddress::is_local() const noexcept {
    if (is_internal()) return true;

    if (is_ipv4()) {
        // 127.0.0.0/8 (loopback)
        return addr_bytes_[0] == 127;
    }

    if (is_ipv6()) {
        // ::1 (loopback)
        bool all_zero = true;
        for (int i = 0; i < 15; ++i) {
            if (addr_bytes_[i] != 0) { all_zero = false; break; }
        }
        if (all_zero && addr_bytes_[15] == 1) return true;

        // fe80::/10 (link-local)
        if (is_rfc4862()) return true;
    }

    return false;
}

bool NetAddress::is_routable() const noexcept {
    if (!is_valid()) return false;
    if (is_local()) return false;
    if (is_internal()) return false;

    if (is_ipv4()) {
        // 0.0.0.0/8 (current network)
        if (addr_bytes_[0] == 0) return false;
        // 169.254.0.0/16 (link-local, RFC 3927)
        if (addr_bytes_[0] == 169 && addr_bytes_[1] == 254) return false;
        // RFC 1918 (private)
        if (is_rfc1918()) return false;
        // 100.64.0.0/10 (carrier-grade NAT, RFC 6598)
        if (addr_bytes_[0] == 100 && (addr_bytes_[1] & 0xC0) == 64) return false;
        // 192.0.0.0/24 (IETF protocol assignments, RFC 6890)
        if (addr_bytes_[0] == 192 && addr_bytes_[1] == 0 && addr_bytes_[2] == 0)
            return false;
        // 192.0.2.0/24 (TEST-NET-1, documentation, RFC 5737)
        if (addr_bytes_[0] == 192 && addr_bytes_[1] == 0 && addr_bytes_[2] == 2)
            return false;
        // 198.51.100.0/24 (TEST-NET-2, documentation, RFC 5737)
        if (addr_bytes_[0] == 198 && addr_bytes_[1] == 51 && addr_bytes_[2] == 100)
            return false;
        // 203.0.113.0/24 (TEST-NET-3, documentation, RFC 5737)
        if (addr_bytes_[0] == 203 && addr_bytes_[1] == 0 && addr_bytes_[2] == 113)
            return false;
        // 198.18.0.0/15 (benchmark testing, RFC 2544)
        if (addr_bytes_[0] == 198 && (addr_bytes_[1] & 0xFE) == 18) return false;
        // 224.0.0.0/4 (multicast, RFC 5771)
        if ((addr_bytes_[0] & 0xF0) == 224) return false;
        // 240.0.0.0/4 (reserved for future use, RFC 1112)
        if (addr_bytes_[0] >= 240) return false;
        // 255.255.255.255/32 (limited broadcast)
        if (addr_bytes_[0] == 255 && addr_bytes_[1] == 255 &&
            addr_bytes_[2] == 255 && addr_bytes_[3] == 255) return false;
        return true;
    }

    if (is_ipv6()) {
        // Unique local (fc00::/7, RFC 4193)
        if (is_rfc4193()) return false;
        // Link-local (fe80::/10, RFC 4862)
        if (is_rfc4862()) return false;
        // Documentation (2001:db8::/32, RFC 3849)
        if (addr_bytes_[0] == 0x20 && addr_bytes_[1] == 0x01 &&
            addr_bytes_[2] == 0x0D && addr_bytes_[3] == 0xB8) return false;
        // Discard-only (100::/64, RFC 6666)
        if (addr_bytes_[0] == 0x01 && addr_bytes_[1] == 0x00 &&
            addr_bytes_[2] == 0x00 && addr_bytes_[3] == 0x00 &&
            addr_bytes_[4] == 0x00 && addr_bytes_[5] == 0x00 &&
            addr_bytes_[6] == 0x00 && addr_bytes_[7] == 0x00) return false;
        // 6to4 relay anycast (2002::/16, RFC 3068) -- often abused
        if (addr_bytes_[0] == 0x20 && addr_bytes_[1] == 0x02) return false;
        // Teredo tunneling (2001:0000::/32, RFC 4380) -- not directly routable
        if (addr_bytes_[0] == 0x20 && addr_bytes_[1] == 0x01 &&
            addr_bytes_[2] == 0x00 && addr_bytes_[3] == 0x00) return false;
        // Multicast (ff00::/8)
        if (addr_bytes_[0] == 0xFF) return false;
        return true;
    }

    // Tor, I2P, CJDNS are always considered routable.
    if (is_tor() || is_i2p() || is_cjdns()) return true;

    return false;
}

bool NetAddress::is_valid() const noexcept {
    if (is_ipv4()) {
        // Must have at least one non-zero byte.
        return !(addr_bytes_[0] == 0 && addr_bytes_[1] == 0 &&
                 addr_bytes_[2] == 0 && addr_bytes_[3] == 0);
    }
    if (is_ipv6()) {
        // Must not be all zeros.
        for (int i = 0; i < 16; ++i) {
            if (addr_bytes_[i] != 0) return true;
        }
        return false;
    }
    if (is_tor()) {
        // Must have some content.
        for (size_t i = 0; i < 32; ++i) {
            if (addr_bytes_[i] != 0) return true;
        }
        return false;
    }
    // I2P, CJDNS: require non-zero content.
    if (is_i2p() || is_cjdns()) {
        for (size_t i = 0; i < 32; ++i) {
            if (addr_bytes_[i] != 0) return true;
        }
        return false;
    }
    // Internal addresses are valid by definition (used for internal routing).
    if (is_internal()) return true;
    return false;
}

Network NetAddress::get_network() const noexcept { return network_; }

uint32_t NetAddress::get_ipv4() const noexcept {
    if (!is_ipv4()) return 0;
    return (static_cast<uint32_t>(addr_bytes_[0]) << 24)
         | (static_cast<uint32_t>(addr_bytes_[1]) << 16)
         | (static_cast<uint32_t>(addr_bytes_[2]) << 8)
         | static_cast<uint32_t>(addr_bytes_[3]);
}

std::span<const uint8_t> NetAddress::get_addr_bytes() const noexcept {
    switch (network_) {
        case Network::IPV4:  return {addr_bytes_.data(), 4};
        case Network::IPV6:  return {addr_bytes_.data(), 16};
        case Network::TORV3: return {addr_bytes_.data(), 32};
        case Network::I2P:   return {addr_bytes_.data(), 32};
        case Network::CJDNS: return {addr_bytes_.data(), 16};
        default:             return {addr_bytes_.data(), 32};
    }
}

uint8_t NetAddress::get_prefix_len() const noexcept { return prefix_len_; }

uint16_t NetAddress::get_group_key() const noexcept {
    // Returns a /16 group key for eclipse-attack bucketing.
    if (is_ipv4()) {
        return static_cast<uint16_t>(
            (static_cast<uint16_t>(addr_bytes_[0]) << 8) | addr_bytes_[1]);
    }
    if (is_ipv6()) {
        return static_cast<uint16_t>(
            (static_cast<uint16_t>(addr_bytes_[0]) << 8) | addr_bytes_[1]);
    }
    // For anonymity networks, group by network type.
    return static_cast<uint16_t>(network_);
}

// ===================================================================
// NetAddress reachability scoring
// ===================================================================

int NetAddress::get_reachability_from(const NetAddress& source) const noexcept {
    // Reachability score from the perspective of a source address.
    // Higher values indicate more reachable / preferred network paths.
    //
    // Scoring table (similar to Bitcoin Core's GetReachabilityFrom):
    //   0 = unreachable
    //   1 = same network type, low priority
    //   2 = cross-network, moderate
    //   3 = same network type, high priority
    //   4 = native same-network, best
    //
    // This helps diversify outbound connections across network types.

    if (!is_valid()) return 0;
    if (!is_routable()) return 0;

    // Internal addresses are never reachable from outside.
    if (is_internal()) return 0;

    Network src_net = source.get_network();
    Network dst_net = get_network();

    // Same network type is generally best.
    if (src_net == dst_net) {
        return 4;
    }

    // IPv4 <-> IPv6 cross-network.
    if ((src_net == Network::IPV4 && dst_net == Network::IPV6) ||
        (src_net == Network::IPV6 && dst_net == Network::IPV4)) {
        return 3;
    }

    // Clearnet to anonymity network.
    if ((src_net == Network::IPV4 || src_net == Network::IPV6) &&
        (dst_net == Network::TORV3 || dst_net == Network::I2P || dst_net == Network::CJDNS)) {
        return 2;
    }

    // Anonymity network to clearnet.
    if ((dst_net == Network::IPV4 || dst_net == Network::IPV6) &&
        (src_net == Network::TORV3 || src_net == Network::I2P || src_net == Network::CJDNS)) {
        return 2;
    }

    // Different anonymity networks.
    if (src_net != dst_net) {
        return 1;
    }

    return 1;
}

// ===================================================================
// NetAddress to_string
// ===================================================================

std::string NetAddress::to_string() const {
    if (is_ipv4()) {
        return std::to_string(addr_bytes_[0]) + "." +
               std::to_string(addr_bytes_[1]) + "." +
               std::to_string(addr_bytes_[2]) + "." +
               std::to_string(addr_bytes_[3]);
    }

    if (is_ipv6()) {
        // Format as canonical IPv6 with :: compression.
        uint16_t groups[8];
        for (int i = 0; i < 8; ++i) {
            groups[i] = static_cast<uint16_t>(
                (static_cast<uint16_t>(addr_bytes_[i * 2]) << 8)
                | addr_bytes_[i * 2 + 1]);
        }

        // Find the longest run of consecutive zero groups for :: compression.
        int best_start = -1, best_len = 0;
        int cur_start = -1, cur_len = 0;
        for (int i = 0; i < 8; ++i) {
            if (groups[i] == 0) {
                if (cur_start < 0) cur_start = i;
                ++cur_len;
                if (cur_len > best_len) {
                    best_start = cur_start;
                    best_len = cur_len;
                }
            } else {
                cur_start = -1;
                cur_len = 0;
            }
        }

        std::string result;
        // Only compress if at least 2 consecutive zero groups.
        if (best_len < 2) best_start = -1;

        for (int i = 0; i < 8; ++i) {
            if (i == best_start) {
                result += "::";
                i += best_len - 1;
                continue;
            }
            if (i > 0 && !(i == best_start + best_len && best_start >= 0)) {
                // Append colon unless we just emitted "::".
                if (result.empty() || result.back() != ':') {
                    result += ':';
                }
            }
            // Hex format without leading zeros.
            char buf[8];
            auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), groups[i], 16);
            result.append(buf, ptr);
        }

        return result;
    }

    if (is_tor()) {
        // Reconstruct the .onion hostname from stored ASCII bytes.
        std::string host;
        for (size_t i = 0; i < 32 && addr_bytes_[i] != 0; ++i) {
            host += static_cast<char>(addr_bytes_[i]);
        }
        return host + ".onion";
    }

    if (is_internal()) {
        return "[internal]";
    }

    // Fallback: hex dump.
    std::string result = "[" + std::string(network_name(network_)) + ":";
    static constexpr char hex_chars[] = "0123456789abcdef";
    auto bytes = get_addr_bytes();
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0 && (i % 2) == 0) result += ':';
        result += hex_chars[bytes[i] >> 4];
        result += hex_chars[bytes[i] & 0x0F];
    }
    result += "]";
    return result;
}

// ===================================================================
// AddressWithPort
// ===================================================================

core::Result<AddressWithPort> AddressWithPort::from_string(
    std::string_view str, uint16_t default_port) {
    if (str.empty()) {
        return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                           "empty address-with-port string");
    }

    // Strip whitespace.
    while (!str.empty() && (str.front() == ' ' || str.front() == '\t')) {
        str.remove_prefix(1);
    }
    while (!str.empty() && (str.back() == ' ' || str.back() == '\t')) {
        str.remove_suffix(1);
    }

    std::string_view addr_part;
    uint16_t port = default_port;
    if (!str.empty() && str.front() == '[') {
        // Bracketed IPv6: "[::1]:9333"
        auto close = str.find(']');
        if (close == std::string_view::npos) {
            return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                               "missing closing bracket in IPv6 address");
        }
        addr_part = str.substr(1, close - 1);
        auto rest = str.substr(close + 1);
        if (!rest.empty()) {
            if (rest.front() != ':') {
                return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                                   "expected ':' after ']' in address");
            }
            auto port_str = rest.substr(1);
            if (port_str.empty()) {
                return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                                   "missing port number after ':'");
            }
            uint32_t parsed = 0;
            auto [ptr, ec] = std::from_chars(
                port_str.data(), port_str.data() + port_str.size(), parsed);
            if (ec != std::errc{} || ptr != port_str.data() + port_str.size()) {
                return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                                   "invalid port: " + std::string(port_str));
            }
            if (parsed > 65535) {
                return core::Error(core::ErrorCode::VALIDATION_RANGE,
                                   "port out of range: " + std::string(port_str));
            }
            port = static_cast<uint16_t>(parsed);
            // port was parsed successfully
        }
    } else {
        // Non-bracketed: could be "1.2.3.4:9333" or just "1.2.3.4".
        // For IPv4, the last colon separates address from port.
        // Count colons -- if more than one, it is a bare IPv6 with no port.
        size_t colon_count = 0;
        size_t last_colon = std::string_view::npos;
        for (size_t i = 0; i < str.size(); ++i) {
            if (str[i] == ':') {
                ++colon_count;
                last_colon = i;
            }
        }

        if (colon_count == 1) {
            // Exactly one colon: "addr:port"
            addr_part = str.substr(0, last_colon);
            auto port_str = str.substr(last_colon + 1);
            if (!port_str.empty()) {
                uint32_t parsed = 0;
                auto [ptr, ec] = std::from_chars(
                    port_str.data(), port_str.data() + port_str.size(), parsed);
                if (ec != std::errc{} || ptr != port_str.data() + port_str.size()) {
                    return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                                       "invalid port: " + std::string(port_str));
                }
                if (parsed > 65535) {
                    return core::Error(core::ErrorCode::VALIDATION_RANGE,
                                       "port out of range: " + std::string(port_str));
                }
                port = static_cast<uint16_t>(parsed);
                // port was parsed successfully
            }
        } else {
            // Zero colons (plain IPv4 / hostname) or multiple colons (bare IPv6).
            addr_part = str;
        }
    }

    auto addr_result = NetAddress::from_string(addr_part);
    if (!addr_result.ok()) {
        return core::Error(addr_result.error().code(),
                           addr_result.error().message());
    }

    AddressWithPort awp;
    awp.addr = std::move(addr_result).value();
    awp.port = port;
    return awp;
}

std::string AddressWithPort::to_string() const {
    if (addr.is_ipv6()) {
        return "[" + addr.to_string() + "]:" + std::to_string(port);
    }
    return addr.to_string() + ":" + std::to_string(port);
}

std::string AddressWithPort::services_to_string(uint64_t flags) {
    if (flags == 0) return "NONE";

    std::string result;

    auto append_flag = [&](uint64_t flag, const char* name) {
        if (flags & flag) {
            if (!result.empty()) result += '|';
            result += name;
        }
    };

    append_flag(NODE_NETWORK, "NETWORK");
    append_flag(NODE_WITNESS, "WITNESS");
    append_flag(NODE_NETWORK_LIMITED, "NETWORK_LIMITED");

    // Check for unknown flags.
    uint64_t known = NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED;
    uint64_t unknown = flags & ~known;
    if (unknown != 0) {
        if (!result.empty()) result += '|';
        result += "0x";
        // Hex format for unknown bits.
        static constexpr char hex_chars[] = "0123456789abcdef";
        bool started = false;
        for (int i = 60; i >= 0; i -= 4) {
            int nibble = static_cast<int>((unknown >> i) & 0xF);
            if (nibble != 0 || started) {
                result += hex_chars[nibble];
                started = true;
            }
        }
        if (!started) result += '0';
    }

    return result;
}

}  // namespace net

// ===================================================================
// std::hash specializations
// ===================================================================

std::size_t std::hash<net::NetAddress>::operator()(
    const net::NetAddress& addr) const noexcept {
    // FNV-1a over the network byte + address bytes.
    std::size_t h = 14695981039346656037ULL;
    h ^= static_cast<std::size_t>(addr.get_network());
    h *= 1099511628211ULL;
    auto bytes = addr.get_addr_bytes();
    for (auto b : bytes) {
        h ^= static_cast<std::size_t>(b);
        h *= 1099511628211ULL;
    }
    return h;
}

std::size_t std::hash<net::AddressWithPort>::operator()(
    const net::AddressWithPort& awp) const noexcept {
    std::size_t h = std::hash<net::NetAddress>{}(awp.addr);
    h ^= std::hash<uint16_t>{}(awp.port) + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
}
