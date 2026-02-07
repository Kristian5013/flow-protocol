#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// NetAddress / AddressWithPort -- network address representation.
//
// NetAddress stores any supported network address type in a fixed-size
// 32-byte buffer, padded to accommodate future address schemes.  The
// accompanying AddressWithPort bundles an address with port, timestamp,
// and service-flag metadata.
// ---------------------------------------------------------------------------

#include "core/error.h"
#include "core/serialize.h"
#include "core/types.h"

#include <array>
#include <compare>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace net {

// ---------------------------------------------------------------------------
// Network type enumeration
// ---------------------------------------------------------------------------
enum class Network : uint8_t {
    IPV4     = 1,
    IPV6     = 2,
    TORV3    = 4,
    I2P      = 5,
    CJDNS    = 6,
    INTERNAL = 8,
};

/// Human-readable name for a Network value.
[[nodiscard]] std::string_view network_name(Network net) noexcept;

// ---------------------------------------------------------------------------
// Service flags (bitmask constants)
// ---------------------------------------------------------------------------
inline constexpr uint64_t NODE_NETWORK         = (1ULL << 0);
inline constexpr uint64_t NODE_WITNESS          = (1ULL << 3);
inline constexpr uint64_t NODE_NETWORK_LIMITED  = (1ULL << 10);

// ---------------------------------------------------------------------------
// NetAddress
// ---------------------------------------------------------------------------
class NetAddress {
public:
    // -- Construction -------------------------------------------------------

    /// Default: invalid / zero address.
    NetAddress() noexcept;

    /// Create an IPv4 address from a host-order 32-bit integer.
    static NetAddress from_ipv4(uint32_t ip) noexcept;

    /// Create an IPv6 address from a 16-byte network-order span.
    static NetAddress from_ipv6(std::span<const uint8_t, 16> ip) noexcept;

    /// Parse a human-readable address string.
    /// Supports: "1.2.3.4", "[::1]", "::1", "x.onion", etc.
    static core::Result<NetAddress> from_string(std::string_view str);

    // -- Queries ------------------------------------------------------------

    [[nodiscard]] bool is_ipv4() const noexcept;
    [[nodiscard]] bool is_ipv6() const noexcept;
    [[nodiscard]] bool is_tor() const noexcept;
    [[nodiscard]] bool is_i2p() const noexcept;
    [[nodiscard]] bool is_cjdns() const noexcept;
    [[nodiscard]] bool is_internal() const noexcept;
    [[nodiscard]] bool is_local() const noexcept;
    [[nodiscard]] bool is_routable() const noexcept;
    [[nodiscard]] bool is_valid() const noexcept;
    [[nodiscard]] bool is_rfc1918() const noexcept;   // private IPv4
    [[nodiscard]] bool is_rfc3927() const noexcept;   // link-local IPv4 (169.254/16)
    [[nodiscard]] bool is_rfc4193() const noexcept;   // private IPv6 (fc00::/7)
    [[nodiscard]] bool is_rfc4862() const noexcept;   // link-local IPv6 (fe80::/10)
    [[nodiscard]] bool is_rfc6598() const noexcept;   // carrier-grade NAT (100.64/10)
    [[nodiscard]] bool is_multicast() const noexcept; // IPv4 224/4 or IPv6 ff00::/8

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] Network get_network() const noexcept;
    [[nodiscard]] uint32_t get_ipv4() const noexcept;      // only meaningful if is_ipv4()
    [[nodiscard]] std::span<const uint8_t> get_addr_bytes() const noexcept;
    [[nodiscard]] uint8_t get_prefix_len() const noexcept;
    [[nodiscard]] uint16_t get_group_key() const noexcept;  // /16 bucket group

    /// Reachability score (higher = more preferred for outbound connections).
    /// Used for network diversification in peer selection.
    [[nodiscard]] int get_reachability_from(const NetAddress& source) const noexcept;

    // -- Comparison ---------------------------------------------------------

    auto operator<=>(const NetAddress&) const = default;
    bool operator==(const NetAddress&) const = default;

    // -- Serialization ------------------------------------------------------

    template <typename Stream>
    void serialize(Stream& s) const {
        core::ser_write_u8(s, static_cast<uint8_t>(network_));
        core::ser_write_u8(s, prefix_len_);
        core::ser_write_array(s, addr_bytes_);
    }

    template <typename Stream>
    static NetAddress deserialize(Stream& s) {
        NetAddress addr;
        addr.network_ = static_cast<Network>(core::ser_read_u8(s));
        addr.prefix_len_ = core::ser_read_u8(s);
        addr.addr_bytes_ = core::ser_read_array<Stream, 32>(s);
        return addr;
    }

private:
    Network                  network_    = Network::IPV4;
    std::array<uint8_t, 32>  addr_bytes_ = {};   // padded to 32 for future-proofing
    uint8_t                  prefix_len_ = 0;     // meaningful bits

    // Internal factory helper.
    static NetAddress make(Network net, std::span<const uint8_t> bytes, uint8_t prefix);
};

// ---------------------------------------------------------------------------
// AddressWithPort
// ---------------------------------------------------------------------------
struct AddressWithPort {
    NetAddress addr;
    uint16_t   port      = 9333;
    int64_t    timestamp = 0;   // last seen time (Unix epoch seconds)
    uint64_t   services  = 0;   // service flags bitmask

    /// Parse "1.2.3.4:9333" or "[::1]:9333".  If no port is present, the
    /// default port (9333) is used.
    static core::Result<AddressWithPort> from_string(std::string_view str,
                                                     uint16_t default_port = 9333);

    [[nodiscard]] std::string to_string() const;

    /// Return a human-readable service flags description (e.g. "NETWORK|WITNESS").
    [[nodiscard]] static std::string services_to_string(uint64_t flags);

    auto operator<=>(const AddressWithPort&) const = default;
    bool operator==(const AddressWithPort&) const = default;

    template <typename Stream>
    void serialize(Stream& s) const {
        addr.serialize(s);
        core::ser_write_u16(s, port);
        core::ser_write_i64(s, timestamp);
        core::ser_write_u64(s, services);
    }

    template <typename Stream>
    static AddressWithPort deserialize(Stream& s) {
        AddressWithPort awp;
        awp.addr      = NetAddress::deserialize(s);
        awp.port      = core::ser_read_u16(s);
        awp.timestamp = core::ser_read_i64(s);
        awp.services  = core::ser_read_u64(s);
        return awp;
    }
};

}  // namespace net

// ---------------------------------------------------------------------------
// std::hash specialization for NetAddress
// ---------------------------------------------------------------------------
template <>
struct std::hash<net::NetAddress> {
    std::size_t operator()(const net::NetAddress& addr) const noexcept;
};

template <>
struct std::hash<net::AddressWithPort> {
    std::size_t operator()(const net::AddressWithPort& awp) const noexcept;
};
