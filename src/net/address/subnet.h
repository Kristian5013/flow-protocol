#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Subnet -- CIDR-style subnet matching for NetAddress.
//
// Represents a network prefix (e.g. "10.0.0.0/8", "2001:db8::/32") and
// provides efficient containment tests.
// ---------------------------------------------------------------------------

#include "core/error.h"
#include "core/serialize.h"
#include "net/address/netaddress.h"

#include <compare>
#include <cstdint>
#include <string>
#include <string_view>

namespace net {

class Subnet {
public:
    // -- Construction -------------------------------------------------------

    /// Default: matches nothing (0.0.0.0/0 with invalid state).
    Subnet() noexcept;

    /// Construct directly from a network address and prefix bit count.
    Subnet(NetAddress network_addr, uint8_t prefix_bits) noexcept;

    /// Parse CIDR notation: "10.0.0.0/8", "2001:db8::/32", etc.
    /// A bare address with no prefix (e.g. "1.2.3.4") is treated as a /32
    /// for IPv4 or /128 for IPv6.
    static core::Result<Subnet> from_string(std::string_view str);

    // -- Queries ------------------------------------------------------------

    /// Construct a single-host subnet from an address (/32 for IPv4, /128 for IPv6).
    static Subnet from_address(const NetAddress& addr);

    /// Returns true if the given address falls within this subnet.
    [[nodiscard]] bool contains(const NetAddress& addr) const noexcept;

    /// Returns true if the given other subnet is entirely contained in this one.
    [[nodiscard]] bool contains_subnet(const Subnet& other) const noexcept;

    /// Returns the human-readable CIDR string (e.g. "10.0.0.0/8").
    [[nodiscard]] std::string to_string() const;

    /// Returns true if the subnet represents a valid, non-empty prefix.
    [[nodiscard]] bool is_valid() const noexcept;

    /// Returns true if this subnet matches exactly one host address.
    [[nodiscard]] bool is_single_host() const noexcept;

    /// Returns the network type of this subnet.
    [[nodiscard]] Network network_type() const noexcept;

    /// Returns the number of host addresses in this subnet (capped at UINT64_MAX).
    [[nodiscard]] uint64_t host_count() const noexcept;

    /// Access the base network address.
    [[nodiscard]] const NetAddress& network_addr() const noexcept;

    /// Access the prefix length in bits.
    [[nodiscard]] uint8_t prefix_bits() const noexcept;

    // -- Comparison ---------------------------------------------------------

    auto operator<=>(const Subnet&) const = default;
    bool operator==(const Subnet&) const = default;

    // -- Serialization ------------------------------------------------------

    template <typename Stream>
    void serialize(Stream& s) const {
        network_addr_.serialize(s);
        core::ser_write_u8(s, prefix_bits_);
    }

    template <typename Stream>
    static Subnet deserialize(Stream& s) {
        auto addr = NetAddress::deserialize(s);
        auto bits = core::ser_read_u8(s);
        return Subnet(std::move(addr), bits);
    }

private:
    NetAddress network_addr_;
    uint8_t    prefix_bits_ = 0;

    /// Mask the stored network address so only the prefix bits are retained.
    void apply_mask() noexcept;
};

}  // namespace net
