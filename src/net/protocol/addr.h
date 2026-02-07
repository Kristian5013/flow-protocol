#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace net::protocol {

// ---------------------------------------------------------------------------
// Protocol constants for address messages
// ---------------------------------------------------------------------------

/// Maximum number of address entries per ADDR message.
/// Bitcoin Core enforces this limit to prevent memory exhaustion.
inline constexpr size_t MAX_ADDR_ENTRIES = 1000;

/// Size of a single serialized address entry on the wire:
///   timestamp (4) + services (8) + ip (16) + port (2) = 30 bytes.
inline constexpr size_t ADDR_ENTRY_SIZE = 30;

/// IPv4-mapped IPv6 prefix: ::ffff:0:0/96 (first 12 bytes).
/// When a peer has an IPv4 address, it is encoded as an IPv4-mapped IPv6
/// address: the first 10 bytes are zero, bytes 10-11 are 0xFF, and bytes
/// 12-15 contain the IPv4 address.
inline constexpr std::array<uint8_t, 12> IPV4_MAPPED_PREFIX = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF
};

// ---------------------------------------------------------------------------
// AddressEntry -- a single peer address record
// ---------------------------------------------------------------------------
// Each entry carries a timestamp (last time the address was seen active),
// service flags, a 16-byte IPv6-mapped address, and a port number.
//
// IPv4 addresses are encoded as IPv4-mapped IPv6 addresses following the
// convention ::ffff:x.x.x.x.  For example, 192.168.1.1 is stored as:
//   00 00 00 00 00 00 00 00 00 00 FF FF C0 A8 01 01
//
// Wire format:
//   timestamp    uint32   (4 bytes LE)
//   services     uint64   (8 bytes LE)
//   ip           bytes    (16 bytes)
//   port         uint16   (2 bytes BE / network byte order)
// ---------------------------------------------------------------------------
struct AddressEntry {
    uint32_t                timestamp = 0;   // last-seen time (Unix epoch)
    uint64_t                services  = 0;   // service flags
    std::array<uint8_t, 16> ip        = {};  // IPv6 (or IPv4-mapped) address
    uint16_t                port      = 0;   // port in host byte order

    /// Serialize a single address entry to a stream.
    template <typename Stream>
    void serialize_to(Stream& s) const;

    /// Deserialize a single address entry from a stream.
    template <typename Stream>
    static AddressEntry deserialize_from(Stream& s);

    /// Check whether this entry represents an IPv4-mapped IPv6 address.
    [[nodiscard]] bool is_ipv4() const noexcept;

    /// Return a human-readable string like "[::ffff:192.168.1.1]:9333".
    [[nodiscard]] std::string to_string() const;

    /// Return true if the address is routable (not loopback, private, etc.).
    /// This is a basic check; full routability analysis may be more complex.
    [[nodiscard]] bool is_routable() const noexcept;

    [[nodiscard]] bool operator==(const AddressEntry& other) const;
    [[nodiscard]] bool operator!=(const AddressEntry& other) const;
};

// ---------------------------------------------------------------------------
// AddrMessage -- announce known peer addresses (ADDR command)
// ---------------------------------------------------------------------------
// Nodes periodically send ADDR messages to share peer addresses with their
// neighbors, enabling network discovery.  The message carries up to 1000
// address entries.  Nodes should not forward ADDR messages containing more
// than 10 entries at a time to limit bandwidth consumption.
//
// Wire format:
//   count       compact_size  (1-3 bytes)
//   addresses   [count]       (30 bytes each)
// ---------------------------------------------------------------------------
struct AddrMessage {
    std::vector<AddressEntry> addresses;

    /// Serialize the addr message payload.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize an addr message from raw bytes.
    [[nodiscard]] static core::Result<AddrMessage> deserialize(
        std::span<const uint8_t> data);

    /// Validate the message (entry count limits).
    [[nodiscard]] core::Result<void> validate() const;
};

// ---------------------------------------------------------------------------
// GetAddrMessage -- request peer addresses (GETADDR command, empty payload)
// ---------------------------------------------------------------------------
// Sent once after the version handshake to request the peer's known
// addresses.  The peer responds with one or more ADDR messages.
// ---------------------------------------------------------------------------
struct GetAddrMessage {
    /// Serialize returns an empty byte vector (no payload).
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize verifies the span is empty and returns a GetAddrMessage.
    [[nodiscard]] static core::Result<GetAddrMessage> deserialize(
        std::span<const uint8_t> data);
};

} // namespace net::protocol
