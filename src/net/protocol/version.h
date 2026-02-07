#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "core/types.h"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace net::protocol {

// ---------------------------------------------------------------------------
// Service flag bits for the VERSION handshake
// ---------------------------------------------------------------------------
// Each bit represents a capability that the node advertises.  The flags are
// a bitmask that is carried in the VERSION message and in ADDR entries.
// ---------------------------------------------------------------------------
enum ServiceFlags : uint64_t {
    /// No services advertised.
    NODE_NONE              = 0,

    /// Full node: can serve the complete blockchain (non-pruned).
    NODE_NETWORK           = (1 << 0),

    /// BIP144: node can relay and validate segregated witness transactions.
    NODE_WITNESS           = (1 << 3),

    /// BIP157/158: node supports compact block filters (Golomb-coded sets).
    NODE_COMPACT_FILTERS   = (1 << 6),

    /// BIP159: node serves a limited (pruned) chain but still validates.
    NODE_NETWORK_LIMITED   = (1 << 10),
};

/// Return a human-readable description of the service flags bitmask.
[[nodiscard]] std::string service_flags_to_string(uint64_t flags);

// ---------------------------------------------------------------------------
// Protocol version constants
// ---------------------------------------------------------------------------

/// The current protocol version spoken by this implementation.
inline constexpr int32_t  PROTOCOL_VERSION = 70015;

/// The minimum protocol version we are willing to connect to.
inline constexpr int32_t  MIN_PEER_PROTO_VERSION = 70002;

/// Magic bytes identifying the FTC network on the wire.
inline constexpr uint32_t FTC_MAGIC        = 0x46544321;

/// Default P2P listen port for the FTC mainnet.
inline constexpr uint16_t FTC_DEFAULT_PORT = 9333;

/// Maximum length of the user_agent string (BIP14).
inline constexpr size_t   MAX_USER_AGENT_LENGTH = 256;

/// Maximum acceptable start_height (sanity check).
inline constexpr int32_t  MAX_START_HEIGHT = 100'000'000;

// ---------------------------------------------------------------------------
// VersionMessage -- exchanged during the initial handshake
// ---------------------------------------------------------------------------
// Layout on the wire (little-endian unless noted):
//
//   version               int32    (4 bytes)
//   services              uint64   (8 bytes)
//   timestamp             int64    (8 bytes)
//   addr_recv_services    uint64   (8 bytes)
//   addr_recv_ip          bytes    (16 bytes, IPv6-mapped)
//   addr_recv_port        uint16   (2 bytes, BIG-endian / network order)
//   addr_from_services    uint64   (8 bytes)
//   addr_from_ip          bytes    (16 bytes, IPv6-mapped)
//   addr_from_port        uint16   (2 bytes, BIG-endian / network order)
//   nonce                 uint64   (8 bytes)
//   user_agent            var_str  (compact-size + bytes)
//   start_height          int32    (4 bytes)
//   relay                 bool     (1 byte, optional -- BIP37)
//                                  ----------
//                                  ~86 bytes fixed + user_agent
// ---------------------------------------------------------------------------
struct VersionMessage {
    int32_t  version  = PROTOCOL_VERSION;
    uint64_t services = NODE_NETWORK | NODE_WITNESS;
    int64_t  timestamp = 0;

    // Address fields for the receiving node
    uint64_t                 addr_recv_services = 0;
    std::array<uint8_t, 16>  addr_recv_ip       = {};
    uint16_t                 addr_recv_port     = 0;

    // Address fields for the sending node
    uint64_t                 addr_from_services = 0;
    std::array<uint8_t, 16>  addr_from_ip       = {};
    uint16_t                 addr_from_port     = 0;

    uint64_t    nonce        = 0;
    std::string user_agent   = "/FTC:1.0.0/";
    int32_t     start_height = 0;
    bool        relay        = true;

    /// Serialize the version message to a byte vector.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize a version message from a raw byte span.
    [[nodiscard]] static core::Result<VersionMessage> deserialize(
        std::span<const uint8_t> data);

    /// Validate the message fields (version range, user_agent length, etc.).
    [[nodiscard]] core::Result<void> validate() const;

    /// Check whether a particular service flag is set.
    [[nodiscard]] bool has_service(ServiceFlags flag) const noexcept;

    /// Return the expected minimum serialized size (without user agent).
    [[nodiscard]] static constexpr size_t min_payload_size() noexcept {
        // 4+8+8 + (8+16+2) + (8+16+2) + 8 + 1(compact_size for empty str) + 4
        return 85;
    }
};

// ---------------------------------------------------------------------------
// VerackMessage -- acknowledgement of a version message (empty payload)
// ---------------------------------------------------------------------------
// VERACK has no payload.  The struct exists solely for type safety and
// consistency with the rest of the message-handling framework.
// ---------------------------------------------------------------------------
struct VerackMessage {
    /// Serialize returns an empty byte vector (no payload).
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize verifies the span is empty and returns a VerackMessage.
    [[nodiscard]] static core::Result<VerackMessage> deserialize(
        std::span<const uint8_t> data);
};

} // namespace net::protocol
