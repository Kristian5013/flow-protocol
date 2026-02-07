#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// PeerInfo -- identification and negotiated capabilities of a peer.
//
// Populated progressively during the handshake:
//   1. id, address, port, inbound -- set at construction (before VERSION)
//   2. version, services, user_agent, start_height, relay, nonce
//      -- filled from the remote peer's VERSION message
//   3. send_headers, compact_blocks, compact_high_bw, fee_filter
//      -- updated when the corresponding feature-negotiation messages
//         (SENDHEADERS, SENDCMPCT, FEEFILTER) are received
//   4. best_height, best_hash
//      -- updated continuously from INV/HEADERS announcements
//
// All fields are plain-old-data and are accessed under the owning Peer's
// state_mutex_ -- no internal synchronization is needed here.
// ---------------------------------------------------------------------------

#include "core/types.h"

#include <cstdint>
#include <string>

namespace net {

// ===========================================================================
// Protocol version constants
// ===========================================================================

/// Minimum protocol version we are willing to communicate with.
inline constexpr int32_t MIN_PEER_PROTO_VERSION = 70015;

/// Our own advertised protocol version.
inline constexpr int32_t PROTOCOL_VERSION = 70020;

/// Protocol version that introduced SENDHEADERS.
inline constexpr int32_t SENDHEADERS_VERSION = 70012;

/// Protocol version that introduced SENDCMPCT (compact blocks).
inline constexpr int32_t COMPACT_BLOCKS_VERSION = 70014;

/// Protocol version that introduced FEEFILTER.
inline constexpr int32_t FEEFILTER_VERSION = 70013;

// ===========================================================================
// Service flag constants  (re-exported from netaddress.h for convenience)
// ===========================================================================

inline constexpr uint64_t SERVICE_NODE_NETWORK         = (1ULL << 0);
inline constexpr uint64_t SERVICE_NODE_WITNESS          = (1ULL << 3);
inline constexpr uint64_t SERVICE_NODE_NETWORK_LIMITED  = (1ULL << 10);

// ===========================================================================
// PeerInfo
// ===========================================================================

struct PeerInfo {
    // --- Set at construction ------------------------------------------------

    uint64_t    id       = 0;         // unique peer ID (auto-incremented)
    std::string address;              // "1.2.3.4:9333"
    uint16_t    port     = 0;
    bool        inbound  = false;     // true if they connected to us

    // --- From the remote VERSION message ------------------------------------

    int32_t     version      = 0;        // protocol version
    uint64_t    services     = 0;        // service flags bitmask
    std::string user_agent;              // sub-version string
    int32_t     start_height = 0;        // height the peer reported at connect
    bool        relay        = true;     // fRelay from VERSION
    uint64_t    nonce        = 0;        // self-connection detection nonce

    // --- Feature negotiation ------------------------------------------------

    bool    send_headers     = false;    // SENDHEADERS received
    bool    compact_blocks   = false;    // SENDCMPCT received
    bool    compact_high_bw  = false;    // high-bandwidth compact relay mode
    int64_t fee_filter       = 0;        // FEEFILTER threshold (sat/kvB)

    // --- Dynamic peer knowledge ---------------------------------------------

    int32_t        best_height = 0;      // their announced best chain height
    core::uint256  best_hash;            // their announced best block hash

    // --- Convenience --------------------------------------------------------

    /// Returns true if the peer advertises NODE_NETWORK service.
    [[nodiscard]] bool is_full_node() const noexcept;

    /// Returns true if the peer advertises NODE_WITNESS service.
    [[nodiscard]] bool has_witness() const noexcept;

    /// Returns true if the peer's protocol version meets the minimum.
    [[nodiscard]] bool is_version_acceptable() const noexcept;

    /// Returns true if the peer supports SENDHEADERS.
    [[nodiscard]] bool supports_send_headers() const noexcept;

    /// Returns true if the peer supports compact blocks.
    [[nodiscard]] bool supports_compact_blocks() const noexcept;

    /// Returns true if the peer supports FEEFILTER.
    [[nodiscard]] bool supports_fee_filter() const noexcept;

    /// Human-readable single-line summary for logging.
    [[nodiscard]] std::string to_string() const;
};

} // namespace net
