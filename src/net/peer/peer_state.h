#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// PeerState / PeerStats / PeerConfig -- peer lifecycle and metrics tracking.
//
// Each peer connection progresses through a deterministic state machine:
//
//   CONNECTING -> CONNECTED -> VERSION_SENT -> HANDSHAKE_DONE -> ACTIVE
//                                                             -> DISCONNECTING -> DISCONNECTED
//
// State transitions are protected by the owning Peer's state_mutex_.
// PeerStats aggregates per-peer traffic and latency counters.
// PeerConfig exposes compile-time protocol tuning constants.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <string>
#include <string_view>

namespace net {

// ===========================================================================
// PeerState -- lifecycle state of a single peer connection
// ===========================================================================

enum class PeerState : uint8_t {
    CONNECTING,       // TCP connection in progress
    CONNECTED,        // TCP connected, awaiting VERSION exchange
    VERSION_SENT,     // We sent our VERSION, awaiting their VERSION
    HANDSHAKE_DONE,   // VERSION/VERACK exchange completed
    ACTIVE,           // Fully operational -- relaying messages
    DISCONNECTING,    // Graceful disconnect in progress
    DISCONNECTED      // Connection closed (terminal state)
};

/// Returns a short human-readable label for the given state.
[[nodiscard]] std::string_view peer_state_name(PeerState state) noexcept;

/// Returns true if the peer is in a state where it can send/receive
/// application-level messages (ACTIVE or HANDSHAKE_DONE).
[[nodiscard]] bool peer_state_is_operational(PeerState state) noexcept;

/// Returns true if the peer has reached a terminal state and its
/// resources can be reclaimed.
[[nodiscard]] bool peer_state_is_terminal(PeerState state) noexcept;

/// Returns true if the given state transition is legal.
[[nodiscard]] bool peer_state_transition_valid(PeerState from,
                                                PeerState to) noexcept;

// ===========================================================================
// PeerStats -- per-peer traffic and latency counters
// ===========================================================================

struct PeerStats {
    int64_t  connected_time     = 0;   // Unix epoch seconds when connected
    int64_t  last_send          = 0;   // Unix epoch seconds of last send
    int64_t  last_recv          = 0;   // Unix epoch seconds of last recv
    uint64_t bytes_sent         = 0;   // total bytes sent
    uint64_t bytes_recv         = 0;   // total bytes received
    uint64_t msgs_sent          = 0;   // total messages sent
    uint64_t msgs_recv          = 0;   // total messages received
    int64_t  ping_time          = -1;  // last measured ping in ms (-1 = unknown)
    uint64_t pending_ping_nonce = 0;   // nonce of the outstanding PING (0 = none)
    int64_t  ping_sent_time     = 0;   // epoch-ms when the last PING was sent
    int32_t  misbehavior_score  = 0;   // accumulated misbehavior penalty points

    /// Reset all counters to their default (zero / unknown) values.
    void reset() noexcept;

    /// Returns a human-readable summary of the stats (single line).
    [[nodiscard]] std::string to_string() const;
};

// ===========================================================================
// DisconnectReason -- why a peer was (or is being) disconnected
// ===========================================================================

enum class DisconnectReason : uint8_t {
    NONE,                 // not disconnected / unknown
    TIMEOUT,              // handshake or inactivity timeout
    PROTOCOL_ERROR,       // invalid message framing or checksum failure
    MISBEHAVIOR,          // misbehavior score exceeded threshold
    TOO_MANY_CONNECTIONS, // connection slot limits reached
    DUPLICATE,            // duplicate connection to the same peer
    BANNED,               // peer address is in the ban list
    USER_REQUESTED        // operator / RPC requested disconnect
};

/// Returns a short human-readable label for the disconnect reason.
[[nodiscard]] std::string_view disconnect_reason_name(
    DisconnectReason reason) noexcept;

// ===========================================================================
// PeerConfig -- compile-time protocol tuning constants
// ===========================================================================

struct PeerConfig {
    /// Maximum time (seconds) allowed for VERSION/VERACK handshake.
    static constexpr int HANDSHAKE_TIMEOUT = 10;

    /// Interval (seconds) between outgoing PING probes.
    static constexpr int PING_INTERVAL = 120;

    /// Maximum idle time (seconds) before a peer is disconnected.
    static constexpr int TIMEOUT = 300;

    /// Misbehavior points at which a peer is banned.
    static constexpr int MISBEHAVIOR_THRESHOLD = 100;

    /// Maximum number of inventory items in a single INV/GETDATA message.
    static constexpr int MAX_INVENTORY_SIZE = 50000;

    /// Maximum number of headers returned in a HEADERS response.
    static constexpr int MAX_HEADERS_RESULTS = 2000;

    /// Maximum number of blocks simultaneously in transit from one peer.
    static constexpr int MAX_BLOCKS_IN_TRANSIT = 16;

    /// Size of the per-peer outgoing message queue before back-pressure.
    static constexpr int SEND_QUEUE_CAPACITY = 512;

    /// Receive buffer size (bytes) for the read loop.
    static constexpr int RECV_BUFFER_SIZE = 65536;
};

} // namespace net
