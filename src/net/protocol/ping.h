#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"

#include <cstdint>
#include <span>
#include <vector>

namespace net::protocol {

// ---------------------------------------------------------------------------
// Protocol constants for ping/pong messages
// ---------------------------------------------------------------------------

/// Size of the ping/pong payload: a single 64-bit nonce.
inline constexpr size_t PING_PAYLOAD_SIZE = 8;

/// Timeout (in seconds) after which a peer is considered unresponsive if
/// no pong has been received.  This constant is provided for reference;
/// the actual timeout handling occurs in the connection manager.
inline constexpr int64_t PING_TIMEOUT_SECONDS = 20 * 60;  // 20 minutes

// ---------------------------------------------------------------------------
// PingMessage -- keepalive / latency probe (PING command)
// ---------------------------------------------------------------------------
// A ping message carries a random 64-bit nonce.  The receiving node must
// respond with a pong message echoing the same nonce.  This mechanism
// serves two purposes:
//
//   1. Latency measurement: the sender records when it sent the ping and
//      computes the round-trip time when the pong arrives.
//   2. Liveness detection: if no pong is received within the timeout
//      period, the connection is considered stale and is dropped.
//
// The nonce should be generated using a cryptographically secure random
// number generator to prevent nonce prediction attacks.
//
// Wire format:
//   nonce    uint64   (8 bytes LE)
//
// Historical note: pre-BIP31 (protocol < 60001) ping messages had no
// payload.  We handle the legacy case in deserialization by defaulting
// the nonce to zero.
// ---------------------------------------------------------------------------
struct PingMessage {
    uint64_t nonce = 0;

    /// Serialize the ping message payload (8 bytes: nonce as LE u64).
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize a ping message from raw bytes.
    /// Handles legacy (empty) ping messages by returning nonce=0.
    [[nodiscard]] static core::Result<PingMessage> deserialize(
        std::span<const uint8_t> data);

    /// Create a PingMessage with a specific nonce value.
    [[nodiscard]] static PingMessage with_nonce(uint64_t nonce_val) noexcept;
};

// ---------------------------------------------------------------------------
// PongMessage -- response to a ping (PONG command)
// ---------------------------------------------------------------------------
// The pong message echoes back the nonce received in the corresponding
// ping message.  The sender of the original ping can then:
//   - Match the nonce to verify this is the response to its specific ping
//   - Compute the round-trip time (RTT)
//
// Wire format:
//   nonce    uint64   (8 bytes LE)
// ---------------------------------------------------------------------------
struct PongMessage {
    uint64_t nonce = 0;

    /// Serialize the pong message payload (8 bytes: nonce as LE u64).
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize a pong message from raw bytes.
    [[nodiscard]] static core::Result<PongMessage> deserialize(
        std::span<const uint8_t> data);

    /// Create a PongMessage echoing a received ping nonce.
    [[nodiscard]] static PongMessage from_ping(const PingMessage& ping) noexcept;
};

} // namespace net::protocol
