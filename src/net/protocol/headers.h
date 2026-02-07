#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "core/types.h"
#include "primitives/block_header.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace net::protocol {

// ---------------------------------------------------------------------------
// Protocol constants for header-related messages
// ---------------------------------------------------------------------------

/// Maximum number of headers per HEADERS message.
/// Bitcoin Core returns at most 2000 headers per request.
inline constexpr size_t MAX_HEADERS = 2000;

/// Maximum number of locator hashes in a GETHEADERS request.
/// Same as the getblocks locator limit.
inline constexpr size_t MAX_GETHEADERS_LOCATOR = 101;

/// Wire size of a single block header entry in a HEADERS message:
///   80 bytes (header) + 1 byte (compact_size zero tx_count) = 81 bytes.
inline constexpr size_t HEADER_ENTRY_SIZE = 81;

// ---------------------------------------------------------------------------
// HeadersMessage -- deliver block headers (HEADERS command)
// ---------------------------------------------------------------------------
// The headers message sends one or more block headers to a node which
// previously requested certain headers with a getheaders message.
//
// Each header is followed by a transaction count (compact_size) that is
// always zero in the headers message, since the message carries only
// headers, not full blocks.  This zero count is present for historical
// compatibility with the block serialization format.
//
// Wire format:
//   count         compact_size   (1-3 bytes)
//   headers[]     [count]        (81 bytes each: 80-byte header + 1-byte zero)
//
// The receiving node should call getheaders again if it received exactly
// MAX_HEADERS headers, indicating there may be more available.
// ---------------------------------------------------------------------------
struct HeadersMessage {
    std::vector<primitives::BlockHeader> headers;

    /// Serialize the headers message payload.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize a headers message from raw bytes.
    [[nodiscard]] static core::Result<HeadersMessage> deserialize(
        std::span<const uint8_t> data);

    /// Validate the message (header count, chain continuity).
    [[nodiscard]] core::Result<void> validate() const;

    /// Return true if the message is "full" (may have more headers available).
    [[nodiscard]] bool is_full() const noexcept;
};

// ---------------------------------------------------------------------------
// GetHeadersMessage -- request block headers (GETHEADERS command)
// ---------------------------------------------------------------------------
// Similar to getblocks but returns headers instead of inventory items.
// The locator pattern and hash_stop semantics are identical:
//   - locator_hashes: a set of block hashes describing the sender's chain
//   - hash_stop: the last header hash to return (zero = return maximum)
//
// Wire format:
//   version          uint32       (4 bytes)
//   hash_count       compact_size (1-9 bytes)
//   locator_hashes   [hash_count] uint256 (32 bytes each)
//   hash_stop        uint256      (32 bytes)
// ---------------------------------------------------------------------------
struct GetHeadersMessage {
    uint32_t version = 70015;
    std::vector<core::uint256> locator_hashes;
    core::uint256 hash_stop;  // zero = get as many as possible

    /// Serialize the getheaders message payload.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize a getheaders message from raw bytes.
    [[nodiscard]] static core::Result<GetHeadersMessage> deserialize(
        std::span<const uint8_t> data);

    /// Validate the message fields.
    [[nodiscard]] core::Result<void> validate() const;

    /// Return true if hash_stop is zero (requesting maximum headers).
    [[nodiscard]] bool requests_maximum() const noexcept;
};

// ---------------------------------------------------------------------------
// SendHeadersMessage -- signal headers announcement preference (BIP130)
// ---------------------------------------------------------------------------
// SENDHEADERS has no payload.  Upon receipt, the peer should announce new
// blocks via headers messages instead of inv messages.  This allows the
// receiving node to immediately validate headers without an extra round
// trip (getdata + block).
//
// This message is typically sent once during the initial handshake phase,
// immediately after the version/verack exchange.
// ---------------------------------------------------------------------------
struct SendHeadersMessage {
    /// Serialize returns an empty byte vector (no payload).
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize verifies the span is empty and returns a SendHeadersMessage.
    [[nodiscard]] static core::Result<SendHeadersMessage> deserialize(
        std::span<const uint8_t> data);
};

} // namespace net::protocol
