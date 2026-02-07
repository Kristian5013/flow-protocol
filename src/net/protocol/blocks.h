#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "core/types.h"
#include "primitives/block.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace net::protocol {

// ---------------------------------------------------------------------------
// Protocol constants for block-related messages
// ---------------------------------------------------------------------------

/// Maximum number of block hashes in a locator (getblocks / getheaders).
/// This corresponds to the Bitcoin Core limit: the locator uses exponentially
/// spaced hashes from the tip, so 101 entries is sufficient to cover any
/// realistic chain height.
inline constexpr size_t MAX_LOCATOR_HASHES = 101;

/// Maximum number of block inv items returned per getblocks response.
inline constexpr size_t MAX_BLOCKS_RESPONSE = 500;

/// Maximum serialized size of a single block message (4 MB).
/// This serves as a DoS protection limit; actual consensus limits may differ.
inline constexpr size_t MAX_BLOCK_MESSAGE_SIZE = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// GetBlocksMessage -- request an inv list of blocks following a locator
// ---------------------------------------------------------------------------
// The getblocks message requests an inv message that provides block header
// hashes starting from a particular point in the blockchain.  It allows a
// node that has been disconnected or started for the first time to get the
// data it needs to request the blocks it hasn't seen.
//
// Wire format:
//   version          uint32       (4 bytes)
//   hash_count       compact_size (1-9 bytes)
//   locator_hashes   [hash_count] uint256 (32 bytes each)
//   hash_stop        uint256      (32 bytes)
//
// If hash_stop is all zeros, the receiver sends as many blocks as the
// protocol limit allows (MAX_BLOCKS_RESPONSE = 500).
// ---------------------------------------------------------------------------
struct GetBlocksMessage {
    uint32_t version = 70015;
    std::vector<core::uint256> locator_hashes;
    core::uint256 hash_stop;  // zero = get as many as possible

    /// Serialize the getblocks message payload.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize a getblocks message from raw bytes.
    [[nodiscard]] static core::Result<GetBlocksMessage> deserialize(
        std::span<const uint8_t> data);

    /// Validate the message fields.
    [[nodiscard]] core::Result<void> validate() const;

    /// Return true if hash_stop is zero (requesting maximum blocks).
    [[nodiscard]] bool requests_maximum() const noexcept;
};

// ---------------------------------------------------------------------------
// BlockMessage -- wraps a primitives::Block for P2P serialization
// ---------------------------------------------------------------------------
// The block message delivers a single serialized block in response to a
// getdata message.  The payload is the full serialized block including
// header, transaction count, and all transactions (with witness data if
// present).
// ---------------------------------------------------------------------------
struct BlockMessage {
    primitives::Block block;

    /// Serialize the block message payload.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize a block message from raw bytes.
    [[nodiscard]] static core::Result<BlockMessage> deserialize(
        std::span<const uint8_t> data);

    /// Return the block hash (delegated to the block header).
    [[nodiscard]] core::uint256 hash() const;
};

} // namespace net::protocol
