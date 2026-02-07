// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/protocol/blocks.h"

#include "core/error.h"
#include "core/serialize.h"
#include "core/stream.h"
#include "primitives/block.h"

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>

namespace net::protocol {

// ===========================================================================
// GetBlocksMessage serialization
// ===========================================================================

std::vector<uint8_t> GetBlocksMessage::serialize() const {
    core::DataStream stream;
    // version (4) + compact_size (up to 9) + N * 32 + hash_stop (32)
    stream.reserve(4 + 9 + locator_hashes.size() * 32 + 32);

    // Protocol version field (usually matches the version from the handshake)
    core::ser_write_u32(stream, version);

    // Write the number of locator hashes as a compact size
    core::ser_write_compact_size(stream, locator_hashes.size());

    // Write each locator hash.  The locator is ordered from the tip
    // of the sender's chain backwards, with exponentially increasing
    // step sizes (1, 1, 2, 4, 8, 16, ...) to cover the full chain.
    for (const auto& hash : locator_hashes) {
        core::ser_write_uint256(stream, hash);
    }

    // Hash of the last desired block.  Zero means "send as many as possible"
    // up to MAX_BLOCKS_RESPONSE.
    core::ser_write_uint256(stream, hash_stop);

    return stream.release();
}

// ===========================================================================
// GetBlocksMessage deserialization
// ===========================================================================

core::Result<GetBlocksMessage> GetBlocksMessage::deserialize(
    std::span<const uint8_t> data) {
    try {
        // Minimum: version (4) + compact_size(0) (1) + hash_stop (32) = 37
        if (data.size() < 37) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "GetBlocksMessage payload too short: "
                + std::to_string(data.size()) + " bytes (min 37)");
        }

        core::SpanReader reader{data};
        GetBlocksMessage msg;

        msg.version = core::ser_read_u32(reader);

        uint64_t count = core::ser_read_compact_size(reader);
        if (count > MAX_LOCATOR_HASHES) {
            return core::Error(core::ErrorCode::PARSE_OVERFLOW,
                "GetBlocksMessage locator count " + std::to_string(count)
                + " exceeds MAX_LOCATOR_HASHES ("
                + std::to_string(MAX_LOCATOR_HASHES) + ")");
        }

        // Verify that enough data remains for all locator hashes + hash_stop
        size_t needed = static_cast<size_t>(count) * 32 + 32;
        if (reader.remaining() < needed) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "GetBlocksMessage: insufficient data for "
                + std::to_string(count) + " locator hashes plus hash_stop");
        }

        msg.locator_hashes.reserve(static_cast<size_t>(count));
        for (uint64_t i = 0; i < count; ++i) {
            msg.locator_hashes.push_back(core::ser_read_uint256(reader));
        }

        msg.hash_stop = core::ser_read_uint256(reader);

        return msg;
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to deserialize GetBlocksMessage: ") + e.what());
    }
}

// ===========================================================================
// GetBlocksMessage validation
// ===========================================================================

core::Result<void> GetBlocksMessage::validate() const {
    if (locator_hashes.size() > MAX_LOCATOR_HASHES) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "GetBlocksMessage: locator contains "
            + std::to_string(locator_hashes.size()) + " hashes (max "
            + std::to_string(MAX_LOCATOR_HASHES) + ")");
    }

    // The locator should not be empty in practice, but an empty locator
    // is technically valid (the receiver starts from the genesis block).

    return core::make_ok();
}

bool GetBlocksMessage::requests_maximum() const noexcept {
    return hash_stop.is_zero();
}

// ===========================================================================
// BlockMessage serialization
// ===========================================================================

std::vector<uint8_t> BlockMessage::serialize() const {
    // Delegate to the primitives::Block serialization which produces the
    // correct wire format: header (80 bytes) + compact-size tx count +
    // each transaction serialized with BIP144 witness data.
    return block.serialize();
}

// ===========================================================================
// BlockMessage deserialization
// ===========================================================================

core::Result<BlockMessage> BlockMessage::deserialize(
    std::span<const uint8_t> data) {
    try {
        // Reject obviously oversized block messages as a DoS precaution
        if (data.size() > MAX_BLOCK_MESSAGE_SIZE) {
            return core::Error(core::ErrorCode::PARSE_OVERFLOW,
                "BlockMessage payload exceeds MAX_BLOCK_MESSAGE_SIZE ("
                + std::to_string(MAX_BLOCK_MESSAGE_SIZE) + " bytes), got "
                + std::to_string(data.size()));
        }

        // Minimum block: 80 (header) + 1 (compact_size for 0 txs) = 81 bytes.
        // A valid block must have at least a coinbase tx, but we leave that
        // validation to the consensus layer.
        if (data.size() < 81) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "BlockMessage payload too short for a block: "
                + std::to_string(data.size()) + " bytes (min 81)");
        }

        core::DataStream stream{data};

        auto block_result = primitives::Block::deserialize(stream);
        if (!block_result.ok()) {
            return core::Error(core::ErrorCode::PARSE_ERROR,
                "Failed to deserialize BlockMessage: "
                + block_result.error().message());
        }

        BlockMessage msg;
        msg.block = std::move(block_result).value();
        return msg;
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to deserialize BlockMessage: ") + e.what());
    }
}

core::uint256 BlockMessage::hash() const {
    return block.hash();
}

} // namespace net::protocol
