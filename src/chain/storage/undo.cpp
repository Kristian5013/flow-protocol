// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/storage/undo.h"

#include "core/serialize.h"
#include "core/stream.h"

#include <cstdint>
#include <utility>

namespace chain { namespace storage {

// ===========================================================================
// TxUndo -- serialization
// ===========================================================================

std::vector<uint8_t> TxUndo::serialize() const {
    core::DataStream stream;

    // Write the number of spent coins.
    core::ser_write_compact_size(stream,
                                 static_cast<uint64_t>(spent_coins.size()));

    // Write each coin. We use the Coin's own serialize() which returns
    // a byte vector, then write the length-prefixed bytes.
    for (const auto& coin : spent_coins) {
        std::vector<uint8_t> coin_bytes = coin.serialize();
        core::ser_write_compact_size(stream,
                                     static_cast<uint64_t>(coin_bytes.size()));
        core::ser_write_bytes(stream,
                              std::span<const uint8_t>(coin_bytes));
    }

    return stream.release();
}

core::Result<TxUndo> TxUndo::deserialize(core::DataStream& stream) {
    TxUndo undo;

    // Read the count of spent coins.
    uint64_t count = 0;
    try {
        count = core::ser_read_compact_size(stream);
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to read TxUndo coin count: ") + e.what());
    }

    if (count > core::MAX_VECTOR_SIZE) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            "TxUndo coin count exceeds maximum: " +
            std::to_string(count));
    }

    undo.spent_coins.reserve(static_cast<size_t>(count));

    for (uint64_t i = 0; i < count; ++i) {
        // Read the length-prefixed coin bytes.
        uint64_t coin_len = 0;
        try {
            coin_len = core::ser_read_compact_size(stream);
        } catch (const std::exception& e) {
            return core::Error(core::ErrorCode::PARSE_ERROR,
                std::string("Failed to read coin byte length in TxUndo: ") +
                e.what());
        }

        if (coin_len > core::MAX_VECTOR_SIZE) {
            return core::Error(core::ErrorCode::PARSE_ERROR,
                "Coin data length exceeds maximum in TxUndo");
        }

        std::vector<uint8_t> coin_bytes(static_cast<size_t>(coin_len));
        try {
            core::ser_read_bytes(stream,
                                 std::span<uint8_t>(coin_bytes));
        } catch (const std::exception& e) {
            return core::Error(core::ErrorCode::PARSE_ERROR,
                std::string("Failed to read coin bytes in TxUndo: ") +
                e.what());
        }

        auto coin_result = chain::Coin::deserialize(
            std::span<const uint8_t>(coin_bytes));
        if (!coin_result.ok()) {
            return core::Error(core::ErrorCode::PARSE_ERROR,
                "Failed to deserialize coin in TxUndo: " +
                coin_result.error().message());
        }

        undo.spent_coins.push_back(std::move(coin_result).value());
    }

    return undo;
}

// ===========================================================================
// BlockUndo -- serialization
// ===========================================================================

std::vector<uint8_t> BlockUndo::serialize() const {
    core::DataStream stream;

    // Write the number of transaction undo entries.
    core::ser_write_compact_size(stream,
                                 static_cast<uint64_t>(tx_undo.size()));

    // Write each TxUndo as a length-prefixed blob.
    for (const auto& tu : tx_undo) {
        std::vector<uint8_t> tu_bytes = tu.serialize();
        core::ser_write_compact_size(stream,
                                     static_cast<uint64_t>(tu_bytes.size()));
        core::ser_write_bytes(stream,
                              std::span<const uint8_t>(tu_bytes));
    }

    return stream.release();
}

core::Result<BlockUndo> BlockUndo::deserialize(
    std::span<const uint8_t> data) {

    core::DataStream stream(std::vector<uint8_t>(data.begin(), data.end()));
    BlockUndo undo;

    // Read the number of TxUndo entries.
    uint64_t count = 0;
    try {
        count = core::ser_read_compact_size(stream);
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to read BlockUndo tx_undo count: ") +
            e.what());
    }

    if (count > core::MAX_VECTOR_SIZE) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            "BlockUndo tx_undo count exceeds maximum: " +
            std::to_string(count));
    }

    undo.tx_undo.reserve(static_cast<size_t>(count));

    for (uint64_t i = 0; i < count; ++i) {
        // Read the length-prefixed TxUndo blob.
        uint64_t tu_len = 0;
        try {
            tu_len = core::ser_read_compact_size(stream);
        } catch (const std::exception& e) {
            return core::Error(core::ErrorCode::PARSE_ERROR,
                std::string("Failed to read TxUndo blob length: ") +
                e.what());
        }

        if (tu_len > core::MAX_VECTOR_SIZE) {
            return core::Error(core::ErrorCode::PARSE_ERROR,
                "TxUndo blob length exceeds maximum in BlockUndo");
        }

        // Extract the TxUndo bytes, then deserialize via TxUndo::deserialize.
        std::vector<uint8_t> tu_bytes(static_cast<size_t>(tu_len));
        try {
            core::ser_read_bytes(stream, std::span<uint8_t>(tu_bytes));
        } catch (const std::exception& e) {
            return core::Error(core::ErrorCode::PARSE_ERROR,
                std::string("Failed to read TxUndo blob bytes: ") +
                e.what());
        }

        core::DataStream tu_stream(std::move(tu_bytes));
        auto tu_result = TxUndo::deserialize(tu_stream);
        if (!tu_result.ok()) {
            return core::Error(core::ErrorCode::PARSE_ERROR,
                "Failed to deserialize TxUndo in BlockUndo: " +
                tu_result.error().message());
        }

        undo.tx_undo.push_back(std::move(tu_result).value());
    }

    // Verify no trailing data.
    if (!stream.eof()) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            "Trailing data after BlockUndo deserialization (" +
            std::to_string(stream.remaining()) + " bytes remaining)");
    }

    return undo;
}

}} // namespace chain::storage
