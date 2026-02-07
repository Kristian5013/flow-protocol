// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/protocol/compact.h"

#include "core/error.h"
#include "core/serialize.h"
#include "core/stream.h"
#include "primitives/block_header.h"
#include "primitives/transaction.h"

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>

namespace net::protocol {

// ===========================================================================
// Helpers: 6-byte short transaction ID read/write
// ===========================================================================
// BIP152 short IDs are 6 bytes (48 bits) stored as little-endian on the wire.
// We represent them as uint64_t with the upper 16 bits always zero.

namespace {

/// Write a 6-byte little-endian short ID to the stream.
template <typename Stream>
void write_short_id(Stream& s, uint64_t short_id) {
    uint8_t buf[SHORT_ID_SIZE];
    buf[0] = static_cast<uint8_t>(short_id & 0xFF);
    buf[1] = static_cast<uint8_t>((short_id >> 8) & 0xFF);
    buf[2] = static_cast<uint8_t>((short_id >> 16) & 0xFF);
    buf[3] = static_cast<uint8_t>((short_id >> 24) & 0xFF);
    buf[4] = static_cast<uint8_t>((short_id >> 32) & 0xFF);
    buf[5] = static_cast<uint8_t>((short_id >> 40) & 0xFF);
    core::ser_write_bytes(s, std::span<const uint8_t>(buf, SHORT_ID_SIZE));
}

/// Read a 6-byte little-endian short ID from the stream.
template <typename Stream>
uint64_t read_short_id(Stream& s) {
    uint8_t buf[SHORT_ID_SIZE];
    core::ser_read_bytes(s, std::span<uint8_t>(buf, SHORT_ID_SIZE));
    uint64_t id = 0;
    id |= static_cast<uint64_t>(buf[0]);
    id |= static_cast<uint64_t>(buf[1]) << 8;
    id |= static_cast<uint64_t>(buf[2]) << 16;
    id |= static_cast<uint64_t>(buf[3]) << 24;
    id |= static_cast<uint64_t>(buf[4]) << 32;
    id |= static_cast<uint64_t>(buf[5]) << 40;
    return id;
}

/// Write prefilled transactions with differential index encoding.
template <typename Stream>
void write_prefilled_txs(Stream& s,
                         const std::vector<PrefilledTransaction>& entries) {
    core::ser_write_compact_size(s, entries.size());

    uint16_t last_index = 0;
    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& entry = entries[i];

        // Differential encoding: first entry stores the absolute index,
        // subsequent entries store (index - previous_index - 1).
        uint16_t diff_index = (i == 0)
            ? entry.index
            : static_cast<uint16_t>(entry.index - last_index - 1);
        core::ser_write_compact_size(s, diff_index);
        last_index = entry.index;

        // Serialize the full transaction using BIP144 format
        auto tx_bytes = entry.tx.serialize();
        core::ser_write_bytes(s, std::span<const uint8_t>(
            tx_bytes.data(), tx_bytes.size()));
    }
}

/// Read prefilled transactions with differential index decoding.
/// Reads from a DataStream because Transaction::deserialize requires it.
core::Result<std::vector<PrefilledTransaction>>
read_prefilled_txs(core::DataStream& ds, uint64_t count) {
    std::vector<PrefilledTransaction> result;
    result.reserve(static_cast<size_t>(count));

    uint16_t last_index = 0;
    for (uint64_t i = 0; i < count; ++i) {
        PrefilledTransaction entry;

        // Read differentially-encoded index
        uint64_t diff = core::ser_read_compact_size(ds);
        if (i == 0) {
            if (diff > 0xFFFF) {
                return core::Error(core::ErrorCode::PARSE_OVERFLOW,
                    "CmpctBlockMessage: prefilled index overflow at entry 0");
            }
            entry.index = static_cast<uint16_t>(diff);
        } else {
            uint64_t abs_index = static_cast<uint64_t>(last_index) + diff + 1;
            if (abs_index > 0xFFFF) {
                return core::Error(core::ErrorCode::PARSE_OVERFLOW,
                    "CmpctBlockMessage: prefilled index overflow at entry "
                    + std::to_string(i));
            }
            entry.index = static_cast<uint16_t>(abs_index);
        }
        last_index = entry.index;

        // Deserialize the transaction from the DataStream
        auto tx_result = primitives::Transaction::deserialize(ds);
        if (!tx_result.ok()) {
            return core::Error(core::ErrorCode::PARSE_ERROR,
                "CmpctBlockMessage: failed to deserialize prefilled tx at index "
                + std::to_string(i) + ": " + tx_result.error().message());
        }
        entry.tx = std::move(tx_result).value();

        result.push_back(std::move(entry));
    }

    return result;
}

} // anonymous namespace

// ===========================================================================
// SendCmpctMessage serialization
// ===========================================================================

std::vector<uint8_t> SendCmpctMessage::serialize() const {
    core::DataStream stream;
    stream.reserve(9);

    // high_bandwidth flag (1 byte: 0 or 1)
    core::ser_write_bool(stream, high_bandwidth);

    // compact block version (8 bytes LE)
    core::ser_write_u64(stream, version);

    return stream.release();
}

core::Result<SendCmpctMessage> SendCmpctMessage::deserialize(
    std::span<const uint8_t> data) {
    try {
        if (data.size() < 9) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "SendCmpctMessage payload too short: expected 9 bytes, got "
                + std::to_string(data.size()));
        }

        core::SpanReader reader{data};
        SendCmpctMessage msg;

        msg.high_bandwidth = core::ser_read_bool(reader);
        msg.version        = core::ser_read_u64(reader);

        return msg;
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to deserialize SendCmpctMessage: ") + e.what());
    }
}

core::Result<void> SendCmpctMessage::validate() const {
    // We only support compact block version 1
    if (version != COMPACT_BLOCK_VERSION) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "SendCmpctMessage: unsupported compact block version "
            + std::to_string(version) + " (expected "
            + std::to_string(COMPACT_BLOCK_VERSION) + ")");
    }
    return core::make_ok();
}

// ===========================================================================
// CmpctBlockMessage serialization
// ===========================================================================

std::vector<uint8_t> CmpctBlockMessage::serialize() const {
    core::DataStream stream;
    // Rough estimate: header(80) + nonce(8) + short_ids + prefilled
    stream.reserve(80 + 8 + 9 + short_ids.size() * SHORT_ID_SIZE + 9);

    // Block header (80 bytes)
    header.serialize(stream);

    // Nonce used for SipHash short-ID computation (8 bytes)
    core::ser_write_u64(stream, nonce);

    // Short IDs: compact_size count followed by 6-byte entries
    core::ser_write_compact_size(stream, short_ids.size());
    for (uint64_t sid : short_ids) {
        write_short_id(stream, sid);
    }

    // Prefilled transactions with differentially-encoded indices
    write_prefilled_txs(stream, prefilled_txs);

    return stream.release();
}

// ===========================================================================
// CmpctBlockMessage deserialization
// ===========================================================================

core::Result<CmpctBlockMessage> CmpctBlockMessage::deserialize(
    std::span<const uint8_t> data) {
    try {
        // We need a DataStream because Transaction::deserialize requires it.
        // Parse the fixed fields with a SpanReader first, then switch to
        // a DataStream for the variable-length transaction data.
        core::SpanReader reader{data};
        CmpctBlockMessage msg;

        // Block header (80 bytes)
        msg.header = primitives::BlockHeader::deserialize(reader);

        // Nonce (8 bytes)
        msg.nonce = core::ser_read_u64(reader);

        // Short IDs
        uint64_t short_id_count = core::ser_read_compact_size(reader);
        if (short_id_count > MAX_COMPACT_SHORT_IDS) {
            return core::Error(core::ErrorCode::PARSE_OVERFLOW,
                "CmpctBlockMessage short_id count " + std::to_string(short_id_count)
                + " exceeds MAX_COMPACT_SHORT_IDS ("
                + std::to_string(MAX_COMPACT_SHORT_IDS) + ")");
        }

        // Verify sufficient data for the short IDs
        size_t short_ids_bytes = static_cast<size_t>(short_id_count) * SHORT_ID_SIZE;
        if (reader.remaining() < short_ids_bytes) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "CmpctBlockMessage: insufficient data for "
                + std::to_string(short_id_count) + " short IDs");
        }

        msg.short_ids.reserve(static_cast<size_t>(short_id_count));
        for (uint64_t i = 0; i < short_id_count; ++i) {
            msg.short_ids.push_back(read_short_id(reader));
        }

        // For prefilled transactions, we need a DataStream because
        // Transaction::deserialize(DataStream&) requires that type.
        // Read the remaining bytes from the SpanReader into a DataStream.
        std::vector<uint8_t> remaining_bytes(reader.remaining());
        if (!remaining_bytes.empty()) {
            core::ser_read_bytes(reader,
                std::span<uint8_t>(remaining_bytes.data(), remaining_bytes.size()));
        }

        core::DataStream ds{std::span<const uint8_t>(remaining_bytes)};

        // Read prefilled transaction count
        uint64_t prefilled_count = core::ser_read_compact_size(ds);
        if (prefilled_count > MAX_COMPACT_PREFILLED_TXS) {
            return core::Error(core::ErrorCode::PARSE_OVERFLOW,
                "CmpctBlockMessage prefilled count " + std::to_string(prefilled_count)
                + " exceeds MAX_COMPACT_PREFILLED_TXS ("
                + std::to_string(MAX_COMPACT_PREFILLED_TXS) + ")");
        }

        // Read prefilled transactions with differential index decoding
        auto prefilled_result = read_prefilled_txs(ds, prefilled_count);
        if (!prefilled_result.ok()) {
            return prefilled_result.error();
        }
        msg.prefilled_txs = std::move(prefilled_result).value();

        return msg;
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to deserialize CmpctBlockMessage: ") + e.what());
    }
}

core::Result<void> CmpctBlockMessage::validate() const {
    if (short_ids.size() > MAX_COMPACT_SHORT_IDS) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "CmpctBlockMessage: short_id count " + std::to_string(short_ids.size())
            + " exceeds limit");
    }

    if (prefilled_txs.size() > MAX_COMPACT_PREFILLED_TXS) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "CmpctBlockMessage: prefilled_tx count "
            + std::to_string(prefilled_txs.size()) + " exceeds limit");
    }

    // Verify that prefilled indices are strictly increasing
    for (size_t i = 1; i < prefilled_txs.size(); ++i) {
        if (prefilled_txs[i].index <= prefilled_txs[i - 1].index) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "CmpctBlockMessage: prefilled indices not strictly increasing "
                "at position " + std::to_string(i));
        }
    }

    // Verify that prefilled indices do not exceed total transaction count
    size_t total = total_tx_count();
    for (const auto& pf : prefilled_txs) {
        if (pf.index >= total) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "CmpctBlockMessage: prefilled index " + std::to_string(pf.index)
                + " >= total tx count " + std::to_string(total));
        }
    }

    return core::make_ok();
}

core::uint256 CmpctBlockMessage::block_hash() const {
    return header.hash();
}

size_t CmpctBlockMessage::total_tx_count() const noexcept {
    return short_ids.size() + prefilled_txs.size();
}

// ===========================================================================
// GetBlockTxnMessage serialization
// ===========================================================================

std::vector<uint8_t> GetBlockTxnMessage::serialize() const {
    core::DataStream stream;
    // block_hash (32) + compact_size + differential indices
    stream.reserve(32 + 9 + indices.size() * 3);

    // Block hash identifying which compact block we need txns for
    core::ser_write_uint256(stream, block_hash);

    // Number of requested transaction indices
    core::ser_write_compact_size(stream, indices.size());

    // Differential encoding: first index is absolute, subsequent are
    // (current - previous - 1).  This compresses well when indices are
    // close together, which is typical.
    uint16_t last_index = 0;
    for (size_t i = 0; i < indices.size(); ++i) {
        uint16_t diff = (i == 0)
            ? indices[i]
            : static_cast<uint16_t>(indices[i] - last_index - 1);
        core::ser_write_compact_size(stream, diff);
        last_index = indices[i];
    }

    return stream.release();
}

// ===========================================================================
// GetBlockTxnMessage deserialization
// ===========================================================================

core::Result<GetBlockTxnMessage> GetBlockTxnMessage::deserialize(
    std::span<const uint8_t> data) {
    try {
        // Minimum: block_hash (32) + compact_size(0) (1) = 33
        if (data.size() < 33) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "GetBlockTxnMessage payload too short: "
                + std::to_string(data.size()) + " bytes (min 33)");
        }

        core::SpanReader reader{data};
        GetBlockTxnMessage msg;

        msg.block_hash = core::ser_read_uint256(reader);

        uint64_t count = core::ser_read_compact_size(reader);
        if (count > MAX_BLOCKTXN_INDICES) {
            return core::Error(core::ErrorCode::PARSE_OVERFLOW,
                "GetBlockTxnMessage index count " + std::to_string(count)
                + " exceeds MAX_BLOCKTXN_INDICES ("
                + std::to_string(MAX_BLOCKTXN_INDICES) + ")");
        }

        msg.indices.reserve(static_cast<size_t>(count));

        // Differential decoding: reconstruct absolute indices from deltas
        uint16_t last_index = 0;
        for (uint64_t i = 0; i < count; ++i) {
            uint64_t diff = core::ser_read_compact_size(reader);
            uint64_t abs_index;
            if (i == 0) {
                abs_index = diff;
            } else {
                abs_index = static_cast<uint64_t>(last_index) + diff + 1;
            }

            if (abs_index > 0xFFFF) {
                return core::Error(core::ErrorCode::PARSE_OVERFLOW,
                    "GetBlockTxnMessage: index overflow at position "
                    + std::to_string(i));
            }

            msg.indices.push_back(static_cast<uint16_t>(abs_index));
            last_index = static_cast<uint16_t>(abs_index);
        }

        return msg;
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to deserialize GetBlockTxnMessage: ") + e.what());
    }
}

core::Result<void> GetBlockTxnMessage::validate() const {
    if (indices.size() > MAX_BLOCKTXN_INDICES) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "GetBlockTxnMessage: index count "
            + std::to_string(indices.size()) + " exceeds limit");
    }

    if (block_hash.is_zero()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "GetBlockTxnMessage: block_hash is zero");
    }

    // Verify indices are strictly increasing
    for (size_t i = 1; i < indices.size(); ++i) {
        if (indices[i] <= indices[i - 1]) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "GetBlockTxnMessage: indices not strictly increasing at position "
                + std::to_string(i));
        }
    }

    return core::make_ok();
}

// ===========================================================================
// BlockTxnMessage serialization
// ===========================================================================

std::vector<uint8_t> BlockTxnMessage::serialize() const {
    core::DataStream stream;
    // Rough estimate: hash(32) + compact_size + transaction data
    stream.reserve(32 + 9 + txs.size() * 256);

    // Block hash
    core::ser_write_uint256(stream, block_hash);

    // Transaction count
    core::ser_write_compact_size(stream, txs.size());

    // Each transaction serialized in full BIP144 format
    for (const auto& tx : txs) {
        auto tx_bytes = tx.serialize();
        core::ser_write_bytes(stream,
            std::span<const uint8_t>(tx_bytes.data(), tx_bytes.size()));
    }

    return stream.release();
}

// ===========================================================================
// BlockTxnMessage deserialization
// ===========================================================================

core::Result<BlockTxnMessage> BlockTxnMessage::deserialize(
    std::span<const uint8_t> data) {
    try {
        // Minimum: block_hash (32) + compact_size(0) (1) = 33
        if (data.size() < 33) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "BlockTxnMessage payload too short: "
                + std::to_string(data.size()) + " bytes (min 33)");
        }

        // We need a DataStream because Transaction::deserialize expects it.
        core::DataStream ds{data};
        BlockTxnMessage msg;

        // Read block hash (32 bytes)
        msg.block_hash = core::ser_read_uint256(ds);

        // Read transaction count
        uint64_t count = core::ser_read_compact_size(ds);
        if (count > MAX_BLOCKTXN_TXS) {
            return core::Error(core::ErrorCode::PARSE_OVERFLOW,
                "BlockTxnMessage tx count " + std::to_string(count)
                + " exceeds MAX_BLOCKTXN_TXS ("
                + std::to_string(MAX_BLOCKTXN_TXS) + ")");
        }

        msg.txs.reserve(static_cast<size_t>(count));

        // Deserialize each transaction
        for (uint64_t i = 0; i < count; ++i) {
            auto tx_result = primitives::Transaction::deserialize(ds);
            if (!tx_result.ok()) {
                return core::Error(core::ErrorCode::PARSE_ERROR,
                    "BlockTxnMessage: failed to deserialize tx at index "
                    + std::to_string(i) + ": " + tx_result.error().message());
            }
            msg.txs.push_back(std::move(tx_result).value());
        }

        return msg;
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to deserialize BlockTxnMessage: ") + e.what());
    }
}

core::Result<void> BlockTxnMessage::validate() const {
    if (txs.size() > MAX_BLOCKTXN_TXS) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "BlockTxnMessage: tx count " + std::to_string(txs.size())
            + " exceeds limit");
    }

    if (block_hash.is_zero()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "BlockTxnMessage: block_hash is zero");
    }

    return core::make_ok();
}

} // namespace net::protocol
