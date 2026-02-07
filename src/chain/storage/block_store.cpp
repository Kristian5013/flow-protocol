// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/storage/block_store.h"

#include "core/serialize.h"
#include "core/stream.h"

#include <cassert>
#include <cstring>
#include <utility>

namespace chain { namespace storage {

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

BlockStore::BlockStore(const std::filesystem::path& data_dir)
    : data_dir_(data_dir) {}

BlockStore::~BlockStore() = default;

// ---------------------------------------------------------------------------
// init -- open (or create) blockchain.dat
// ---------------------------------------------------------------------------

core::Result<void> BlockStore::init() {
    auto blockchain_path = data_dir_ / "blockchain.dat";
    file_ = std::make_unique<FlatFile>(blockchain_path);

    auto res = file_->open();
    if (!res.ok()) {
        return std::move(res).error();
    }

    return core::make_ok();
}

// ---------------------------------------------------------------------------
// write_block -- serialize a block and append it as a BLOCK record
// ---------------------------------------------------------------------------

core::Result<int64_t> BlockStore::write_block(
    const primitives::Block& block) {

    std::vector<uint8_t> serialized = block.serialize();
    return write_record(RECORD_TYPE_BLOCK,
                        std::span<const uint8_t>(serialized));
}

// ---------------------------------------------------------------------------
// read_block -- read a BLOCK record and deserialize it into a Block
// ---------------------------------------------------------------------------

core::Result<primitives::Block> BlockStore::read_block(int64_t pos) {
    // Read and validate the record header.
    auto hdr_result = read_record_header(pos);
    if (!hdr_result.ok()) {
        return std::move(hdr_result).error();
    }
    auto hdr = std::move(hdr_result).value();

    if (hdr.type != RECORD_TYPE_BLOCK) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
            "Expected block record at offset " + std::to_string(pos) +
            ", found type " + std::to_string(hdr.type));
    }

    // Read the payload.
    auto payload_result = file_->read_at(pos + static_cast<int64_t>(RECORD_HEADER_SIZE),
                                          hdr.size);
    if (!payload_result.ok()) {
        return std::move(payload_result).error();
    }
    auto payload = std::move(payload_result).value();

    // Deserialize the block from the payload bytes.
    core::DataStream stream(std::move(payload));
    auto block_result = primitives::Block::deserialize(stream);
    if (!block_result.ok()) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
            "Failed to deserialize block at offset " +
            std::to_string(pos) + ": " +
            block_result.error().message());
    }

    return std::move(block_result).value();
}

// ---------------------------------------------------------------------------
// write_undo -- append raw undo bytes as an UNDO record
// ---------------------------------------------------------------------------

core::Result<int64_t> BlockStore::write_undo(
    const std::vector<uint8_t>& undo_data) {

    return write_record(RECORD_TYPE_UNDO,
                        std::span<const uint8_t>(undo_data));
}

// ---------------------------------------------------------------------------
// read_undo -- read an UNDO record and return the raw payload
// ---------------------------------------------------------------------------

core::Result<std::vector<uint8_t>> BlockStore::read_undo(int64_t pos) {
    // Read and validate the record header.
    auto hdr_result = read_record_header(pos);
    if (!hdr_result.ok()) {
        return std::move(hdr_result).error();
    }
    auto hdr = std::move(hdr_result).value();

    if (hdr.type != RECORD_TYPE_UNDO) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
            "Expected undo record at offset " + std::to_string(pos) +
            ", found type " + std::to_string(hdr.type));
    }

    // Read the payload.
    auto payload_result = file_->read_at(pos + static_cast<int64_t>(RECORD_HEADER_SIZE),
                                          hdr.size);
    if (!payload_result.ok()) {
        return std::move(payload_result).error();
    }

    return std::move(payload_result).value();
}

// ---------------------------------------------------------------------------
// flush
// ---------------------------------------------------------------------------

core::Result<void> BlockStore::flush() {
    if (!file_ || !file_->is_open()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "BlockStore not initialized");
    }
    return file_->flush();
}

// ---------------------------------------------------------------------------
// total_size
// ---------------------------------------------------------------------------

core::Result<int64_t> BlockStore::total_size() const {
    if (!file_ || !file_->is_open()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "BlockStore not initialized");
    }
    return file_->size();
}

// ---------------------------------------------------------------------------
// write_record -- serialize a RecordHeader + payload and append to the file
// ---------------------------------------------------------------------------

core::Result<int64_t> BlockStore::write_record(
    uint8_t type, std::span<const uint8_t> data) {

    if (!file_ || !file_->is_open()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "BlockStore not initialized");
    }

    if (data.size() > static_cast<size_t>(UINT32_MAX)) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Record payload too large: " + std::to_string(data.size()));
    }

    // Build the record header: magic (4) + size (4) + type (1) = 9 bytes.
    core::DataStream hdr_stream;
    core::ser_write_u32(hdr_stream, RECORD_MAGIC);
    core::ser_write_u32(hdr_stream, static_cast<uint32_t>(data.size()));
    core::ser_write_u8(hdr_stream, type);

    // Combine header and payload into a single write for atomicity.
    std::vector<uint8_t> record;
    record.reserve(RECORD_HEADER_SIZE + data.size());
    record.insert(record.end(), hdr_stream.data(),
                  hdr_stream.data() + hdr_stream.size());
    record.insert(record.end(), data.begin(), data.end());

    return file_->append(std::span<const uint8_t>(record));
}

// ---------------------------------------------------------------------------
// read_record_header -- read and validate a RecordHeader at a given offset
// ---------------------------------------------------------------------------

core::Result<RecordHeader> BlockStore::read_record_header(int64_t pos) {
    if (!file_ || !file_->is_open()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "BlockStore not initialized");
    }

    auto hdr_result = file_->read_at(pos, RECORD_HEADER_SIZE);
    if (!hdr_result.ok()) {
        return std::move(hdr_result).error();
    }
    auto hdr_bytes = std::move(hdr_result).value();

    // Parse the header fields.
    core::DataStream stream(std::move(hdr_bytes));
    RecordHeader hdr{};
    hdr.magic = core::ser_read_u32(stream);
    hdr.size  = core::ser_read_u32(stream);
    hdr.type  = core::ser_read_u8(stream);

    // Validate magic number.
    if (hdr.magic != RECORD_MAGIC) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
            "Invalid record magic at offset " + std::to_string(pos) +
            ": expected 0x46544321, got 0x" +
            [&]() {
                char buf[9];
                std::snprintf(buf, sizeof(buf), "%08X", hdr.magic);
                return std::string(buf);
            }());
    }

    // Validate record type.
    if (hdr.type != RECORD_TYPE_BLOCK && hdr.type != RECORD_TYPE_UNDO) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
            "Unknown record type at offset " + std::to_string(pos) +
            ": " + std::to_string(hdr.type));
    }

    return hdr;
}

}} // namespace chain::storage
