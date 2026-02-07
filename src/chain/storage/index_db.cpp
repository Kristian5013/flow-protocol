// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/storage/index_db.h"

#include "core/serialize.h"
#include "core/stream.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <utility>

namespace chain { namespace storage {

// ===========================================================================
// BlockIndexDiskEntry -- fixed-size binary serialization (172 bytes)
// ===========================================================================

std::vector<uint8_t> BlockIndexDiskEntry::serialize() const {
    core::DataStream stream;
    stream.reserve(SERIALIZED_SIZE);

    core::ser_write_uint256(stream, block_hash);
    core::ser_write_uint256(stream, prev_hash);
    core::ser_write_i32(stream, version);
    core::ser_write_uint256(stream, hash_merkle_root);
    core::ser_write_u32(stream, time);
    core::ser_write_u32(stream, bits);
    core::ser_write_u32(stream, nonce);
    core::ser_write_i32(stream, height);
    core::ser_write_u32(stream, status);
    core::ser_write_i64(stream, data_pos);
    core::ser_write_i64(stream, undo_pos);
    core::ser_write_i32(stream, tx_count);
    core::ser_write_uint256(stream, chain_work);

    return stream.release();
}

core::Result<BlockIndexDiskEntry> BlockIndexDiskEntry::deserialize(
    std::span<const uint8_t> data) {

    if (data.size() < SERIALIZED_SIZE) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            "BlockIndexDiskEntry data too short: expected " +
            std::to_string(SERIALIZED_SIZE) + " bytes, got " +
            std::to_string(data.size()));
    }

    core::DataStream stream(
        std::vector<uint8_t>(data.begin(), data.begin() + SERIALIZED_SIZE));

    BlockIndexDiskEntry entry;
    try {
        entry.block_hash       = core::ser_read_uint256(stream);
        entry.prev_hash        = core::ser_read_uint256(stream);
        entry.version          = core::ser_read_i32(stream);
        entry.hash_merkle_root = core::ser_read_uint256(stream);
        entry.time             = core::ser_read_u32(stream);
        entry.bits             = core::ser_read_u32(stream);
        entry.nonce            = core::ser_read_u32(stream);
        entry.height           = core::ser_read_i32(stream);
        entry.status           = core::ser_read_u32(stream);
        entry.data_pos         = core::ser_read_i64(stream);
        entry.undo_pos         = core::ser_read_i64(stream);
        entry.tx_count         = core::ser_read_i32(stream);
        entry.chain_work       = core::ser_read_uint256(stream);
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to deserialize BlockIndexDiskEntry: ") +
            e.what());
    }

    return entry;
}

// ===========================================================================
// IndexDB -- simple binary file database for the block index
// ===========================================================================

// File format:
//   [8-byte file header: magic "FTCIDX\x01\x00"]
//   [BlockIndexDiskEntry]  -- 172 bytes each
//   [BlockIndexDiskEntry]
//   ...
//
// The file header allows detection of corruption and versioning.

static constexpr size_t FILE_HEADER_SIZE = 8;
static constexpr uint8_t FILE_HEADER[FILE_HEADER_SIZE] = {
    'F', 'T', 'C', 'I', 'D', 'X', 0x01, 0x00
};

IndexDB::IndexDB(const std::filesystem::path& path)
    : path_(path) {}

// ---------------------------------------------------------------------------
// load -- read all entries from the index database file
// ---------------------------------------------------------------------------

core::Result<std::vector<BlockIndexDiskEntry>> IndexDB::load() {
    std::vector<BlockIndexDiskEntry> entries;

    // If the file does not exist, return an empty vector (fresh start).
    std::error_code ec;
    if (!std::filesystem::exists(path_, ec)) {
        return entries;
    }

    std::ifstream file(path_, std::ios::binary);
    if (!file.is_open()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to open index database: " + path_.string());
    }

    // Determine file size.
    file.seekg(0, std::ios::end);
    auto file_size = static_cast<int64_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    if (file_size == 0) {
        return entries;
    }

    // Validate file header.
    if (file_size < static_cast<int64_t>(FILE_HEADER_SIZE)) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
            "Index database too small for header: " + path_.string());
    }

    uint8_t header_buf[FILE_HEADER_SIZE];
    file.read(reinterpret_cast<char*>(header_buf), FILE_HEADER_SIZE);
    if (file.fail()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to read index database header: " + path_.string());
    }

    for (size_t i = 0; i < FILE_HEADER_SIZE; ++i) {
        if (header_buf[i] != FILE_HEADER[i]) {
            return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                "Invalid index database header: " + path_.string());
        }
    }

    // Calculate the number of entries.
    int64_t data_size = file_size - static_cast<int64_t>(FILE_HEADER_SIZE);
    if (data_size % static_cast<int64_t>(BlockIndexDiskEntry::SERIALIZED_SIZE) != 0) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
            "Index database size not aligned to record boundary: " +
            path_.string() + " (data_size=" + std::to_string(data_size) +
            ", record_size=" +
            std::to_string(BlockIndexDiskEntry::SERIALIZED_SIZE) + ")");
    }

    size_t num_entries = static_cast<size_t>(
        data_size / static_cast<int64_t>(BlockIndexDiskEntry::SERIALIZED_SIZE));
    entries.reserve(num_entries);

    // Read each entry.
    std::vector<uint8_t> record_buf(BlockIndexDiskEntry::SERIALIZED_SIZE);
    for (size_t i = 0; i < num_entries; ++i) {
        file.read(reinterpret_cast<char*>(record_buf.data()),
                  static_cast<std::streamsize>(record_buf.size()));
        if (file.fail()) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "Failed to read entry " + std::to_string(i) +
                " from index database: " + path_.string());
        }

        auto entry_result = BlockIndexDiskEntry::deserialize(
            std::span<const uint8_t>(record_buf));
        if (!entry_result.ok()) {
            return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                "Failed to deserialize entry " + std::to_string(i) +
                ": " + entry_result.error().message());
        }

        entries.push_back(std::move(entry_result).value());
    }

    return entries;
}

// ---------------------------------------------------------------------------
// save -- overwrite the entire database with the given entries
// ---------------------------------------------------------------------------

core::Result<void> IndexDB::save(
    const std::vector<BlockIndexDiskEntry>& entries) {

    // Ensure the parent directory exists.
    std::error_code ec;
    auto parent = path_.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "Failed to create directory: " + parent.string() +
                " (" + ec.message() + ")");
        }
    }

    // Write to a temporary file, then rename for crash safety.
    auto tmp_path = path_;
    tmp_path += ".tmp";

    std::ofstream file(tmp_path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to create temporary index database: " +
            tmp_path.string());
    }

    // Write file header.
    file.write(reinterpret_cast<const char*>(FILE_HEADER), FILE_HEADER_SIZE);
    if (file.fail()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to write index database header: " + tmp_path.string());
    }

    // Write each entry.
    for (size_t i = 0; i < entries.size(); ++i) {
        std::vector<uint8_t> record = entries[i].serialize();
        file.write(reinterpret_cast<const char*>(record.data()),
                   static_cast<std::streamsize>(record.size()));
        if (file.fail()) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "Failed to write entry " + std::to_string(i) +
                " to index database: " + tmp_path.string());
        }
    }

    file.flush();
    if (file.fail()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to flush index database: " + tmp_path.string());
    }
    file.close();

    // Atomically replace the old file with the new one.
    std::filesystem::rename(tmp_path, path_, ec);
    if (ec) {
        // On some Windows filesystems, rename fails if the target exists.
        // Fall back to remove + rename.
        std::filesystem::remove(path_, ec);
        std::filesystem::rename(tmp_path, path_, ec);
        if (ec) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "Failed to rename temporary index database: " +
                tmp_path.string() + " -> " + path_.string() +
                " (" + ec.message() + ")");
        }
    }

    return core::make_ok();
}

// ---------------------------------------------------------------------------
// append -- add a single entry to the end of the database file
// ---------------------------------------------------------------------------

core::Result<void> IndexDB::append(const BlockIndexDiskEntry& entry) {
    // Ensure the parent directory exists.
    std::error_code ec;
    auto parent = path_.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "Failed to create directory: " + parent.string() +
                " (" + ec.message() + ")");
        }
    }

    // If the file does not exist, create it with the header first.
    bool file_exists = std::filesystem::exists(path_, ec);

    if (!file_exists) {
        std::ofstream creator(path_, std::ios::binary);
        if (!creator.is_open()) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "Failed to create index database: " + path_.string());
        }
        creator.write(reinterpret_cast<const char*>(FILE_HEADER),
                      FILE_HEADER_SIZE);
        if (creator.fail()) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "Failed to write header to new index database: " +
                path_.string());
        }
        creator.close();
    }

    // Open the file for appending.
    std::ofstream file(path_,
                       std::ios::binary | std::ios::app);
    if (!file.is_open()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to open index database for append: " +
            path_.string());
    }

    std::vector<uint8_t> record = entry.serialize();
    file.write(reinterpret_cast<const char*>(record.data()),
               static_cast<std::streamsize>(record.size()));
    if (file.fail()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to append entry to index database: " +
            path_.string());
    }

    file.flush();
    if (file.fail()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to flush index database after append: " +
            path_.string());
    }

    return core::make_ok();
}

// ---------------------------------------------------------------------------
// flush -- no-op for this simple implementation (writes are flushed inline)
// ---------------------------------------------------------------------------

core::Result<void> IndexDB::flush() {
    // The save() and append() methods flush before closing.
    // This method exists for interface consistency; it is a no-op.
    return core::make_ok();
}

}} // namespace chain::storage
