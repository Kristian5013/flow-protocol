#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/storage/flatfile.h"
#include "core/error.h"
#include "primitives/block.h"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <vector>

namespace chain { namespace storage {

// ---------------------------------------------------------------------------
// RecordHeader -- magic + size + type prefix for each record in blockchain.dat
// ---------------------------------------------------------------------------
struct RecordHeader {
    uint32_t magic;    // 0x46544321 ("FTC!")
    uint32_t size;     // byte count of the payload following this header
    uint8_t  type;     // 0x01 = block, 0x02 = undo
};

/// Size of a serialized RecordHeader: 4 (magic) + 4 (size) + 1 (type).
static constexpr size_t RECORD_HEADER_SIZE = 9;

/// Magic constant written at the start of every record.
static constexpr uint32_t RECORD_MAGIC = 0x46544321;

/// Record type: serialized block data.
static constexpr uint8_t RECORD_TYPE_BLOCK = 0x01;

/// Record type: undo data for a block.
static constexpr uint8_t RECORD_TYPE_UNDO  = 0x02;

// ---------------------------------------------------------------------------
// BlockStore -- manages writing/reading blocks and undo data to blockchain.dat
// ---------------------------------------------------------------------------
// The single blockchain.dat file uses an append-only layout:
//
//   [RecordHeader][payload bytes]  -- first record
//   [RecordHeader][payload bytes]  -- second record
//   ...
//
// Block records (type 0x01) contain the full serialized block.
// Undo records (type 0x02) contain raw undo bytes.
// ---------------------------------------------------------------------------
class BlockStore {
public:
    explicit BlockStore(const std::filesystem::path& data_dir);
    ~BlockStore();

    /// Initialize the store (opens or creates blockchain.dat).
    core::Result<void> init();

    /// Write a serialized block to storage.
    /// Returns the byte offset of the record header in blockchain.dat.
    core::Result<int64_t> write_block(const primitives::Block& block);

    /// Read a block from storage at the given byte offset.
    core::Result<primitives::Block> read_block(int64_t pos);

    /// Write raw undo data to storage.
    /// Returns the byte offset of the record header in blockchain.dat.
    core::Result<int64_t> write_undo(const std::vector<uint8_t>& undo_data);

    /// Read raw undo data from storage at the given byte offset.
    core::Result<std::vector<uint8_t>> read_undo(int64_t pos);

    /// Flush pending writes to disk.
    core::Result<void> flush();

    /// Return the total size of blockchain.dat in bytes.
    core::Result<int64_t> total_size() const;

private:
    std::filesystem::path data_dir_;
    std::unique_ptr<FlatFile> file_;

    /// Write a record (header + payload) and return the offset of the header.
    core::Result<int64_t> write_record(uint8_t type,
                                       std::span<const uint8_t> data);

    /// Read and validate the record header at the given offset.
    core::Result<RecordHeader> read_record_header(int64_t pos);
};

}} // namespace chain::storage
