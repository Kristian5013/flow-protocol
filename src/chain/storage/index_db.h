#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "core/serialize.h"
#include "core/stream.h"
#include "core/types.h"

#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

namespace chain { namespace storage {

// ---------------------------------------------------------------------------
// BlockIndexDiskEntry -- on-disk representation of a single block index node
// ---------------------------------------------------------------------------
// Fixed-size binary record that persists the essential fields of a
// chain::BlockIndex to disk so the block tree can be reconstructed on
// restart without re-scanning blockchain.dat.
// ---------------------------------------------------------------------------
struct BlockIndexDiskEntry {
    core::uint256 block_hash;
    core::uint256 prev_hash;
    int32_t  version          = 0;
    core::uint256 hash_merkle_root;
    uint32_t time             = 0;
    uint32_t bits             = 0;
    uint32_t nonce            = 0;
    int32_t  height           = -1;
    uint32_t status           = 0;
    int64_t  data_pos         = -1;
    int64_t  undo_pos         = -1;
    int32_t  tx_count         = 0;
    core::uint256 chain_work;

    /// Serialize to a fixed-size binary record.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize from a fixed-size binary record.
    [[nodiscard]] static core::Result<BlockIndexDiskEntry> deserialize(
        std::span<const uint8_t> data);

    /// Fixed serialized size in bytes:
    ///   32 (block_hash) + 32 (prev_hash) + 4 (version)
    /// + 32 (merkle_root) + 4 (time) + 4 (bits) + 4 (nonce)
    /// + 4 (height) + 4 (status) + 8 (data_pos) + 8 (undo_pos)
    /// + 4 (tx_count) + 32 (chain_work)
    /// = 172 bytes
    static constexpr size_t SERIALIZED_SIZE =
        32 + 32 + 4 + 32 + 4 + 4 + 4 + 4 + 4 + 8 + 8 + 4 + 32;
};

// ---------------------------------------------------------------------------
// IndexDB -- simple binary file database for the block index
// ---------------------------------------------------------------------------
// Avoids external dependencies (LevelDB, etc.) by using a flat binary file
// of fixed-size BlockIndexDiskEntry records.  Supports full rewrite, load,
// and incremental append.
// ---------------------------------------------------------------------------
class IndexDB {
public:
    explicit IndexDB(const std::filesystem::path& path);

    /// Load all block index entries from the database file.
    core::Result<std::vector<BlockIndexDiskEntry>> load();

    /// Overwrite the database file with the given entries.
    core::Result<void> save(const std::vector<BlockIndexDiskEntry>& entries);

    /// Append a single entry to the end of the database file.
    core::Result<void> append(const BlockIndexDiskEntry& entry);

    /// Flush the database file to disk.
    core::Result<void> flush();

private:
    std::filesystem::path path_;
};

}} // namespace chain::storage
