#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/utxo/cache.h"
#include "core/error.h"
#include "core/types.h"

#include <cstdint>
#include <filesystem>

namespace chain::utxo {

// ---------------------------------------------------------------------------
// UtxoDB -- UTXO snapshot persistence
// ---------------------------------------------------------------------------
// Saves and loads the entire UTXO set to/from a binary snapshot file.
// This allows fast node restart without replaying the entire blockchain.
//
// Snapshot file format:
//   [magic: 4 bytes = 0x46544321 ("FTC!")]
//   [version: 4 bytes = 1]
//   [best_block_hash: 32 bytes]
//   [coin_count: 8 bytes (uint64_t)]
//   For each coin:
//     [txid: 32 bytes]
//     [output_index: 4 bytes (uint32_t)]
//     [height: 4 bytes (int32_t)]
//     [is_coinbase: 1 byte]
//     [amount: 8 bytes (int64_t)]
//     [script_pubkey_len: 4 bytes (uint32_t)]
//     [script_pubkey: variable bytes]
// ---------------------------------------------------------------------------
class UtxoDB {
public:
    explicit UtxoDB(const std::filesystem::path& path);

    /// Save the entire UTXO cache to disk as a snapshot.
    core::Result<void> save_snapshot(const UtxoCache& cache);

    /// Load a UTXO snapshot from disk into the cache.
    /// The cache is cleared before loading.
    core::Result<void> load_snapshot(UtxoCache& cache);

    /// Check if a snapshot file exists at the configured path.
    bool has_snapshot() const;

    /// Read only the block hash from the snapshot header without loading
    /// the full coin set.
    core::Result<core::uint256> get_snapshot_hash() const;

    /// Magic bytes identifying a valid FTC UTXO snapshot file.
    static constexpr uint32_t SNAPSHOT_MAGIC   = 0x46544321; // "FTC!"
    /// Current snapshot format version.
    static constexpr uint32_t SNAPSHOT_VERSION = 1;

private:
    std::filesystem::path path_;
};

} // namespace chain::utxo
