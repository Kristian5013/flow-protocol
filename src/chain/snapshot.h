#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// UTXO snapshot handling for fast initial synchronization
// ---------------------------------------------------------------------------
// Supports an "assumeUTXO"-style bootstrap: a snapshot of the UTXO set at
// a known-good block height can be loaded to allow a node to begin
// validating new blocks immediately, while background validation of the
// historical chain catches up.
//
// The snapshot format:
//   [SnapshotMetadata header]  -- block hash, height, coin count, integrity hash
//   [coin entries]             -- serialized (outpoint, coin) pairs
// ---------------------------------------------------------------------------

#include "chain/block_index.h"
#include "chain/coins.h"
#include "core/error.h"
#include "core/types.h"
#include "primitives/outpoint.h"

#include <cstdint>
#include <functional>
#include <span>
#include <vector>

namespace chain::utxo {
    // Forward declaration -- full definition lives in utxo/cache.h
    class UtxoCache;
} // namespace chain::utxo

namespace chain {

// ---------------------------------------------------------------------------
// SnapshotMetadata -- header for a UTXO snapshot
// ---------------------------------------------------------------------------
struct SnapshotMetadata {
    /// Hash of the block at which this snapshot was taken.
    core::uint256 block_hash;

    /// Height of the block at which this snapshot was taken.
    int height = 0;

    /// Number of unspent coins in the snapshot.
    uint64_t coin_count = 0;

    /// Deterministic hash of every coin in the snapshot, used as an
    /// integrity check.  Computed by compute_utxo_hash().
    core::uint256 coins_hash;

    /// Serialize the metadata to a byte vector.
    /// Layout: block_hash (32) | height (4) | coin_count (8) | coins_hash (32)
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize metadata from a byte span.
    [[nodiscard]] static core::Result<SnapshotMetadata> deserialize(
        std::span<const uint8_t> data);

    /// Expected serialized size of the metadata.
    static constexpr size_t SERIALIZED_SIZE = 32 + 4 + 8 + 32; // 76 bytes
};

// ---------------------------------------------------------------------------
// Snapshot utility functions
// ---------------------------------------------------------------------------

/// Compute a deterministic hash of the entire UTXO set for snapshot
/// verification.
///
/// Algorithm:
///   1. Collect all (outpoint, coin) pairs from the cache.
///   2. Sort by outpoint (txid, then index) for determinism.
///   3. Feed each pair into an incremental Keccak-256 hasher.
///   4. Return the final digest.
///
/// This produces a unique fingerprint of the UTXO set state that can be
/// compared against a known-good value to verify snapshot integrity.
core::uint256 compute_utxo_hash(const utxo::UtxoCache& cache);

/// Validate a loaded snapshot against expected metadata.
///
/// Checks:
///   - The coin count matches.
///   - The computed UTXO hash matches the expected coins_hash.
///
/// @param cache     The UTXO cache populated from the snapshot.
/// @param expected  The metadata that was bundled with the snapshot.
/// @returns core::make_ok() on success, or an error describing the mismatch.
core::Result<void> validate_snapshot(
    const utxo::UtxoCache& cache,
    const SnapshotMetadata& expected);

/// Create snapshot metadata from the current UTXO state and chain tip.
///
/// @param cache  The current UTXO cache.
/// @param tip    The block index at the tip of the active chain.
/// @returns A fully populated SnapshotMetadata.
SnapshotMetadata create_snapshot_metadata(
    const utxo::UtxoCache& cache,
    const BlockIndex* tip);

} // namespace chain
