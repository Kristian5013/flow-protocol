// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/snapshot.h"

#include "chain/block_index.h"
#include "chain/coins.h"
#include "chain/utxo/cache.h"
#include "core/error.h"
#include "core/logging.h"
#include "core/serialize.h"
#include "core/stream.h"
#include "core/types.h"
#include "crypto/keccak.h"
#include "primitives/outpoint.h"

#include <algorithm>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace chain {

// ===========================================================================
// SnapshotMetadata serialization
// ===========================================================================

std::vector<uint8_t> SnapshotMetadata::serialize() const {
    std::vector<uint8_t> buf;
    buf.reserve(SERIALIZED_SIZE);

    core::VectorWriter w(buf);
    core::ser_write_uint256(w, block_hash);
    core::ser_write_i32(w, static_cast<int32_t>(height));
    core::ser_write_u64(w, coin_count);
    core::ser_write_uint256(w, coins_hash);

    return buf;
}

core::Result<SnapshotMetadata> SnapshotMetadata::deserialize(
    std::span<const uint8_t> data)
{
    if (data.size() < SERIALIZED_SIZE) {
        return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
            "snapshot metadata too short: expected " +
            std::to_string(SERIALIZED_SIZE) + " bytes, got " +
            std::to_string(data.size()));
    }

    core::SpanReader reader(data);

    SnapshotMetadata meta;
    meta.block_hash = core::ser_read_uint256(reader);
    meta.height     = static_cast<int>(core::ser_read_i32(reader));
    meta.coin_count = core::ser_read_u64(reader);
    meta.coins_hash = core::ser_read_uint256(reader);

    return meta;
}

// ===========================================================================
// compute_utxo_hash
// ===========================================================================
//
// The UTXO hash is a deterministic digest of the entire unspent output set.
// Determinism requires a canonical ordering: we sort all (outpoint, coin)
// pairs lexicographically by outpoint (txid bytes, then output index), then
// serialize each pair into an incremental Keccak-256 hasher.
//
// The UtxoCache provides a for_each_coin() method that invokes a callback
// for every (OutPoint, Coin) pair in the cache.  We collect all pairs,
// sort them, and hash.
// ===========================================================================

core::uint256 compute_utxo_hash(const utxo::UtxoCache& cache) {
    // Collect all coins into a sortable container.
    using CoinEntry = std::pair<primitives::OutPoint, Coin>;
    std::vector<CoinEntry> entries;
    entries.reserve(cache.size());

    auto outpoints = cache.get_all_outpoints();
    for (const auto& outpoint : outpoints) {
        const Coin* coin = cache.get_coin(outpoint);
        if (coin) {
            entries.emplace_back(outpoint, *coin);
        }
    }

    // Sort by outpoint for deterministic ordering.
    // OutPoint comparison: first by txid (uint256 <=> operator), then by
    // output index.
    std::sort(entries.begin(), entries.end(),
        [](const CoinEntry& a, const CoinEntry& b) {
            if (a.first.txid != b.first.txid) {
                return a.first.txid < b.first.txid;
            }
            return a.first.n < b.first.n;
        });

    // Incrementally hash all serialized (outpoint, coin) pairs.
    crypto::Keccak256Hasher hasher;

    for (const auto& [outpoint, coin] : entries) {
        // Serialize the outpoint: 32-byte txid + 4-byte LE index.
        core::DataStream os;
        outpoint.serialize(os);
        auto coin_bytes = coin.serialize();
        core::ser_write_bytes(os,
            std::span<const uint8_t>(coin_bytes));

        // Feed serialized bytes into the hasher.
        std::span<const uint8_t> bytes(os.data(), os.size());
        hasher.write(bytes);
    }

    return hasher.finalize();
}

// ===========================================================================
// validate_snapshot
// ===========================================================================

core::Result<void> validate_snapshot(
    const utxo::UtxoCache& cache,
    const SnapshotMetadata& expected)
{
    // Check coin count.
    uint64_t actual_count = static_cast<uint64_t>(cache.size());
    if (actual_count != expected.coin_count) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "snapshot coin count mismatch: expected " +
            std::to_string(expected.coin_count) + ", got " +
            std::to_string(actual_count));
    }

    // Check integrity hash.
    core::uint256 actual_hash = compute_utxo_hash(cache);
    if (actual_hash != expected.coins_hash) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "snapshot coins hash mismatch: expected " +
            expected.coins_hash.to_hex() + ", got " +
            actual_hash.to_hex());
    }

    LOG_INFO(core::LogCategory::CHAIN,
             "Snapshot validated: " + std::to_string(actual_count) +
             " coins at height " + std::to_string(expected.height));

    return core::make_ok();
}

// ===========================================================================
// create_snapshot_metadata
// ===========================================================================

SnapshotMetadata create_snapshot_metadata(
    const utxo::UtxoCache& cache,
    const BlockIndex* tip)
{
    SnapshotMetadata meta;

    if (tip != nullptr) {
        meta.block_hash = tip->block_hash;
        meta.height     = tip->height;
    }

    meta.coin_count = static_cast<uint64_t>(cache.size());
    meta.coins_hash = compute_utxo_hash(cache);

    LOG_INFO(core::LogCategory::CHAIN,
             "Created snapshot metadata: " +
             std::to_string(meta.coin_count) + " coins at height " +
             std::to_string(meta.height) + ", hash " +
             meta.coins_hash.to_hex());

    return meta;
}

} // namespace chain
