#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/coins.h"
#include "chain/utxo/view.h"
#include "core/error.h"
#include "core/types.h"
#include "primitives/block.h"
#include "primitives/outpoint.h"

#include <cstddef>
#include <optional>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace chain::utxo {

// ---------------------------------------------------------------------------
// UtxoCache -- in-memory UTXO set (the primary UTXO storage)
// ---------------------------------------------------------------------------
// The entire UTXO set lives in memory as an unordered_map keyed by OutPoint.
// This provides O(1) lookup and modification.  The cache is persisted to disk
// as a snapshot file for fast restart (see UtxoDB).
//
// Thread safety: all public methods are protected by a shared_mutex.
// Read operations (get_coin, has_coin, etc.) acquire a shared lock;
// write operations (add_coin, spend_coin, connect_block, etc.) acquire an
// exclusive lock.
// ---------------------------------------------------------------------------
class UtxoCache : public UtxoView {
public:
    UtxoCache();
    ~UtxoCache() override;

    // -- UtxoView interface (read-only, shared-locked) ----------------------

    const Coin* get_coin(const primitives::OutPoint& outpoint) const override;
    bool has_coin(const primitives::OutPoint& outpoint) const override;
    core::uint256 get_best_block() const override;
    size_t size() const override;
    size_t dynamic_memory_usage() const override;

    // -- Mutating operations (exclusive-locked) -----------------------------

    /// Add a coin to the set.  If a coin already exists at this outpoint,
    /// it is overwritten.
    void add_coin(const primitives::OutPoint& outpoint, Coin coin);

    /// Spend (remove) a coin.  Returns the coin that was removed, or
    /// std::nullopt if the outpoint was not found.
    std::optional<Coin> spend_coin(const primitives::OutPoint& outpoint);

    /// Apply a block: add all outputs as new coins, spend all inputs.
    /// Returns the vector of spent coins in input order (for undo data).
    ///
    /// Processing order:
    ///   1. For each non-coinbase transaction, spend all inputs.
    ///   2. For every transaction (including coinbase), add all outputs.
    core::Result<std::vector<Coin>> connect_block(
        const primitives::Block& block, int height);

    /// Disconnect a block: undo all changes using the undo data produced
    /// by connect_block.
    ///
    /// Processing order (reverse of connect_block):
    ///   1. For each transaction in reverse, remove all outputs.
    ///   2. For each non-coinbase transaction in reverse, restore spent coins.
    core::Result<void> disconnect_block(
        const primitives::Block& block,
        const std::vector<Coin>& spent_coins);

    /// Set the best block hash.
    void set_best_block(const core::uint256& hash);

    /// Clear all coins and reset the best block hash.
    void clear();

    /// Get all outpoints currently in the set (for iteration / snapshot).
    std::vector<primitives::OutPoint> get_all_outpoints() const;

    /// Get a mutable reference to a coin.  If the outpoint does not exist,
    /// a default-constructed (null) Coin is inserted and returned.
    /// WARNING: caller must hold no other references into the cache.
    Coin& access_coin(const primitives::OutPoint& outpoint);

    // -- Hash functor exposed for use by UtxoDiff ---------------------------

    struct OutPointHash {
        size_t operator()(const primitives::OutPoint& op) const;
    };

private:
    /// The main UTXO map: OutPoint -> Coin.
    std::unordered_map<primitives::OutPoint, Coin, OutPointHash> coins_;

    /// Hash of the block that this UTXO set represents.
    core::uint256 best_block_;

    /// Guards all access to coins_ and best_block_.
    mutable std::shared_mutex mutex_;
};

} // namespace chain::utxo
