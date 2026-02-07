#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/coins.h"
#include "chain/utxo/cache.h"
#include "chain/utxo/view.h"
#include "core/error.h"
#include "core/types.h"
#include "primitives/block.h"
#include "primitives/outpoint.h"

#include <cstddef>
#include <unordered_map>

namespace chain::utxo {

// ---------------------------------------------------------------------------
// UtxoDiff -- tracks UTXO changes for a single block
// ---------------------------------------------------------------------------
// Used during block validation to accumulate changes before committing them
// to the main UtxoCache.  This allows validation to fail without corrupting
// the live UTXO set.
//
// The diff contains two maps:
//   - added:  coins created by the block's transaction outputs
//   - spent:  coins consumed by the block's transaction inputs
//             (stored with their original value so they can be restored)
// ---------------------------------------------------------------------------
struct UtxoDiff {
    /// Coins added by this block (new outputs).
    std::unordered_map<primitives::OutPoint, Coin, UtxoCache::OutPointHash> added;

    /// Coins spent by this block (original coins before spending, for undo).
    std::unordered_map<primitives::OutPoint, Coin, UtxoCache::OutPointHash> spent;

    /// The block hash this diff applies to.
    core::uint256 block_hash;

    // -- Operations ---------------------------------------------------------

    /// Apply this diff to a cache: remove all spent entries, add all added
    /// entries, and update the best block hash.
    void apply_to(UtxoCache& cache) const;

    /// Reverse this diff from a cache: remove all added entries, restore all
    /// spent entries, and leave the best block hash unchanged (caller must
    /// update it separately).
    void reverse_from(UtxoCache& cache) const;

    /// Build a diff from a block against an existing UTXO view.
    /// For each non-coinbase input, looks up the coin in `view` and records
    /// it in `spent`.  For each output, creates a new Coin and records it
    /// in `added`.
    static core::Result<UtxoDiff> from_block(
        const UtxoView& view,
        const primitives::Block& block,
        int height);

    // -- Queries ------------------------------------------------------------

    /// Look up a coin in the added set.  Returns nullptr if not found.
    const Coin* find_added(const primitives::OutPoint& outpoint) const;

    /// Check if an outpoint was spent in this diff.
    bool is_spent(const primitives::OutPoint& outpoint) const;

    /// Total number of new coins added.
    size_t added_count() const { return added.size(); }

    /// Total number of coins spent.
    size_t spent_count() const { return spent.size(); }
};

} // namespace chain::utxo
