// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/utxo/diff.h"

#include "chain/coins.h"
#include "chain/utxo/cache.h"
#include "chain/utxo/view.h"
#include "core/error.h"
#include "core/types.h"
#include "primitives/block.h"
#include "primitives/outpoint.h"
#include "primitives/transaction.h"
#include "primitives/txin.h"
#include "primitives/txout.h"

#include <cstdint>

namespace chain::utxo {

// ---------------------------------------------------------------------------
// apply_to
// ---------------------------------------------------------------------------

void UtxoDiff::apply_to(UtxoCache& cache) const {
    // Remove all spent coins from the cache.
    for (const auto& [op, coin] : spent) {
        cache.spend_coin(op);
    }

    // Add all new coins to the cache.
    for (const auto& [op, coin] : added) {
        cache.add_coin(op, coin);
    }

    // Update the best block hash.
    cache.set_best_block(block_hash);
}

// ---------------------------------------------------------------------------
// reverse_from
// ---------------------------------------------------------------------------

void UtxoDiff::reverse_from(UtxoCache& cache) const {
    // Remove all coins that were added by this block.
    for (const auto& [op, coin] : added) {
        cache.spend_coin(op);
    }

    // Restore all coins that were spent by this block.
    for (const auto& [op, coin] : spent) {
        cache.add_coin(op, coin);
    }
}

// ---------------------------------------------------------------------------
// from_block
// ---------------------------------------------------------------------------

core::Result<UtxoDiff> UtxoDiff::from_block(
    const UtxoView& view,
    const primitives::Block& block,
    int height)
{
    const auto& txs = block.transactions();
    if (txs.empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "block has no transactions");
    }

    UtxoDiff diff;
    diff.block_hash = block.hash();

    // Process each transaction.
    for (size_t tx_idx = 0; tx_idx < txs.size(); ++tx_idx) {
        const auto& tx = txs[tx_idx];
        bool is_coinbase = tx.is_coinbase();

        // Collect spent coins (skip coinbase -- it has no real inputs).
        if (!is_coinbase) {
            for (const auto& input : tx.vin()) {
                // First check if this input spends a coin that was created
                // earlier in the same block (within this diff's added set).
                auto added_it = diff.added.find(input.prevout);
                if (added_it != diff.added.end()) {
                    // Move the coin from added to spent -- it was created
                    // and consumed within the same block.
                    diff.spent.insert_or_assign(input.prevout,
                                                std::move(added_it->second));
                    diff.added.erase(added_it);
                    continue;
                }

                // Look up in the base view.
                const Coin* coin = view.get_coin(input.prevout);
                if (!coin) {
                    return core::Error(core::ErrorCode::VALIDATION_ERROR,
                        "missing input coin: " + input.prevout.to_string());
                }
                if (coin->is_spent()) {
                    return core::Error(core::ErrorCode::VALIDATION_ERROR,
                        "attempt to spend already-spent coin: " +
                        input.prevout.to_string());
                }

                diff.spent.insert_or_assign(input.prevout, *coin);
            }
        }

        // Add all outputs as new coins.
        const core::uint256& txid = tx.txid();
        for (uint32_t out_idx = 0; out_idx < tx.vout().size(); ++out_idx) {
            const auto& output = tx.vout()[out_idx];
            primitives::OutPoint outpoint(txid, out_idx);
            Coin coin(output, static_cast<int32_t>(height), is_coinbase);
            diff.added.insert_or_assign(outpoint, std::move(coin));
        }
    }

    return diff;
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

const Coin* UtxoDiff::find_added(const primitives::OutPoint& outpoint) const {
    auto it = added.find(outpoint);
    if (it == added.end()) {
        return nullptr;
    }
    return &it->second;
}

bool UtxoDiff::is_spent(const primitives::OutPoint& outpoint) const {
    return spent.find(outpoint) != spent.end();
}

} // namespace chain::utxo
