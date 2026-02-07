// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/utxo/view.h"

#include "core/error.h"
#include "primitives/amount.h"
#include "primitives/outpoint.h"
#include "primitives/transaction.h"
#include "primitives/txin.h"

namespace chain::utxo {

bool have_inputs(const UtxoView& view, const primitives::Transaction& tx) {
    // Coinbase transactions create coins from nothing -- they have no
    // real inputs to look up.
    if (tx.is_coinbase()) {
        return true;
    }

    for (const auto& input : tx.vin()) {
        if (!view.has_coin(input.prevout)) {
            return false;
        }
    }
    return true;
}

core::Result<primitives::Amount> get_value_in(
    const UtxoView& view, const primitives::Transaction& tx)
{
    // Coinbase transactions have no real inputs -- their value comes from
    // the block subsidy + fees, not from existing coins.
    if (tx.is_coinbase()) {
        return primitives::Amount(0);
    }

    int64_t total = 0;

    for (const auto& input : tx.vin()) {
        const Coin* coin = view.get_coin(input.prevout);
        if (!coin) {
            return core::Error(core::ErrorCode::STORAGE_NOT_FOUND,
                "input coin not found: " + input.prevout.to_string());
        }

        if (coin->is_spent()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "input coin is spent: " + input.prevout.to_string());
        }

        int64_t val = coin->out.amount.value();
        total += val;

        // Overflow check: total should remain within the valid money range.
        if (total < 0 || total > primitives::Amount::MAX_MONEY) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "input value sum out of range");
        }
    }

    return primitives::Amount(total);
}

} // namespace chain::utxo
