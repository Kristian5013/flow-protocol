#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/coins.h"
#include "core/error.h"
#include "core/types.h"
#include "primitives/amount.h"
#include "primitives/outpoint.h"
#include "primitives/transaction.h"

#include <cstddef>

namespace chain::utxo {

// ---------------------------------------------------------------------------
// UtxoView -- abstract read-only interface to the UTXO set
// ---------------------------------------------------------------------------
// Provides a uniform way to query unspent coins regardless of the
// underlying storage (in-memory cache, overlay diff, etc.).
// ---------------------------------------------------------------------------
class UtxoView {
public:
    virtual ~UtxoView() = default;

    /// Look up a coin by outpoint.  Returns nullptr if not found.
    virtual const Coin* get_coin(const primitives::OutPoint& outpoint) const = 0;

    /// Check if a coin exists and is unspent.
    virtual bool has_coin(const primitives::OutPoint& outpoint) const = 0;

    /// Get the best block hash this view represents.
    virtual core::uint256 get_best_block() const = 0;

    /// Get total number of unspent outputs.
    virtual size_t size() const = 0;

    /// Estimate dynamic memory usage in bytes.
    virtual size_t dynamic_memory_usage() const = 0;
};

// ---------------------------------------------------------------------------
// Free functions operating on a UtxoView
// ---------------------------------------------------------------------------

/// Check whether all inputs of a transaction are available in the view.
/// Returns true if every input's prevout can be found as an unspent coin.
/// Always returns true for coinbase transactions (they have no real inputs).
bool have_inputs(const UtxoView& view, const primitives::Transaction& tx);

/// Get the total value of all inputs for a transaction by looking up each
/// input's prevout in the view and summing the coin amounts.
/// Returns an error if any input is missing from the view.
core::Result<primitives::Amount> get_value_in(
    const UtxoView& view, const primitives::Transaction& tx);

} // namespace chain::utxo
