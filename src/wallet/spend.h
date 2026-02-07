#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "primitives/amount.h"
#include "primitives/fees.h"
#include "wallet/coins.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace wallet {

// ---------------------------------------------------------------------------
// CoinSelection -- result of coin selection
// ---------------------------------------------------------------------------

struct CoinSelection {
    std::vector<WalletCoin> inputs;
    primitives::Amount total_in;
    primitives::Amount fee;
    primitives::Amount change;
    bool has_change = false;
};

// ---------------------------------------------------------------------------
// Coin selection algorithms
// ---------------------------------------------------------------------------
// Three algorithms are tried in order:
//   1. Branch-and-Bound (BnB) -- finds an exact match with no change
//   2. Knapsack solver -- combinatorial fallback
//   3. Single random draw -- simple fallback
// ---------------------------------------------------------------------------

/// Main coin selection entry point.
/// @param target     The target amount to fund (excluding fees).
/// @param available  Available UTXOs to choose from.
/// @param fee_rate   Fee rate to use for size estimation.
/// @param change_cost  Cost of creating a change output (for BnB threshold).
/// @returns A CoinSelection result, or an error if funding is insufficient.
core::Result<CoinSelection> select_coins(
    primitives::Amount target,
    const std::vector<WalletCoin>& available,
    const primitives::FeeRate& fee_rate,
    primitives::Amount change_cost = primitives::Amount(0));

/// Estimate the virtual size of a transaction given input and output counts.
/// @param num_inputs   Number of inputs (assumed P2WPKH).
/// @param num_outputs  Number of outputs.
/// @returns Estimated size in virtual bytes.
size_t estimate_tx_size(size_t num_inputs, size_t num_outputs);

/// Estimate the fee for a transaction.
primitives::Amount estimate_fee(size_t num_inputs, size_t num_outputs,
                                 const primitives::FeeRate& fee_rate);

/// Get the dust threshold for change outputs.
primitives::Amount get_change_dust_threshold(
    const primitives::FeeRate& dust_relay_fee);

// ---------------------------------------------------------------------------
// Individual algorithms (exposed for testing)
// ---------------------------------------------------------------------------

namespace detail {

/// Branch-and-Bound coin selection.
/// Attempts to find a set of coins whose total equals target + fees exactly
/// (within the change_cost tolerance), avoiding creation of a change output.
core::Result<CoinSelection> select_coins_bnb(
    primitives::Amount target,
    const std::vector<WalletCoin>& available,
    const primitives::FeeRate& fee_rate,
    primitives::Amount change_cost);

/// Knapsack solver.
/// Repeatedly selects random subsets and finds the one closest to the target.
core::Result<CoinSelection> select_coins_knapsack(
    primitives::Amount target,
    const std::vector<WalletCoin>& available,
    const primitives::FeeRate& fee_rate);

/// Single random draw.
/// Selects coins randomly until the target is met.
core::Result<CoinSelection> select_coins_random(
    primitives::Amount target,
    const std::vector<WalletCoin>& available,
    const primitives::FeeRate& fee_rate);

} // namespace detail

} // namespace wallet
