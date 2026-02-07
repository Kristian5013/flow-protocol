// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/spend.h"
#include "core/logging.h"
#include "core/random.h"
#include "primitives/script/script.h"

#include <algorithm>
#include <numeric>

namespace wallet {

// ---------------------------------------------------------------------------
// Size estimation
// ---------------------------------------------------------------------------

size_t estimate_tx_size(size_t num_inputs, size_t num_outputs) {
    // P2WPKH transaction size estimation (vbytes):
    // Overhead: 10 bytes (version 4 + locktime 4 + segwit marker 0.5 + flag 0.5 + vin count + vout count)
    // Per input:  ~68 vbytes (outpoint 36 + scriptSig len 1 + sequence 4 + witness ~27 vbytes)
    //   Witness: sig ~72 bytes + pubkey 33 bytes = 105 bytes -> 105/4 ~= 27 vbytes
    // Per output: ~31 bytes (amount 8 + scriptPubKey len 1 + P2WPKH script 22)
    constexpr size_t OVERHEAD = 11;  // rounded up
    constexpr size_t PER_INPUT = 68;
    constexpr size_t PER_OUTPUT = 31;

    return OVERHEAD + num_inputs * PER_INPUT + num_outputs * PER_OUTPUT;
}

primitives::Amount estimate_fee(size_t num_inputs, size_t num_outputs,
                                 const primitives::FeeRate& fee_rate) {
    size_t vsize = estimate_tx_size(num_inputs, num_outputs);
    return fee_rate.compute_fee(vsize);
}

primitives::Amount get_change_dust_threshold(
    const primitives::FeeRate& dust_relay_fee) {
    // P2WPKH change output dust threshold.
    primitives::script::Script p2wpkh_script;
    p2wpkh_script.push_opcode(primitives::script::Opcode::OP_0);
    std::vector<uint8_t> dummy_hash(20, 0);
    p2wpkh_script.push_data(std::span<const uint8_t>(dummy_hash));
    return primitives::dust_threshold(p2wpkh_script, dust_relay_fee);
}

// ---------------------------------------------------------------------------
// Main selection entry point
// ---------------------------------------------------------------------------

core::Result<CoinSelection> select_coins(
    primitives::Amount target,
    const std::vector<WalletCoin>& available,
    const primitives::FeeRate& fee_rate,
    primitives::Amount change_cost) {

    if (available.empty()) {
        return core::Error(core::ErrorCode::WALLET_NO_FUNDS,
                           "No coins available for selection");
    }

    // Calculate total available.
    int64_t total_available = 0;
    for (const auto& coin : available) {
        total_available += coin.output.amount.value();
    }

    if (total_available < target.value()) {
        return core::Error(core::ErrorCode::WALLET_NO_FUNDS,
                           "Insufficient funds: have " +
                           std::to_string(total_available) +
                           ", need " + std::to_string(target.value()));
    }

    // Try BnB first (exact match, no change).
    auto bnb_result = detail::select_coins_bnb(
        target, available, fee_rate, change_cost);
    if (bnb_result.ok()) {
        LOG_DEBUG(core::LogCategory::WALLET,
                  "Coin selection: BnB found exact match");
        return bnb_result;
    }

    // Try knapsack solver.
    auto knapsack_result = detail::select_coins_knapsack(
        target, available, fee_rate);
    if (knapsack_result.ok()) {
        LOG_DEBUG(core::LogCategory::WALLET,
                  "Coin selection: knapsack solver succeeded");
        return knapsack_result;
    }

    // Fall back to random selection.
    auto random_result = detail::select_coins_random(
        target, available, fee_rate);
    if (random_result.ok()) {
        LOG_DEBUG(core::LogCategory::WALLET,
                  "Coin selection: random draw succeeded");
        return random_result;
    }

    return core::Error(core::ErrorCode::WALLET_NO_FUNDS,
                       "All coin selection algorithms failed");
}

// ---------------------------------------------------------------------------
// Branch-and-Bound
// ---------------------------------------------------------------------------

namespace detail {

core::Result<CoinSelection> select_coins_bnb(
    primitives::Amount target,
    const std::vector<WalletCoin>& available,
    const primitives::FeeRate& fee_rate,
    primitives::Amount change_cost) {

    // We want: sum(inputs) - fee = target (exactly, within change_cost).
    // This means: sum(inputs) = target + fee
    // And the "waste" (excess) should be <= change_cost.

    // Sort coins by value descending for better pruning.
    std::vector<size_t> indices(available.size());
    std::iota(indices.begin(), indices.end(), 0);
    std::sort(indices.begin(), indices.end(),
              [&](size_t a, size_t b) {
                  return available[a].output.amount.value() >
                         available[b].output.amount.value();
              });

    // Precompute suffix sums for pruning.
    std::vector<int64_t> suffix_sum(available.size() + 1, 0);
    for (int i = static_cast<int>(indices.size()) - 1; i >= 0; --i) {
        suffix_sum[i] = suffix_sum[i + 1] +
                        available[indices[i]].output.amount.value();
    }

    // Depth-first search.
    constexpr int MAX_TRIES = 100000;
    int tries = 0;

    std::vector<bool> best_selection;
    int64_t best_waste = std::numeric_limits<int64_t>::max();
    int64_t change_cost_val = change_cost.value();

    std::vector<bool> current_selection(available.size(), false);
    int64_t current_value = 0;

    // Use an iterative approach with a stack.
    struct StackEntry {
        size_t depth;
        bool included;
    };

    std::vector<StackEntry> stack;
    stack.push_back({0, true});
    stack.push_back({0, false});

    while (!stack.empty() && tries < MAX_TRIES) {
        ++tries;

        auto [depth, included] = stack.back();
        stack.pop_back();

        // Undo any selections beyond this depth.
        for (size_t i = depth; i < available.size(); ++i) {
            if (current_selection[i]) {
                current_value -= available[indices[i]].output.amount.value();
                current_selection[i] = false;
            }
        }

        if (included) {
            current_selection[depth] = true;
            current_value += available[indices[depth]].output.amount.value();
        }

        // Estimate fee for current selection.
        size_t num_selected = 0;
        for (bool s : current_selection) {
            if (s) ++num_selected;
        }

        if (num_selected == 0 && depth + 1 < available.size()) {
            // Push children.
            if (depth + 1 < available.size()) {
                stack.push_back({depth + 1, false});
                stack.push_back({depth + 1, true});
            }
            continue;
        }

        int64_t est_fee = estimate_fee(
            num_selected > 0 ? num_selected : 1,
            2, fee_rate).value();
        int64_t target_with_fee = target.value() + est_fee;

        // Check if current selection is sufficient.
        if (current_value >= target_with_fee) {
            int64_t waste = current_value - target_with_fee;
            if (waste <= change_cost_val && waste < best_waste) {
                best_waste = waste;
                best_selection = current_selection;

                // Exact match found.
                if (waste == 0) break;
            }
            // No need to go deeper -- adding more coins increases waste.
            continue;
        }

        // Pruning: if remaining coins can't reach target, skip.
        if (depth + 1 < available.size()) {
            int64_t remaining = suffix_sum[depth + 1];
            if (current_value + remaining < target_with_fee) {
                continue;
            }
            stack.push_back({depth + 1, false});
            stack.push_back({depth + 1, true});
        }
    }

    if (best_selection.empty()) {
        return core::Error(core::ErrorCode::WALLET_NO_FUNDS,
                           "BnB: no exact match found");
    }

    // Build result.
    CoinSelection result;
    int64_t total_in = 0;
    for (size_t i = 0; i < best_selection.size(); ++i) {
        if (best_selection[i]) {
            result.inputs.push_back(available[indices[i]]);
            total_in += available[indices[i]].output.amount.value();
        }
    }

    result.total_in = primitives::Amount(total_in);
    result.fee = estimate_fee(result.inputs.size(), 1, fee_rate);
    int64_t change_val = total_in - target.value() - result.fee.value();
    result.change = primitives::Amount(std::max(change_val, int64_t(0)));
    result.has_change = false;  // BnB specifically avoids change.

    return result;
}

// ---------------------------------------------------------------------------
// Knapsack solver
// ---------------------------------------------------------------------------

core::Result<CoinSelection> select_coins_knapsack(
    primitives::Amount target,
    const std::vector<WalletCoin>& available,
    const primitives::FeeRate& fee_rate) {

    constexpr int KNAPSACK_ITERATIONS = 1000;

    // Estimate fee assuming 2 outputs (recipient + change).
    int64_t target_val = target.value();

    // Sort by value descending.
    std::vector<size_t> indices(available.size());
    std::iota(indices.begin(), indices.end(), 0);
    std::sort(indices.begin(), indices.end(),
              [&](size_t a, size_t b) {
                  return available[a].output.amount.value() >
                         available[b].output.amount.value();
              });

    // First, try to find a single coin that is >= target + fee.
    for (size_t idx : indices) {
        int64_t fee = estimate_fee(1, 2, fee_rate).value();
        int64_t needed = target_val + fee;
        if (available[idx].output.amount.value() >= needed) {
            CoinSelection result;
            result.inputs.push_back(available[idx]);
            result.total_in = available[idx].output.amount;
            result.fee = primitives::Amount(fee);
            int64_t change_val = available[idx].output.amount.value() - needed;

            auto dust = get_change_dust_threshold(
                primitives::DEFAULT_MIN_RELAY_FEE);
            if (change_val >= dust.value()) {
                result.change = primitives::Amount(change_val);
                result.has_change = true;
            } else {
                // Absorb sub-dust change into fee.
                result.fee = primitives::Amount(
                    available[idx].output.amount.value() - target_val);
                result.change = primitives::Amount(0);
                result.has_change = false;
            }
            return result;
        }
    }

    // Random subset selection with multiple iterations.
    core::InsecureRandom rng;
    std::vector<bool> best_selection;
    int64_t best_total = std::numeric_limits<int64_t>::max();
    int64_t best_fee = 0;

    for (int iter = 0; iter < KNAPSACK_ITERATIONS; ++iter) {
        std::vector<bool> selection(available.size(), false);
        int64_t current_total = 0;
        size_t num_selected = 0;

        // Shuffle and greedily select.
        std::vector<size_t> shuffled(indices);
        for (size_t i = shuffled.size() - 1; i > 0; --i) {
            size_t j = static_cast<size_t>(rng.range(i + 1));
            std::swap(shuffled[i], shuffled[j]);
        }

        for (size_t idx : shuffled) {
            int64_t fee_est = estimate_fee(
                num_selected + 1, 2, fee_rate).value();
            int64_t needed = target_val + fee_est;

            if (current_total >= needed) break;

            selection[idx] = true;
            current_total += available[idx].output.amount.value();
            ++num_selected;
        }

        int64_t fee_est = estimate_fee(num_selected, 2, fee_rate).value();
        int64_t needed = target_val + fee_est;

        if (current_total >= needed && current_total < best_total) {
            best_total = current_total;
            best_selection = selection;
            best_fee = fee_est;
        }
    }

    if (best_selection.empty()) {
        return core::Error(core::ErrorCode::WALLET_NO_FUNDS,
                           "Knapsack: insufficient funds after " +
                           std::to_string(KNAPSACK_ITERATIONS) + " iterations");
    }

    // Build result.
    CoinSelection result;
    for (size_t i = 0; i < best_selection.size(); ++i) {
        if (best_selection[i]) {
            result.inputs.push_back(available[i]);
        }
    }

    result.total_in = primitives::Amount(best_total);
    result.fee = primitives::Amount(best_fee);
    int64_t change_val = best_total - target_val - best_fee;

    auto dust = get_change_dust_threshold(primitives::DEFAULT_MIN_RELAY_FEE);
    if (change_val >= dust.value()) {
        result.change = primitives::Amount(change_val);
        result.has_change = true;
    } else {
        // Absorb sub-dust change into fee.
        result.fee = primitives::Amount(best_total - target_val);
        result.change = primitives::Amount(0);
        result.has_change = false;
    }

    return result;
}

// ---------------------------------------------------------------------------
// Single random draw
// ---------------------------------------------------------------------------

core::Result<CoinSelection> select_coins_random(
    primitives::Amount target,
    const std::vector<WalletCoin>& available,
    const primitives::FeeRate& fee_rate) {

    int64_t target_val = target.value();

    // Shuffle coins randomly.
    std::vector<size_t> indices(available.size());
    std::iota(indices.begin(), indices.end(), 0);

    core::InsecureRandom rng;
    for (size_t i = indices.size() - 1; i > 0; --i) {
        size_t j = static_cast<size_t>(rng.range(i + 1));
        std::swap(indices[i], indices[j]);
    }

    // Select coins until we have enough.
    CoinSelection result;
    int64_t total_in = 0;

    for (size_t idx : indices) {
        result.inputs.push_back(available[idx]);
        total_in += available[idx].output.amount.value();

        int64_t fee = estimate_fee(
            result.inputs.size(), 2, fee_rate).value();
        int64_t needed = target_val + fee;

        if (total_in >= needed) {
            result.total_in = primitives::Amount(total_in);
            result.fee = primitives::Amount(fee);
            int64_t change_val = total_in - needed;

            auto dust = get_change_dust_threshold(
                primitives::DEFAULT_MIN_RELAY_FEE);
            if (change_val >= dust.value()) {
                result.change = primitives::Amount(change_val);
                result.has_change = true;
            } else {
                result.fee = primitives::Amount(total_in - target_val);
                result.change = primitives::Amount(0);
                result.has_change = false;
            }

            return result;
        }
    }

    return core::Error(core::ErrorCode::WALLET_NO_FUNDS,
                       "Random draw: insufficient funds");
}

} // namespace detail
} // namespace wallet
