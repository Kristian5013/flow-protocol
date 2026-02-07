// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/fees.h"
#include "wallet/spend.h"

namespace wallet {

// ---------------------------------------------------------------------------
// FeePriority string conversion
// ---------------------------------------------------------------------------

std::string fee_priority_string(FeePriority priority) {
    switch (priority) {
        case FeePriority::LOW:    return "low";
        case FeePriority::MEDIUM: return "medium";
        case FeePriority::HIGH:   return "high";
        case FeePriority::CUSTOM: return "custom";
        default:                  return "unknown";
    }
}

// ---------------------------------------------------------------------------
// FeeManager
// ---------------------------------------------------------------------------

FeeManager::FeeManager()
    : low_fee_rate_(primitives::Amount(1000))       // 1 sat/vB
    , medium_fee_rate_(primitives::Amount(5000))     // 5 sat/vB
    , high_fee_rate_(primitives::Amount(20000))      // 20 sat/vB
    , custom_fee_rate_(primitives::Amount(0))
    , min_relay_fee_(primitives::DEFAULT_MIN_RELAY_FEE)
    , max_fee_rate_(primitives::DEFAULT_MAX_FEE_RATE) {}

// ---------------------------------------------------------------------------
// Fee rate queries
// ---------------------------------------------------------------------------

primitives::FeeRate FeeManager::get_fee_rate(FeePriority priority) const {
    std::lock_guard lock(mutex_);

    primitives::FeeRate rate;

    switch (priority) {
        case FeePriority::LOW:
            rate = low_fee_rate_;
            break;
        case FeePriority::MEDIUM:
            rate = medium_fee_rate_;
            break;
        case FeePriority::HIGH:
            rate = high_fee_rate_;
            break;
        case FeePriority::CUSTOM:
            if (has_custom_rate_) {
                rate = custom_fee_rate_;
            } else {
                rate = medium_fee_rate_;  // Fallback to medium.
            }
            break;
        default:
            rate = medium_fee_rate_;
            break;
    }

    return clamp_fee_rate(rate);
}

primitives::Amount FeeManager::estimate_fee(
    size_t tx_vsize, FeePriority priority) const {
    auto rate = get_fee_rate(priority);
    return rate.compute_fee(tx_vsize);
}

primitives::Amount FeeManager::estimate_fee(
    size_t num_inputs, size_t num_outputs,
    FeePriority priority) const {
    size_t vsize = estimate_tx_size(num_inputs, num_outputs);
    return estimate_fee(vsize, priority);
}

// ---------------------------------------------------------------------------
// Fee rate configuration
// ---------------------------------------------------------------------------

void FeeManager::set_custom_fee_rate(primitives::FeeRate rate) {
    std::lock_guard lock(mutex_);
    custom_fee_rate_ = rate;
    has_custom_rate_ = true;
}

void FeeManager::clear_custom_fee_rate() {
    std::lock_guard lock(mutex_);
    custom_fee_rate_ = primitives::FeeRate(primitives::Amount(0));
    has_custom_rate_ = false;
}

void FeeManager::update_fee_rates(primitives::FeeRate low,
                                    primitives::FeeRate medium,
                                    primitives::FeeRate high) {
    std::lock_guard lock(mutex_);
    low_fee_rate_ = low;
    medium_fee_rate_ = medium;
    high_fee_rate_ = high;
}

void FeeManager::set_min_relay_fee(primitives::FeeRate fee) {
    std::lock_guard lock(mutex_);
    min_relay_fee_ = fee;
}

void FeeManager::set_max_fee_rate(primitives::FeeRate fee) {
    std::lock_guard lock(mutex_);
    max_fee_rate_ = fee;
}

primitives::FeeRate FeeManager::min_relay_fee() const {
    std::lock_guard lock(mutex_);
    return min_relay_fee_;
}

primitives::FeeRate FeeManager::max_fee_rate() const {
    std::lock_guard lock(mutex_);
    return max_fee_rate_;
}

// ---------------------------------------------------------------------------
// Dust threshold
// ---------------------------------------------------------------------------

primitives::Amount FeeManager::dust_threshold(
    const primitives::script::Script& script) const {
    std::lock_guard lock(mutex_);
    return primitives::dust_threshold(script, min_relay_fee_);
}

primitives::Amount FeeManager::p2wpkh_dust_threshold() const {
    // Build a P2WPKH dummy script.
    primitives::script::Script p2wpkh_script;
    p2wpkh_script.push_opcode(primitives::script::Opcode::OP_0);
    std::vector<uint8_t> dummy_hash(20, 0);
    p2wpkh_script.push_data(std::span<const uint8_t>(dummy_hash));
    return dust_threshold(p2wpkh_script);
}

bool FeeManager::is_dust(primitives::Amount amount,
                           const primitives::script::Script& script) const {
    return amount < dust_threshold(script);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

primitives::FeeRate FeeManager::clamp_fee_rate(
    primitives::FeeRate rate) const {
    // Enforce minimum.
    if (rate < min_relay_fee_) {
        rate = min_relay_fee_;
    }

    // Enforce maximum.
    if (rate > max_fee_rate_) {
        rate = max_fee_rate_;
    }

    return rate;
}

} // namespace wallet
