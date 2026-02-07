#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "primitives/amount.h"
#include "primitives/fees.h"
#include "primitives/script/script.h"

#include <cstdint>
#include <mutex>
#include <string>

namespace wallet {

// ---------------------------------------------------------------------------
// FeePriority -- user-facing fee urgency levels
// ---------------------------------------------------------------------------

enum class FeePriority : uint8_t {
    LOW    = 0,  // Economical, may take longer to confirm.
    MEDIUM = 1,  // Standard priority.
    HIGH   = 2,  // Fast confirmation target.
    CUSTOM = 3,  // User-specified fee rate.
};

/// Convert a FeePriority to a human-readable string.
[[nodiscard]] std::string fee_priority_string(FeePriority priority);

// ---------------------------------------------------------------------------
// FeeManager -- fee rate selection for wallet transactions
// ---------------------------------------------------------------------------
// Provides fee rate recommendations based on priority level, with
// configurable overrides, floor enforcement, and dust threshold calculation.
// ---------------------------------------------------------------------------

class FeeManager {
public:
    FeeManager();

    // -- Fee rate queries ---------------------------------------------------

    /// Get the recommended fee rate for the given priority level.
    /// @param priority  The urgency level.
    /// @returns Fee rate in satoshis per kvB (kilo-virtual-byte).
    [[nodiscard]] primitives::FeeRate get_fee_rate(
        FeePriority priority) const;

    /// Estimate the total fee for a transaction of the given virtual size.
    [[nodiscard]] primitives::Amount estimate_fee(
        size_t tx_vsize, FeePriority priority) const;

    /// Estimate the total fee for a transaction with the given input/output
    /// counts (assuming P2WPKH).
    [[nodiscard]] primitives::Amount estimate_fee(
        size_t num_inputs, size_t num_outputs,
        FeePriority priority) const;

    // -- Fee rate configuration ---------------------------------------------

    /// Set a custom fee rate override. When set, get_fee_rate(CUSTOM)
    /// returns this value.
    void set_custom_fee_rate(primitives::FeeRate rate);

    /// Clear the custom fee rate.
    void clear_custom_fee_rate();

    /// Set the fee rates for each priority level (typically from fee
    /// estimation).
    void update_fee_rates(primitives::FeeRate low,
                           primitives::FeeRate medium,
                           primitives::FeeRate high);

    /// Set the minimum relay fee floor. Recommended fee rates will never
    /// be below this value.
    void set_min_relay_fee(primitives::FeeRate fee);

    /// Set the maximum fee rate ceiling for safety.
    void set_max_fee_rate(primitives::FeeRate fee);

    /// Get the current minimum relay fee.
    [[nodiscard]] primitives::FeeRate min_relay_fee() const;

    /// Get the current maximum fee rate.
    [[nodiscard]] primitives::FeeRate max_fee_rate() const;

    // -- Dust threshold -----------------------------------------------------

    /// Calculate the dust threshold for a given script type.
    [[nodiscard]] primitives::Amount dust_threshold(
        const primitives::script::Script& script) const;

    /// Calculate the dust threshold for a P2WPKH output.
    [[nodiscard]] primitives::Amount p2wpkh_dust_threshold() const;

    /// Check if an amount is dust for the given script type.
    [[nodiscard]] bool is_dust(primitives::Amount amount,
                                const primitives::script::Script& script) const;

private:
    mutable std::mutex mutex_;

    // Current fee rate estimates.
    primitives::FeeRate low_fee_rate_;
    primitives::FeeRate medium_fee_rate_;
    primitives::FeeRate high_fee_rate_;

    // Custom user override.
    primitives::FeeRate custom_fee_rate_;
    bool has_custom_rate_ = false;

    // Safety bounds.
    primitives::FeeRate min_relay_fee_;
    primitives::FeeRate max_fee_rate_;

    /// Apply floor and ceiling to a fee rate.
    [[nodiscard]] primitives::FeeRate clamp_fee_rate(
        primitives::FeeRate rate) const;
};

} // namespace wallet
