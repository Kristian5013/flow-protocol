#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/amount.h"
#include "primitives/script/script.h"

#include <compare>
#include <cstddef>
#include <cstdint>
#include <string>

namespace primitives {

// ---------------------------------------------------------------------------
// FeeRate  --  fee expressed as base-units per 1000 virtual bytes
// ---------------------------------------------------------------------------

struct FeeRate {
    /// Fee per 1000 virtual bytes (1 kvB).
    Amount fee_per_kvb;

    /// Default: zero fee rate.
    FeeRate() : fee_per_kvb(Amount(0)) {}

    /// Construct from an explicit fee-per-kvB value.
    explicit FeeRate(Amount fee_per_kvb_in)
        : fee_per_kvb(fee_per_kvb_in) {}

    /// Compute the fee for a transaction of the given virtual size.
    ///
    /// The result is rounded up to ensure the fee always meets the minimum
    /// required rate (never undercharges due to integer truncation).
    ///
    /// @param vsize  Virtual size of the transaction in bytes.
    /// @returns The computed fee in base units.
    [[nodiscard]] Amount compute_fee(size_t vsize) const;

    /// Derive a FeeRate from a known total fee and virtual size.
    ///
    /// @param fee    Total fee paid by the transaction.
    /// @param vsize  Virtual size of the transaction in bytes.
    /// @returns The per-kvB fee rate.
    static FeeRate from_fee_and_size(Amount fee, size_t vsize);

    /// Human-readable representation: "X.XX sat/vB".
    [[nodiscard]] std::string to_string() const;

    bool operator==(const FeeRate& other) const {
        return fee_per_kvb == other.fee_per_kvb;
    }
    auto operator<=>(const FeeRate& other) const {
        return fee_per_kvb <=> other.fee_per_kvb;
    }
};

// ---------------------------------------------------------------------------
// Dust threshold
// ---------------------------------------------------------------------------

/// Compute the dust threshold for a given script type and dust relay fee.
///
/// An output is considered "dust" if the cost to spend it (as estimated by
/// the dust relay fee rate) exceeds its value.  The spending cost depends
/// on the script type:
///
///   - P2PKH:  spending input is ~148 bytes
///   - P2SH:   spending input is ~91 bytes (assuming P2SH-P2WPKH)
///   - P2WPKH: spending input is ~68 vbytes
///   - P2WSH:  spending input is ~104 vbytes
///   - P2TR:   spending input is ~57.5 vbytes
///   - Other:  spending input is estimated as ~32 + scriptPubKey.size()
///
/// The threshold is the minimum output value such that the output is not
/// considered dust.
///
/// @param script         The scriptPubKey of the output.
/// @param dust_relay_fee The fee rate used for dust evaluation.
/// @returns The minimum non-dust amount for the given script type.
Amount dust_threshold(const script::Script& script,
                      const FeeRate& dust_relay_fee);

// ---------------------------------------------------------------------------
// Default fee rate constants
// ---------------------------------------------------------------------------

/// Minimum relay fee: 1000 base-units per kvB (equivalent to 1 sat/vB).
inline const FeeRate DEFAULT_MIN_RELAY_FEE{Amount(1000)};

/// Fallback fee for when no estimation data is available:
/// 20000 base-units per kvB (equivalent to 20 sat/vB).
inline const FeeRate DEFAULT_FALLBACK_FEE{Amount(20000)};

/// Incremental relay fee: the minimum fee rate bump for package relay and
/// mempool eviction.  1000 base-units per kvB (1 sat/vB).
inline const FeeRate DEFAULT_INCREMENTAL_RELAY_FEE{Amount(1000)};

/// Maximum fee rate a wallet will set by default to prevent accidents:
/// 1 FTC per kvB.
inline const FeeRate DEFAULT_MAX_FEE_RATE{Amount(Amount::COIN)};

} // namespace primitives
