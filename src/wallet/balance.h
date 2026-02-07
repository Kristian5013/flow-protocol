#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/amount.h"
#include "wallet/coins.h"

#include <cstdint>
#include <string>
#include <vector>

namespace wallet {

// ---------------------------------------------------------------------------
// WalletBalance -- complete balance breakdown
// ---------------------------------------------------------------------------

struct WalletBalance {
    /// Confirmed balance: outputs with 1+ confirmations (excluding
    /// immature coinbase outputs).
    primitives::Amount confirmed;

    /// Unconfirmed balance: outputs with 0 confirmations (in mempool).
    primitives::Amount unconfirmed;

    /// Immature balance: coinbase outputs with fewer than
    /// COINBASE_MATURITY confirmations.
    primitives::Amount immature;

    /// Total balance: confirmed + unconfirmed + immature.
    primitives::Amount total;

    /// Total number of UTXOs across all categories.
    size_t utxo_count = 0;

    /// Number of confirmed UTXOs.
    size_t confirmed_utxo_count = 0;

    /// Number of unconfirmed UTXOs.
    size_t unconfirmed_utxo_count = 0;

    /// Number of immature UTXOs.
    size_t immature_utxo_count = 0;
};

// ---------------------------------------------------------------------------
// Balance computation
// ---------------------------------------------------------------------------

/// Default coinbase maturity: number of confirmations required before
/// coinbase outputs become spendable.
static constexpr int COINBASE_MATURITY = 100;

/// Compute the full wallet balance from a set of coins.
///
/// Categorizes each UTXO as confirmed, unconfirmed, or immature based on
/// its height and the current chain height.
///
/// @param coins              All tracked wallet coins (including spent).
/// @param chain_height       Current active chain height.
/// @param coinbase_maturity  Number of confirmations for coinbase maturity
///                           (default 100).
/// @returns A WalletBalance with all categories populated.
WalletBalance compute_balance(
    const std::vector<WalletCoin>& coins,
    int chain_height,
    int coinbase_maturity = COINBASE_MATURITY);

/// Format a WalletBalance as a human-readable multi-line string.
std::string format_balance(const WalletBalance& balance);

/// Format a single Amount as a human-readable FTC string (e.g., "1.23456789 FTC").
std::string format_amount(primitives::Amount amount);

/// Compute just the confirmed balance (convenience wrapper).
primitives::Amount compute_confirmed_balance(
    const std::vector<WalletCoin>& coins,
    int chain_height);

/// Compute the spendable balance (confirmed, excluding immature coinbase).
primitives::Amount compute_spendable_balance(
    const std::vector<WalletCoin>& coins,
    int chain_height,
    int coinbase_maturity = COINBASE_MATURITY);

} // namespace wallet
