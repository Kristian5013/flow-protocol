// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/balance.h"

#include <cmath>
#include <iomanip>
#include <sstream>

namespace wallet {

// ---------------------------------------------------------------------------
// Balance computation
// ---------------------------------------------------------------------------

WalletBalance compute_balance(
    const std::vector<WalletCoin>& coins,
    int chain_height,
    int coinbase_maturity) {

    WalletBalance balance;
    balance.confirmed = primitives::Amount(0);
    balance.unconfirmed = primitives::Amount(0);
    balance.immature = primitives::Amount(0);
    balance.total = primitives::Amount(0);
    balance.utxo_count = 0;
    balance.confirmed_utxo_count = 0;
    balance.unconfirmed_utxo_count = 0;
    balance.immature_utxo_count = 0;

    int64_t confirmed_val = 0;
    int64_t unconfirmed_val = 0;
    int64_t immature_val = 0;

    for (const auto& coin : coins) {
        // Skip spent coins.
        if (coin.is_spent) continue;

        int64_t amount = coin.output.amount.value();

        // Calculate confirmations.
        int confirmations = 0;
        if (coin.height > 0 && chain_height >= coin.height) {
            confirmations = chain_height - coin.height + 1;
        }

        ++balance.utxo_count;

        if (confirmations == 0) {
            // Unconfirmed (in mempool, height 0).
            unconfirmed_val += amount;
            ++balance.unconfirmed_utxo_count;
        } else if (coin.is_coinbase && confirmations < coinbase_maturity) {
            // Immature coinbase output.
            immature_val += amount;
            ++balance.immature_utxo_count;
        } else {
            // Confirmed and spendable.
            confirmed_val += amount;
            ++balance.confirmed_utxo_count;
        }
    }

    balance.confirmed = primitives::Amount(confirmed_val);
    balance.unconfirmed = primitives::Amount(unconfirmed_val);
    balance.immature = primitives::Amount(immature_val);
    balance.total = primitives::Amount(
        confirmed_val + unconfirmed_val + immature_val);

    return balance;
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

std::string format_amount(primitives::Amount amount) {
    int64_t value = amount.value();
    bool negative = value < 0;
    if (negative) value = -value;

    int64_t whole = value / primitives::Amount::COIN;
    int64_t frac = value % primitives::Amount::COIN;

    std::ostringstream oss;
    if (negative) oss << "-";
    oss << whole << "." << std::setfill('0') << std::setw(8) << frac;
    oss << " FTC";

    return oss.str();
}

std::string format_balance(const WalletBalance& balance) {
    std::ostringstream oss;

    oss << "Wallet Balance:\n";
    oss << "  Confirmed:   " << format_amount(balance.confirmed)
        << " (" << balance.confirmed_utxo_count << " UTXOs)\n";
    oss << "  Unconfirmed: " << format_amount(balance.unconfirmed)
        << " (" << balance.unconfirmed_utxo_count << " UTXOs)\n";
    oss << "  Immature:    " << format_amount(balance.immature)
        << " (" << balance.immature_utxo_count << " UTXOs)\n";
    oss << "  Total:       " << format_amount(balance.total)
        << " (" << balance.utxo_count << " UTXOs)";

    return oss.str();
}

// ---------------------------------------------------------------------------
// Convenience wrappers
// ---------------------------------------------------------------------------

primitives::Amount compute_confirmed_balance(
    const std::vector<WalletCoin>& coins,
    int chain_height) {

    int64_t total = 0;

    for (const auto& coin : coins) {
        if (coin.is_spent) continue;

        int confirmations = 0;
        if (coin.height > 0 && chain_height >= coin.height) {
            confirmations = chain_height - coin.height + 1;
        }

        if (confirmations >= 1) {
            total += coin.output.amount.value();
        }
    }

    return primitives::Amount(total);
}

primitives::Amount compute_spendable_balance(
    const std::vector<WalletCoin>& coins,
    int chain_height,
    int coinbase_maturity) {

    int64_t total = 0;

    for (const auto& coin : coins) {
        if (coin.is_spent) continue;

        int confirmations = 0;
        if (coin.height > 0 && chain_height >= coin.height) {
            confirmations = chain_height - coin.height + 1;
        }

        // Must have at least 1 confirmation.
        if (confirmations < 1) continue;

        // Coinbase outputs need COINBASE_MATURITY confirmations.
        if (coin.is_coinbase && confirmations < coinbase_maturity) continue;

        total += coin.output.amount.value();
    }

    return primitives::Amount(total);
}

} // namespace wallet
