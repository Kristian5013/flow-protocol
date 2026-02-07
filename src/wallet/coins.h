#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "core/types.h"
#include "primitives/amount.h"
#include "primitives/block.h"
#include "primitives/outpoint.h"
#include "primitives/transaction.h"
#include "primitives/txout.h"
#include "wallet/keys.h"
#include "wallet/walletdb.h"

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace wallet {

// ---------------------------------------------------------------------------
// WalletCoin -- a single UTXO owned by the wallet
// ---------------------------------------------------------------------------

struct WalletCoin {
    primitives::OutPoint outpoint;
    primitives::TxOutput output;
    int height = 0;          // block height where this output was created
    bool is_change = false;  // true if this is a change output
    bool is_coinbase = false;
    bool is_spent = false;
    core::uint256 spending_txid;  // txid of the spending transaction (if spent)
};

// ---------------------------------------------------------------------------
// CoinTracker -- tracks wallet-owned UTXOs
// ---------------------------------------------------------------------------
// Scans blocks and transactions to identify outputs belonging to this
// wallet, and maintains the set of spendable coins.
// ---------------------------------------------------------------------------

class CoinTracker {
public:
    CoinTracker() = default;

    /// Initialize with a key manager (to check ownership) and database.
    core::Result<void> init(const KeyManager& keys, WalletDB& db);

    // -- Block scanning -----------------------------------------------------

    /// Scan a full block for wallet-relevant transactions.
    /// Returns the number of relevant transactions found.
    core::Result<size_t> scan_block(const primitives::Block& block,
                                     int height);

    /// Scan a single transaction (e.g., from the mempool).
    /// @param height  Use 0 for unconfirmed transactions.
    core::Result<bool> scan_transaction(
        const primitives::Transaction& tx, int height);

    // -- Ownership checks ---------------------------------------------------

    /// Check if a script belongs to this wallet.
    [[nodiscard]] bool is_mine(
        const std::vector<uint8_t>& script_pubkey) const;

    /// Callback type for ownership checking (used during scanning).
    using OwnershipCheck = std::function<bool(const std::vector<uint8_t>&)>;

    /// Set a custom ownership check function (e.g., to include HD keys).
    void set_ownership_check(OwnershipCheck check);

    // -- UTXO queries -------------------------------------------------------

    /// Get all spendable coins with at least minconf confirmations.
    [[nodiscard]] std::vector<WalletCoin> get_spendable_coins(
        int minconf, int chain_height) const;

    /// Get all coins (including spent ones).
    [[nodiscard]] std::vector<WalletCoin> get_all_coins() const;

    /// Get the total balance (spendable coins only).
    [[nodiscard]] primitives::Amount get_balance(
        int minconf, int chain_height) const;

    /// Get a specific coin by outpoint.
    core::Result<WalletCoin> get_coin(
        const primitives::OutPoint& outpoint) const;

    // -- State updates ------------------------------------------------------

    /// Mark an outpoint as spent by a given transaction.
    core::Result<void> mark_spent(const primitives::OutPoint& outpoint,
                                   const core::uint256& spending_txid);

    /// Mark a transaction as confirmed at a given height.
    core::Result<void> mark_confirmed(const core::uint256& txid,
                                       int height);

    /// Remove all unconfirmed coins (for rescan).
    void clear_unconfirmed();

    // -- Stats --------------------------------------------------------------

    [[nodiscard]] size_t utxo_count() const;
    [[nodiscard]] size_t spent_count() const;

private:
    mutable std::mutex mutex_;
    const KeyManager* keys_ = nullptr;
    WalletDB* db_ = nullptr;
    OwnershipCheck custom_check_;

    /// All tracked coins, keyed by outpoint.
    std::unordered_map<primitives::OutPoint, WalletCoin> coins_;

    /// Set of txids that are wallet-relevant.
    std::unordered_set<core::uint256> wallet_txids_;

    /// Check ownership via KeyManager or custom check.
    bool check_ownership(const std::vector<uint8_t>& script_pubkey) const;

    /// Extract pubkey hash from a standard script.
    static std::optional<core::uint160> extract_pubkey_hash(
        const std::vector<uint8_t>& script_pubkey);

    /// Add a coin to the tracker and persist it.
    core::Result<void> add_coin(const WalletCoin& coin);

    /// Load coins from the database.
    core::Result<void> load_coins();

    /// Persist a coin to the database.
    core::Result<void> store_coin(const WalletCoin& coin);
};

} // namespace wallet
