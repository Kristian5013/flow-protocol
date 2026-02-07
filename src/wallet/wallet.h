#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/chainstate.h"
#include "core/error.h"
#include "core/types.h"
#include "primitives/amount.h"
#include "primitives/transaction.h"
#include "wallet/addresses.h"
#include "wallet/balance.h"
#include "wallet/coins.h"
#include "wallet/encrypt.h"
#include "wallet/fees.h"
#include "wallet/hd.h"
#include "wallet/history.h"
#include "wallet/keys.h"
#include "wallet/notify.h"
#include "wallet/create_tx.h"
#include "wallet/walletdb.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace wallet {

// ---------------------------------------------------------------------------
// Wallet -- top-level wallet coordinator
// ---------------------------------------------------------------------------
// Owns and coordinates all wallet subsystems: database, key management,
// address book, coin tracking, fee estimation, encryption, and
// notifications. Provides the high-level API used by RPC and GUI.
//
// The wallet runs a background scanner thread that watches the chain tip
// for new blocks and scans them for wallet-relevant transactions.
// ---------------------------------------------------------------------------

class Wallet {
public:
    /// Construct a wallet associated with the given chainstate.
    explicit Wallet(chain::ChainstateManager& chainstate);
    ~Wallet();

    Wallet(const Wallet&) = delete;
    Wallet& operator=(const Wallet&) = delete;

    // -- Lifecycle -----------------------------------------------------------

    /// Open the wallet at the given filesystem path.
    /// Creates a new wallet if the path does not exist.
    core::Result<void> open(const std::filesystem::path& path);

    /// Close the wallet, flushing all data and stopping the scanner thread.
    void close();

    /// Returns true if the wallet is currently loaded and ready.
    [[nodiscard]] bool is_loaded() const;

    // -- Balance queries ----------------------------------------------------

    /// Get the full balance breakdown.
    [[nodiscard]] WalletBalance get_balance() const;

    /// Get the confirmed spendable balance.
    [[nodiscard]] primitives::Amount get_spendable_balance() const;

    // -- Address management -------------------------------------------------

    /// Generate a new receiving address with an optional label.
    core::Result<std::string> get_new_address(const std::string& label = "");

    /// Generate a new change address (internal chain).
    core::Result<std::string> get_change_address();

    /// Get the address book.
    [[nodiscard]] const AddressBook& address_book() const {
        return address_book_;
    }

    // -- Sending / Transactions ---------------------------------------------

    /// Send to a single address. This is the primary send interface.
    ///
    /// Performs: coin selection -> transaction creation -> signing ->
    /// returning the signed transaction ready for broadcast.
    ///
    /// @param address  Destination address.
    /// @param amount   Amount to send.
    /// @param priority Fee priority level.
    /// @returns The signed transaction, or an error.
    core::Result<primitives::Transaction> send_to_address(
        const std::string& address,
        primitives::Amount amount,
        FeePriority priority = FeePriority::MEDIUM);

    /// Send to multiple recipients.
    core::Result<primitives::Transaction> send_many(
        const std::vector<Recipient>& recipients,
        FeePriority priority = FeePriority::MEDIUM);

    // -- Transaction history ------------------------------------------------

    /// List recent transactions.
    std::vector<WalletTx> list_transactions(
        size_t count = 10, size_t skip = 0,
        TxFilter filter = TxFilter::ALL) const;

    /// List unspent outputs.
    std::vector<WalletCoin> list_unspent(
        int minconf = 1, int maxconf = 9999999) const;

    /// Get details for a specific transaction.
    core::Result<WalletTx> get_transaction(
        const core::uint256& txid) const;

    // -- Wallet locking (encryption) ----------------------------------------

    /// Lock the wallet (clear encryption keys from memory).
    void lock();

    /// Unlock the wallet with the given passphrase.
    /// @param passphrase  The wallet passphrase.
    /// @param timeout     Auto-lock timeout (0 = no auto-lock).
    core::Result<void> unlock(std::string_view passphrase,
                               std::chrono::seconds timeout =
                                   std::chrono::seconds(0));

    /// Returns true if the wallet is currently locked.
    [[nodiscard]] bool is_locked() const;

    /// Returns true if the wallet is encrypted.
    [[nodiscard]] bool is_encrypted() const;

    /// Encrypt the wallet with a new passphrase.
    core::Result<void> encrypt_wallet(std::string_view passphrase);

    /// Change the wallet passphrase.
    core::Result<void> change_passphrase(std::string_view old_passphrase,
                                          std::string_view new_passphrase);

    // -- Subsystem access ---------------------------------------------------

    [[nodiscard]] const WalletDB& database() const { return db_; }
    [[nodiscard]] const KeyManager& key_manager() const { return keys_; }
    [[nodiscard]] KeyManager& key_manager() { return keys_; }
    [[nodiscard]] const CoinTracker& coin_tracker() const { return coins_; }
    [[nodiscard]] const FeeManager& fee_manager() const { return fees_; }
    [[nodiscard]] WalletNotify& notifications() { return notify_; }
    [[nodiscard]] const HDWallet& hd_wallet() const { return hd_; }

    // -- Chain scanning control ---------------------------------------------

    /// Force a rescan from the given height.
    core::Result<void> rescan(int from_height = 0);

    /// Get the last scanned block height.
    [[nodiscard]] int last_scanned_height() const;

private:
    chain::ChainstateManager& chainstate_;

    // -- Owned subsystems ---------------------------------------------------
    WalletDB db_;
    KeyManager keys_;
    HDWallet hd_;
    AddressBook address_book_;
    CoinTracker coins_;
    FeeManager fees_;
    WalletEncrypt encryptor_;
    WalletNotify notify_;

    // -- State --------------------------------------------------------------
    mutable std::mutex mutex_;
    std::atomic<bool> loaded_{false};
    std::atomic<int> last_scanned_height_{0};
    std::filesystem::path wallet_path_;

    // -- Auto-lock timer ----------------------------------------------------
    std::chrono::steady_clock::time_point auto_lock_time_;
    bool has_auto_lock_ = false;

    // -- Background scanner thread ------------------------------------------
    std::thread scanner_thread_;
    std::atomic<bool> scanner_running_{false};

    /// Main loop for the background scanner thread.
    void scanner_loop();

    /// Scan a single block for wallet-relevant transactions.
    core::Result<void> scan_block_at_height(int height);

    /// Get the current chain height from the chainstate.
    int chain_height() const;

    /// Check and handle auto-lock timeout.
    void check_auto_lock();

    /// Initialize wallet subsystems after database is open.
    core::Result<void> init_subsystems();

    /// Initialize the HD wallet (create or load).
    core::Result<void> init_hd_wallet();

    /// Store wallet metadata (last scanned height, etc.).
    core::Result<void> store_metadata();

    /// Load wallet metadata.
    core::Result<void> load_metadata();
};

} // namespace wallet
