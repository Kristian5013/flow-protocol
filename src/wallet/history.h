#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "core/types.h"
#include "primitives/amount.h"
#include "wallet/coins.h"
#include "wallet/walletdb.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace wallet {

// Forward declarations.
class KeyManager;
class AddressBook;

// ---------------------------------------------------------------------------
// TxFilter -- filter for transaction history queries
// ---------------------------------------------------------------------------

enum class TxFilter : uint8_t {
    ALL      = 0,
    SEND     = 1,
    RECEIVE  = 2,
    COINBASE = 3,
};

// ---------------------------------------------------------------------------
// TxCategory -- transaction category classification
// ---------------------------------------------------------------------------

enum class TxCategory : uint8_t {
    SEND     = 0,
    RECEIVE  = 1,
    GENERATE = 2,   // Mature coinbase.
    IMMATURE = 3,   // Immature coinbase.
    ORPHAN   = 4,   // Orphaned coinbase.
    UNKNOWN  = 5,
};

/// Convert a TxCategory to a human-readable string.
[[nodiscard]] std::string tx_category_string(TxCategory category);

// ---------------------------------------------------------------------------
// WalletTx -- a single transaction in the wallet history
// ---------------------------------------------------------------------------

struct WalletTx {
    core::uint256 txid;
    primitives::Amount amount;     // Net amount (positive = receive, negative = send).
    primitives::Amount fee;        // Fee paid (for send transactions).
    int confirmations = 0;
    int64_t time = 0;              // Unix timestamp of the block (or time received).
    int height = 0;                // Block height (0 = unconfirmed).
    std::string label;             // Address label.
    std::string address;           // Primary address involved.
    TxCategory category = TxCategory::UNKNOWN;
    bool is_send = false;          // True if this is a send transaction.

    /// List of addresses receiving funds in this transaction.
    std::vector<std::string> output_addresses;

    /// Number of inputs and outputs.
    size_t num_inputs = 0;
    size_t num_outputs = 0;
};

// ---------------------------------------------------------------------------
// Transaction history functions
// ---------------------------------------------------------------------------

/// Get the transaction history for the wallet.
///
/// @param db            The wallet database.
/// @param coins         The coin tracker.
/// @param keys          The key manager.
/// @param addresses     The address book.
/// @param chain_height  Current chain height.
/// @param count         Maximum number of transactions to return.
/// @param skip          Number of transactions to skip (for pagination).
/// @param filter        Filter by transaction type.
/// @returns A vector of WalletTx entries, newest first.
std::vector<WalletTx> get_transactions(
    const WalletDB& db,
    const CoinTracker& coins,
    const KeyManager& keys,
    const AddressBook& addresses,
    int chain_height,
    size_t count = 100,
    size_t skip = 0,
    TxFilter filter = TxFilter::ALL);

/// Get detailed information about a single transaction.
///
/// @param db            The wallet database.
/// @param coins         The coin tracker.
/// @param keys          The key manager.
/// @param addresses     The address book.
/// @param txid          The transaction ID to look up.
/// @param chain_height  Current chain height.
/// @returns The WalletTx detail, or an error if the transaction is not found.
core::Result<WalletTx> get_transaction_detail(
    const WalletDB& db,
    const CoinTracker& coins,
    const KeyManager& keys,
    const AddressBook& addresses,
    const core::uint256& txid,
    int chain_height);

/// Store a transaction record in the wallet database.
core::Result<void> store_wallet_tx(WalletDB& db, const WalletTx& wtx);

/// Load a transaction record from the wallet database.
core::Result<WalletTx> load_wallet_tx(const WalletDB& db,
                                       const core::uint256& txid);

/// Determine the category of a wallet transaction.
TxCategory categorize_transaction(
    const WalletTx& wtx,
    int chain_height,
    int coinbase_maturity = 100);

} // namespace wallet
