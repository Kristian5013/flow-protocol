#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "primitives/amount.h"
#include "primitives/transaction.h"
#include "wallet/spend.h"

#include <cstdint>
#include <string>
#include <vector>

namespace wallet {

// ---------------------------------------------------------------------------
// Recipient -- destination for a transaction output
// ---------------------------------------------------------------------------

struct Recipient {
    std::string address;
    primitives::Amount amount;
    bool subtract_fee = false;  // If true, fee is subtracted from this output.
};

// ---------------------------------------------------------------------------
// TransactionRequest -- all parameters needed to build a transaction
// ---------------------------------------------------------------------------

struct TransactionRequest {
    std::vector<Recipient> recipients;
    CoinSelection coin_selection;
    std::string change_address;
    int current_height = 0;        // For anti-fee-sniping locktime.
    bool enable_rbf = false;       // Opt-in RBF via sequence number.
    int32_t tx_version = 2;
};

// ---------------------------------------------------------------------------
// Transaction construction
// ---------------------------------------------------------------------------

/// Create an unsigned transaction from a set of recipients and selected coins.
///
/// Builds the transaction with:
///   - Inputs from the coin selection
///   - Outputs for each recipient
///   - A change output if the coin selection has change
///   - Locktime set to current_height for anti-fee-sniping
///   - RBF sequence numbers if requested
///
/// @param request  Complete transaction request with recipients, coins, etc.
/// @returns An unsigned Transaction ready for signing.
core::Result<primitives::Transaction> create_transaction(
    const TransactionRequest& request);

/// Simplified interface: create a transaction to a single recipient.
core::Result<primitives::Transaction> create_simple_transaction(
    const std::string& dest_address,
    primitives::Amount amount,
    const CoinSelection& selection,
    const std::string& change_address,
    int current_height = 0,
    bool enable_rbf = false);

/// Validate a transaction request before building.
core::Result<void> validate_transaction_request(
    const TransactionRequest& request);

/// Calculate the total amount being sent (sum of all recipient amounts).
primitives::Amount total_send_amount(
    const std::vector<Recipient>& recipients);

} // namespace wallet
