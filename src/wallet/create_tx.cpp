// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/create_tx.h"
#include "core/logging.h"
#include "primitives/address.h"
#include "primitives/script/script.h"
#include "wallet/addresses.h"

#include <algorithm>

namespace wallet {

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

core::Result<void> validate_transaction_request(
    const TransactionRequest& request) {

    if (request.recipients.empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "Transaction must have at least one recipient");
    }

    for (const auto& recipient : request.recipients) {
        if (recipient.address.empty()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                               "Recipient address must not be empty");
        }

        if (recipient.amount.value() <= 0 && !recipient.subtract_fee) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                               "Recipient amount must be positive");
        }

        if (!recipient.amount.is_valid()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                               "Recipient amount out of valid range");
        }

        // Validate the address format.
        auto addr_result = primitives::Address::from_string(
            recipient.address);
        if (!addr_result.ok()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                               "Invalid recipient address: " +
                               recipient.address);
        }
    }

    if (request.coin_selection.inputs.empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "Coin selection must have at least one input");
    }

    if (request.coin_selection.has_change &&
        request.change_address.empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "Change address required when coin selection "
                           "produces change");
    }

    if (request.coin_selection.has_change &&
        !request.change_address.empty()) {
        auto addr_result = primitives::Address::from_string(
            request.change_address);
        if (!addr_result.ok()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                               "Invalid change address: " +
                               request.change_address);
        }
    }

    // Verify that total inputs cover total outputs + fee.
    int64_t total_out = 0;
    for (const auto& r : request.recipients) {
        total_out += r.amount.value();
    }
    if (request.coin_selection.has_change) {
        total_out += request.coin_selection.change.value();
    }
    total_out += request.coin_selection.fee.value();

    if (request.coin_selection.total_in.value() < total_out) {
        return core::Error(core::ErrorCode::WALLET_NO_FUNDS,
                           "Inputs (" +
                           std::to_string(
                               request.coin_selection.total_in.value()) +
                           ") do not cover outputs + fee (" +
                           std::to_string(total_out) + ")");
    }

    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// Transaction construction
// ---------------------------------------------------------------------------

core::Result<primitives::Transaction> create_transaction(
    const TransactionRequest& request) {

    // Validate the request.
    auto valid_result = validate_transaction_request(request);
    if (!valid_result.ok()) {
        return valid_result.error();
    }

    // Build inputs.
    std::vector<primitives::TxInput> vin;
    vin.reserve(request.coin_selection.inputs.size());

    for (const auto& coin : request.coin_selection.inputs) {
        primitives::TxInput input;
        input.prevout = coin.outpoint;
        input.script_sig = {};  // Will be filled during signing.

        if (request.enable_rbf) {
            // BIP125 RBF: sequence number must be < 0xFFFFFFFE.
            input.sequence = primitives::TxInput::SEQUENCE_FINAL - 2;
        } else {
            // Standard sequence: enable relative locktime but not RBF.
            input.sequence = primitives::TxInput::SEQUENCE_FINAL - 1;
        }

        vin.push_back(std::move(input));
    }

    // Build outputs.
    std::vector<primitives::TxOutput> vout;
    vout.reserve(request.recipients.size() + (request.coin_selection.has_change ? 1 : 0));

    // Handle fee subtraction if requested.
    int64_t fee_to_distribute = 0;
    size_t subtract_fee_count = 0;
    for (const auto& r : request.recipients) {
        if (r.subtract_fee) ++subtract_fee_count;
    }
    if (subtract_fee_count > 0) {
        fee_to_distribute = request.coin_selection.fee.value();
    }

    for (const auto& recipient : request.recipients) {
        auto addr_result = primitives::Address::from_string(
            recipient.address);
        if (!addr_result.ok()) {
            return addr_result.error();
        }

        auto script = addr_result.value().to_script();

        int64_t output_amount = recipient.amount.value();
        if (recipient.subtract_fee && subtract_fee_count > 0) {
            // Distribute fee evenly among subtract-fee outputs.
            int64_t fee_share = fee_to_distribute /
                                static_cast<int64_t>(subtract_fee_count);
            output_amount -= fee_share;

            if (output_amount <= 0) {
                return core::Error(core::ErrorCode::VALIDATION_ERROR,
                                   "Fee exceeds output amount for " +
                                   recipient.address);
            }
        }

        primitives::TxOutput output(
            primitives::Amount(output_amount),
            script.data());
        vout.push_back(std::move(output));
    }

    // Add change output.
    if (request.coin_selection.has_change &&
        request.coin_selection.change.value() > 0) {

        auto change_addr_result = primitives::Address::from_string(
            request.change_address);
        if (!change_addr_result.ok()) {
            return change_addr_result.error();
        }

        auto change_script = change_addr_result.value().to_script();

        primitives::TxOutput change_output(
            request.coin_selection.change,
            change_script.data());

        // Insert change output at a random position to improve privacy.
        // But for simplicity, we append it.
        vout.push_back(std::move(change_output));
    }

    // Set locktime for anti-fee-sniping.
    uint32_t locktime = 0;
    if (request.current_height > 0) {
        // Set locktime to current height. This prevents fee-sniping where
        // a miner replays a transaction in an earlier block.
        locktime = static_cast<uint32_t>(request.current_height);
    }

    // Construct the transaction.
    primitives::Transaction tx(
        std::move(vin), std::move(vout),
        request.tx_version, locktime);

    LOG_INFO(core::LogCategory::WALLET,
             "Created transaction with " +
             std::to_string(tx.vin().size()) + " inputs and " +
             std::to_string(tx.vout().size()) + " outputs, fee=" +
             std::to_string(request.coin_selection.fee.value()));

    return tx;
}

// ---------------------------------------------------------------------------
// Simplified interface
// ---------------------------------------------------------------------------

core::Result<primitives::Transaction> create_simple_transaction(
    const std::string& dest_address,
    primitives::Amount amount,
    const CoinSelection& selection,
    const std::string& change_address,
    int current_height,
    bool enable_rbf) {

    TransactionRequest request;
    request.recipients.push_back({dest_address, amount, false});
    request.coin_selection = selection;
    request.change_address = change_address;
    request.current_height = current_height;
    request.enable_rbf = enable_rbf;

    return create_transaction(request);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

primitives::Amount total_send_amount(
    const std::vector<Recipient>& recipients) {
    int64_t total = 0;
    for (const auto& r : recipients) {
        total += r.amount.value();
    }
    return primitives::Amount(total);
}

} // namespace wallet
