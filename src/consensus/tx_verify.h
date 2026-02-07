#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Transaction-level consensus validation rules
// ---------------------------------------------------------------------------
// check_transaction()           -- context-free structural checks
// check_transaction_contextual() -- context-dependent checks (BIP65/68)
// get_transaction_sig_op_cost() -- weighted signature operation counting
// ---------------------------------------------------------------------------

#include "core/error.h"
#include "primitives/transaction.h"

#include <cstdint>

namespace consensus {

struct ConsensusParams;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum weight of a single transaction (same as max block weight).
static constexpr size_t MAX_TX_WEIGHT = 4'000'000;

/// Witness scale factor: non-witness data is weighted 4x.
static constexpr int WITNESS_SCALE_FACTOR = 4;

// ---------------------------------------------------------------------------
// Context-free transaction validation
// ---------------------------------------------------------------------------

/// Perform context-free ("CheckTransaction") validation of a transaction.
///
/// Checks performed:
///   - vin must not be empty
///   - vout must not be empty
///   - Transaction weight must not exceed MAX_TX_WEIGHT
///   - Each output amount must be in [0, MAX_MONEY]
///   - Sum of all output amounts must not exceed MAX_MONEY
///   - No duplicate inputs (uniqueness of prevout)
///   - Coinbase: scriptSig size in [2, 100]
///   - Non-coinbase: no null prevouts
///
/// Returns core::make_ok() on success, or an appropriate error.
[[nodiscard]] core::Result<void> check_transaction(
    const primitives::Transaction& tx);

// ---------------------------------------------------------------------------
// Context-dependent transaction validation
// ---------------------------------------------------------------------------

/// Perform context-dependent ("ContextualCheckTransaction") validation.
///
/// Checks performed:
///   - BIP65 (CLTV): if active at the given height, verify that the
///     transaction locktime is satisfied.
///   - BIP68 (relative lock-time): if tx.version() >= 2, verify that
///     relative lock-time constraints encoded in input sequences are met.
///
/// @param tx                The transaction to validate.
/// @param height            The block height at which the transaction
///                          would be included.
/// @param median_time_past  The median time past of the previous block.
/// @param params            Consensus parameters.
///
/// Returns core::make_ok() on success, or an appropriate error.
[[nodiscard]] core::Result<void> check_transaction_contextual(
    const primitives::Transaction& tx,
    int height,
    int64_t median_time_past,
    const ConsensusParams& params);

// ---------------------------------------------------------------------------
// Signature operation cost counting
// ---------------------------------------------------------------------------

/// Count the weighted signature operations ("sigops") in a transaction.
///
/// For legacy inputs, each OP_CHECKSIG costs WITNESS_SCALE_FACTOR (4),
/// and each OP_CHECKMULTISIG costs up to 20 * WITNESS_SCALE_FACTOR.
/// For witness inputs, each sigop costs 1 weight unit.
///
/// @param tx          The transaction to examine.
/// @param is_coinbase True if this is a coinbase transaction.
///
/// @returns The total signature operation cost in weight units.
[[nodiscard]] int64_t get_transaction_sig_op_cost(
    const primitives::Transaction& tx,
    bool is_coinbase);

} // namespace consensus
