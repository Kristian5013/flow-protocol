#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Mempool relay policy -- standardness checks and fee/size constants
// ---------------------------------------------------------------------------
// These checks are *policy*, not *consensus*: a transaction that fails them
// is still valid on-chain, but will not be relayed or accepted into the
// mempool by default. Miners can include such transactions if they wish.
// ---------------------------------------------------------------------------

#include "core/error.h"
#include "core/types.h"
#include "primitives/amount.h"
#include "primitives/outpoint.h"
#include "primitives/transaction.h"
#include "primitives/txin.h"
#include "primitives/txout.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace mempool {

// ---------------------------------------------------------------------------
// Fee and relay constants
// ---------------------------------------------------------------------------

/// Minimum relay fee rate in base-units per kvB (1000 virtual bytes).
/// 1000 sat/kvB  ==  1.0 sat/vB.
constexpr int64_t MIN_RELAY_FEE = 1000;

/// Incremental relay fee used for RBF bumps and package eviction.
/// 1000 sat/kvB  ==  1.0 sat/vB.
constexpr int64_t INCREMENTAL_RELAY_FEE = 1000;

/// Dust threshold: outputs below this value (in base units) are rejected.
/// This value applies to P2PKH-like outputs; witness outputs have a lower
/// computed dust threshold (see get_dust_threshold()).
constexpr int64_t DUST_THRESHOLD = 546;

// ---------------------------------------------------------------------------
// Transaction size / weight limits
// ---------------------------------------------------------------------------

/// Maximum weight of a standard (relay-eligible) transaction: 400,000 WU.
/// This is below the consensus limit of 4,000,000 WU (the full block weight).
constexpr size_t MAX_STANDARD_TX_WEIGHT = 400000;

/// Maximum serialized size of a standard transaction: 100 KB.
/// Applied to total_size() (includes witness).
constexpr size_t MAX_STANDARD_TX_SIZE = 100000;

/// Maximum weighted signature operations in a standard transaction.
constexpr size_t MAX_STANDARD_TX_SIGOPS = 4000;

/// Maximum number of inputs in a standard transaction.
constexpr size_t MAX_STANDARD_TX_INPUTS = 2500;

/// Maximum number of outputs in a standard transaction.
constexpr size_t MAX_STANDARD_TX_OUTPUTS = 2500;

/// Maximum size of a single scriptSig in a standard transaction.
constexpr size_t MAX_STANDARD_SCRIPTSIG_SIZE = 1650;

/// Maximum number of stack items in a standard P2SH scriptSig.
constexpr size_t MAX_STANDARD_P2SH_STACK_ITEMS = 15;

/// Maximum size of a single stack item in a standard P2SH scriptSig.
constexpr size_t MAX_STANDARD_P2SH_STACK_ITEM_SIZE = 80;

// ---------------------------------------------------------------------------
// Mempool size and expiry
// ---------------------------------------------------------------------------

/// Default maximum mempool size in bytes: 300 MB.
constexpr size_t DEFAULT_MAX_MEMPOOL_SIZE = 300 * 1024 * 1024;

/// Default minimum mempool size in bytes: 5 MB (never evict below this).
constexpr size_t MIN_MEMPOOL_SIZE = 5 * 1024 * 1024;

/// Mempool transaction expiry time in seconds: 336 hours (2 weeks).
constexpr int64_t MEMPOOL_EXPIRY = 336 * 3600;

// ---------------------------------------------------------------------------
// Package (ancestor/descendant) limits
// ---------------------------------------------------------------------------

/// Maximum number of in-mempool ancestors (including the tx itself).
constexpr size_t MAX_ANCESTORS = 25;

/// Maximum number of in-mempool descendants (including the tx itself).
constexpr size_t MAX_DESCENDANTS = 25;

/// Maximum sum of virtual sizes of in-mempool ancestors (including self).
constexpr size_t MAX_ANCESTOR_SIZE = 101000;

/// Maximum sum of virtual sizes of in-mempool descendants (including self).
constexpr size_t MAX_DESCENDANT_SIZE = 101000;

// ---------------------------------------------------------------------------
// RBF constants
// ---------------------------------------------------------------------------

/// Maximum number of direct conflicts for replace-by-fee.
constexpr size_t MAX_RBF_CONFLICTS = 100;

/// Maximum total number of transactions (conflicts + their descendants)
/// that can be evicted by a single replacement.
constexpr size_t MAX_REPLACEMENT_CANDIDATES = 100;

// ---------------------------------------------------------------------------
// Script type constants for standardness checking
// ---------------------------------------------------------------------------

/// Maximum number of public keys in a bare multisig output.
constexpr size_t MAX_STANDARD_MULTISIG_KEYS = 3;

// ---------------------------------------------------------------------------
// Standardness checks
// ---------------------------------------------------------------------------

/// Check whether a transaction satisfies relay policy ("standard" checks).
///
/// Checks performed:
///   - version is 1 or 2
///   - total_size() <= MAX_STANDARD_TX_SIZE
///   - weight() <= MAX_STANDARD_TX_WEIGHT
///   - no empty vin or vout
///   - number of inputs <= MAX_STANDARD_TX_INPUTS
///   - number of outputs <= MAX_STANDARD_TX_OUTPUTS
///   - scriptSig sizes <= MAX_STANDARD_SCRIPTSIG_SIZE
///   - all output amounts are non-negative
///   - no OP_RETURN outputs with value > 0
///   - (additional script-type checks may be added)
///
/// @param tx  The transaction to check.
/// @returns   core::make_ok() on success, or a VALIDATION_ERROR with a
///            human-readable reason.
[[nodiscard]] core::Result<void> check_standard(
    const primitives::Transaction& tx);

/// Determine whether a single output is "dust" given a relay fee rate.
///
/// An output is dust if the cost to create and later spend it exceeds the
/// output value. The spending cost is estimated based on the scriptPubKey
/// type.
///
/// @param output        The output to evaluate.
/// @param min_relay_fee Fee rate in sat/kvB used for dust evaluation.
/// @returns True if the output is dust.
[[nodiscard]] bool is_dust(const primitives::TxOutput& output,
                           int64_t min_relay_fee);

/// Compute the dust threshold (minimum non-dust amount) for a given output.
///
/// The threshold depends on the scriptPubKey length and type:
///   - P2PKH  (25 bytes): ~148-byte spend input  => 546 sat at 1 sat/vB
///   - P2SH   (23 bytes): ~91-byte spend input    => 540 sat at 1 sat/vB
///   - P2WPKH (22 bytes): ~68-vbyte spend input   => 294 sat at 1 sat/vB
///   - P2WSH  (34 bytes): ~104-vbyte spend input  => 330 sat at 1 sat/vB
///   - P2TR   (34 bytes): ~57.5-vbyte spend input => 330 sat at 1 sat/vB
///   - Other:  ~(32 + scriptPubKey.size())-byte input
///
/// @param output        The output whose dust threshold to compute.
/// @param min_relay_fee Fee rate in sat/kvB.
/// @returns The dust threshold amount.
[[nodiscard]] primitives::Amount get_dust_threshold(
    const primitives::TxOutput& output,
    int64_t min_relay_fee);

/// Compute the "virtual fee" that a transaction of the given fee rate
/// would pay for its actual virtual size.
///
/// @param tx        The transaction (used to obtain vsize).
/// @param fee_rate  Fee rate in sat/kvB.
/// @returns The computed fee in base units.
[[nodiscard]] int64_t get_virtual_fee(const primitives::Transaction& tx,
                                      int64_t fee_rate);

/// Check whether a transaction pays at least the minimum relay fee.
///
/// @param tx   The transaction.
/// @param fee  The fee paid by the transaction.
/// @returns    core::make_ok() on success, or a VALIDATION_ERROR.
[[nodiscard]] core::Result<void> check_min_relay_fee(
    const primitives::Transaction& tx,
    primitives::Amount fee);

/// Check all outputs of a transaction for dust.
///
/// @param tx             The transaction.
/// @param min_relay_fee  Fee rate in sat/kvB used for dust evaluation.
/// @returns              core::make_ok() on success, or a VALIDATION_ERROR
///                       listing the first dust output found.
[[nodiscard]] core::Result<void> check_dust(
    const primitives::Transaction& tx,
    int64_t min_relay_fee = MIN_RELAY_FEE);

/// Check whether a transaction has any bare multisig outputs.
/// Bare multisig outputs (not wrapped in P2SH/P2WSH) are considered
/// non-standard for relay.
///
/// @param tx  The transaction to check.
/// @returns   core::make_ok() on success, or a VALIDATION_ERROR.
[[nodiscard]] core::Result<void> check_bare_multisig(
    const primitives::Transaction& tx);

// ---------------------------------------------------------------------------
// OP_RETURN detection
// ---------------------------------------------------------------------------

/// Returns true if the given scriptPubKey is an OP_RETURN (null data) output.
[[nodiscard]] bool is_op_return(const std::vector<uint8_t>& script_pubkey);

// ---------------------------------------------------------------------------
// Script type classification (simplified for policy purposes)
// ---------------------------------------------------------------------------

enum class ScriptType : uint8_t {
    NONSTANDARD     = 0,
    P2PKH           = 1,   // Pay-to-PubKey-Hash (25 bytes)
    P2SH            = 2,   // Pay-to-Script-Hash (23 bytes)
    P2WPKH          = 3,   // Pay-to-Witness-PubKey-Hash (22 bytes)
    P2WSH           = 4,   // Pay-to-Witness-Script-Hash (34 bytes)
    P2TR            = 5,   // Pay-to-Taproot (34 bytes)
    OP_RETURN       = 6,   // Null data / provably unspendable
    MULTISIG        = 7,   // Bare multisig
    P2PK            = 8,   // Pay-to-PubKey
    WITNESS_UNKNOWN = 9,   // Future witness version
};

/// Classify a scriptPubKey for policy purposes.
///
/// @param script_pubkey  The raw scriptPubKey bytes.
/// @returns The detected script type.
[[nodiscard]] ScriptType classify_script(
    const std::vector<uint8_t>& script_pubkey);

/// Returns the estimated spending input size in virtual bytes for a given
/// script type. Used by dust threshold calculations.
[[nodiscard]] size_t estimated_input_vsize(ScriptType type);

/// Returns the estimated spending input size in virtual bytes for a given
/// scriptPubKey.
[[nodiscard]] size_t estimated_input_vsize(
    const std::vector<uint8_t>& script_pubkey);

/// Returns a human-readable name for a ScriptType.
[[nodiscard]] const char* script_type_name(ScriptType type);

/// Returns a comprehensive policy summary for a transaction.
/// Useful for diagnostic logging and debugging.
///
/// @param tx   The transaction to summarize.
/// @param fee  The fee paid by the transaction.
/// @returns A multi-line string describing the policy check results.
[[nodiscard]] std::string summarize_policy_check(
    const primitives::Transaction& tx,
    primitives::Amount fee);

// ---------------------------------------------------------------------------
// Output type analysis
// ---------------------------------------------------------------------------

/// Count the number of outputs of each type in a transaction.
/// Returns a vector of pairs (ScriptType, count).
///
/// @param tx  The transaction to analyze.
/// @returns A vector of (type, count) pairs for non-zero counts.
[[nodiscard]] std::vector<std::pair<ScriptType, size_t>>
count_output_types(const primitives::Transaction& tx);

/// Returns true if all outputs of the transaction are standard types
/// (anything except NONSTANDARD).
///
/// @param tx  The transaction to check.
/// @returns True if all outputs are standard.
[[nodiscard]] bool all_outputs_standard(const primitives::Transaction& tx);

/// Returns true if the transaction has any witness outputs (P2WPKH,
/// P2WSH, P2TR, or WITNESS_UNKNOWN).
///
/// @param tx  The transaction to check.
/// @returns True if at least one output is a witness type.
[[nodiscard]] bool has_witness_outputs(const primitives::Transaction& tx);

/// Compute the total dust amount across all outputs of a transaction.
/// Returns the sum of (threshold - amount) for all dust outputs.
///
/// @param tx             The transaction.
/// @param min_relay_fee  Fee rate in sat/kvB.
/// @returns The total dust deficit in satoshis (0 if no dust).
[[nodiscard]] int64_t compute_total_dust_deficit(
    const primitives::Transaction& tx,
    int64_t min_relay_fee = MIN_RELAY_FEE);

/// Return the number of OP_RETURN outputs in a transaction.
///
/// @param tx  The transaction to check.
/// @returns The number of OP_RETURN outputs.
[[nodiscard]] size_t count_op_return_outputs(
    const primitives::Transaction& tx);

/// Return the total data payload size of all OP_RETURN outputs.
/// This counts only the bytes after the OP_RETURN opcode.
///
/// @param tx  The transaction to check.
/// @returns Total OP_RETURN data bytes.
[[nodiscard]] size_t total_op_return_data_size(
    const primitives::Transaction& tx);

// ---------------------------------------------------------------------------
// Policy check result type
// ---------------------------------------------------------------------------

/// Comprehensive policy check result with details about each check.
struct PolicyCheckResult {
    bool is_standard = false;
    bool fee_ok = false;
    bool dust_ok = false;
    bool multisig_ok = false;
    std::string rejection_reason;

    /// The fee rate in sat/vB.
    double fee_rate = 0.0;

    /// The required minimum fee in satoshis.
    int64_t min_required_fee = 0;

    /// The number of dust outputs found.
    size_t dust_output_count = 0;

    /// The number of non-standard outputs found.
    size_t nonstandard_output_count = 0;

    /// Returns true if all checks passed.
    [[nodiscard]] bool all_passed() const {
        return is_standard && fee_ok && dust_ok && multisig_ok;
    }

    /// Returns a human-readable summary.
    [[nodiscard]] std::string to_string() const;
};

/// Run all policy checks on a transaction and return a comprehensive result.
///
/// @param tx   The transaction to check.
/// @param fee  The fee paid by the transaction.
/// @returns A PolicyCheckResult with details about each check.
[[nodiscard]] PolicyCheckResult run_all_policy_checks(
    const primitives::Transaction& tx,
    primitives::Amount fee);

} // namespace mempool
