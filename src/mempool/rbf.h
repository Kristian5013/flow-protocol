#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Replace-by-fee (RBF) policy -- BIP125-based transaction replacement
// ---------------------------------------------------------------------------
// A transaction may replace (evict) one or more conflicting transactions
// in the mempool if:
//
//   1. The conflicting transactions all signal replaceability (BIP125).
//   2. The replacement pays a strictly higher absolute fee than the sum
//      of all evicted transactions (conflicts + their descendants).
//   3. The replacement pays a fee rate at least as high as the minimum
//      relay fee on the additional virtual size it introduces.
//   4. The number of transactions to be evicted does not exceed
//      MAX_REPLACEMENT_CANDIDATES.
//   5. The replacement does not introduce any new unconfirmed inputs
//      that were not already present in the conflicts (anti-pinning).
//
// This module provides the check_rbf() function that evaluates these rules
// and returns an RBFCheck result describing whether replacement is allowed.
// ---------------------------------------------------------------------------

#include "core/types.h"
#include "mempool/entry.h"
#include "mempool/policy.h"
#include "primitives/amount.h"
#include "primitives/transaction.h"
#include "primitives/txin.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace mempool {

// Forward declaration: the Mempool class is used by check_rbf.
class Mempool;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// BIP125 maximum sequence number that still signals opt-in RBF.
/// Sequences <= MAX_BIP125_SEQUENCE (0xfffffffd) signal replaceability.
/// SEQUENCE_FINAL (0xffffffff) and 0xfffffffe do NOT signal RBF.
constexpr uint32_t MAX_BIP125_SEQUENCE = 0xfffffffd;

// ---------------------------------------------------------------------------
// RBFResult -- outcome of an RBF check
// ---------------------------------------------------------------------------

enum class RBFResult : uint8_t {
    /// Replacement is allowed.
    OK = 0,

    /// One or more conflicting transactions do not signal replaceability.
    NOT_REPLACEABLE = 1,

    /// The replacement fee is insufficient (either absolute or fee-rate).
    INSUFFICIENT_FEE = 2,

    /// Too many transactions would be evicted.
    TOO_MANY_CONFLICTS = 3,

    /// The replacement introduces new unconfirmed inputs.
    NEW_UNCONFIRMED_INPUTS = 4,
};

/// Convert an RBFResult to a human-readable string.
[[nodiscard]] const char* rbf_result_string(RBFResult result);

// ---------------------------------------------------------------------------
// RBFCheck -- full result of an RBF evaluation
// ---------------------------------------------------------------------------

struct RBFCheck {
    /// The overall result code.
    RBFResult result = RBFResult::OK;

    /// Human-readable reason string (populated on failure).
    std::string reason;

    /// The set of txids that would be replaced (direct conflicts).
    std::vector<core::uint256> conflicts;

    /// The full set of txids that would be evicted (conflicts + descendants).
    std::vector<core::uint256> all_evicted;

    /// Total fee of all evicted transactions.
    primitives::Amount evicted_fee{0};

    /// Total virtual size of all evicted transactions.
    size_t evicted_vsize = 0;

    /// Returns true if replacement is allowed.
    [[nodiscard]] bool is_ok() const { return result == RBFResult::OK; }
};

// ---------------------------------------------------------------------------
// RBF signaling check
// ---------------------------------------------------------------------------

/// Returns true if a transaction opts in to BIP125 replace-by-fee.
///
/// A transaction signals RBF if any of its inputs has a sequence number
/// less than or equal to MAX_BIP125_SEQUENCE (0xfffffffd). In practice,
/// most wallets use sequence 0xfffffffd for RBF-enabled transactions
/// and 0xffffffff (SEQUENCE_FINAL) for non-replaceable ones.
///
/// @param tx  The transaction to check.
/// @returns True if the transaction signals RBF.
[[nodiscard]] bool signals_rbf(const primitives::Transaction& tx);

// ---------------------------------------------------------------------------
// RBF evaluation
// ---------------------------------------------------------------------------

/// Evaluate whether a new transaction can replace conflicting transactions
/// in the mempool according to BIP125 rules.
///
/// The caller must provide a valid MempoolEntry (with fee and size already
/// computed) and a reference to the Mempool.
///
/// @param new_entry  The candidate replacement transaction.
/// @param pool       The mempool (used to look up conflicts and their
///                   descendants).
/// @returns An RBFCheck describing whether replacement is allowed.
[[nodiscard]] RBFCheck check_rbf(const MempoolEntry& new_entry,
                                 const Mempool& pool);

// ---------------------------------------------------------------------------
// Helper: compute the minimum required fee for a replacement
// ---------------------------------------------------------------------------

/// Compute the minimum fee a replacement must pay.
///
/// BIP125 rule 3: the replacement must pay a higher absolute fee than
/// the sum of all evicted transactions.
/// BIP125 rule 4: the replacement must also pay for its own relay cost
/// (the incremental relay fee on the new virtual bytes introduced).
///
/// @param evicted_fee     Sum of fees of all transactions to be evicted.
/// @param new_vsize       Virtual size of the replacement transaction.
/// @param evicted_vsize   Total virtual size of evicted transactions.
/// @returns The minimum fee the replacement must pay.
[[nodiscard]] primitives::Amount compute_rbf_min_fee(
    primitives::Amount evicted_fee,
    size_t new_vsize,
    size_t evicted_vsize);

// ---------------------------------------------------------------------------
// Helper: check if a tx spends only confirmed inputs plus conflict inputs
// ---------------------------------------------------------------------------

/// Check that a replacement transaction does not introduce new unconfirmed
/// parents that were not already present among the conflict set.
///
/// @param new_tx       The replacement transaction.
/// @param conflicts    Txids of the direct conflicts.
/// @param pool         The mempool (to check if inputs are unconfirmed).
/// @param reason       [out] Reason string on failure.
/// @returns True if no new unconfirmed parents are introduced.
[[nodiscard]] bool check_no_new_unconfirmed(
    const primitives::Transaction& new_tx,
    const std::vector<core::uint256>& conflicts,
    const Mempool& pool,
    std::string& reason);

// ---------------------------------------------------------------------------
// Diagnostic: summarize an RBF check result
// ---------------------------------------------------------------------------

/// Return a multi-line human-readable summary of an RBF check result.
/// Useful for logging and debugging.
///
/// @param check      The RBF check result.
/// @param new_entry  The candidate replacement entry.
/// @returns A multi-line summary string.
[[nodiscard]] std::string summarize_rbf_check(
    const RBFCheck& check,
    const MempoolEntry& new_entry);

// ---------------------------------------------------------------------------
// RBF analysis helpers
// ---------------------------------------------------------------------------

/// Compute the fee surplus (how much extra fee the replacement pays
/// beyond the minimum required).
///
/// @param check      The RBF check result (must have been computed).
/// @param new_entry  The candidate replacement entry.
/// @returns Fee surplus in satoshis (can be negative if insufficient).
[[nodiscard]] inline int64_t rbf_fee_surplus(
    const RBFCheck& check,
    const MempoolEntry& new_entry) {
    primitives::Amount min_fee = compute_rbf_min_fee(
        check.evicted_fee, new_entry.vsize, check.evicted_vsize);
    return new_entry.fee.value() - min_fee.value();
}

/// Compute the fee rate improvement ratio between the replacement
/// and the average fee rate of the evicted transactions.
///
/// @param check      The RBF check result.
/// @param new_entry  The candidate replacement entry.
/// @returns The ratio new_fee_rate / evicted_fee_rate, or 0.0 if
///          evicted_vsize is zero.
[[nodiscard]] inline double rbf_fee_rate_improvement(
    const RBFCheck& check,
    const MempoolEntry& new_entry) {
    if (check.evicted_vsize == 0) return 0.0;
    double evicted_rate = static_cast<double>(check.evicted_fee.value())
                        / static_cast<double>(check.evicted_vsize);
    double new_rate = new_entry.fee_rate();
    if (evicted_rate <= 0.0) return 0.0;
    return new_rate / evicted_rate;
}

/// Check whether a transaction's RBF signaling is consistent: either
/// all inputs signal RBF or none do. Mixed signaling, while valid per
/// BIP125, may indicate a software bug.
///
/// @param tx  The transaction to check.
/// @returns True if all inputs agree on RBF signaling.
[[nodiscard]] bool is_rbf_signaling_consistent(
    const primitives::Transaction& tx);

/// Return the number of inputs that signal RBF in a transaction.
///
/// @param tx  The transaction to check.
/// @returns Number of inputs with sequence <= MAX_BIP125_SEQUENCE.
[[nodiscard]] size_t count_rbf_signals(const primitives::Transaction& tx);

/// Compute the net vsize change for a replacement: how much additional
/// (or less) virtual bytes the replacement adds to the mempool compared
/// to the evicted set.
///
/// @param check      The RBF check result.
/// @param new_entry  The candidate replacement entry.
/// @returns Positive if the replacement is larger, negative if smaller.
[[nodiscard]] inline int64_t rbf_vsize_delta(
    const RBFCheck& check,
    const MempoolEntry& new_entry) {
    return static_cast<int64_t>(new_entry.vsize)
         - static_cast<int64_t>(check.evicted_vsize);
}

/// Compute the net fee change for a replacement: how much additional
/// fee the replacement adds to the mempool compared to the evicted set.
///
/// @param check      The RBF check result.
/// @param new_entry  The candidate replacement entry.
/// @returns Positive if the replacement pays more, negative if less.
[[nodiscard]] inline int64_t rbf_fee_delta(
    const RBFCheck& check,
    const MempoolEntry& new_entry) {
    return new_entry.fee.value() - check.evicted_fee.value();
}

} // namespace mempool
