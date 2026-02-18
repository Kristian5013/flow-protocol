// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mempool/rbf.h"

#include "core/logging.h"
#include "core/types.h"
#include "mempool/entry.h"
#include "mempool/mempool.h"
#include "mempool/policy.h"
#include "primitives/amount.h"
#include "primitives/outpoint.h"
#include "primitives/transaction.h"
#include "primitives/txin.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_set>
#include <vector>

namespace mempool {

// ---------------------------------------------------------------------------
// rbf_result_string
// ---------------------------------------------------------------------------

const char* rbf_result_string(RBFResult result) {
    switch (result) {
        case RBFResult::OK:
            return "OK";
        case RBFResult::NOT_REPLACEABLE:
            return "NOT_REPLACEABLE";
        case RBFResult::INSUFFICIENT_FEE:
            return "INSUFFICIENT_FEE";
        case RBFResult::TOO_MANY_CONFLICTS:
            return "TOO_MANY_CONFLICTS";
        case RBFResult::NEW_UNCONFIRMED_INPUTS:
            return "NEW_UNCONFIRMED_INPUTS";
        default:
            return "UNKNOWN";
    }
}

// ---------------------------------------------------------------------------
// signals_rbf
// ---------------------------------------------------------------------------

bool signals_rbf(const primitives::Transaction& tx) {
    // BIP125: A transaction is considered to have opted in to allowing
    // replacement if any of its inputs have an nSequence number less than
    // or equal to MAX_BIP125_SEQUENCE (0xfffffffd).
    //
    // Sequence number breakdown:
    //   0xffffffff (SEQUENCE_FINAL): no RBF, no relative timelock
    //   0xfffffffe: no RBF, but opt-in to BIP68 relative timelock
    //   0x00000000 - 0xfffffffd: signals RBF (opt-in replacement)
    //
    // Most wallets use 0xfffffffd for RBF-enabled transactions and
    // 0xffffffff for non-replaceable ones. Some also use 0xfffffffe
    // to opt into relative timelocks without signaling RBF.
    for (const auto& input : tx.vin()) {
        if (input.sequence <= MAX_BIP125_SEQUENCE) {
            return true;
        }
    }
    return false;
}



// ---------------------------------------------------------------------------
// compute_rbf_min_fee
// ---------------------------------------------------------------------------

primitives::Amount compute_rbf_min_fee(
    primitives::Amount evicted_fee,
    size_t new_vsize,
    size_t evicted_vsize) {

    // Rule 3: must pay strictly more than the sum of evicted fees.
    int64_t rule3_fee = evicted_fee.value() + 1;

    // Rule 4: must also pay the incremental relay fee for the new
    // virtual bytes introduced.
    //
    // If the replacement is larger than the total evicted set, the
    // additional bytes must be paid for at INCREMENTAL_RELAY_FEE rate.
    // If the replacement is smaller, rule 4 imposes no additional cost
    // beyond rule 3.
    int64_t additional_vsize = 0;
    if (new_vsize > evicted_vsize) {
        additional_vsize = static_cast<int64_t>(new_vsize - evicted_vsize);
    }
    // Incremental fee = additional_vsize * INCREMENTAL_RELAY_FEE / 1000
    // (INCREMENTAL_RELAY_FEE is in sat/kvB).
    int64_t incremental_fee =
        (additional_vsize * INCREMENTAL_RELAY_FEE + 999) / 1000;

    // The minimum fee is the maximum of rule 3 and rule 4.
    int64_t min_fee = rule3_fee;
    if (evicted_fee.value() + incremental_fee > min_fee) {
        min_fee = evicted_fee.value() + incremental_fee;
    }

    return primitives::Amount{min_fee};
}

// ---------------------------------------------------------------------------
// check_no_new_unconfirmed
// ---------------------------------------------------------------------------

bool check_no_new_unconfirmed(
    const primitives::Transaction& new_tx,
    const std::vector<core::uint256>& conflicts,
    const Mempool& pool,
    std::string& reason) {

    // Build a set of the conflict txids for quick lookup.
    struct Uint256Hash {
        std::size_t operator()(const core::uint256& v) const noexcept {
            return std::hash<core::uint256>{}(v);
        }
    };
    std::unordered_set<core::uint256, Uint256Hash> conflict_set(
        conflicts.begin(), conflicts.end());

    // For each input of the replacement transaction, check if it spends
    // an unconfirmed output that does not belong to a conflict.
    for (const auto& input : new_tx.vin()) {
        // If the input's prevout txid is in the mempool but not a conflict,
        // this is a new unconfirmed parent.
        if (pool.exists(input.prevout.txid)) {
            if (conflict_set.count(input.prevout.txid) == 0) {
                reason = "replacement spends new unconfirmed input "
                       + input.prevout.txid.to_hex() + ":"
                       + std::to_string(input.prevout.n)
                       + " not present in original conflicts";
                return false;
            }
        }

        // Also check: the input could be spending an output created by
        // a different mempool tx (not the prevout's tx). This would also
        // be a new unconfirmed dependency.
        // (The above check already handles this since we check existence
        // of the prevout txid in the mempool.)
    }

    return true;
}

// ---------------------------------------------------------------------------
// check_rbf -- main RBF evaluation
// ---------------------------------------------------------------------------

RBFCheck check_rbf(const MempoolEntry& new_entry,
                   const Mempool& pool) {
    RBFCheck result;

    // -----------------------------------------------------------------------
    // Step 1: Find direct conflicts
    // -----------------------------------------------------------------------
    // A conflict is a mempool transaction that spends the same outpoint
    // as one of the inputs of the new transaction.

    result.conflicts = pool.get_conflicts(new_entry.tx);

    if (result.conflicts.empty()) {
        // No conflicts: this is not an RBF scenario. The transaction can
        // be added normally (if it passes other checks).
        result.result = RBFResult::OK;
        return result;
    }

    LOG_DEBUG(core::LogCategory::MEMPOOL,
        "RBF: tx " + new_entry.txid.to_hex()
        + " conflicts with " + std::to_string(result.conflicts.size())
        + " mempool transactions");

    // -----------------------------------------------------------------------
    // Step 2: Check that all conflicts signal replaceability
    // -----------------------------------------------------------------------
    // BIP125 rule 1: all directly conflicting transactions must signal
    // opt-in RBF via their sequence numbers.

    for (const auto& conflict_txid : result.conflicts) {
        const MempoolEntry* conflict = pool.get(conflict_txid);
        if (conflict == nullptr) {
            // Conflict was removed between get_conflicts() and now; skip.
            continue;
        }

        if (!signals_rbf(conflict->tx)) {
            result.result = RBFResult::NOT_REPLACEABLE;
            result.reason = "conflict " + conflict_txid.to_hex()
                          + " does not signal BIP125 replaceability "
                          + "(no input with sequence <= 0x"
                          + "fffffffd)";
            LOG_DEBUG(core::LogCategory::MEMPOOL,
                "RBF rejected: " + result.reason);
            return result;
        }
    }

    // -----------------------------------------------------------------------
    // Step 3: Gather the full eviction set (conflicts + their descendants)
    // -----------------------------------------------------------------------

    struct Uint256Hash {
        std::size_t operator()(const core::uint256& v) const noexcept {
            return std::hash<core::uint256>{}(v);
        }
    };
    std::unordered_set<core::uint256, Uint256Hash> evicted_set;

    for (const auto& conflict_txid : result.conflicts) {
        evicted_set.insert(conflict_txid);

        // The Mempool does not expose the AncestorTracker directly, but
        // we can infer descendants by checking the new transaction is not
        // in them. We look up each conflict and accumulate.
        const MempoolEntry* conflict = pool.get(conflict_txid);
        if (conflict == nullptr) continue;

        // All transactions in the mempool that are descendants of the
        // conflict will also be evicted.
        // We use a BFS approach through the spender index: for each output
        // of the conflict, find who spends it, then recurse.
        std::vector<core::uint256> to_visit;
        to_visit.push_back(conflict_txid);

        while (!to_visit.empty()) {
            core::uint256 current = to_visit.back();
            to_visit.pop_back();

            const MempoolEntry* cur_entry = pool.get(current);
            if (cur_entry == nullptr) continue;

            // For each output of the current transaction, check if it is
            // spent by another mempool transaction.
            for (size_t i = 0; i < cur_entry->tx.vout().size(); ++i) {
                primitives::OutPoint op(current, static_cast<uint32_t>(i));
                const core::uint256* child_txid = pool.get_spender(op);
                if (child_txid != nullptr) {
                    if (evicted_set.insert(*child_txid).second) {
                        to_visit.push_back(*child_txid);
                    }
                }
            }
        }
    }

    result.all_evicted.assign(evicted_set.begin(), evicted_set.end());

    // -----------------------------------------------------------------------
    // Step 4: Check eviction count limit
    // -----------------------------------------------------------------------
    // BIP125 rule 5: the number of original transactions to be evicted
    // must not exceed MAX_REPLACEMENT_CANDIDATES.

    if (result.all_evicted.size() > MAX_REPLACEMENT_CANDIDATES) {
        result.result = RBFResult::TOO_MANY_CONFLICTS;
        result.reason = "replacement would evict "
                      + std::to_string(result.all_evicted.size())
                      + " transactions, exceeding limit of "
                      + std::to_string(MAX_REPLACEMENT_CANDIDATES);
        LOG_DEBUG(core::LogCategory::MEMPOOL,
            "RBF rejected: " + result.reason);
        return result;
    }

    // -----------------------------------------------------------------------
    // Step 5: Compute total evicted fees and virtual size
    // -----------------------------------------------------------------------

    int64_t total_evicted_fee = 0;
    size_t total_evicted_vsize = 0;

    for (const auto& evicted_txid : result.all_evicted) {
        const MempoolEntry* evicted = pool.get(evicted_txid);
        if (evicted == nullptr) continue;
        total_evicted_fee += evicted->fee.value();
        total_evicted_vsize += evicted->vsize;
    }

    result.evicted_fee = primitives::Amount{total_evicted_fee};
    result.evicted_vsize = total_evicted_vsize;

    // -----------------------------------------------------------------------
    // Step 6: Check fee requirements
    // -----------------------------------------------------------------------
    // BIP125 rule 3: replacement must pay strictly higher absolute fee.
    // BIP125 rule 4: replacement must pay incremental relay fee for any
    //                additional virtual bytes.

    primitives::Amount min_fee = compute_rbf_min_fee(
        result.evicted_fee, new_entry.vsize, result.evicted_vsize);

    if (new_entry.fee.value() < min_fee.value()) {
        result.result = RBFResult::INSUFFICIENT_FEE;
        result.reason = "insufficient replacement fee: "
                      + std::to_string(new_entry.fee.value())
                      + " sat < required " + std::to_string(min_fee.value())
                      + " sat (evicted fee: "
                      + std::to_string(total_evicted_fee)
                      + " sat, incremental relay needed for "
                      + std::to_string(new_entry.vsize) + " vB vs "
                      + std::to_string(total_evicted_vsize) + " vB evicted)";
        LOG_DEBUG(core::LogCategory::MEMPOOL,
            "RBF rejected: " + result.reason);
        return result;
    }

    // Also check that the replacement fee rate is at least as high as the
    // fee rate of the original (highest-feerate conflict). This prevents
    // "fee sniping" where a replacement pays a higher absolute fee but
    // lower fee rate.
    double new_fee_rate = new_entry.fee_rate();
    for (const auto& conflict_txid : result.conflicts) {
        const MempoolEntry* conflict = pool.get(conflict_txid);
        if (conflict == nullptr) continue;

        double conflict_rate = conflict->fee_rate();
        if (new_fee_rate < conflict_rate) {
            result.result = RBFResult::INSUFFICIENT_FEE;
            result.reason = "replacement fee rate "
                          + std::to_string(new_fee_rate) + " sat/vB"
                          + " is lower than conflict "
                          + conflict_txid.to_hex() + " fee rate "
                          + std::to_string(conflict_rate) + " sat/vB";
            LOG_DEBUG(core::LogCategory::MEMPOOL,
                "RBF rejected: " + result.reason);
            return result;
        }
    }

    // -----------------------------------------------------------------------
    // Step 7: Check for new unconfirmed inputs
    // -----------------------------------------------------------------------
    // BIP125 rule 2: the replacement must not introduce any new unconfirmed
    // parents that were not already present among the conflicts.

    {
        std::string unconfirmed_reason;
        if (!check_no_new_unconfirmed(new_entry.tx, result.conflicts,
                                      pool, unconfirmed_reason)) {
            result.result = RBFResult::NEW_UNCONFIRMED_INPUTS;
            result.reason = unconfirmed_reason;
            LOG_DEBUG(core::LogCategory::MEMPOOL,
                "RBF rejected: " + result.reason);
            return result;
        }
    }

    // -----------------------------------------------------------------------
    // All checks passed
    // -----------------------------------------------------------------------

    result.result = RBFResult::OK;
    LOG_DEBUG(core::LogCategory::MEMPOOL,
        "RBF approved: tx " + new_entry.txid.to_hex()
        + " replaces " + std::to_string(result.all_evicted.size())
        + " transactions (evicted fee: "
        + std::to_string(total_evicted_fee) + " sat, new fee: "
        + std::to_string(new_entry.fee.value()) + " sat)");

    return result;
}

// ===========================================================================
// RBF policy design notes
// ===========================================================================
//
// BIP125 defines opt-in replace-by-fee. The five rules are:
//
// Rule 1: Signaling.
//   At least one of the conflicting transactions must signal RBF by having
//   at least one input with nSequence <= 0xfffffffd. In our implementation,
//   we require ALL direct conflicts to signal, which is stricter than
//   BIP125 but matches common node implementations.
//
// Rule 2: No new unconfirmed inputs.
//   The replacement transaction may only spend unconfirmed inputs if those
//   inputs were already present in one of the conflicting transactions.
//   This prevents "pinning" attacks where an attacker adds a chain of
//   unconfirmed transactions to make replacement expensive.
//
//   Note: This rule has been relaxed in some implementations (e.g., Bitcoin
//   Core's fullrbf mode), but we enforce it here for compatibility.
//
// Rule 3: Higher absolute fee.
//   The replacement must pay a strictly higher total fee than the sum of
//   fees of all transactions it would evict (direct conflicts plus their
//   descendants). "Strictly higher" means at least 1 satoshi more.
//
// Rule 4: Incremental relay fee.
//   In addition to rule 3, the replacement must pay for the "bandwidth
//   cost" of relaying the new transaction. If the replacement is larger
//   than the evicted set, the additional virtual bytes must be paid for
//   at INCREMENTAL_RELAY_FEE rate (1 sat/vB).
//
// Rule 5: Eviction count limit.
//   The total number of transactions evicted (conflicts + descendants)
//   must not exceed MAX_REPLACEMENT_CANDIDATES (100). This prevents a
//   single replacement from causing a cascading eviction of the entire
//   mempool.
//
// Fee rate check (additional):
//   We also require that the replacement fee rate be at least as high as
//   the fee rate of each direct conflict. This prevents "fee rate
//   downgrade" attacks where a replacement pays a higher absolute fee but
//   lower fee rate, wasting block space.
//
// Interaction with CPFP (Child-Pays-for-Parent):
//   If a low-fee parent has a high-fee child, the parent's descendant fee
//   rate is high. Replacing the parent requires paying more than the
//   combined parent+child fees, which naturally protects CPFP arrangements
//   from being cheaply disrupted.
//
// Interaction with package limits:
//   After a replacement, the new transaction is subject to normal package
//   limit checks. If the replacement would violate ancestor/descendant
//   limits, it is rejected independently of the RBF check.
//

// ---------------------------------------------------------------------------
// Helper: summarize an RBF check result for logging
// ---------------------------------------------------------------------------

std::string summarize_rbf_check(const RBFCheck& check,
                                const MempoolEntry& new_entry) {
    std::string summary;

    summary += "RBF check for tx " + new_entry.txid.to_hex() + ":\n";
    summary += "  result: " + std::string(rbf_result_string(check.result)) + "\n";

    if (!check.reason.empty()) {
        summary += "  reason: " + check.reason + "\n";
    }

    summary += "  direct conflicts: " + std::to_string(check.conflicts.size()) + "\n";
    for (const auto& conflict : check.conflicts) {
        summary += "    " + conflict.to_hex() + "\n";
    }

    summary += "  total evicted: " + std::to_string(check.all_evicted.size()) + "\n";
    summary += "  evicted fee: " + std::to_string(check.evicted_fee.value()) + " sat\n";
    summary += "  evicted vsize: " + std::to_string(check.evicted_vsize) + " vB\n";
    summary += "  new fee: " + std::to_string(new_entry.fee.value()) + " sat\n";
    summary += "  new vsize: " + std::to_string(new_entry.vsize) + " vB\n";

    // Compute the minimum required fee.
    primitives::Amount min_fee = compute_rbf_min_fee(
        check.evicted_fee, new_entry.vsize, check.evicted_vsize);
    summary += "  min required fee: " + std::to_string(min_fee.value()) + " sat\n";

    // Fee surplus.
    int64_t surplus = new_entry.fee.value() - min_fee.value();
    summary += "  fee surplus: " + std::to_string(surplus) + " sat\n";

    return summary;
}

// ---------------------------------------------------------------------------
// is_rbf_signaling_consistent
// ---------------------------------------------------------------------------

bool is_rbf_signaling_consistent(const primitives::Transaction& tx) {
    if (tx.vin().empty()) return true;

    bool first_signals = tx.vin()[0].sequence <= MAX_BIP125_SEQUENCE;
    for (size_t i = 1; i < tx.vin().size(); ++i) {
        bool input_signals = tx.vin()[i].sequence <= MAX_BIP125_SEQUENCE;
        if (input_signals != first_signals) {
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// count_rbf_signals
// ---------------------------------------------------------------------------

size_t count_rbf_signals(const primitives::Transaction& tx) {
    size_t count = 0;
    for (const auto& input : tx.vin()) {
        if (input.sequence <= MAX_BIP125_SEQUENCE) {
            ++count;
        }
    }
    return count;
}

// ===========================================================================
// Additional RBF design considerations
// ===========================================================================
//
// FULL RBF vs. OPT-IN RBF
// ------------------------
// Our implementation enforces opt-in RBF (BIP125): only transactions
// that explicitly signal replaceability via their sequence numbers can
// be replaced. This is the default policy in Bitcoin Core versions prior
// to v24.0.
//
// Some implementations support "full RBF" (mempoolfullrbf=1), which
// allows replacement of ANY transaction regardless of signaling. This
// was introduced in Bitcoin Core v24.0 as an optional setting. The
// arguments for full RBF include:
//
//   1. Zero-confirmation transactions are inherently unreliable, and
//      the opt-in signal provides a false sense of security.
//   2. Full RBF improves fee market efficiency by allowing more
//      competitive replacements.
//   3. The BIP125 signaling is easily circumvented by spending an
//      output of a signaling transaction, making the entire chain
//      replaceable regardless of the original intention.
//
// Our implementation does not support full RBF but could be extended
// to do so by adding a configuration flag that bypasses the signaling
// check in step 2 of check_rbf().
//
// TRANSACTION PINNING
// -------------------
// Transaction pinning is an attack where an adversary makes a
// transaction expensive to replace by adding a large, low-fee
// descendant chain. The replacement must pay for the entire
// evicted chain (rule 3), which can be prohibitively expensive.
//
// Mitigations implemented:
//   1. Rule 2 (no new unconfirmed inputs) prevents adding new
//      unconfirmed dependencies that could increase the cost of
//      future replacements.
//   2. Rule 5 (eviction count limit of 100) bounds the maximum
//      cost multiplier from descendant chains.
//
// Mitigations NOT implemented (potential future work):
//   1. Package RBF: allowing a package of transactions to be
//      submitted as a replacement, where the package fee covers
//      the minimum replacement cost.
//   2. Sibling eviction: allowing a new transaction to evict a
//      conflicting sibling (sharing the same parent) without
//      requiring the full descendant chain cost.
//   3. Cluster-based eviction: grouping related transactions into
//      "clusters" and replacing entire clusters at once.
//
// RBF RELAY CONSIDERATIONS
// ------------------------
// When a replacement is accepted, the node should:
//   1. Relay the replacement to peers (same as any new mempool tx).
//   2. NOT relay the evicted transactions (they are no longer valid
//      from this node's perspective).
//   3. Peers will naturally evict the conflicting transactions when
//      they receive the replacement and perform their own RBF checks.
//
// This creates a potential inconsistency window where different nodes
// may have different mempool contents. This is normal and expected;
// the mempool is not a consensus structure.
//
// FEE BUMPING STRATEGIES
// ----------------------
// Users can bump fees using two complementary strategies:
//
//   1. RBF (Replace-by-Fee): Create a new transaction that spends
//      the same inputs as the original, but pays a higher fee.
//      Advantages: directly replaces the stuck transaction.
//      Disadvantages: requires knowledge of the original inputs;
//      changes the txid.
//
//   2. CPFP (Child-Pays-for-Parent): Create a new transaction that
//      spends an output of the stuck transaction, with a high enough
//      fee to incentivize miners to include both.
//      Advantages: does not change the original txid; can be done
//      by either the sender or receiver.
//      Disadvantages: requires an available output; increases the
//      total data that must be included in a block.
//
// When both strategies are available, RBF is generally preferred
// because it results in a more compact mempool and block.
//

} // namespace mempool
