// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mempool/mempool.h"

#include "core/error.h"
#include "core/logging.h"
#include "core/time.h"
#include "core/types.h"
#include "mempool/ancestor.h"
#include "mempool/entry.h"
#include "mempool/fee_estimator.h"
#include "mempool/orphan.h"
#include "mempool/policy.h"
#include "mempool/rbf.h"
#include "primitives/amount.h"
#include "primitives/block.h"
#include "primitives/outpoint.h"
#include "primitives/transaction.h"
#include "primitives/txin.h"
#include "primitives/txout.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <queue>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace mempool {

// ===========================================================================
// Construction
// ===========================================================================

Mempool::Mempool(size_t max_size)
    : max_size_(max_size) {
    LOG_INFO(core::LogCategory::MEMPOOL,
        "mempool initialized with max size "
        + std::to_string(max_size / (1024 * 1024)) + " MB");
}

// ===========================================================================
// add -- public entry point with full policy checks
// ===========================================================================

core::Result<void> Mempool::add(MempoolEntry entry) {
    // -----------------------------------------------------------------------
    // Phase 1: Pre-lock validation (no lock needed for stateless checks)
    // -----------------------------------------------------------------------

    // 1a. Standardness checks.
    {
        auto result = check_standard(entry.tx);
        if (!result.ok()) {
            LOG_DEBUG(core::LogCategory::MEMPOOL,
                "mempool: rejecting tx " + entry.txid.to_hex()
                + ": " + result.error().message());
            return result.error();
        }
    }

    // 1b. Check minimum relay fee.
    {
        auto result = check_min_relay_fee(entry.tx, entry.fee);
        if (!result.ok()) {
            LOG_DEBUG(core::LogCategory::MEMPOOL,
                "mempool: rejecting tx " + entry.txid.to_hex()
                + ": " + result.error().message());
            return result.error();
        }
    }

    // 1c. Dust check on all outputs.
    {
        auto result = check_dust(entry.tx, MIN_RELAY_FEE);
        if (!result.ok()) {
            LOG_DEBUG(core::LogCategory::MEMPOOL,
                "mempool: rejecting tx " + entry.txid.to_hex()
                + ": " + result.error().message());
            return result.error();
        }
    }

    // 1d. Check that the fee is within sane bounds.
    if (entry.fee.value() < 0) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "negative fee");
    }
    if (!entry.fee.is_valid()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "fee exceeds MAX_MONEY");
    }

    // 1e. Validate basic entry fields.
    if (entry.vsize == 0) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "transaction has zero virtual size");
    }
    if (entry.size == 0) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "transaction has zero serialized size");
    }

    // 1f. Check that the transaction is not a coinbase (coinbase txs
    // cannot be in the mempool -- they are created by miners).
    if (entry.tx.is_coinbase()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "coinbase transactions cannot be added to the mempool");
    }

    // 1g. Check that all inputs reference non-null outpoints.
    for (size_t i = 0; i < entry.tx.vin().size(); ++i) {
        const auto& input = entry.tx.vin()[i];
        if (input.prevout.is_null()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "input " + std::to_string(i)
                + " references a null outpoint");
        }
    }

    // 1h. Check that the fee rate is not absurdly high (potential mistake).
    // We warn but don't reject: a fee of > 1 FTC / vB is likely an error.
    {
        double rate = entry.fee_rate();
        if (rate > 100000.0) {
            // 100,000 sat/vB is extremely high (0.001 FTC per vB).
            LOG_WARN(core::LogCategory::MEMPOOL,
                "mempool: tx " + entry.txid.to_hex()
                + " has unusually high fee rate: "
                + std::to_string(rate) + " sat/vB"
                + " (fee: " + std::to_string(entry.fee.value()) + " sat"
                + ", vsize: " + std::to_string(entry.vsize) + " vB)");
        }
    }

    // 1i. Check total output value does not exceed inputs (fee must be >= 0).
    // This is redundant with the fee >= 0 check above but provides a
    // clearer error message.
    {
        int64_t total_output = 0;
        for (const auto& output : entry.tx.vout()) {
            total_output += output.amount.value();
        }
        if (total_output < 0) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "total output value is negative: "
                + std::to_string(total_output));
        }
        if (!primitives::Amount{total_output}.is_valid()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "total output value exceeds MAX_MONEY: "
                + std::to_string(total_output));
        }
    }

    // -----------------------------------------------------------------------
    // Phase 2: Acquire exclusive lock for pool state checks
    // -----------------------------------------------------------------------

    std::unique_lock<std::shared_mutex> lock(mutex_);

    // 2a. Check for duplicate txid.
    if (entries_.count(entry.txid) > 0) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "txid " + entry.txid.to_hex() + " already in mempool");
    }

    // 2b. Check for duplicate wtxid (different tx with same witness hash).
    if (entry.wtxid != entry.txid) {
        auto wit = wtxid_to_txid_.find(entry.wtxid);
        if (wit != wtxid_to_txid_.end() && wit->second != entry.txid) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "wtxid " + entry.wtxid.to_hex()
                + " already in mempool (different txid)");
        }
    }

    // 2c. Check dynamic minimum fee rate (when pool is near full).
    {
        int64_t min_rate = get_min_fee_rate_internal();
        int64_t entry_rate = entry.fee_rate_per_kvb();
        if (entry_rate < min_rate && total_vsize_ >= max_size_ * 9 / 10) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "mempool min fee not met: " + std::to_string(entry_rate)
                + " sat/kvB < " + std::to_string(min_rate) + " sat/kvB");
        }
    }

    // 2d. Find in-mempool parents and check package limits.
    std::vector<core::uint256> parents = get_in_mempool_parents(entry.tx);
    {
        std::string reason;
        if (!ancestors_.check_package_limits(
                entry.txid, parents, entry.vsize,
                [this](const core::uint256& id) -> const MempoolEntry* {
                    auto it = entries_.find(id);
                    return (it != entries_.end()) ? &it->second : nullptr;
                },
                reason)) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "package limits exceeded: " + reason);
        }
    }

    // 2e. Check for conflicts and evaluate RBF if necessary.
    std::vector<core::uint256> conflicts;
    for (const auto& input : entry.tx.vin()) {
        auto sit = outpoint_to_txid_.find(input.prevout);
        if (sit != outpoint_to_txid_.end()) {
            conflicts.push_back(sit->second);
        }
    }

    // Deduplicate conflicts.
    {
        std::sort(conflicts.begin(), conflicts.end());
        auto last = std::unique(conflicts.begin(), conflicts.end());
        conflicts.erase(last, conflicts.end());
    }

    if (!conflicts.empty()) {
        // Evaluate RBF.
        RBFCheck rbf = check_rbf(entry, *this);
        if (!rbf.is_ok()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "RBF check failed: " + rbf.reason);
        }

        // RBF approved: remove all evicted transactions.
        LOG_INFO(core::LogCategory::MEMPOOL,
            "mempool: RBF replacing " + std::to_string(rbf.all_evicted.size())
            + " transactions for tx " + entry.txid.to_hex()
            + " (fee bump: " + std::to_string(entry.fee.value())
            + " sat vs evicted " + std::to_string(rbf.evicted_fee.value())
            + " sat)");

        for (const auto& evicted_txid : rbf.all_evicted) {
            // Notify fee estimator of the eviction.
            fee_estimator_.remove_entry(evicted_txid);
            // Remove from pool indices.
            remove_single(evicted_txid);
        }

        // Recalculate ancestor/descendant state for affected entries.
        // (remove_single already updates the ancestor tracker.)
    }

    // -----------------------------------------------------------------------
    // Phase 3: Insert the entry into the pool
    // -----------------------------------------------------------------------

    add_to_indices(entry);

    // Notify the fee estimator.
    fee_estimator_.process_entry(entry);

    LOG_INFO(core::LogCategory::MEMPOOL,
        "mempool: accepted tx " + entry.txid.to_hex()
        + " (fee: " + std::to_string(entry.fee.value())
        + " sat, vsize: " + std::to_string(entry.vsize)
        + ", pool size: " + std::to_string(entries_.size())
        + ", pool vsize: " + std::to_string(total_vsize_) + ")");

    // -----------------------------------------------------------------------
    // Phase 4: Post-insertion maintenance
    // -----------------------------------------------------------------------

    // Trim the pool if it exceeds the size limit.
    if (total_vsize_ > max_size_) {
        limit_size_internal();
    }

    return core::make_ok();
}

// ===========================================================================
// add_unchecked -- bypass policy checks
// ===========================================================================

core::Result<void> Mempool::add_unchecked(MempoolEntry entry) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    if (entries_.count(entry.txid) > 0) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "txid " + entry.txid.to_hex() + " already in mempool");
    }

    add_to_indices(entry);
    fee_estimator_.process_entry(entry);

    LOG_DEBUG(core::LogCategory::MEMPOOL,
        "mempool: added (unchecked) tx " + entry.txid.to_hex());

    return core::make_ok();
}

// ===========================================================================
// remove -- public removal with optional descendant cascade
// ===========================================================================

void Mempool::remove(const core::uint256& txid, bool remove_descendants) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    if (entries_.count(txid) == 0) return;

    if (remove_descendants) {
        // Get the full descendant set before removing anything.
        std::vector<core::uint256> descendants = ancestors_.get_descendants(txid);

        // Sort descendants in reverse topological order (children first).
        // A simple heuristic: remove in the order returned by BFS (which
        // gives us parents before children), but reversed.
        std::reverse(descendants.begin(), descendants.end());

        for (const auto& desc_txid : descendants) {
            if (desc_txid == txid) continue;
            fee_estimator_.remove_entry(desc_txid);
            remove_single(desc_txid);
        }
    }

    fee_estimator_.remove_entry(txid);
    remove_single(txid);
}

// ===========================================================================
// remove_for_block -- remove transactions confirmed in a block
// ===========================================================================

void Mempool::remove_for_block(const primitives::Block& block, int height) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    // Collect entries that are being removed (for fee estimator).
    std::vector<MempoolEntry> confirmed_entries;
    confirmed_entries.reserve(block.transactions().size());

    // Track which outpoints are now spent by block transactions.
    // Used to identify conflicts.
    struct OutPointHashLocal {
        std::size_t operator()(const primitives::OutPoint& op) const noexcept {
            return std::hash<primitives::OutPoint>{}(op);
        }
    };
    std::unordered_set<primitives::OutPoint, OutPointHashLocal> block_inputs;

    for (const auto& tx : block.transactions()) {
        core::uint256 txid = tx.txid();

        // Record all inputs spent by block transactions.
        if (!tx.is_coinbase()) {
            for (const auto& input : tx.vin()) {
                block_inputs.insert(input.prevout);
            }
        }

        // If this transaction is in the mempool, collect it for the fee
        // estimator and remove it.
        auto it = entries_.find(txid);
        if (it != entries_.end()) {
            confirmed_entries.push_back(it->second);
            remove_single(txid);
        }
    }

    // Remove any mempool transactions that conflict with block transactions.
    // A conflict is a mempool tx that spends an input that was also spent
    // by a block transaction (double-spend that the block resolved).
    std::vector<core::uint256> conflicts_to_remove;
    for (const auto& outpoint : block_inputs) {
        auto sit = outpoint_to_txid_.find(outpoint);
        if (sit != outpoint_to_txid_.end()) {
            conflicts_to_remove.push_back(sit->second);
        }
    }

    // Deduplicate.
    {
        std::sort(conflicts_to_remove.begin(), conflicts_to_remove.end());
        auto last = std::unique(conflicts_to_remove.begin(),
                                conflicts_to_remove.end());
        conflicts_to_remove.erase(last, conflicts_to_remove.end());
    }

    for (const auto& conflict_txid : conflicts_to_remove) {
        // Remove the conflict and all its descendants.
        std::vector<core::uint256> descendants =
            ancestors_.get_descendants(conflict_txid);
        std::reverse(descendants.begin(), descendants.end());

        for (const auto& desc_txid : descendants) {
            if (desc_txid == conflict_txid) continue;
            fee_estimator_.remove_entry(desc_txid);
            remove_single(desc_txid);
        }

        fee_estimator_.remove_entry(conflict_txid);
        remove_single(conflict_txid);

        LOG_INFO(core::LogCategory::MEMPOOL,
            "mempool: removed conflict " + conflict_txid.to_hex()
            + " (resolved by block at height " + std::to_string(height) + ")");
    }

    // Notify the fee estimator about the confirmed block.
    fee_estimator_.process_block(height, confirmed_entries);

    // Invalidate the cached minimum fee rate.
    min_fee_rate_dirty_ = true;

    LOG_INFO(core::LogCategory::MEMPOOL,
        "mempool: removed " + std::to_string(confirmed_entries.size())
        + " confirmed txs + " + std::to_string(conflicts_to_remove.size())
        + " conflicts for block at height " + std::to_string(height)
        + " (pool size: " + std::to_string(entries_.size()) + ")");
}

// ===========================================================================
// remove_for_replacement
// ===========================================================================

void Mempool::remove_for_replacement(const core::uint256& txid) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    if (entries_.count(txid) == 0) return;

    // Remove descendants first.
    std::vector<core::uint256> descendants = ancestors_.get_descendants(txid);
    std::reverse(descendants.begin(), descendants.end());

    for (const auto& desc_txid : descendants) {
        if (desc_txid == txid) continue;
        fee_estimator_.remove_entry(desc_txid);
        remove_single(desc_txid);
    }

    fee_estimator_.remove_entry(txid);
    remove_single(txid);
}

// ===========================================================================
// exists
// ===========================================================================

bool Mempool::exists(const core::uint256& txid) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return entries_.count(txid) > 0;
}

// ===========================================================================
// get
// ===========================================================================

const MempoolEntry* Mempool::get(const core::uint256& txid) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = entries_.find(txid);
    if (it == entries_.end()) return nullptr;
    return &it->second;
}

// ===========================================================================
// get_spender
// ===========================================================================

const core::uint256*
Mempool::get_spender(const primitives::OutPoint& outpoint) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = outpoint_to_txid_.find(outpoint);
    if (it == outpoint_to_txid_.end()) return nullptr;
    return &it->second;
}

// ===========================================================================
// get_conflicts
// ===========================================================================

std::vector<core::uint256>
Mempool::get_conflicts(const primitives::Transaction& tx) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    Uint256Set conflict_set;
    for (const auto& input : tx.vin()) {
        auto it = outpoint_to_txid_.find(input.prevout);
        if (it != outpoint_to_txid_.end()) {
            // Don't count the transaction itself as a conflict.
            if (it->second != tx.txid()) {
                conflict_set.insert(it->second);
            }
        }
    }

    return std::vector<core::uint256>(conflict_set.begin(),
                                       conflict_set.end());
}

// ===========================================================================
// get_all_txids
// ===========================================================================

std::vector<core::uint256> Mempool::get_all_txids() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    std::vector<core::uint256> result;
    result.reserve(entries_.size());
    for (const auto& [txid, entry] : entries_) {
        result.push_back(txid);
    }
    return result;
}

// ===========================================================================
// get_ancestors / get_descendants
// ===========================================================================

std::vector<core::uint256>
Mempool::get_ancestors(const core::uint256& txid) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return ancestors_.get_ancestors(txid);
}

std::vector<core::uint256>
Mempool::get_descendants(const core::uint256& txid) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return ancestors_.get_descendants(txid);
}

// ===========================================================================
// select_for_block -- ancestor feerate mining algorithm
// ===========================================================================

std::vector<MempoolEntry>
Mempool::select_for_block(size_t max_weight,
                          int64_t min_fee_rate) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    // Result: transactions in topological order (parents before children).
    std::vector<MempoolEntry> selected;

    if (entries_.empty()) return selected;

    // Work on a copy of the entries so we can update ancestor scores as
    // we "mine" transactions into the block.
    struct BlockCandidate {
        core::uint256 txid;
        double ancestor_fee_rate;
        size_t ancestor_size;
        primitives::Amount ancestor_fees;
        size_t weight;
        size_t ancestor_count;
        bool included = false;
    };

    // Build candidates.
    std::unordered_map<core::uint256, BlockCandidate, Uint256Hash> candidates;
    candidates.reserve(entries_.size());

    for (const auto& [txid, entry] : entries_) {
        // Skip transactions below the minimum fee rate.
        if (min_fee_rate > 0 && entry.fee_rate() < static_cast<double>(min_fee_rate)) {
            continue;
        }

        BlockCandidate bc;
        bc.txid              = txid;
        bc.ancestor_fee_rate = entry.ancestor_fee_rate();
        bc.ancestor_size     = entry.ancestor_size;
        bc.ancestor_fees     = entry.ancestor_fees;
        bc.weight            = entry.tx.weight();
        bc.ancestor_count    = entry.ancestor_count;
        candidates.emplace(txid, std::move(bc));
    }

    // Priority queue: highest ancestor fee rate first.
    auto cmp = [](const BlockCandidate* a, const BlockCandidate* b) {
        if (a->ancestor_fee_rate != b->ancestor_fee_rate) {
            return a->ancestor_fee_rate < b->ancestor_fee_rate;
        }
        return a->ancestor_size > b->ancestor_size;
    };
    std::priority_queue<const BlockCandidate*,
                        std::vector<const BlockCandidate*>,
                        decltype(cmp)> pq(cmp);

    for (const auto& [txid, bc] : candidates) {
        pq.push(&bc);
    }

    size_t current_weight = 0;
    Uint256Set included_set;

    // Keep a set of selected entries for topological sorting.
    std::vector<core::uint256> selected_txids;

    while (!pq.empty()) {
        const BlockCandidate* best = pq.top();
        pq.pop();

        // Skip if already included.
        if (included_set.count(best->txid) > 0) continue;

        // Re-check: the ancestor fee rate may have changed since we pushed
        // this candidate onto the queue (because an ancestor was already
        // included). Look up the current candidate state.
        auto cit = candidates.find(best->txid);
        if (cit == candidates.end()) continue;
        if (cit->second.included) continue;

        // Check if the candidate's ancestor fee rate changed; if so, the
        // value on the queue is stale. Re-push with updated score.
        if (cit->second.ancestor_fee_rate != best->ancestor_fee_rate) {
            pq.push(&cit->second);
            continue;
        }

        // Gather the ancestor chain for this candidate that is not yet
        // included.
        std::vector<core::uint256> to_include;
        {
            std::vector<core::uint256> ancs =
                ancestors_.get_ancestors(best->txid);
            for (const auto& anc_txid : ancs) {
                if (included_set.count(anc_txid) == 0
                    && entries_.count(anc_txid) > 0) {
                    to_include.push_back(anc_txid);
                }
            }
        }

        // Check total weight of the package.
        size_t package_weight = 0;
        for (const auto& inc_txid : to_include) {
            auto eit = entries_.find(inc_txid);
            if (eit != entries_.end()) {
                package_weight += eit->second.tx.weight();
            }
        }

        if (current_weight + package_weight > max_weight) {
            // Package does not fit. Try the next candidate.
            // Mark as included so we don't try again.
            cit->second.included = true;
            continue;
        }

        // Include the entire ancestor package.
        // Sort topologically: parents before children.
        // Simple approach: include in ancestor-first order (BFS from
        // the ancestors' roots).
        std::vector<core::uint256> sorted_package;
        {
            // Build the set of entries to include.
            Uint256Set package_set(to_include.begin(), to_include.end());

            // Topological sort using Kahn's algorithm (within the package).
            std::unordered_map<core::uint256, size_t, Uint256Hash> in_degree;
            for (const auto& id : to_include) {
                in_degree[id] = 0;
            }
            for (const auto& id : to_include) {
                std::vector<core::uint256> parents =
                    ancestors_.get_parents(id);
                for (const auto& parent : parents) {
                    if (package_set.count(parent) > 0) {
                        in_degree[id]++;
                    }
                }
            }

            std::deque<core::uint256> ready;
            for (const auto& [id, deg] : in_degree) {
                if (deg == 0) {
                    ready.push_back(id);
                }
            }

            while (!ready.empty()) {
                core::uint256 current = ready.front();
                ready.pop_front();
                sorted_package.push_back(current);

                std::vector<core::uint256> children =
                    ancestors_.get_children(current);
                for (const auto& child : children) {
                    if (package_set.count(child) > 0) {
                        auto dit = in_degree.find(child);
                        if (dit != in_degree.end() && dit->second > 0) {
                            dit->second--;
                            if (dit->second == 0) {
                                ready.push_back(child);
                            }
                        }
                    }
                }
            }

            // If topological sort didn't include everything (shouldn't
            // happen with acyclic data), add remaining entries.
            for (const auto& id : to_include) {
                if (included_set.count(id) == 0) {
                    bool found = false;
                    for (const auto& sid : sorted_package) {
                        if (sid == id) { found = true; break; }
                    }
                    if (!found) {
                        sorted_package.push_back(id);
                    }
                }
            }
        }

        // Add each entry in topological order.
        for (const auto& inc_txid : sorted_package) {
            if (included_set.count(inc_txid) > 0) continue;

            auto eit = entries_.find(inc_txid);
            if (eit == entries_.end()) continue;

            included_set.insert(inc_txid);
            selected.push_back(eit->second);
            selected_txids.push_back(inc_txid);
            current_weight += eit->second.tx.weight();

            // Mark as included in the candidate map.
            auto cand_it = candidates.find(inc_txid);
            if (cand_it != candidates.end()) {
                cand_it->second.included = true;
            }
        }

        // Update ancestor scores for remaining candidates that had this
        // package as ancestors. When an ancestor is "mined", its descendants'
        // ancestor_size and ancestor_fees decrease (improving their score).
        for (const auto& inc_txid : sorted_package) {
            auto eit = entries_.find(inc_txid);
            if (eit == entries_.end()) continue;

            size_t inc_vsize = eit->second.vsize;
            int64_t inc_fee  = eit->second.fee.value();

            // For each descendant of the included tx, update its score.
            std::vector<core::uint256> descs =
                ancestors_.get_descendants(inc_txid);
            for (const auto& desc_txid : descs) {
                if (included_set.count(desc_txid) > 0) continue;

                auto dit = candidates.find(desc_txid);
                if (dit == candidates.end()) continue;

                auto& dc = dit->second;
                if (dc.ancestor_size > inc_vsize) {
                    dc.ancestor_size -= inc_vsize;
                } else {
                    dc.ancestor_size = entries_.at(desc_txid).vsize;
                }
                int64_t new_fees = dc.ancestor_fees.value() - inc_fee;
                if (new_fees < entries_.at(desc_txid).fee.value()) {
                    new_fees = entries_.at(desc_txid).fee.value();
                }
                dc.ancestor_fees = primitives::Amount{new_fees};

                if (dc.ancestor_count > 1) {
                    dc.ancestor_count--;
                }

                // Recalculate ancestor fee rate.
                dc.ancestor_fee_rate = (dc.ancestor_size > 0)
                    ? static_cast<double>(dc.ancestor_fees.value())
                      / static_cast<double>(dc.ancestor_size)
                    : 0.0;

                // Re-push with updated score.
                pq.push(&dit->second);
            }
        }
    }

    // Compute summary statistics for the selected set.
    int64_t selected_total_fee = 0;
    size_t selected_total_vsize = 0;
    for (const auto& entry : selected) {
        selected_total_fee += entry.fee.value();
        selected_total_vsize += entry.vsize;
    }

    double selected_avg_fee_rate = 0.0;
    if (selected_total_vsize > 0) {
        selected_avg_fee_rate = static_cast<double>(selected_total_fee)
                              / static_cast<double>(selected_total_vsize);
    }

    LOG_INFO(core::LogCategory::MEMPOOL,
        "mempool: selected " + std::to_string(selected.size())
        + " transactions for block template (weight: "
        + std::to_string(current_weight) + " / "
        + std::to_string(max_weight)
        + ", total fee: " + std::to_string(selected_total_fee)
        + " sat, avg fee rate: " + std::to_string(selected_avg_fee_rate)
        + " sat/vB, pool remaining: " + std::to_string(
            entries_.size() - selected.size()) + ")");

    return selected;
}

// ===========================================================================
// limit_size -- trim to maximum pool size
// ===========================================================================

void Mempool::limit_size() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    limit_size_internal();
}

// Internal implementation (called with lock held).
void Mempool::limit_size_internal() {
    size_t evicted = 0;

    while (total_vsize_ > max_size_ && !entries_.empty()) {
        // Find the entry with the lowest descendant fee rate (eviction
        // candidate).
        const core::uint256* victim = get_eviction_candidate();
        if (victim == nullptr) break;

        core::uint256 victim_txid = *victim;

        // Remove the victim and all its descendants.
        std::vector<core::uint256> descendants =
            ancestors_.get_descendants(victim_txid);
        std::reverse(descendants.begin(), descendants.end());

        for (const auto& desc_txid : descendants) {
            if (desc_txid == victim_txid) continue;
            fee_estimator_.remove_entry(desc_txid);
            remove_single(desc_txid);
            ++evicted;
        }

        fee_estimator_.remove_entry(victim_txid);
        remove_single(victim_txid);
        ++evicted;
    }

    if (evicted > 0) {
        // Update the dynamic minimum fee rate.
        min_fee_rate_dirty_ = true;

        LOG_INFO(core::LogCategory::MEMPOOL,
            "mempool: evicted " + std::to_string(evicted)
            + " transactions to enforce size limit (pool vsize: "
            + std::to_string(total_vsize_) + " / "
            + std::to_string(max_size_) + ")");
    }
}

// ===========================================================================
// expire -- remove old transactions
// ===========================================================================

void Mempool::expire(int64_t now) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    std::vector<core::uint256> expired;

    for (const auto& [txid, entry] : entries_) {
        if (entry.time + MEMPOOL_EXPIRY <= now) {
            expired.push_back(txid);
        }
    }

    for (const auto& txid : expired) {
        // Remove the expired entry and its descendants.
        if (entries_.count(txid) == 0) continue;

        std::vector<core::uint256> descendants =
            ancestors_.get_descendants(txid);
        std::reverse(descendants.begin(), descendants.end());

        for (const auto& desc_txid : descendants) {
            if (desc_txid == txid) continue;
            fee_estimator_.remove_entry(desc_txid);
            remove_single(desc_txid);
        }

        fee_estimator_.remove_entry(txid);
        remove_single(txid);
    }

    if (!expired.empty()) {
        min_fee_rate_dirty_ = true;

        LOG_INFO(core::LogCategory::MEMPOOL,
            "mempool: expired " + std::to_string(expired.size())
            + " transactions (pool size: "
            + std::to_string(entries_.size()) + ")");
    }

    // Also expire orphans.
    orphans_.expire(now);
}

// ===========================================================================
// Statistics
// ===========================================================================

size_t Mempool::size() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return entries_.size();
}

size_t Mempool::dynamic_memory_usage() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    size_t usage = 0;

    // MempoolEntry map overhead.
    usage += entries_.size() * (sizeof(core::uint256) + sizeof(MempoolEntry)
                                + 64); // hash bucket overhead estimate

    // Per-entry dynamic memory.
    for (const auto& [txid, entry] : entries_) {
        usage += entry.dynamic_memory_usage();
    }

    // Outpoint-to-txid map overhead.
    usage += outpoint_to_txid_.size()
           * (sizeof(primitives::OutPoint) + sizeof(core::uint256) + 64);

    // Wtxid-to-txid map overhead.
    usage += wtxid_to_txid_.size()
           * (sizeof(core::uint256) * 2 + 64);

    // Ancestor tracker overhead (rough estimate).
    usage += ancestors_.size() * 256;

    return usage;
}

size_t Mempool::total_tx_size() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return total_vsize_;
}

size_t Mempool::total_tx_bytes() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return total_bytes_;
}

primitives::Amount Mempool::total_fee() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return primitives::Amount{total_fees_};
}

MempoolStats Mempool::get_stats() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    MempoolStats stats;
    stats.tx_count    = entries_.size();
    stats.total_vsize = total_vsize_;
    stats.total_bytes = total_bytes_;
    stats.total_fee   = primitives::Amount{total_fees_};
    stats.orphan_count = orphans_.size();

    // Compute min/max/avg fee rates.
    stats.min_fee_rate = std::numeric_limits<double>::max();
    stats.max_fee_rate = 0.0;
    double sum_fee_rate = 0.0;
    std::vector<double> all_rates;
    all_rates.reserve(entries_.size());

    for (const auto& [txid, entry] : entries_) {
        double rate = entry.fee_rate();
        if (rate < stats.min_fee_rate) stats.min_fee_rate = rate;
        if (rate > stats.max_fee_rate) stats.max_fee_rate = rate;
        sum_fee_rate += rate;
        all_rates.push_back(rate);
    }

    if (entries_.empty()) {
        stats.min_fee_rate = 0.0;
        stats.avg_fee_rate = 0.0;
        stats.median_fee_rate = 0.0;
    } else {
        stats.avg_fee_rate = sum_fee_rate
                           / static_cast<double>(entries_.size());

        // Compute median.
        std::sort(all_rates.begin(), all_rates.end());
        size_t n = all_rates.size();
        if (n % 2 == 0) {
            stats.median_fee_rate = (all_rates[n / 2 - 1]
                                   + all_rates[n / 2]) / 2.0;
        } else {
            stats.median_fee_rate = all_rates[n / 2];
        }
    }

    // Memory usage.
    stats.memory_usage = 0;
    stats.memory_usage += entries_.size()
        * (sizeof(core::uint256) + sizeof(MempoolEntry) + 64);
    for (const auto& [txid, entry] : entries_) {
        stats.memory_usage += entry.dynamic_memory_usage();
    }
    stats.memory_usage += outpoint_to_txid_.size()
        * (sizeof(primitives::OutPoint) + sizeof(core::uint256) + 64);

    stats.min_entry_fee_rate = get_min_fee_rate_internal();

    // Pool fullness.
    if (max_size_ > 0) {
        stats.fullness_pct = static_cast<double>(total_vsize_) * 100.0
                           / static_cast<double>(max_size_);
    }

    // Fee estimator info.
    stats.fee_estimator_tracked = fee_estimator_.tracked_count();
    stats.fee_estimator_height  = fee_estimator_.best_height();

    return stats;
}

// ---------------------------------------------------------------------------
// MempoolStats::to_string
// ---------------------------------------------------------------------------

std::string MempoolStats::to_string() const {
    std::string result;
    result += "Mempool stats:\n";
    result += "  tx_count:       " + std::to_string(tx_count) + "\n";
    result += "  total_vsize:    " + std::to_string(total_vsize) + " vB\n";
    result += "  total_bytes:    " + std::to_string(total_bytes) + " bytes\n";
    result += "  total_fee:      " + std::to_string(total_fee.value()) + " sat\n";
    result += "  memory_usage:   " + std::to_string(memory_usage) + " bytes\n";
    result += "  min_fee_rate:   " + std::to_string(min_fee_rate) + " sat/vB\n";
    result += "  max_fee_rate:   " + std::to_string(max_fee_rate) + " sat/vB\n";
    result += "  avg_fee_rate:   " + std::to_string(avg_fee_rate) + " sat/vB\n";
    result += "  median_fee_rate: " + std::to_string(median_fee_rate) + " sat/vB\n";
    result += "  min_entry_rate: " + std::to_string(min_entry_fee_rate) + " sat/kvB\n";
    result += "  orphan_count:   " + std::to_string(orphan_count) + "\n";
    result += "  fullness:       " + std::to_string(fullness_pct) + "%\n";
    result += "  estimator tracked: " + std::to_string(fee_estimator_tracked) + "\n";
    result += "  estimator height:  " + std::to_string(fee_estimator_height) + "\n";
    return result;
}

int64_t Mempool::get_min_fee_rate() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return get_min_fee_rate_internal();
}

// Internal: compute minimum entry fee rate (called with lock held).
int64_t Mempool::get_min_fee_rate_internal() const {
    // If pool is less than 90% full, use the base relay fee.
    if (total_vsize_ < max_size_ * 9 / 10) {
        cached_min_fee_rate_ = MIN_RELAY_FEE;
        min_fee_rate_dirty_ = false;
        return cached_min_fee_rate_;
    }

    // If the cached value is still valid, return it.
    if (!min_fee_rate_dirty_) {
        return cached_min_fee_rate_;
    }

    // Pool is near full: compute the rolling minimum fee rate.
    // The minimum fee rate is set to the fee rate of the worst (lowest)
    // entry in the pool plus the incremental relay fee.
    double min_rate = std::numeric_limits<double>::max();
    for (const auto& [txid, entry] : entries_) {
        double rate = entry.descendant_fee_rate();
        if (rate < min_rate) {
            min_rate = rate;
        }
    }

    if (min_rate == std::numeric_limits<double>::max()) {
        cached_min_fee_rate_ = MIN_RELAY_FEE;
    } else {
        // Convert sat/vB to sat/kvB and add incremental relay fee.
        int64_t rate_kvb = static_cast<int64_t>(min_rate * 1000.0);
        cached_min_fee_rate_ = std::max(rate_kvb + INCREMENTAL_RELAY_FEE,
                                        MIN_RELAY_FEE);
    }

    min_fee_rate_dirty_ = false;
    return cached_min_fee_rate_;
}

// ===========================================================================
// Fee estimation
// ===========================================================================

int64_t Mempool::estimate_fee(int target_blocks) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return fee_estimator_.estimate_fee(target_blocks);
}

// ===========================================================================
// Orphan pool access
// ===========================================================================

OrphanPool& Mempool::orphan_pool() {
    return orphans_;
}

const OrphanPool& Mempool::orphan_pool() const {
    return orphans_;
}

// ===========================================================================
// Configuration
// ===========================================================================

void Mempool::set_max_size(size_t max_size) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    max_size_ = max_size;
    min_fee_rate_dirty_ = true;

    LOG_INFO(core::LogCategory::MEMPOOL,
        "mempool: max size set to "
        + std::to_string(max_size / (1024 * 1024)) + " MB");
}

size_t Mempool::max_size() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return max_size_;
}

void Mempool::clear() {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    entries_.clear();
    outpoint_to_txid_.clear();
    wtxid_to_txid_.clear();
    ancestors_.clear();
    fee_estimator_.clear();

    total_vsize_ = 0;
    total_bytes_ = 0;
    total_fees_  = 0;
    sequence_    = 0;
    min_fee_rate_dirty_ = true;

    LOG_INFO(core::LogCategory::MEMPOOL, "mempool: cleared");
}

// ===========================================================================
// Internal helpers
// ===========================================================================

// ---------------------------------------------------------------------------
// add_to_indices -- insert entry into all internal maps
// ---------------------------------------------------------------------------

void Mempool::add_to_indices(MempoolEntry& entry) {
    const core::uint256& txid = entry.txid;

    // Update cumulative size/fee counters.
    total_vsize_ += entry.vsize;
    total_bytes_ += entry.size;
    total_fees_  += entry.fee.value();

    // Index every input's outpoint -> spending txid.
    for (const auto& input : entry.tx.vin()) {
        outpoint_to_txid_[input.prevout] = txid;
    }

    // Wtxid mapping.
    wtxid_to_txid_[entry.wtxid] = txid;

    // Determine in-mempool parents.
    std::vector<core::uint256> parents = get_in_mempool_parents(entry.tx);

    // Register in ancestor tracker.
    ancestors_.add_entry(txid, parents);

    // Update ancestor/descendant state for this entry.
    auto lookup = [this](const core::uint256& id) -> const MempoolEntry* {
        auto it = entries_.find(id);
        return (it != entries_.end()) ? &it->second : nullptr;
    };

    // Insert the entry into the main map.
    auto [it, inserted] = entries_.emplace(txid, std::move(entry));

    if (inserted) {
        // Update the ancestor state for the newly inserted entry.
        ancestors_.update_ancestor_state(it->second, lookup);
        ancestors_.update_descendant_state(it->second, lookup);

        // Recalculate affected ancestors and descendants.
        ancestors_.recalculate_affected(
            txid, lookup,
            [this](MempoolEntry& updated) {
                auto eit = entries_.find(updated.txid);
                if (eit != entries_.end()) {
                    eit->second.ancestor_count    = updated.ancestor_count;
                    eit->second.ancestor_size     = updated.ancestor_size;
                    eit->second.ancestor_fees     = updated.ancestor_fees;
                    eit->second.descendant_count  = updated.descendant_count;
                    eit->second.descendant_size   = updated.descendant_size;
                    eit->second.descendant_fees   = updated.descendant_fees;
                }
            });
    }

    ++sequence_;
    min_fee_rate_dirty_ = true;
}

// ---------------------------------------------------------------------------
// remove_from_indices -- remove entry from all internal maps
// ---------------------------------------------------------------------------

void Mempool::remove_from_indices(const core::uint256& txid) {
    auto it = entries_.find(txid);
    if (it == entries_.end()) return;

    const MempoolEntry& entry = it->second;

    // Update cumulative size/fee counters.
    if (total_vsize_ >= entry.vsize) {
        total_vsize_ -= entry.vsize;
    } else {
        total_vsize_ = 0;
    }
    if (total_bytes_ >= entry.size) {
        total_bytes_ -= entry.size;
    } else {
        total_bytes_ = 0;
    }
    total_fees_ -= entry.fee.value();
    if (total_fees_ < 0) total_fees_ = 0;

    // Remove outpoint mappings.
    for (const auto& input : entry.tx.vin()) {
        auto oit = outpoint_to_txid_.find(input.prevout);
        if (oit != outpoint_to_txid_.end() && oit->second == txid) {
            outpoint_to_txid_.erase(oit);
        }
    }

    // Remove wtxid mapping.
    {
        auto wit = wtxid_to_txid_.find(entry.wtxid);
        if (wit != wtxid_to_txid_.end() && wit->second == txid) {
            wtxid_to_txid_.erase(wit);
        }
    }

    // Remove from ancestor tracker.
    ancestors_.remove_entry(txid);

    // Remove from main map.
    entries_.erase(it);

    min_fee_rate_dirty_ = true;
}

// ---------------------------------------------------------------------------
// remove_single -- remove one entry (no descendant cascade)
// ---------------------------------------------------------------------------

void Mempool::remove_single(const core::uint256& txid) {
    if (entries_.count(txid) == 0) return;

    // Capture affected set before removal for recalculation.
    core::uint256 removed_txid = txid;

    remove_from_indices(txid);

    // Recalculate ancestor/descendant state for entries that were
    // affected by this removal.
    auto lookup = [this](const core::uint256& id) -> const MempoolEntry* {
        auto it = entries_.find(id);
        return (it != entries_.end()) ? &it->second : nullptr;
    };

    ancestors_.recalculate_affected(
        removed_txid, lookup,
        [this](MempoolEntry& updated) {
            auto eit = entries_.find(updated.txid);
            if (eit != entries_.end()) {
                eit->second.ancestor_count    = updated.ancestor_count;
                eit->second.ancestor_size     = updated.ancestor_size;
                eit->second.ancestor_fees     = updated.ancestor_fees;
                eit->second.descendant_count  = updated.descendant_count;
                eit->second.descendant_size   = updated.descendant_size;
                eit->second.descendant_fees   = updated.descendant_fees;
            }
        });
}

// ---------------------------------------------------------------------------
// get_in_mempool_parents
// ---------------------------------------------------------------------------

std::vector<core::uint256>
Mempool::get_in_mempool_parents(const primitives::Transaction& tx) const {
    Uint256Set parent_set;

    for (const auto& input : tx.vin()) {
        // A parent is a mempool transaction whose txid matches the
        // prevout txid of one of our inputs.
        if (entries_.count(input.prevout.txid) > 0) {
            parent_set.insert(input.prevout.txid);
        }
    }

    return std::vector<core::uint256>(parent_set.begin(), parent_set.end());
}

// ---------------------------------------------------------------------------
// update_for_add / update_for_remove
// ---------------------------------------------------------------------------

void Mempool::update_for_add(const core::uint256& txid) {
    auto lookup = [this](const core::uint256& id) -> const MempoolEntry* {
        auto it = entries_.find(id);
        return (it != entries_.end()) ? &it->second : nullptr;
    };

    ancestors_.recalculate_affected(
        txid, lookup,
        [this](MempoolEntry& updated) {
            auto eit = entries_.find(updated.txid);
            if (eit != entries_.end()) {
                eit->second.ancestor_count    = updated.ancestor_count;
                eit->second.ancestor_size     = updated.ancestor_size;
                eit->second.ancestor_fees     = updated.ancestor_fees;
                eit->second.descendant_count  = updated.descendant_count;
                eit->second.descendant_size   = updated.descendant_size;
                eit->second.descendant_fees   = updated.descendant_fees;
            }
        });
}

void Mempool::update_for_remove(const core::uint256& txid) {
    // Same logic as update_for_add: recalculate affected entries.
    update_for_add(txid);
}

// ---------------------------------------------------------------------------
// get_min_eviction_score / get_eviction_candidate
// ---------------------------------------------------------------------------

double Mempool::get_min_eviction_score() const {
    double min_score = std::numeric_limits<double>::max();
    for (const auto& [txid, entry] : entries_) {
        double score = entry.descendant_fee_rate();
        if (score < min_score) {
            min_score = score;
        }
    }
    return min_score;
}

const core::uint256* Mempool::get_eviction_candidate() const {
    if (entries_.empty()) return nullptr;

    const core::uint256* worst = nullptr;
    double worst_score = std::numeric_limits<double>::max();

    for (const auto& [txid, entry] : entries_) {
        double score = entry.descendant_fee_rate();
        if (score < worst_score) {
            worst_score = score;
            worst = &txid;
        } else if (score == worst_score && worst != nullptr) {
            // Tie-break: evict the larger (by descendant vsize) entry first,
            // as this frees more space.
            auto wit = entries_.find(*worst);
            if (wit != entries_.end()
                && entry.descendant_size > wit->second.descendant_size) {
                worst = &txid;
            }
        }
    }

    return worst;
}

// ===========================================================================
// Detailed add() implementation notes
// ===========================================================================
//
// The add() method follows a multi-phase protocol:
//
//   Phase 1 (no lock): Stateless policy checks that don't depend on pool
//   state. These include standardness (check_standard), minimum relay fee
//   (check_min_relay_fee), dust checks (check_dust), and basic sanity.
//   Running these without the lock maximizes concurrency since multiple
//   threads can validate different transactions in parallel.
//
//   Phase 2 (exclusive lock): Pool-state-dependent checks. We acquire the
//   write lock and verify:
//     - No duplicate txid or wtxid.
//     - The dynamic minimum fee rate is met (when pool is nearly full).
//     - Package limits (ancestor/descendant counts and sizes).
//     - RBF evaluation if there are conflicts.
//   If RBF succeeds, the conflicting transactions and their descendants
//   are evicted before the new entry is inserted.
//
//   Phase 3 (still under exclusive lock): Insert the entry into all
//   internal indices: entries_ map, outpoint_to_txid_, wtxid_to_txid_,
//   and the AncestorTracker. Update ancestor/descendant state.
//
//   Phase 4 (still under exclusive lock): Trim the pool if it exceeds
//   max_size_ after the insertion. This is done by evicting the entries
//   with the lowest descendant fee rate until total_vsize_ <= max_size_.
//
// This design ensures that:
//   - Readers (get, exists, select_for_block) are not blocked during the
//     stateless validation phase.
//   - Writers are serialized during the state-mutation phases.
//   - RBF eviction and pool trimming happen atomically with the insertion.
//

// ===========================================================================
// select_for_block implementation notes
// ===========================================================================
//
// The block template construction algorithm uses ancestor-feerate mining,
// which is the standard approach used by Bitcoin Core:
//
//   1. For each mempool entry, compute the "ancestor score" as:
//        ancestor_fees / ancestor_size
//      This represents the marginal fee rate you get by including this
//      transaction along with all its unconfirmed ancestors.
//
//   2. Build a max-heap (priority queue) sorted by ancestor score.
//
//   3. Pop the entry with the highest ancestor score. Include it and all
//      of its not-yet-included ancestors in the block (in topological
//      order: parents before children).
//
//   4. After including a package, update the ancestor scores of all
//      descendants: since some ancestors are now "included", the
//      remaining descendants have fewer ancestors to pay for, so their
//      ancestor_fees and ancestor_size decrease, potentially improving
//      their score.
//
//   5. Re-push updated descendants onto the priority queue.
//
//   6. Repeat until the block is full (weight limit reached) or no more
//      entries are eligible.
//
// The topological ordering within each package is computed using Kahn's
// algorithm (in-degree-based BFS). This ensures that parents always appear
// before children in the block, satisfying the consensus requirement that
// a transaction's inputs must be available (either in a prior block or in
// a preceding position within the same block).
//
// Complexity: O(N * A * log N) in the worst case, where N is the number
// of mempool entries and A is the average ancestor chain length. In
// practice this is very fast because ancestor chains are bounded by
// MAX_ANCESTORS (25).
//

// ===========================================================================
// Eviction algorithm notes
// ===========================================================================
//
// When the mempool exceeds max_size_, entries are evicted using the
// "descendant fee rate" metric:
//
//   eviction_score = descendant_fees / descendant_size
//
// The entry with the lowest eviction score is removed first, along with
// all of its descendants. The rationale is:
//
//   - The descendant package is the "minimum viable eviction unit": you
//     cannot remove a parent without also removing its children (since
//     the children spend the parent's outputs).
//
//   - By evicting the package with the lowest fee rate per virtual byte,
//     we maximize the total remaining fee density in the pool.
//
//   - This also naturally handles "pinning" attacks: a large low-fee
//     child attached to a high-fee parent will have a low descendant
//     fee rate on the parent, causing the parent to be evicted if the
//     pool is full.
//
// After eviction, the dynamic minimum entry fee rate is updated. New
// transactions must pay at least this rate (plus the incremental relay
// fee) to be admitted, which creates natural back-pressure when the
// pool is congested.
//

// ===========================================================================
// Thread safety notes
// ===========================================================================
//
// The Mempool uses a std::shared_mutex to implement a readers-writer lock:
//
//   - Read operations (get, exists, get_spender, get_conflicts,
//     get_all_txids, get_ancestors, get_descendants, select_for_block,
//     size, dynamic_memory_usage, total_tx_size, total_tx_bytes,
//     total_fee, get_stats, get_min_fee_rate, estimate_fee) acquire a
//     shared_lock, allowing multiple concurrent readers.
//
//   - Write operations (add, add_unchecked, remove, remove_for_block,
//     remove_for_replacement, limit_size, expire, set_max_size, clear)
//     acquire a unique_lock, blocking all other readers and writers.
//
// The OrphanPool has its own internal mutex and is independently
// thread-safe. The Mempool may call into the OrphanPool while holding
// its own lock, but the OrphanPool never calls back into the Mempool,
// preventing deadlock.
//
// The AncestorTracker and FeeEstimator do NOT have their own locks.
// They are only accessed while the Mempool's mutex is held (either
// shared or exclusive, as appropriate).
//
// Note: the mutable cached_min_fee_rate_ and min_fee_rate_dirty_ fields
// are accessed under both shared and exclusive locks. This is safe because:
//   - They are only written under shared_lock in get_min_fee_rate_internal(),
//     which uses mutable semantics for caching.
//   - The std::shared_mutex guarantees memory visibility between shared
//     and exclusive lock acquisitions.
//   - The worst-case race (two shared readers both computing the cache)
//     results in redundant computation but no data corruption.
//

// ---------------------------------------------------------------------------
// dump
// ---------------------------------------------------------------------------

std::string Mempool::dump() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    std::string result;

    result += "Mempool dump:\n";
    result += "  entries:       " + std::to_string(entries_.size()) + "\n";
    result += "  total_vsize:   " + std::to_string(total_vsize_) + " vB\n";
    result += "  total_bytes:   " + std::to_string(total_bytes_) + " bytes\n";
    result += "  total_fees:    " + std::to_string(total_fees_) + " sat\n";
    result += "  max_size:      " + std::to_string(max_size_) + " bytes\n";
    result += "  sequence:      " + std::to_string(sequence_) + "\n";
    result += "  outpoint_idx:  " + std::to_string(outpoint_to_txid_.size()) + "\n";
    result += "  wtxid_idx:     " + std::to_string(wtxid_to_txid_.size()) + "\n";

    // List top 10 entries by fee rate.
    std::vector<const MempoolEntry*> sorted_entries;
    sorted_entries.reserve(entries_.size());
    for (const auto& [txid, entry] : entries_) {
        sorted_entries.push_back(&entry);
    }
    std::sort(sorted_entries.begin(), sorted_entries.end(),
        [](const MempoolEntry* a, const MempoolEntry* b) {
            return a->fee_rate() > b->fee_rate();
        });

    size_t display_count = std::min(sorted_entries.size(), size_t{10});
    result += "\n  Top " + std::to_string(display_count) + " entries by fee rate:\n";
    for (size_t i = 0; i < display_count; ++i) {
        result += "    " + sorted_entries[i]->to_string() + "\n";
    }

    // Ancestor tracker summary.
    result += "\n" + ancestors_.stats_string();

    // Fee estimator summary.
    result += "\n  Fee estimator: tracked="
            + std::to_string(fee_estimator_.tracked_count())
            + " height=" + std::to_string(fee_estimator_.best_height()) + "\n";

    // Orphan pool summary.
    result += "  Orphan pool: " + std::to_string(orphans_.size()) + " orphans\n";

    return result;
}

// ---------------------------------------------------------------------------
// check_consistency
// ---------------------------------------------------------------------------

bool Mempool::check_consistency(std::string& reason) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    // Check 1: verify total_vsize_ matches the sum of entry vsizes.
    {
        size_t computed_vsize = 0;
        for (const auto& [txid, entry] : entries_) {
            computed_vsize += entry.vsize;
        }
        if (computed_vsize != total_vsize_) {
            reason = "total_vsize_ mismatch: stored="
                   + std::to_string(total_vsize_) + " computed="
                   + std::to_string(computed_vsize);
            return false;
        }
    }

    // Check 2: verify total_bytes_ matches the sum of entry sizes.
    {
        size_t computed_bytes = 0;
        for (const auto& [txid, entry] : entries_) {
            computed_bytes += entry.size;
        }
        if (computed_bytes != total_bytes_) {
            reason = "total_bytes_ mismatch: stored="
                   + std::to_string(total_bytes_) + " computed="
                   + std::to_string(computed_bytes);
            return false;
        }
    }

    // Check 3: verify total_fees_ matches the sum of entry fees.
    {
        int64_t computed_fees = 0;
        for (const auto& [txid, entry] : entries_) {
            computed_fees += entry.fee.value();
        }
        if (computed_fees != total_fees_) {
            reason = "total_fees_ mismatch: stored="
                   + std::to_string(total_fees_) + " computed="
                   + std::to_string(computed_fees);
            return false;
        }
    }

    // Check 4: verify outpoint index consistency.
    // Every outpoint in the index should correspond to an input of the
    // entry it maps to.
    for (const auto& [outpoint, txid] : outpoint_to_txid_) {
        auto it = entries_.find(txid);
        if (it == entries_.end()) {
            reason = "outpoint index references non-existent entry: "
                   + txid.to_hex();
            return false;
        }

        // Verify the entry actually spends this outpoint.
        bool found_input = false;
        for (const auto& input : it->second.tx.vin()) {
            if (input.prevout.txid == outpoint.txid
                && input.prevout.n == outpoint.n) {
                found_input = true;
                break;
            }
        }
        if (!found_input) {
            reason = "outpoint " + outpoint.txid.to_hex() + ":"
                   + std::to_string(outpoint.n)
                   + " is indexed under txid " + txid.to_hex()
                   + " but the entry does not spend it";
            return false;
        }
    }

    // Check 5: verify wtxid index consistency.
    for (const auto& [wtxid, txid] : wtxid_to_txid_) {
        auto it = entries_.find(txid);
        if (it == entries_.end()) {
            reason = "wtxid index references non-existent entry: "
                   + txid.to_hex();
            return false;
        }
        if (it->second.wtxid != wtxid) {
            reason = "wtxid index mismatch for entry " + txid.to_hex()
                   + ": indexed wtxid=" + wtxid.to_hex()
                   + " actual wtxid=" + it->second.wtxid.to_hex();
            return false;
        }
    }

    // Check 6: verify ancestor tracker consistency.
    {
        std::string anc_reason;
        if (!ancestors_.check_consistency(anc_reason)) {
            reason = "ancestor tracker inconsistency: " + anc_reason;
            return false;
        }
    }

    // Check 7: verify that every entry in entries_ is tracked by the
    // ancestor tracker.
    for (const auto& [txid, entry] : entries_) {
        if (!ancestors_.has_entry(txid)) {
            reason = "entry " + txid.to_hex()
                   + " not tracked by ancestor tracker";
            return false;
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// outpoint_index_size / wtxid_index_size
// ---------------------------------------------------------------------------

size_t Mempool::outpoint_index_size() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return outpoint_to_txid_.size();
}

size_t Mempool::wtxid_index_size() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return wtxid_to_txid_.size();
}

// ---------------------------------------------------------------------------
// fee_estimator / ancestor_tracker (diagnostic access)
// ---------------------------------------------------------------------------

const FeeEstimator& Mempool::fee_estimator() const {
    return fee_estimator_;
}

const AncestorTracker& Mempool::ancestor_tracker() const {
    return ancestors_;
}

// ---------------------------------------------------------------------------
// is_full / remaining_capacity
// ---------------------------------------------------------------------------

bool Mempool::is_full() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return total_vsize_ >= max_size_;
}

size_t Mempool::remaining_capacity() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (total_vsize_ >= max_size_) return 0;
    return max_size_ - total_vsize_;
}

// ---------------------------------------------------------------------------
// get_by_wtxid
// ---------------------------------------------------------------------------

const MempoolEntry* Mempool::get_by_wtxid(const core::uint256& wtxid) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    auto wit = wtxid_to_txid_.find(wtxid);
    if (wit == wtxid_to_txid_.end()) {
        return nullptr;
    }

    auto it = entries_.find(wit->second);
    if (it == entries_.end()) {
        return nullptr;
    }

    return &it->second;
}

// ---------------------------------------------------------------------------
// get_descendant_entries / get_ancestor_entries
// ---------------------------------------------------------------------------

std::vector<MempoolEntry>
Mempool::get_descendant_entries(const core::uint256& txid) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    std::vector<MempoolEntry> result;
    auto desc_txids = ancestors_.get_descendants(txid);

    result.reserve(desc_txids.size());
    for (const auto& desc_txid : desc_txids) {
        auto it = entries_.find(desc_txid);
        if (it != entries_.end()) {
            result.push_back(it->second);
        }
    }

    return result;
}

std::vector<MempoolEntry>
Mempool::get_ancestor_entries(const core::uint256& txid) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    std::vector<MempoolEntry> result;
    auto anc_txids = ancestors_.get_ancestors(txid);

    result.reserve(anc_txids.size());
    for (const auto& anc_txid : anc_txids) {
        auto it = entries_.find(anc_txid);
        if (it != entries_.end()) {
            result.push_back(it->second);
        }
    }

    return result;
}

} // namespace mempool
