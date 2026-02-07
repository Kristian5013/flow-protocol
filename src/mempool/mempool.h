#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Mempool -- the in-memory transaction pool
// ---------------------------------------------------------------------------
// The Mempool stores unconfirmed transactions that have been validated and
// accepted for relay. It serves as the source of candidate transactions for
// block template construction (mining) and as a relay cache for the P2P
// network.
//
// Thread safety: all public methods are thread-safe. The Mempool uses a
// shared_mutex to allow concurrent reads (get, exists, select_for_block)
// while serializing writes (add, remove, remove_for_block, limit_size).
//
// Internal subsystems:
//   - AncestorTracker: maintains parent/child relationships and enforces
//     package limits (MAX_ANCESTORS, MAX_DESCENDANTS).
//   - OrphanPool: holds transactions whose inputs are not yet available.
//   - FeeEstimator: tracks fee rates for smart fee estimation.
//   - RBF: evaluates replace-by-fee policy for conflicting transactions.
//
// The Mempool does NOT perform consensus validation. It is the caller's
// responsibility to verify scripts, check the UTXO set, and run consensus
// checks before calling add().
// ---------------------------------------------------------------------------

#include "core/error.h"
#include "core/types.h"
#include "mempool/ancestor.h"
#include "mempool/entry.h"
#include "mempool/fee_estimator.h"
#include "mempool/orphan.h"
#include "mempool/policy.h"
#include "primitives/amount.h"
#include "primitives/block.h"
#include "primitives/outpoint.h"
#include "primitives/transaction.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace mempool {

// ---------------------------------------------------------------------------
// Hash functors (re-exported for map/set key types)
// ---------------------------------------------------------------------------

struct OutPointHash {
    std::size_t operator()(const primitives::OutPoint& op) const noexcept {
        return std::hash<primitives::OutPoint>{}(op);
    }
};

// ---------------------------------------------------------------------------
// MempoolStats -- aggregate statistics snapshot
// ---------------------------------------------------------------------------

struct MempoolStats {
    /// Number of transactions in the mempool.
    size_t tx_count = 0;

    /// Total virtual size of all transactions (sum of vsize).
    size_t total_vsize = 0;

    /// Total serialized size of all transactions (sum of total_size).
    size_t total_bytes = 0;

    /// Total fees of all transactions.
    primitives::Amount total_fee{0};

    /// Estimated dynamic memory usage.
    size_t memory_usage = 0;

    /// Minimum fee rate in the pool (sat/vB), or 0 if empty.
    double min_fee_rate = 0.0;

    /// Maximum fee rate in the pool (sat/vB), or 0 if empty.
    double max_fee_rate = 0.0;

    /// Average fee rate in the pool (sat/vB), or 0 if empty.
    double avg_fee_rate = 0.0;

    /// Median fee rate in the pool (sat/vB), or 0 if empty.
    double median_fee_rate = 0.0;

    /// Minimum fee rate needed to enter the pool (sat/kvB).
    /// When the pool is below max size, this is MIN_RELAY_FEE.
    /// When the pool is full, this is the eviction threshold.
    int64_t min_entry_fee_rate = 0;

    /// Number of orphan transactions.
    size_t orphan_count = 0;

    /// Pool fullness as a percentage (0.0 to 100.0+).
    double fullness_pct = 0.0;

    /// Number of tracked entries in the fee estimator.
    size_t fee_estimator_tracked = 0;

    /// Best block height known to the fee estimator.
    int fee_estimator_height = 0;

    /// Return a human-readable summary of the stats.
    [[nodiscard]] std::string to_string() const;
};

// ---------------------------------------------------------------------------
// Mempool
// ---------------------------------------------------------------------------

class Mempool {
public:
    // -- Construction -------------------------------------------------------

    /// Construct a mempool with the given maximum size in bytes.
    ///
    /// @param max_size  Maximum total virtual size in bytes.
    ///                  Defaults to DEFAULT_MAX_MEMPOOL_SIZE (300 MB).
    explicit Mempool(size_t max_size = DEFAULT_MAX_MEMPOOL_SIZE);

    ~Mempool() = default;

    // Non-copyable, non-movable (contains mutex).
    Mempool(const Mempool&)            = delete;
    Mempool& operator=(const Mempool&) = delete;
    Mempool(Mempool&&)                 = delete;
    Mempool& operator=(Mempool&&)      = delete;

    // -- Transaction addition -----------------------------------------------

    /// Add a transaction to the mempool.
    ///
    /// The caller must have already:
    ///   1. Validated the transaction against consensus rules.
    ///   2. Computed the fee (inputs minus outputs).
    ///   3. Constructed a MempoolEntry via MempoolEntry::from_tx().
    ///
    /// This method performs policy checks (standardness, dust, min relay
    /// fee, package limits) and RBF evaluation. On success, the entry is
    /// stored in the pool and all internal indices are updated.
    ///
    /// @param entry  The entry to add (moved on success).
    /// @returns core::make_ok() on success, or an error describing why
    ///          the transaction was rejected.
    [[nodiscard]] core::Result<void> add(MempoolEntry entry);

    /// Add a transaction with explicit bypass of policy checks.
    /// Used for block-connected transaction reinsertion and testing.
    ///
    /// @param entry  The entry to add.
    /// @returns core::make_ok() on success, or an error.
    [[nodiscard]] core::Result<void> add_unchecked(MempoolEntry entry);

    // -- Transaction removal ------------------------------------------------

    /// Remove a transaction and optionally its descendants.
    ///
    /// @param txid              The txid to remove.
    /// @param remove_descendants  If true, also remove all descendants.
    void remove(const core::uint256& txid, bool remove_descendants = true);

    /// Remove transactions confirmed in a block.
    ///
    /// For each transaction in the block:
    ///   1. Record it in the fee estimator (as confirmed).
    ///   2. Remove it and its conflicts from the pool.
    ///   3. Remove any orphans that are now invalid.
    ///
    /// @param block   The connected block.
    /// @param height  The height of the block.
    void remove_for_block(const primitives::Block& block, int height);

    /// Remove a transaction due to RBF replacement.
    /// This removes the transaction and all of its descendants, and records
    /// the eviction in the fee estimator.
    ///
    /// @param txid  The txid to remove.
    void remove_for_replacement(const core::uint256& txid);

    // -- Queries (read-only) ------------------------------------------------

    /// Check if a transaction with the given txid is in the pool.
    [[nodiscard]] bool exists(const core::uint256& txid) const;

    /// Get a read-only pointer to a mempool entry, or nullptr if not found.
    /// The returned pointer is valid only while the caller holds a read lock
    /// (i.e., within the same call scope; do not store the pointer).
    [[nodiscard]] const MempoolEntry* get(const core::uint256& txid) const;

    /// Get the txid of the transaction that spends a given outpoint,
    /// or nullptr if the outpoint is not spent by any mempool transaction.
    [[nodiscard]] const core::uint256*
    get_spender(const primitives::OutPoint& outpoint) const;

    /// Get all txids that conflict with the given transaction.
    /// A conflict is a mempool transaction that spends the same outpoint
    /// as one of the inputs of tx.
    [[nodiscard]] std::vector<core::uint256>
    get_conflicts(const primitives::Transaction& tx) const;

    /// Get all txids currently in the mempool.
    [[nodiscard]] std::vector<core::uint256> get_all_txids() const;

    /// Get the ancestors of a transaction (including self).
    [[nodiscard]] std::vector<core::uint256>
    get_ancestors(const core::uint256& txid) const;

    /// Get the descendants of a transaction (including self).
    [[nodiscard]] std::vector<core::uint256>
    get_descendants(const core::uint256& txid) const;

    // -- Block template construction ----------------------------------------

    /// Select transactions for inclusion in a block template.
    ///
    /// Uses a greedy ancestor-feerate algorithm:
    ///   1. Build a priority queue sorted by ancestor fee rate (descending).
    ///   2. Pop the best entry. Include it and all its ancestors.
    ///   3. Update descendant scores for remaining entries.
    ///   4. Repeat until the block is full or no more eligible entries.
    ///
    /// @param max_weight    Maximum block weight in weight units.
    /// @param min_fee_rate  Minimum individual fee rate (sat/vB) to include.
    ///                      Defaults to 0 (include everything).
    /// @returns A vector of MempoolEntry in the order they should appear
    ///          in the block (respecting topological ordering).
    [[nodiscard]] std::vector<MempoolEntry>
    select_for_block(size_t max_weight, int64_t min_fee_rate = 0) const;

    // -- Size management ----------------------------------------------------

    /// Trim the mempool to its maximum size by evicting the lowest-scoring
    /// transactions (by descendant fee rate).
    ///
    /// This is called automatically after add() and can also be called
    /// externally (e.g., after a configuration change).
    void limit_size();

    /// Expire transactions that have been in the pool longer than
    /// MEMPOOL_EXPIRY seconds.
    ///
    /// @param now  Current Unix timestamp in seconds.
    void expire(int64_t now);

    // -- Statistics ---------------------------------------------------------

    /// Number of transactions in the mempool.
    [[nodiscard]] size_t size() const;

    /// Estimated dynamic (heap) memory usage of the mempool.
    [[nodiscard]] size_t dynamic_memory_usage() const;

    /// Total virtual size of all transactions.
    [[nodiscard]] size_t total_tx_size() const;

    /// Total serialized size of all transactions.
    [[nodiscard]] size_t total_tx_bytes() const;

    /// Total fees of all transactions.
    [[nodiscard]] primitives::Amount total_fee() const;

    /// Get an aggregate statistics snapshot.
    [[nodiscard]] MempoolStats get_stats() const;

    /// Get the minimum fee rate (sat/kvB) needed to enter the pool.
    /// When the pool is below max size, this is MIN_RELAY_FEE.
    /// When the pool is full, this is dynamically computed.
    [[nodiscard]] int64_t get_min_fee_rate() const;

    // -- Fee estimation -----------------------------------------------------

    /// Estimate the fee rate (sat/kvB) for a target number of confirmation
    /// blocks.
    ///
    /// @param target_blocks  Desired confirmation target (1 to MAX_TARGET).
    /// @returns Estimated fee rate, or -1 if no reliable estimate available.
    [[nodiscard]] int64_t estimate_fee(int target_blocks) const;

    // -- Orphan pool access -------------------------------------------------

    /// Access the orphan pool (for adding/querying orphan transactions).
    [[nodiscard]] OrphanPool& orphan_pool();
    [[nodiscard]] const OrphanPool& orphan_pool() const;

    // -- Configuration ------------------------------------------------------

    /// Set the maximum mempool size.
    void set_max_size(size_t max_size);

    /// Get the current maximum mempool size.
    [[nodiscard]] size_t max_size() const;

    /// Clear all transactions from the mempool.
    void clear();

    // -- Diagnostic and debug ------------------------------------------------

    /// Return a human-readable summary of the mempool state.
    /// Includes entry count, size, fee stats, ancestor tracker stats,
    /// orphan pool stats, and fee estimator stats.
    [[nodiscard]] std::string dump() const;

    /// Check internal consistency of all mempool data structures.
    /// Returns true if consistent, false otherwise (with reason set).
    /// This is an expensive operation and should only be used for testing.
    ///
    /// @param reason  [out] Human-readable reason on failure.
    /// @returns True if all data structures are consistent.
    [[nodiscard]] bool check_consistency(std::string& reason) const;

    /// Return the number of outpoints tracked in the spender index.
    [[nodiscard]] size_t outpoint_index_size() const;

    /// Return the number of entries in the wtxid-to-txid mapping.
    [[nodiscard]] size_t wtxid_index_size() const;

    /// Return the fee estimator (read-only access for diagnostics).
    [[nodiscard]] const FeeEstimator& fee_estimator() const;

    /// Return the ancestor tracker (read-only access for diagnostics).
    [[nodiscard]] const AncestorTracker& ancestor_tracker() const;

    /// Check if the mempool is currently full (total_vsize >= max_size).
    [[nodiscard]] bool is_full() const;

    /// Return the amount of free capacity remaining (max_size - total_vsize).
    /// Returns 0 if the pool is full or over capacity.
    [[nodiscard]] size_t remaining_capacity() const;

    /// Look up an entry by its witness txid (wtxid) instead of txid.
    [[nodiscard]] const MempoolEntry*
    get_by_wtxid(const core::uint256& wtxid) const;

    /// Return the set of all txids that depend on the given transaction
    /// (i.e., transactions that have this txid as an ancestor).
    /// Alias for get_descendants but returns entries instead of txids.
    [[nodiscard]] std::vector<MempoolEntry>
    get_descendant_entries(const core::uint256& txid) const;

    /// Return the set of all entries that the given transaction depends on.
    /// Alias for get_ancestors but returns entries instead of txids.
    [[nodiscard]] std::vector<MempoolEntry>
    get_ancestor_entries(const core::uint256& txid) const;

private:
    // -- Internal helpers (must be called with appropriate lock held) --------

    /// Add an entry to all internal indices. Called under exclusive lock.
    void add_to_indices(MempoolEntry& entry);

    /// Remove an entry from all internal indices. Called under exclusive lock.
    void remove_from_indices(const core::uint256& txid);

    /// Remove a single entry (no descendant cascade). Called under exclusive
    /// lock.
    void remove_single(const core::uint256& txid);

    /// Compute the in-mempool parents of a transaction.
    [[nodiscard]] std::vector<core::uint256>
    get_in_mempool_parents(const primitives::Transaction& tx) const;

    /// Update ancestor/descendant state for the entry and all affected
    /// entries after adding a new transaction.
    void update_for_add(const core::uint256& txid);

    /// Update ancestor/descendant state for all affected entries after
    /// removing a transaction.
    void update_for_remove(const core::uint256& txid);

    /// Compute the minimum eviction score (descendant fee rate) in the pool.
    [[nodiscard]] double get_min_eviction_score() const;

    /// Get the entry with the lowest eviction score (for eviction).
    [[nodiscard]] const core::uint256* get_eviction_candidate() const;

    /// Internal limit_size implementation (called with lock held).
    void limit_size_internal();

    /// Internal get_min_fee_rate implementation (called with lock held).
    [[nodiscard]] int64_t get_min_fee_rate_internal() const;

    // -- Data ---------------------------------------------------------------

    /// Shared mutex: readers use shared_lock, writers use unique_lock.
    mutable std::shared_mutex mutex_;

    /// Primary storage: txid -> MempoolEntry.
    std::unordered_map<core::uint256, MempoolEntry, Uint256Hash> entries_;

    /// Outpoint -> txid of the spending transaction.
    /// Used for conflict detection and CPFP.
    std::unordered_map<primitives::OutPoint, core::uint256, OutPointHash>
        outpoint_to_txid_;

    /// Wtxid -> txid mapping (for witness-aware relay).
    std::unordered_map<core::uint256, core::uint256, Uint256Hash>
        wtxid_to_txid_;

    /// Ancestor/descendant tracker.
    AncestorTracker ancestors_;

    /// Orphan transaction pool.
    OrphanPool orphans_;

    /// Fee rate estimator.
    FeeEstimator fee_estimator_;

    /// Maximum total virtual size of the pool in bytes.
    size_t max_size_ = DEFAULT_MAX_MEMPOOL_SIZE;

    /// Current total virtual size of all entries.
    size_t total_vsize_ = 0;

    /// Current total serialized size of all entries.
    size_t total_bytes_ = 0;

    /// Current total fees of all entries.
    int64_t total_fees_ = 0;

    /// Sequence number for ordering entries (monotonically increasing).
    uint64_t sequence_ = 0;

    /// Cached minimum fee rate for entry (sat/kvB). Updated when the pool
    /// is full and transactions are being evicted.
    mutable int64_t cached_min_fee_rate_ = MIN_RELAY_FEE;

    /// Whether the cached min fee rate needs recomputation.
    mutable bool min_fee_rate_dirty_ = true;
};

} // namespace mempool
