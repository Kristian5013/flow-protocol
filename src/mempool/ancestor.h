#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// AncestorTracker -- tracks parent/child relationships between mempool txs
// ---------------------------------------------------------------------------
// Maintains bidirectional parent <-> child maps for all transactions in the
// mempool. Provides BFS-based ancestor/descendant enumeration and enforces
// package limits (MAX_ANCESTORS, MAX_DESCENDANTS, MAX_ANCESTOR_SIZE, etc.).
//
// The tracker does NOT hold its own lock; the caller (Mempool) is expected
// to hold the mempool mutex when calling into this class.
// ---------------------------------------------------------------------------

#include "core/types.h"
#include "mempool/entry.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace mempool {

// ---------------------------------------------------------------------------
// Uint256Hash -- hash functor for use in unordered containers
// ---------------------------------------------------------------------------

struct Uint256Hash {
    std::size_t operator()(const core::uint256& v) const noexcept {
        return std::hash<core::uint256>{}(v);
    }
};

using Uint256Set = std::unordered_set<core::uint256, Uint256Hash>;

// ---------------------------------------------------------------------------
// AncestorTracker
// ---------------------------------------------------------------------------

class AncestorTracker {
public:
    AncestorTracker() = default;

    // -- Mutation -----------------------------------------------------------

    /// Register a new transaction and its in-mempool parents.
    ///
    /// @param txid    The txid of the newly added transaction.
    /// @param parents Set of txids that this transaction directly spends
    ///                from (only those already in the mempool).
    void add_entry(const core::uint256& txid,
                   const std::vector<core::uint256>& parents);

    /// Remove a transaction from the tracker.
    /// This removes the txid from all parent/child maps but does NOT
    /// cascade-remove descendants. The caller is responsible for removing
    /// descendants if desired (the Mempool does this).
    void remove_entry(const core::uint256& txid);

    /// Clear all tracking data.
    void clear();

    // -- Queries -----------------------------------------------------------

    /// Compute the full ancestor set of a transaction (BFS over parents).
    /// The result includes the transaction itself.
    ///
    /// @param txid  The transaction whose ancestors to compute.
    /// @returns     A vector of txids (including txid itself).
    [[nodiscard]] std::vector<core::uint256>
    get_ancestors(const core::uint256& txid) const;

    /// Compute the full descendant set of a transaction (BFS over children).
    /// The result includes the transaction itself.
    ///
    /// @param txid  The transaction whose descendants to compute.
    /// @returns     A vector of txids (including txid itself).
    [[nodiscard]] std::vector<core::uint256>
    get_descendants(const core::uint256& txid) const;

    /// Return the direct parent txids of a transaction.
    [[nodiscard]] std::vector<core::uint256>
    get_parents(const core::uint256& txid) const;

    /// Return the direct child txids of a transaction.
    [[nodiscard]] std::vector<core::uint256>
    get_children(const core::uint256& txid) const;

    /// Count the number of ancestors (including self).
    [[nodiscard]] size_t count_ancestors(const core::uint256& txid) const;

    /// Count the number of descendants (including self).
    [[nodiscard]] size_t count_descendants(const core::uint256& txid) const;

    /// Check whether txid is tracked.
    [[nodiscard]] bool has_entry(const core::uint256& txid) const;

    /// Return the number of tracked transactions.
    [[nodiscard]] size_t size() const;

    // -- Ancestor/descendant state update -----------------------------------

    /// Update the ancestor_count, ancestor_size, and ancestor_fees fields
    /// on a MempoolEntry by walking the ancestor chain.
    ///
    /// @param entry   The entry to update (modified in place).
    /// @param lookup  A callable: (const core::uint256&) -> const MempoolEntry*
    ///                that looks up entries by txid.
    void update_ancestor_state(
        MempoolEntry& entry,
        const std::function<const MempoolEntry*(const core::uint256&)>& lookup)
        const;

    /// Update the descendant_count, descendant_size, and descendant_fees
    /// fields on a MempoolEntry by walking the descendant chain.
    ///
    /// @param entry   The entry to update (modified in place).
    /// @param lookup  A callable: (const core::uint256&) -> const MempoolEntry*
    void update_descendant_state(
        MempoolEntry& entry,
        const std::function<const MempoolEntry*(const core::uint256&)>& lookup)
        const;

    /// Recalculate the ancestor and descendant state for a single entry
    /// and all of its ancestors and descendants. Called after adding or
    /// removing entries.
    ///
    /// @param txid   The transaction that was added or removed.
    /// @param lookup Callable to look up entries by txid.
    /// @param update Callable to mutate an entry: (MempoolEntry&) -> void.
    void recalculate_affected(
        const core::uint256& txid,
        const std::function<const MempoolEntry*(const core::uint256&)>& lookup,
        const std::function<void(MempoolEntry&)>& update) const;

    // -- Package limit checks -----------------------------------------------

    /// Check whether adding a transaction with the given txid would violate
    /// ancestor or descendant limits.
    ///
    /// This is typically called BEFORE add_entry(), using hypothetical parent
    /// information and the entry's own vsize.
    ///
    /// @param txid              The txid to check.
    /// @param parents           The in-mempool parent txids.
    /// @param own_vsize         The vsize of the transaction to be added.
    /// @param max_ancestors     Maximum ancestor count.
    /// @param max_descendants   Maximum descendant count.
    /// @param max_ancestor_size Maximum sum of ancestor vsizes.
    /// @param max_descendant_size Maximum sum of descendant vsizes.
    /// @param lookup            Callable to look up entries by txid.
    /// @param reason            [out] Human-readable reason on failure.
    /// @returns True if limits are satisfied; false otherwise.
    [[nodiscard]] bool check_limits(
        const core::uint256& txid,
        const std::vector<core::uint256>& parents,
        size_t own_vsize,
        size_t max_ancestors,
        size_t max_descendants,
        size_t max_ancestor_size,
        size_t max_descendant_size,
        const std::function<const MempoolEntry*(const core::uint256&)>& lookup,
        std::string& reason) const;

    /// Simplified limit check that uses the default policy constants.
    [[nodiscard]] bool check_package_limits(
        const core::uint256& txid,
        const std::vector<core::uint256>& parents,
        size_t own_vsize,
        const std::function<const MempoolEntry*(const core::uint256&)>& lookup,
        std::string& reason) const;

    // -- Topological ordering -----------------------------------------------

    /// Return all tracked transactions in topological order (parents before
    /// children). Uses Kahn's algorithm internally.
    ///
    /// @param lookup  Callable to check existence by txid.
    /// @returns A vector of txids in topological order.
    [[nodiscard]] std::vector<core::uint256> topological_sort() const;

    /// Return the subset of txids in topological order.
    ///
    /// @param txids  The set of txids to sort.
    /// @returns A vector of txids in topological order.
    [[nodiscard]] std::vector<core::uint256> topological_sort(
        const std::vector<core::uint256>& txids) const;

    // -- Diagnostics --------------------------------------------------------

    /// Return a human-readable summary of the tracker state.
    [[nodiscard]] std::string dump() const;

    /// Check internal consistency of the parent/child maps.
    /// Returns true if consistent, false otherwise (with reason set).
    [[nodiscard]] bool check_consistency(std::string& reason) const;

    /// Return the maximum ancestor chain depth in the tracker.
    [[nodiscard]] size_t max_depth() const;

    // -- Chain analysis -------------------------------------------------------

    /// Return the longest ancestor chain starting from the given txid.
    /// The chain is ordered from the root (oldest ancestor) to the given txid.
    ///
    /// @param txid  The transaction to trace back from.
    /// @returns A vector of txids from root to txid (inclusive).
    [[nodiscard]] std::vector<core::uint256>
    longest_ancestor_chain(const core::uint256& txid) const;

    /// Return the longest descendant chain starting from the given txid.
    /// The chain is ordered from the given txid to the deepest descendant.
    ///
    /// @param txid  The transaction to trace forward from.
    /// @returns A vector of txids from txid to the deepest descendant (inclusive).
    [[nodiscard]] std::vector<core::uint256>
    longest_descendant_chain(const core::uint256& txid) const;

    /// Return the set of all root transactions (those with no in-mempool parents).
    /// Root transactions are the starting points for ancestor chains.
    [[nodiscard]] std::vector<core::uint256> get_roots() const;

    /// Return the set of all leaf transactions (those with no in-mempool children).
    /// Leaf transactions are the endpoints for descendant chains.
    [[nodiscard]] std::vector<core::uint256> get_leaves() const;

    /// Compute the depth (longest ancestor chain length) of a specific transaction.
    /// Returns 1 if the transaction has no in-mempool parents (is a root).
    ///
    /// @param txid  The transaction whose depth to compute.
    /// @returns The depth, or 0 if the txid is not tracked.
    [[nodiscard]] size_t depth_of(const core::uint256& txid) const;

    /// Return all transactions at a specific depth level in the DAG.
    /// Depth 1 = roots, depth 2 = children of roots, etc.
    ///
    /// @param depth  The depth level (1-based).
    /// @returns A vector of txids at that depth.
    [[nodiscard]] std::vector<core::uint256>
    transactions_at_depth(size_t depth) const;

    /// Return the number of independent connected components in the
    /// ancestor/descendant graph. Each component is a set of transactions
    /// connected through parent/child relationships.
    [[nodiscard]] size_t connected_component_count() const;

    /// Return the connected component containing the given txid.
    /// The component includes all transactions reachable from txid
    /// by following both parent and child edges.
    ///
    /// @param txid  The transaction whose component to find.
    /// @returns A vector of txids in the same connected component.
    [[nodiscard]] std::vector<core::uint256>
    connected_component(const core::uint256& txid) const;

    // -- Statistics -----------------------------------------------------------

    /// Compute aggregate statistics over all tracked entries.
    /// Returns (total_entries, total_edges, max_ancestor_count,
    /// max_descendant_count, max_depth, avg_ancestor_count).
    struct TrackerStats {
        size_t total_entries = 0;
        size_t total_parent_edges = 0;
        size_t total_child_edges = 0;
        size_t max_ancestor_count = 0;
        size_t max_descendant_count = 0;
        size_t max_chain_depth = 0;
        size_t root_count = 0;
        size_t leaf_count = 0;
        size_t component_count = 0;
        double avg_parents_per_tx = 0.0;
        double avg_children_per_tx = 0.0;
    };

    /// Compute comprehensive statistics about the tracker state.
    [[nodiscard]] TrackerStats compute_stats() const;

    /// Return a detailed human-readable statistics summary.
    [[nodiscard]] std::string stats_string() const;

    // -- Batch operations -----------------------------------------------------

    /// Remove multiple entries at once. More efficient than calling
    /// remove_entry() in a loop because it batches the index updates.
    ///
    /// @param txids  The set of txids to remove.
    void remove_entries(const std::vector<core::uint256>& txids);

    /// Check whether adding a batch of transactions would violate any
    /// package limits. Returns true if all can be added, false if any
    /// would exceed limits.
    ///
    /// @param entries  Pairs of (txid, parents) for each new transaction.
    /// @param lookup   Callable to look up existing entries.
    /// @param reason   [out] Reason for failure.
    /// @returns True if all entries can be added within limits.
    [[nodiscard]] bool check_batch_limits(
        const std::vector<std::pair<core::uint256,
                                     std::vector<core::uint256>>>& entries,
        const std::function<const MempoolEntry*(const core::uint256&)>& lookup,
        std::string& reason) const;

private:
    // -- Internal BFS helpers -----------------------------------------------

    /// BFS walk starting from txid, following the given adjacency map.
    /// Returns the set of all reachable txids including the starting txid.
    [[nodiscard]] Uint256Set bfs_walk(
        const core::uint256& txid,
        const std::unordered_map<core::uint256, Uint256Set, Uint256Hash>& adj)
        const;

    // -- Data ---------------------------------------------------------------

    /// Maps txid -> set of direct parent txids (transactions this one spends).
    std::unordered_map<core::uint256, Uint256Set, Uint256Hash> parents_;

    /// Maps txid -> set of direct child txids (transactions that spend this).
    std::unordered_map<core::uint256, Uint256Set, Uint256Hash> children_;
};

} // namespace mempool
