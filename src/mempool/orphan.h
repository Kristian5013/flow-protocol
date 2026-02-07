#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// OrphanPool -- holds transactions whose inputs are not yet available
// ---------------------------------------------------------------------------
// When a transaction references inputs that are not in the UTXO set or
// mempool, it is placed in the orphan pool. Once the missing parent
// transaction arrives (either from a peer or in a block), the orphan's
// children are reconsidered for mempool admission.
//
// The orphan pool is size-limited and entries expire after ORPHAN_EXPIRY
// seconds. Each entry tracks which peer sent it, allowing per-peer eviction
// when a peer misbehaves.
//
// Thread safety: the OrphanPool has its own mutex and is internally
// thread-safe. The Mempool may hold its own lock while calling into the
// OrphanPool; the OrphanPool never calls back into the Mempool, so there
// is no deadlock risk.
// ---------------------------------------------------------------------------

#include "core/types.h"
#include "primitives/outpoint.h"
#include "primitives/transaction.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace mempool {

// ---------------------------------------------------------------------------
// Forward declarations and hash functors
// ---------------------------------------------------------------------------

struct OrphanEntry {
    /// The orphan transaction.
    primitives::Transaction tx;

    /// Cached transaction ID.
    core::uint256 txid;

    /// Peer that sent this orphan.
    uint64_t peer_id = 0;

    /// Unix timestamp when this orphan was added.
    int64_t expiry_time = 0;

    /// Total serialized size in bytes (used for memory tracking).
    size_t size = 0;
};

// ---------------------------------------------------------------------------
// OrphanPool
// ---------------------------------------------------------------------------

class OrphanPool {
public:
    /// Maximum number of orphan transactions stored at once.
    static constexpr size_t MAX_ORPHAN_TRANSACTIONS = 100;

    /// Orphan expiry time in seconds (20 minutes).
    static constexpr int64_t ORPHAN_EXPIRY = 20 * 60;

    /// Maximum size in bytes of a single orphan transaction.
    /// Orphans larger than this are rejected outright.
    static constexpr size_t MAX_ORPHAN_TX_SIZE = 100000;

    OrphanPool() = default;

    // -- Mutation -----------------------------------------------------------

    /// Add an orphan transaction to the pool.
    ///
    /// The transaction is rejected (returns false) if:
    ///   - It already exists in the pool.
    ///   - It exceeds MAX_ORPHAN_TX_SIZE.
    ///   - The pool is full (after limit_size()).
    ///
    /// @param tx       The orphan transaction.
    /// @param peer_id  The peer that sent this transaction.
    /// @returns True if the transaction was added successfully.
    bool add(const primitives::Transaction& tx, uint64_t peer_id);

    /// Remove an orphan transaction by txid.
    void erase(const core::uint256& txid);

    /// Remove all orphan transactions that were sent by a specific peer.
    /// Called when a peer is disconnected or misbehaving.
    ///
    /// @param peer_id  The peer whose orphans to remove.
    void erase_for_peer(uint64_t peer_id);

    /// Remove expired orphans and trim the pool to MAX_ORPHAN_TRANSACTIONS.
    /// Eviction is random (by iteration order of the unordered_map) to
    /// prevent an attacker from predicting which orphans survive.
    void limit_size();

    /// Remove expired orphans based on the given current time.
    ///
    /// @param now  Current Unix timestamp in seconds.
    void expire(int64_t now);

    /// Clear all orphan transactions.
    void clear();

    // -- Queries -----------------------------------------------------------

    /// Check if a transaction with the given txid exists in the pool.
    [[nodiscard]] bool exists(const core::uint256& txid) const;

    /// Get a pointer to the orphan entry, or nullptr if not found.
    [[nodiscard]] const OrphanEntry* get(const core::uint256& txid) const;

    /// Return all orphan transactions that spend the given outpoint.
    /// These are candidates for reconsidering when the parent arrives.
    ///
    /// @param outpoint  The outpoint to search for in orphan inputs.
    /// @returns Transactions that reference this outpoint as an input.
    [[nodiscard]] std::vector<primitives::Transaction>
    get_children(const primitives::OutPoint& outpoint) const;

    /// Return all orphan transactions that spend any output of the given
    /// parent transaction. Convenience wrapper around get_children.
    ///
    /// @param parent_txid  The txid of the parent transaction.
    /// @param num_outputs  The number of outputs in the parent transaction.
    /// @returns All orphans referencing any output of parent_txid.
    [[nodiscard]] std::vector<primitives::Transaction>
    get_children_of_tx(const core::uint256& parent_txid,
                       uint32_t num_outputs) const;

    /// Return the current number of orphan transactions.
    [[nodiscard]] size_t size() const;

    /// Return the total memory usage of all orphan transactions.
    [[nodiscard]] size_t memory_usage() const;

    /// Return all txids currently in the orphan pool.
    [[nodiscard]] std::vector<core::uint256> get_all_txids() const;

    /// Return the number of orphans from a specific peer.
    [[nodiscard]] size_t count_for_peer(uint64_t peer_id) const;

    /// Return the set of unique outpoints that orphan transactions are
    /// waiting on (i.e., outpoints that no known parent provides).
    [[nodiscard]] std::vector<primitives::OutPoint>
    get_missing_outpoints() const;

    /// Return the number of unique outpoints tracked in the index.
    [[nodiscard]] size_t outpoint_index_size() const;

    /// Return a human-readable summary of the orphan pool.
    [[nodiscard]] std::string dump() const;

    /// Check whether a specific outpoint is referenced by any orphan.
    [[nodiscard]] bool has_outpoint(const primitives::OutPoint& outpoint) const;

    /// Return the peer IDs of all peers that have sent orphan transactions.
    [[nodiscard]] std::vector<uint64_t> get_peer_ids() const;

    // -- Statistics -----------------------------------------------------------

    /// Aggregate statistics about the orphan pool.
    struct OrphanStats {
        /// Total number of orphan transactions.
        size_t count = 0;

        /// Total serialized size of all orphans.
        size_t total_size = 0;

        /// Number of unique outpoints in the index.
        size_t indexed_outpoints = 0;

        /// Number of unique peers with orphans.
        size_t peer_count = 0;

        /// Maximum orphans from a single peer.
        size_t max_per_peer = 0;

        /// Average orphan age in seconds (relative to provided now).
        double avg_age = 0.0;

        /// Number of orphans that have expired (expiry_time <= now).
        size_t expired_count = 0;

        /// Total number of inputs across all orphans.
        size_t total_inputs = 0;

        /// Total number of outputs across all orphans.
        size_t total_outputs = 0;

        /// Estimated heap memory usage in bytes.
        size_t memory_bytes = 0;

        /// Returns a human-readable summary.
        [[nodiscard]] std::string to_string() const;
    };

    /// Compute comprehensive statistics about the orphan pool.
    ///
    /// @param now  The current Unix timestamp (for age computation).
    /// @returns Aggregate statistics.
    [[nodiscard]] OrphanStats compute_stats(int64_t now) const;

    /// Return the oldest orphan in the pool (by expiry_time), or nullptr
    /// if the pool is empty.
    [[nodiscard]] const OrphanEntry* oldest_orphan() const;

    /// Return the newest orphan in the pool (by expiry_time), or nullptr
    /// if the pool is empty.
    [[nodiscard]] const OrphanEntry* newest_orphan() const;

    /// Return the orphan with the largest serialized size, or nullptr
    /// if the pool is empty.
    [[nodiscard]] const OrphanEntry* largest_orphan() const;

    /// Check whether any orphan in the pool spends any output of the
    /// given transaction. Used to determine if a newly confirmed
    /// transaction has orphan children waiting.
    ///
    /// @param parent_txid   The txid of the parent transaction.
    /// @param num_outputs   The number of outputs in the parent.
    /// @returns True if at least one orphan spends an output of parent_txid.
    [[nodiscard]] bool has_children_of(const core::uint256& parent_txid,
                                       uint32_t num_outputs) const;

    /// Return the number of distinct parent transactions that orphans
    /// in the pool are waiting on.
    [[nodiscard]] size_t waiting_parent_count() const;

private:
    // -- Internal helpers ---------------------------------------------------

    /// Remove an entry from the outpoint index.
    void remove_from_outpoint_index(const OrphanEntry& entry);

    /// Add an entry to the outpoint index.
    void add_to_outpoint_index(const OrphanEntry& entry);

    // -- Data ---------------------------------------------------------------

    /// Lock protecting all internal state.
    mutable std::mutex mutex_;

    /// Primary storage: txid -> OrphanEntry.
    struct Uint256Hash {
        std::size_t operator()(const core::uint256& v) const noexcept {
            return std::hash<core::uint256>{}(v);
        }
    };

    std::unordered_map<core::uint256, OrphanEntry, Uint256Hash> orphans_;

    /// Secondary index: outpoint -> set of orphan txids that spend it.
    /// Used for efficient lookup when a parent transaction arrives.
    struct OutPointHash {
        std::size_t operator()(const primitives::OutPoint& op) const noexcept {
            return std::hash<primitives::OutPoint>{}(op);
        }
    };

    using Uint256Set = std::unordered_set<core::uint256, Uint256Hash>;

    std::unordered_map<primitives::OutPoint, Uint256Set, OutPointHash>
        outpoint_index_;

    /// Per-peer count of orphan transactions (for per-peer limiting).
    std::unordered_map<uint64_t, size_t> peer_orphan_count_;
};

} // namespace mempool
