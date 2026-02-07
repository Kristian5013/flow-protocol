#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// MempoolEntry -- represents a single transaction stored in the mempool
// ---------------------------------------------------------------------------
// Each entry wraps a Transaction together with its fee, size metrics,
// ancestor/descendant tracking state, and the timestamp and block height
// at which it entered the pool. These fields are maintained by the Mempool
// and AncestorTracker classes.
// ---------------------------------------------------------------------------

#include "core/error.h"
#include "core/types.h"
#include "primitives/amount.h"
#include "primitives/transaction.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace mempool {

// ---------------------------------------------------------------------------
// MempoolEntry
// ---------------------------------------------------------------------------

struct MempoolEntry {
    // -- Core transaction data -----------------------------------------------

    /// The full transaction.
    primitives::Transaction tx;

    /// Cached transaction ID (non-witness hash).
    core::uint256 txid;

    /// Cached witness transaction ID. Equals txid when no witness is present.
    core::uint256 wtxid;

    /// Fee paid by this transaction (total inputs minus total outputs).
    primitives::Amount fee;

    /// Total serialized size in bytes (including witness data).
    size_t size = 0;

    /// Virtual size in vbytes: (weight + 3) / 4.
    size_t vsize = 0;

    /// Unix timestamp (seconds) when the entry was accepted into the pool.
    int64_t time = 0;

    /// Block height at the time the entry was accepted into the pool.
    int32_t height = 0;

    // -- Ancestor tracking (package-relay limits) ----------------------------
    // "Ancestors" include the transaction itself.

    /// Number of in-mempool ancestors, including self.
    size_t ancestor_count = 1;

    /// Sum of virtual sizes of all in-mempool ancestors, including self.
    size_t ancestor_size = 0;

    /// Sum of fees of all in-mempool ancestors, including self.
    primitives::Amount ancestor_fees{0};

    // -- Descendant tracking -------------------------------------------------

    /// Number of in-mempool descendants, including self.
    size_t descendant_count = 1;

    /// Sum of virtual sizes of all in-mempool descendants, including self.
    size_t descendant_size = 0;

    /// Sum of fees of all in-mempool descendants, including self.
    primitives::Amount descendant_fees{0};

    // -- Fee rate helpers ----------------------------------------------------

    /// Individual fee rate in sat/vB (fee / vsize).
    /// Returns 0.0 if vsize is zero.
    [[nodiscard]] double fee_rate() const;

    /// Ancestor-package fee rate in sat/vB (ancestor_fees / ancestor_size).
    /// Used by the block-assembly algorithm (ancestor-feerate mining).
    /// Returns 0.0 if ancestor_size is zero.
    [[nodiscard]] double ancestor_fee_rate() const;

    /// Modified fee rate used for eviction scoring: the descendant package
    /// fee rate (descendant_fees / descendant_size) in sat/vB.
    /// Returns 0.0 if descendant_size is zero.
    [[nodiscard]] double descendant_fee_rate() const;

    /// Fee rate expressed in sat/kvB (fee_per_kvb) for compatibility with
    /// the primitives::FeeRate convention. Equals fee_rate() * 1000.
    [[nodiscard]] int64_t fee_rate_per_kvb() const;

    // -- Size helpers --------------------------------------------------------

    /// Estimate the dynamic (heap) memory used by this entry, including the
    /// transaction's inputs, outputs, witness stacks, and script data.
    [[nodiscard]] size_t dynamic_memory_usage() const;

    // -- Construction --------------------------------------------------------

    /// Build a MempoolEntry from a transaction and contextual metadata.
    /// The ancestor/descendant fields are initialized to cover only self.
    ///
    /// @param tx     The transaction (moved into the entry).
    /// @param fee    Pre-computed fee (inputs - outputs).
    /// @param height Block height at time of acceptance.
    /// @param time   Unix timestamp at time of acceptance.
    static MempoolEntry from_tx(const primitives::Transaction& tx,
                                primitives::Amount fee,
                                int32_t height,
                                int64_t time);

    // -- Comparison (by txid) ------------------------------------------------

    bool operator==(const MempoolEntry& other) const {
        return txid == other.txid;
    }
    bool operator!=(const MempoolEntry& other) const {
        return txid != other.txid;
    }

    // -- Scoring helpers -----------------------------------------------------

    /// Compute the "mining score" for this entry: the ancestor fee rate.
    /// Higher is better for block inclusion.
    [[nodiscard]] double mining_score() const;

    /// Compute the "eviction score" for this entry: the descendant fee rate.
    /// Lower values are evicted first when the pool is full.
    [[nodiscard]] double eviction_score() const;

    /// Returns true if this entry should be preferred over `other` for
    /// block inclusion (higher mining score wins).
    [[nodiscard]] bool is_better_for_mining(const MempoolEntry& other) const;

    /// Returns true if this entry should be evicted before `other`
    /// (lower eviction score loses).
    [[nodiscard]] bool should_evict_before(const MempoolEntry& other) const;

    // -- Time helpers --------------------------------------------------------

    /// Return the age of this entry in seconds, given the current time.
    [[nodiscard]] int64_t age(int64_t now) const;

    /// Return the number of blocks this entry has been in the pool,
    /// given the current chain height.
    [[nodiscard]] int32_t blocks_in_pool(int32_t current_height) const;

    // -- Validation helpers --------------------------------------------------

    /// Returns true if the entry represents a coinbase transaction.
    [[nodiscard]] bool is_coinbase() const;

    /// Returns true if the entry has witness data.
    [[nodiscard]] bool has_witness() const;

    /// Returns the weight of the transaction.
    [[nodiscard]] size_t weight() const;

    /// Returns the number of inputs.
    [[nodiscard]] size_t input_count() const;

    /// Returns the number of outputs.
    [[nodiscard]] size_t output_count() const;

    /// Returns the total value of all outputs.
    [[nodiscard]] primitives::Amount total_output_value() const;

    // -- Human-readable summary ----------------------------------------------

    /// Returns a short human-readable summary string:
    /// "txid=<hex> fee=<n> vsize=<n> feerate=<n.nn>"
    [[nodiscard]] std::string to_string() const;

    /// Returns a detailed multi-line summary for debug logging.
    [[nodiscard]] std::string to_debug_string() const;
};

// ---------------------------------------------------------------------------
// Comparison functors (for use in priority queues and sorted sets)
// ---------------------------------------------------------------------------

/// Compare entries by individual fee rate (descending).
struct CompareByFeeRate {
    bool operator()(const MempoolEntry& a, const MempoolEntry& b) const {
        return a.fee_rate() > b.fee_rate();
    }
};

/// Compare entries by ancestor fee rate (descending).
/// Used for block template construction (ancestor-feerate mining).
struct CompareByAncestorFeeRate {
    bool operator()(const MempoolEntry& a, const MempoolEntry& b) const {
        double ar = a.ancestor_fee_rate();
        double br = b.ancestor_fee_rate();
        if (ar != br) return ar > br;
        // Tie-break: prefer the entry with the smaller ancestor size
        // (so the miner can fit more transactions).
        return a.ancestor_size < b.ancestor_size;
    }
};

/// Compare entries by descendant fee rate (ascending).
/// Used for eviction: evict the entry with the lowest descendant score.
struct CompareByDescendantFeeRate {
    bool operator()(const MempoolEntry& a, const MempoolEntry& b) const {
        double ar = a.descendant_fee_rate();
        double br = b.descendant_fee_rate();
        if (ar != br) return ar < br;
        // Tie-break: evict the entry with the larger descendant size first.
        return a.descendant_size > b.descendant_size;
    }
};

/// Compare entries by entry time (oldest first).
struct CompareByTime {
    bool operator()(const MempoolEntry& a, const MempoolEntry& b) const {
        return a.time < b.time;
    }
};

/// Compare entries by total serialized size (largest first).
struct CompareBySize {
    bool operator()(const MempoolEntry& a, const MempoolEntry& b) const {
        if (a.size != b.size) return a.size > b.size;
        return a.fee_rate() > b.fee_rate();
    }
};

/// Compare entries by mining score (highest first), with full tie-breaking.
struct CompareByMiningScore {
    bool operator()(const MempoolEntry& a, const MempoolEntry& b) const {
        return a.is_better_for_mining(b);
    }
};

/// Compare entries by eviction priority (most evictable first).
struct CompareByEvictionPriority {
    bool operator()(const MempoolEntry& a, const MempoolEntry& b) const {
        return a.should_evict_before(b);
    }
};

// ---------------------------------------------------------------------------
// MempoolEntry helper functions (non-member)
// ---------------------------------------------------------------------------

/// Compute the total fee and total vsize of a vector of entries.
/// Returns a pair of (total_fee, total_vsize).
inline std::pair<int64_t, size_t> compute_package_stats(
    const std::vector<MempoolEntry>& entries) {
    int64_t total_fee = 0;
    size_t total_vsize = 0;
    for (const auto& entry : entries) {
        total_fee += entry.fee.value();
        total_vsize += entry.vsize;
    }
    return {total_fee, total_vsize};
}

/// Compute the package fee rate of a set of entries.
inline double compute_package_fee_rate(
    const std::vector<MempoolEntry>& entries) {
    auto [fee, vsize] = compute_package_stats(entries);
    if (vsize == 0) return 0.0;
    return static_cast<double>(fee) / static_cast<double>(vsize);
}

/// Sort entries in descending order by mining score.
inline void sort_by_mining_score(std::vector<MempoolEntry>& entries) {
    std::sort(entries.begin(), entries.end(), CompareByMiningScore{});
}

/// Sort entries in ascending order by eviction priority (most evictable first).
inline void sort_by_eviction_priority(std::vector<MempoolEntry>& entries) {
    std::sort(entries.begin(), entries.end(), CompareByEvictionPriority{});
}

/// Sort entries by fee rate (descending).
inline void sort_by_fee_rate(std::vector<MempoolEntry>& entries) {
    std::sort(entries.begin(), entries.end(), CompareByFeeRate{});
}

/// Sort entries by entry time (oldest first).
inline void sort_by_time(std::vector<MempoolEntry>& entries) {
    std::sort(entries.begin(), entries.end(), CompareByTime{});
}

/// Sort entries by total serialized size (largest first).
inline void sort_by_size(std::vector<MempoolEntry>& entries) {
    std::sort(entries.begin(), entries.end(), CompareBySize{});
}

// ---------------------------------------------------------------------------
// Filtering helpers
// ---------------------------------------------------------------------------

/// Filter entries to only include those with a fee rate >= min_fee_rate.
///
/// @param entries       The entries to filter.
/// @param min_fee_rate  Minimum fee rate in sat/vB.
/// @returns A new vector containing only qualifying entries.
inline std::vector<MempoolEntry> filter_by_min_fee_rate(
    const std::vector<MempoolEntry>& entries,
    double min_fee_rate) {
    std::vector<MempoolEntry> result;
    result.reserve(entries.size());
    for (const auto& entry : entries) {
        if (entry.fee_rate() >= min_fee_rate) {
            result.push_back(entry);
        }
    }
    return result;
}

/// Filter entries to only include those added after the given timestamp.
///
/// @param entries  The entries to filter.
/// @param after    Only include entries with time > after.
/// @returns A new vector containing only qualifying entries.
inline std::vector<MempoolEntry> filter_by_time_after(
    const std::vector<MempoolEntry>& entries,
    int64_t after) {
    std::vector<MempoolEntry> result;
    result.reserve(entries.size());
    for (const auto& entry : entries) {
        if (entry.time > after) {
            result.push_back(entry);
        }
    }
    return result;
}

/// Filter entries to only include those with vsize <= max_vsize.
///
/// @param entries    The entries to filter.
/// @param max_vsize  Maximum virtual size in vbytes.
/// @returns A new vector containing only qualifying entries.
inline std::vector<MempoolEntry> filter_by_max_vsize(
    const std::vector<MempoolEntry>& entries,
    size_t max_vsize) {
    std::vector<MempoolEntry> result;
    result.reserve(entries.size());
    for (const auto& entry : entries) {
        if (entry.vsize <= max_vsize) {
            result.push_back(entry);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Aggregate statistics helpers
// ---------------------------------------------------------------------------

/// Compute the median fee rate of a set of entries.
/// Returns 0.0 if the set is empty.
///
/// @param entries  The entries to compute the median for.
/// @returns The median fee rate in sat/vB.
double compute_median_fee_rate(std::vector<MempoolEntry> entries);

/// Compute the average fee rate of a set of entries, weighted by vsize.
/// Returns 0.0 if total vsize is zero.
///
/// @param entries  The entries to compute the average for.
/// @returns The weighted average fee rate in sat/vB.
inline double compute_weighted_avg_fee_rate(
    const std::vector<MempoolEntry>& entries) {
    auto [fee, vsize] = compute_package_stats(entries);
    if (vsize == 0) return 0.0;
    return static_cast<double>(fee) / static_cast<double>(vsize);
}

/// Compute the total dynamic memory usage of a vector of entries.
///
/// @param entries  The entries to measure.
/// @returns Total dynamic memory usage in bytes.
inline size_t compute_total_memory_usage(
    const std::vector<MempoolEntry>& entries) {
    size_t total = 0;
    for (const auto& entry : entries) {
        total += entry.dynamic_memory_usage();
    }
    return total;
}

/// Compute the total weight of all entries.
///
/// @param entries  The entries to measure.
/// @returns Total weight in weight units.
inline size_t compute_total_weight(
    const std::vector<MempoolEntry>& entries) {
    size_t total = 0;
    for (const auto& entry : entries) {
        total += entry.weight();
    }
    return total;
}

/// Find the entry with the highest fee rate, or nullptr if empty.
///
/// @param entries  The entries to search.
/// @returns Pointer to the highest fee rate entry, or nullptr.
inline const MempoolEntry* find_highest_fee_rate(
    const std::vector<MempoolEntry>& entries) {
    if (entries.empty()) return nullptr;
    const MempoolEntry* best = &entries[0];
    for (size_t i = 1; i < entries.size(); ++i) {
        if (entries[i].fee_rate() > best->fee_rate()) {
            best = &entries[i];
        }
    }
    return best;
}

/// Find the entry with the lowest fee rate, or nullptr if empty.
///
/// @param entries  The entries to search.
/// @returns Pointer to the lowest fee rate entry, or nullptr.
inline const MempoolEntry* find_lowest_fee_rate(
    const std::vector<MempoolEntry>& entries) {
    if (entries.empty()) return nullptr;
    const MempoolEntry* worst = &entries[0];
    for (size_t i = 1; i < entries.size(); ++i) {
        if (entries[i].fee_rate() < worst->fee_rate()) {
            worst = &entries[i];
        }
    }
    return worst;
}

// ---------------------------------------------------------------------------
// Fee rate percentile computation
// ---------------------------------------------------------------------------

/// Compute the Nth percentile fee rate from a set of entries.
/// Entries are not modified (a copy is sorted internally).
///
/// @param entries     The entries to compute the percentile for.
/// @param percentile  The percentile (0-100). E.g., 50 for median.
/// @returns The fee rate in sat/vB at the given percentile.
double compute_fee_rate_percentile(
    std::vector<MempoolEntry> entries,
    int percentile);

} // namespace mempool
