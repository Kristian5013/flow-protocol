#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// FeeEstimator -- estimates fee rates for target confirmation times
// ---------------------------------------------------------------------------
// Tracks the fee rates of transactions entering the mempool and being
// confirmed in blocks. Maintains bucketed histograms over multiple time
// horizons (short, medium, long) to provide fee rate estimates for a
// given target number of confirmation blocks.
//
// The algorithm is loosely based on Bitcoin Core's CBlockPolicyEstimator:
//   - Fee rates are bucketed into exponentially-spaced buckets.
//   - For each bucket, we track the number of transactions that were
//     confirmed within N blocks and the total fee rate they paid.
//   - To estimate a fee for target T blocks, we find the lowest bucket
//     where a sufficient fraction (SUCCESS_THRESHOLD) of tracked
//     transactions were confirmed within T blocks.
//
// Thread safety: the FeeEstimator does NOT hold its own lock. The caller
// (Mempool) is expected to hold the mempool mutex when calling into this
// class. This avoids unnecessary double-locking.
// ---------------------------------------------------------------------------

#include "core/types.h"
#include "mempool/entry.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace mempool {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum confirmation target in blocks (~1 week at 10-minute blocks).
static constexpr int MAX_TARGET = 1008;

/// Short-horizon target: ~2 hours (12 blocks).
static constexpr int SHORT_TARGET = 12;

/// Medium-horizon target: ~8 hours (48 blocks).
static constexpr int MED_TARGET = 48;

/// Long-horizon target: ~1 week (1008 blocks).
static constexpr int LONG_TARGET = 1008;

/// Number of fee rate buckets. Buckets are exponentially spaced.
static constexpr size_t NUM_BUCKETS = 48;

/// Base fee rate for the lowest bucket (in sat/kvB).
static constexpr double BUCKET_BASE_FEE = 1000.0;

/// Spacing factor between adjacent buckets.
/// bucket[i] = BUCKET_BASE_FEE * BUCKET_SPACING^i
static constexpr double BUCKET_SPACING = 1.2;

/// Minimum fraction of tracked transactions that must have been confirmed
/// within the target to consider a bucket's estimate reliable.
static constexpr double SUCCESS_THRESHOLD = 0.85;

/// Minimum number of tracked transactions in a bucket to consider
/// its estimate reliable.
static constexpr size_t MIN_BUCKET_SAMPLES = 2;

/// Fallback fee rate when no reliable estimate is available (sat/kvB).
/// This is returned as a "safe" default when there is insufficient data.
static constexpr int64_t FALLBACK_FEE = 20000;

/// Minimum estimable fee rate (sat/kvB). Estimates below this floor are
/// clamped upward.
static constexpr int64_t MIN_ESTIMATE_FEE = 1000;

/// Maximum number of unconfirmed entries to track for estimation.
static constexpr size_t MAX_TRACKED_ENTRIES = 50000;

/// Decay factor for exponential moving average (applied per block).
/// A value of 0.998 means ~0.2% decay per block (~13.5% per day).
static constexpr double DECAY_FACTOR = 0.998;

// ---------------------------------------------------------------------------
// EstimationResult -- detailed estimation output
// ---------------------------------------------------------------------------

struct EstimationResult {
    /// Estimated fee rate in sat/kvB. -1 means "no estimate available".
    int64_t fee_rate = -1;

    /// Confidence level (0.0 - 1.0). Higher is better.
    double confidence = 0.0;

    /// The bucket index from which the estimate was derived.
    int bucket_index = -1;

    /// Which horizon (short/med/long) provided the best estimate.
    int horizon_blocks = 0;

    /// The actual number of tracked transactions used.
    size_t sample_count = 0;

    /// True if the estimate used the fallback rate.
    bool is_fallback = false;
};

// ---------------------------------------------------------------------------
// FeeEstimator
// ---------------------------------------------------------------------------

class FeeEstimator {
public:
    FeeEstimator();

    // -- Block processing ---------------------------------------------------

    /// Called when a new block is connected. Records which tracked
    /// transactions were confirmed and at what height.
    ///
    /// @param height   The height of the new block.
    /// @param removed  The MempoolEntries that were removed from the mempool
    ///                 because they were included in this block.
    void process_block(int height,
                       const std::vector<MempoolEntry>& removed);

    // -- Entry tracking -----------------------------------------------------

    /// Called when a new transaction enters the mempool.
    /// Records its fee rate and entry height for later tracking.
    ///
    /// @param entry  The new mempool entry.
    void process_entry(const MempoolEntry& entry);

    /// Called when a transaction is removed from the mempool without being
    /// confirmed (e.g., eviction, expiry, RBF replacement).
    ///
    /// @param txid  The txid of the removed transaction.
    void remove_entry(const core::uint256& txid);

    // -- Estimation ---------------------------------------------------------

    /// Estimate the fee rate (in sat/kvB) needed for confirmation within
    /// target_blocks blocks.
    ///
    /// @param target_blocks  Desired number of blocks to confirmation.
    ///                       Clamped to [1, MAX_TARGET].
    /// @returns Estimated fee rate in sat/kvB, or -1 if no reliable estimate
    ///          is available (caller should use FALLBACK_FEE).
    [[nodiscard]] int64_t estimate_fee(int target_blocks) const;

    /// Detailed estimation with confidence information.
    [[nodiscard]] EstimationResult estimate_fee_detailed(
        int target_blocks) const;

    // -- Statistics ---------------------------------------------------------

    /// Return the current number of tracked unconfirmed transactions.
    [[nodiscard]] size_t tracked_count() const;

    /// Return the highest block height that has been processed.
    [[nodiscard]] int best_height() const;

    /// Return a human-readable summary of the estimator state.
    [[nodiscard]] std::string dump_stats() const;

    /// Clear all estimation data and reset to initial state.
    void clear();

private:
    // -- Internal types -----------------------------------------------------

    /// Tracked entry: records when a transaction entered the mempool and
    /// at what fee rate, so we can determine how long it took to confirm.
    struct TrackedTx {
        core::uint256 txid;
        int64_t fee_rate_per_kvb = 0;  // sat/kvB
        int entry_height = 0;
        int bucket_index = 0;
    };

    /// Per-bucket statistics for a single horizon.
    struct BucketStat {
        /// Number of transactions that were confirmed within the target.
        double confirmed = 0.0;

        /// Total number of transactions tracked in this bucket.
        double total = 0.0;

        /// Running average of fee rates of confirmed transactions.
        double avg_fee_rate = 0.0;

        /// Number of distinct samples (for MIN_BUCKET_SAMPLES check).
        size_t sample_count = 0;
    };

    /// Statistics for a single time horizon (short/medium/long).
    struct HorizonStats {
        /// Maximum target blocks for this horizon.
        int max_target = 0;

        /// Per-bucket statistics. Indexed by bucket index.
        std::array<BucketStat, NUM_BUCKETS> buckets{};

        /// Scale factor: how many blocks of history this horizon covers.
        int scale = 1;
    };

    // -- Internal helpers ---------------------------------------------------

    /// Map a fee rate (sat/kvB) to a bucket index.
    [[nodiscard]] int fee_rate_to_bucket(int64_t fee_rate_per_kvb) const;

    /// Get the representative fee rate for a bucket index (sat/kvB).
    [[nodiscard]] int64_t bucket_to_fee_rate(int bucket_index) const;

    /// Apply exponential decay to all bucket statistics.
    void apply_decay();

    /// Record a confirmed transaction in the appropriate buckets.
    void record_confirmation(const TrackedTx& tracked, int confirm_blocks);

    /// Estimate fee for a single horizon.
    [[nodiscard]] EstimationResult estimate_for_horizon(
        const HorizonStats& horizon,
        int target_blocks) const;

    // -- Data ---------------------------------------------------------------

    /// Precomputed bucket fee rate boundaries (sat/kvB).
    std::array<int64_t, NUM_BUCKETS> bucket_boundaries_{};

    /// Short-horizon statistics (~2 hours).
    HorizonStats short_horizon_;

    /// Medium-horizon statistics (~8 hours).
    HorizonStats med_horizon_;

    /// Long-horizon statistics (~1 week).
    HorizonStats long_horizon_;

    /// Map of tracked unconfirmed transactions: txid -> TrackedTx.
    struct Uint256Hash {
        std::size_t operator()(const core::uint256& v) const noexcept {
            return std::hash<core::uint256>{}(v);
        }
    };
    std::unordered_map<core::uint256, TrackedTx, Uint256Hash> tracked_txs_;

    /// Best (highest) block height processed so far.
    int best_height_ = 0;

    /// Total number of blocks processed.
    int blocks_processed_ = 0;
};

// ---------------------------------------------------------------------------
// Convenience functions for common fee estimation targets
// ---------------------------------------------------------------------------

/// Estimate the fee rate for the next block (1-block target).
/// Returns sat/kvB, or -1 if no reliable estimate.
[[nodiscard]] inline int64_t estimate_next_block_fee(
    const FeeEstimator& estimator) {
    return estimator.estimate_fee(1);
}

/// Estimate the fee rate for a ~30-minute confirmation (3 blocks).
[[nodiscard]] inline int64_t estimate_30min_fee(
    const FeeEstimator& estimator) {
    return estimator.estimate_fee(3);
}

/// Estimate the fee rate for a ~1-hour confirmation (6 blocks).
[[nodiscard]] inline int64_t estimate_1hour_fee(
    const FeeEstimator& estimator) {
    return estimator.estimate_fee(6);
}

/// Estimate the fee rate for a ~12-hour confirmation.
[[nodiscard]] inline int64_t estimate_12hour_fee(
    const FeeEstimator& estimator) {
    return estimator.estimate_fee(SHORT_TARGET);
}

/// Estimate the fee rate for a ~48-hour confirmation.
[[nodiscard]] inline int64_t estimate_2day_fee(
    const FeeEstimator& estimator) {
    return estimator.estimate_fee(MED_TARGET);
}

/// Estimate the fee rate for a ~1-week confirmation.
[[nodiscard]] inline int64_t estimate_1week_fee(
    const FeeEstimator& estimator) {
    return estimator.estimate_fee(LONG_TARGET);
}

/// Classify a fee rate into a human-readable priority category.
///
/// @param fee_rate_kvb  Fee rate in sat/kvB.
/// @returns A string like "high", "medium", "low", or "minimum".
[[nodiscard]] inline const char* classify_fee_priority(
    int64_t fee_rate_kvb) {
    if (fee_rate_kvb >= 50000) return "high";
    if (fee_rate_kvb >= 10000) return "medium";
    if (fee_rate_kvb >= 5000)  return "low";
    if (fee_rate_kvb >= 1000)  return "minimum";
    return "below-minimum";
}

// ---------------------------------------------------------------------------
// Fee estimation summary -- convenient aggregated snapshot
// ---------------------------------------------------------------------------

/// A snapshot of fee estimation results for multiple confirmation targets.
/// Used by RPC and wallet code to present fee options to users.
struct FeeEstimationSnapshot {
    /// Estimated fee for next-block confirmation (1 block, highest priority).
    int64_t next_block_fee = -1;

    /// Estimated fee for ~30 minute confirmation (3 blocks).
    int64_t half_hour_fee = -1;

    /// Estimated fee for ~1 hour confirmation (6 blocks).
    int64_t one_hour_fee = -1;

    /// Estimated fee for ~12 hour confirmation (SHORT_TARGET blocks).
    int64_t twelve_hour_fee = -1;

    /// Estimated fee for ~2 day confirmation (MED_TARGET blocks).
    int64_t two_day_fee = -1;

    /// Estimated fee for ~1 week confirmation (LONG_TARGET blocks).
    int64_t one_week_fee = -1;

    /// The current best block height when the snapshot was taken.
    int height = 0;

    /// The number of tracked unconfirmed transactions.
    size_t tracked_count = 0;

    /// The total number of blocks processed.
    int blocks_processed = 0;

    /// Returns a human-readable multi-line summary.
    [[nodiscard]] std::string to_string() const;
};

/// Take a snapshot of fee estimation results for common confirmation targets.
/// This is a convenient function that calls estimate_fee() for each target.
///
/// @param estimator  The fee estimator to query.
/// @returns A snapshot of fee estimates.
[[nodiscard]] FeeEstimationSnapshot
take_fee_snapshot(const FeeEstimator& estimator);

// ---------------------------------------------------------------------------
// Fee rate conversion utilities
// ---------------------------------------------------------------------------

/// Convert a fee rate from sat/kvB to sat/vB (divide by 1000).
///
/// @param fee_rate_kvb  Fee rate in sat/kvB.
/// @returns Fee rate in sat/vB (as double for precision).
[[nodiscard]] inline double kvb_to_vb(int64_t fee_rate_kvb) {
    return static_cast<double>(fee_rate_kvb) / 1000.0;
}

/// Convert a fee rate from sat/vB to sat/kvB (multiply by 1000).
///
/// @param fee_rate_vb  Fee rate in sat/vB.
/// @returns Fee rate in sat/kvB.
[[nodiscard]] inline int64_t vb_to_kvb(double fee_rate_vb) {
    return static_cast<int64_t>(fee_rate_vb * 1000.0 + 0.5);
}

/// Compute the fee in satoshis for a transaction of the given vsize
/// at the given fee rate.
///
/// @param vsize          Transaction virtual size in vbytes.
/// @param fee_rate_kvb   Fee rate in sat/kvB.
/// @returns The fee in satoshis, rounded up.
[[nodiscard]] inline int64_t compute_fee_for_vsize(
    size_t vsize, int64_t fee_rate_kvb) {
    return (static_cast<int64_t>(vsize) * fee_rate_kvb + 999) / 1000;
}

/// Return the recommended fee rate for "economy" priority.
/// Economy priority uses a longer confirmation target (MED_TARGET),
/// resulting in a lower fee rate suitable for non-urgent transactions.
///
/// @param estimator  The fee estimator.
/// @returns Fee rate in sat/kvB, or FALLBACK_FEE if unavailable.
[[nodiscard]] inline int64_t estimate_economy_fee(
    const FeeEstimator& estimator) {
    int64_t fee = estimator.estimate_fee(MED_TARGET);
    return (fee > 0) ? fee : FALLBACK_FEE;
}

/// Return the recommended fee rate for "conservative" priority.
/// Conservative priority uses the short horizon estimate and takes the
/// maximum of the short and medium estimates for safety.
///
/// @param estimator  The fee estimator.
/// @returns Fee rate in sat/kvB.
[[nodiscard]] inline int64_t estimate_conservative_fee(
    const FeeEstimator& estimator) {
    int64_t short_est = estimator.estimate_fee(SHORT_TARGET);
    int64_t next_est  = estimator.estimate_fee(1);
    if (short_est <= 0 && next_est <= 0) return FALLBACK_FEE;
    return std::max(short_est, next_est);
}

} // namespace mempool
