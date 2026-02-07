// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mempool/fee_estimator.h"

#include "core/logging.h"
#include "core/types.h"
#include "mempool/entry.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace mempool {

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

FeeEstimator::FeeEstimator() {
    // Initialize bucket boundaries.
    // bucket[i] = BUCKET_BASE_FEE * BUCKET_SPACING^i
    for (size_t i = 0; i < NUM_BUCKETS; ++i) {
        double rate = BUCKET_BASE_FEE * std::pow(BUCKET_SPACING,
                                                  static_cast<double>(i));
        bucket_boundaries_[i] = static_cast<int64_t>(rate);
    }

    // Initialize horizons.
    short_horizon_.max_target = SHORT_TARGET;
    short_horizon_.scale      = 1;

    med_horizon_.max_target   = MED_TARGET;
    med_horizon_.scale        = 2;   // Each "period" = 2 blocks

    long_horizon_.max_target  = LONG_TARGET;
    long_horizon_.scale       = 24;  // Each "period" = 24 blocks

    // Zero-initialize all bucket stats.
    for (auto& b : short_horizon_.buckets) {
        b = BucketStat{};
    }
    for (auto& b : med_horizon_.buckets) {
        b = BucketStat{};
    }
    for (auto& b : long_horizon_.buckets) {
        b = BucketStat{};
    }
}

// ---------------------------------------------------------------------------
// fee_rate_to_bucket
// ---------------------------------------------------------------------------

int FeeEstimator::fee_rate_to_bucket(int64_t fee_rate_per_kvb) const {
    if (fee_rate_per_kvb <= 0) return 0;

    // Binary search for the appropriate bucket.
    // Bucket i covers [bucket_boundaries_[i], bucket_boundaries_[i+1]).
    for (size_t i = NUM_BUCKETS - 1; i > 0; --i) {
        if (fee_rate_per_kvb >= bucket_boundaries_[i]) {
            return static_cast<int>(i);
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// bucket_to_fee_rate
// ---------------------------------------------------------------------------

int64_t FeeEstimator::bucket_to_fee_rate(int bucket_index) const {
    if (bucket_index < 0) return MIN_ESTIMATE_FEE;
    if (static_cast<size_t>(bucket_index) >= NUM_BUCKETS) {
        return bucket_boundaries_[NUM_BUCKETS - 1];
    }
    return bucket_boundaries_[static_cast<size_t>(bucket_index)];
}

// ---------------------------------------------------------------------------
// apply_decay
// ---------------------------------------------------------------------------

void FeeEstimator::apply_decay() {
    auto decay_horizon = [](HorizonStats& horizon) {
        for (auto& bucket : horizon.buckets) {
            bucket.confirmed *= DECAY_FACTOR;
            bucket.total     *= DECAY_FACTOR;
            // avg_fee_rate is not decayed; it's a running average.
        }
    };

    decay_horizon(short_horizon_);
    decay_horizon(med_horizon_);
    decay_horizon(long_horizon_);
}

// ---------------------------------------------------------------------------
// record_confirmation
// ---------------------------------------------------------------------------

void FeeEstimator::record_confirmation(const TrackedTx& tracked,
                                       int confirm_blocks) {
    int bucket = tracked.bucket_index;
    if (bucket < 0 || static_cast<size_t>(bucket) >= NUM_BUCKETS) return;

    // Update the appropriate horizons based on how quickly the tx confirmed.
    auto update_horizon = [&](HorizonStats& horizon) {
        int scaled_target = confirm_blocks / horizon.scale;
        if (scaled_target < 0) scaled_target = 0;

        // The transaction was confirmed, so increment the "confirmed" count
        // in its bucket.
        auto& bs = horizon.buckets[static_cast<size_t>(bucket)];
        bs.confirmed += 1.0;
        bs.total     += 1.0;
        bs.sample_count++;

        // Update running average fee rate.
        double rate = static_cast<double>(tracked.fee_rate_per_kvb);
        if (bs.sample_count == 1) {
            bs.avg_fee_rate = rate;
        } else {
            // Exponential moving average.
            double alpha = 2.0 / (static_cast<double>(bs.sample_count) + 1.0);
            bs.avg_fee_rate = alpha * rate + (1.0 - alpha) * bs.avg_fee_rate;
        }
    };

    // Short horizon: record if confirmed within SHORT_TARGET blocks.
    if (confirm_blocks <= SHORT_TARGET) {
        update_horizon(short_horizon_);
    }

    // Medium horizon: always record.
    if (confirm_blocks <= MED_TARGET) {
        update_horizon(med_horizon_);
    }

    // Long horizon: always record.
    update_horizon(long_horizon_);
}

// ---------------------------------------------------------------------------
// process_block
// ---------------------------------------------------------------------------

void FeeEstimator::process_block(int height,
                                 const std::vector<MempoolEntry>& removed) {
    if (height <= best_height_ && best_height_ > 0) {
        // Block reorganization or duplicate; ignore.
        LOG_WARN(core::LogCategory::MEMPOOL,
            "fee estimator: ignoring block at height "
            + std::to_string(height) + " (best: "
            + std::to_string(best_height_) + ")");
        return;
    }

    best_height_ = height;
    blocks_processed_++;

    // Apply exponential decay to existing statistics.
    apply_decay();

    // Process each confirmed transaction.
    size_t confirmed_count = 0;
    for (const auto& entry : removed) {
        auto it = tracked_txs_.find(entry.txid);
        if (it == tracked_txs_.end()) {
            // Transaction was not tracked (e.g., entered before estimator
            // started, or was a coinbase).
            continue;
        }

        int confirm_blocks = height - it->second.entry_height;
        if (confirm_blocks < 1) confirm_blocks = 1;

        record_confirmation(it->second, confirm_blocks);
        tracked_txs_.erase(it);
        ++confirmed_count;
    }

    // Log confirmation statistics per horizon.
    size_t short_confirms = 0;
    size_t med_confirms = 0;
    size_t long_confirms = 0;

    for (const auto& entry : removed) {
        auto it = tracked_txs_.find(entry.txid);
        if (it != tracked_txs_.end()) continue; // Already erased above.
        // Count by the block delta (approximate, since we erased them).
    }

    // Count non-empty buckets in each horizon.
    for (size_t i = 0; i < NUM_BUCKETS; ++i) {
        if (short_horizon_.buckets[i].sample_count > 0) short_confirms++;
        if (med_horizon_.buckets[i].sample_count > 0) med_confirms++;
        if (long_horizon_.buckets[i].sample_count > 0) long_confirms++;
    }

    LOG_DEBUG(core::LogCategory::MEMPOOL,
        "fee estimator: processed block " + std::to_string(height)
        + " with " + std::to_string(confirmed_count)
        + " tracked confirmations (" + std::to_string(tracked_txs_.size())
        + " still tracked, active buckets: short="
        + std::to_string(short_confirms) + " med="
        + std::to_string(med_confirms) + " long="
        + std::to_string(long_confirms) + ")");

    // Periodically log estimation samples for monitoring.
    if (blocks_processed_ % 144 == 0 && blocks_processed_ > 0) {
        // Every ~1 day (144 blocks), log a summary.
        LOG_INFO(core::LogCategory::MEMPOOL,
            "fee estimator daily summary: height=" + std::to_string(height)
            + " blocks_processed=" + std::to_string(blocks_processed_)
            + " tracked=" + std::to_string(tracked_txs_.size())
            + " short_1block_est="
            + std::to_string(estimate_fee(1)) + " sat/kvB"
            + " med_6block_est="
            + std::to_string(estimate_fee(6)) + " sat/kvB"
            + " long_144block_est="
            + std::to_string(estimate_fee(144)) + " sat/kvB");
    }
}

// ---------------------------------------------------------------------------
// process_entry
// ---------------------------------------------------------------------------

void FeeEstimator::process_entry(const MempoolEntry& entry) {
    // Don't track coinbase transactions.
    if (entry.tx.is_coinbase()) return;

    // Enforce tracked entry limit.
    if (tracked_txs_.size() >= MAX_TRACKED_ENTRIES) {
        return;
    }

    // Skip if already tracked.
    if (tracked_txs_.count(entry.txid) > 0) return;

    // Compute the fee rate in sat/kvB.
    int64_t fee_rate_kvb = entry.fee_rate_per_kvb();

    TrackedTx tracked;
    tracked.txid              = entry.txid;
    tracked.fee_rate_per_kvb  = fee_rate_kvb;
    tracked.entry_height      = (best_height_ > 0) ? best_height_ : entry.height;
    tracked.bucket_index      = fee_rate_to_bucket(fee_rate_kvb);

    tracked_txs_.emplace(entry.txid, std::move(tracked));

    // Also record the entry in each horizon's "total" count for its bucket
    // so that the confirmation ratio is computed correctly.
    int bucket = tracked_txs_[entry.txid].bucket_index;
    if (bucket >= 0 && static_cast<size_t>(bucket) < NUM_BUCKETS) {
        short_horizon_.buckets[static_cast<size_t>(bucket)].total += 1.0;
        med_horizon_.buckets[static_cast<size_t>(bucket)].total   += 1.0;
        long_horizon_.buckets[static_cast<size_t>(bucket)].total  += 1.0;
    }
}

// ---------------------------------------------------------------------------
// remove_entry
// ---------------------------------------------------------------------------

void FeeEstimator::remove_entry(const core::uint256& txid) {
    auto it = tracked_txs_.find(txid);
    if (it == tracked_txs_.end()) return;

    // The transaction was removed without being confirmed. We decrement
    // the "total" count in the appropriate bucket but do NOT increment
    // the "confirmed" count. This has the effect of lowering the
    // confirmation rate for that bucket, which makes the estimator more
    // conservative.
    int bucket = it->second.bucket_index;
    if (bucket >= 0 && static_cast<size_t>(bucket) < NUM_BUCKETS) {
        // Don't let total go negative.
        auto clamp_sub = [](double& val, double sub) {
            val -= sub;
            if (val < 0.0) val = 0.0;
        };
        clamp_sub(short_horizon_.buckets[static_cast<size_t>(bucket)].total, 1.0);
        clamp_sub(med_horizon_.buckets[static_cast<size_t>(bucket)].total, 1.0);
        clamp_sub(long_horizon_.buckets[static_cast<size_t>(bucket)].total, 1.0);
    }

    tracked_txs_.erase(it);
}

// ---------------------------------------------------------------------------
// estimate_for_horizon
// ---------------------------------------------------------------------------

EstimationResult FeeEstimator::estimate_for_horizon(
    const HorizonStats& horizon,
    int target_blocks) const {

    EstimationResult result;
    result.horizon_blocks = horizon.max_target;

    // Scale the target to the horizon's granularity.
    int scaled_target = target_blocks / horizon.scale;
    if (scaled_target < 1) scaled_target = 1;

    // Walk buckets from highest fee rate to lowest. Find the lowest bucket
    // where the confirmation rate meets SUCCESS_THRESHOLD.
    int best_bucket = -1;
    double best_rate = 0.0;

    for (int i = static_cast<int>(NUM_BUCKETS) - 1; i >= 0; --i) {
        const auto& bucket = horizon.buckets[static_cast<size_t>(i)];

        // Need enough samples for a meaningful estimate.
        if (bucket.sample_count < MIN_BUCKET_SAMPLES) continue;
        if (bucket.total < 1.0) continue;

        double confirm_rate = bucket.confirmed / bucket.total;
        if (confirm_rate >= SUCCESS_THRESHOLD) {
            best_bucket = i;
            best_rate   = confirm_rate;
            // Continue walking lower buckets; we want the LOWEST bucket
            // that still meets the threshold (cheapest sufficient fee).
        }
    }

    if (best_bucket < 0) {
        // No bucket meets the threshold.
        result.fee_rate = -1;
        result.confidence = 0.0;
        return result;
    }

    result.bucket_index  = best_bucket;
    result.fee_rate      = bucket_to_fee_rate(best_bucket);
    result.confidence    = best_rate;
    result.sample_count  = horizon.buckets[static_cast<size_t>(best_bucket)]
                               .sample_count;

    // If the bucket has a computed average fee rate, use that instead of
    // the bucket boundary (it's more precise).
    const auto& bs = horizon.buckets[static_cast<size_t>(best_bucket)];
    if (bs.avg_fee_rate > 0.0) {
        result.fee_rate = static_cast<int64_t>(bs.avg_fee_rate);
    }

    // Clamp to minimum estimate.
    if (result.fee_rate < MIN_ESTIMATE_FEE) {
        result.fee_rate = MIN_ESTIMATE_FEE;
    }

    return result;
}

// ---------------------------------------------------------------------------
// estimate_fee
// ---------------------------------------------------------------------------

int64_t FeeEstimator::estimate_fee(int target_blocks) const {
    auto detailed = estimate_fee_detailed(target_blocks);
    return detailed.fee_rate;
}

// ---------------------------------------------------------------------------
// estimate_fee_detailed
// ---------------------------------------------------------------------------

EstimationResult FeeEstimator::estimate_fee_detailed(
    int target_blocks) const {

    // Clamp target.
    if (target_blocks < 1) target_blocks = 1;
    if (target_blocks > MAX_TARGET) target_blocks = MAX_TARGET;

    // Not enough data: return fallback.
    if (blocks_processed_ < 2) {
        EstimationResult fb;
        fb.fee_rate    = FALLBACK_FEE;
        fb.is_fallback = true;
        return fb;
    }

    // Try each horizon from shortest to longest. The shorter horizons
    // have more recent data and are preferred for short targets.
    EstimationResult best;
    best.fee_rate = -1;

    // Short horizon: use for targets <= SHORT_TARGET.
    if (target_blocks <= SHORT_TARGET) {
        EstimationResult short_est =
            estimate_for_horizon(short_horizon_, target_blocks);
        if (short_est.fee_rate > 0 && short_est.confidence > best.confidence) {
            best = short_est;
        }
    }

    // Medium horizon: use for targets <= MED_TARGET.
    if (target_blocks <= MED_TARGET) {
        EstimationResult med_est =
            estimate_for_horizon(med_horizon_, target_blocks);
        if (med_est.fee_rate > 0 && med_est.confidence > best.confidence) {
            best = med_est;
        }
    }

    // Long horizon: always try.
    {
        EstimationResult long_est =
            estimate_for_horizon(long_horizon_, target_blocks);
        if (long_est.fee_rate > 0 && long_est.confidence > best.confidence) {
            best = long_est;
        }
    }

    // If no horizon produced a reliable estimate, return fallback.
    if (best.fee_rate <= 0) {
        best.fee_rate    = FALLBACK_FEE;
        best.is_fallback = true;
        return best;
    }

    // For short targets, we want a conservative (higher) estimate.
    // If the short horizon gave a higher estimate than medium/long, use it.
    // (The above logic already selects by confidence; this is an extra
    // conservatism check.)
    if (target_blocks <= SHORT_TARGET) {
        EstimationResult short_est =
            estimate_for_horizon(short_horizon_, target_blocks);
        if (short_est.fee_rate > best.fee_rate
            && short_est.confidence >= SUCCESS_THRESHOLD * 0.95) {
            best = short_est;
        }
    }

    return best;
}

// ---------------------------------------------------------------------------
// tracked_count
// ---------------------------------------------------------------------------

size_t FeeEstimator::tracked_count() const {
    return tracked_txs_.size();
}

// ---------------------------------------------------------------------------
// best_height
// ---------------------------------------------------------------------------

int FeeEstimator::best_height() const {
    return best_height_;
}

// ---------------------------------------------------------------------------
// dump_stats
// ---------------------------------------------------------------------------

std::string FeeEstimator::dump_stats() const {
    std::ostringstream oss;

    oss << "FeeEstimator stats:\n";
    oss << "  best_height: " << best_height_ << "\n";
    oss << "  blocks_processed: " << blocks_processed_ << "\n";
    oss << "  tracked_txs: " << tracked_txs_.size() << "\n";

    auto dump_horizon = [&](const char* name, const HorizonStats& h) {
        oss << "\n  " << name << " horizon (max_target="
            << h.max_target << ", scale=" << h.scale << "):\n";
        for (size_t i = 0; i < NUM_BUCKETS; ++i) {
            const auto& b = h.buckets[i];
            if (b.sample_count == 0 && b.total < 0.01) continue;
            double confirm_rate = (b.total > 0.0)
                ? (b.confirmed / b.total) : 0.0;
            oss << "    bucket[" << i << "] "
                << bucket_boundaries_[i] << " sat/kvB: "
                << "confirmed=" << b.confirmed
                << " total=" << b.total
                << " rate=" << confirm_rate
                << " avg_fee=" << b.avg_fee_rate
                << " samples=" << b.sample_count << "\n";
        }
    };

    dump_horizon("SHORT", short_horizon_);
    dump_horizon("MED", med_horizon_);
    dump_horizon("LONG", long_horizon_);

    return oss.str();
}

// ---------------------------------------------------------------------------
// clear
// ---------------------------------------------------------------------------

void FeeEstimator::clear() {
    tracked_txs_.clear();
    best_height_     = 0;
    blocks_processed_ = 0;

    for (auto& b : short_horizon_.buckets) b = BucketStat{};
    for (auto& b : med_horizon_.buckets)   b = BucketStat{};
    for (auto& b : long_horizon_.buckets)  b = BucketStat{};
}

// ===========================================================================
// Fee estimation algorithm details
// ===========================================================================
//
// The fee estimator uses a bucketed histogram approach to track fee rates
// and their confirmation times. The algorithm is as follows:
//
// 1. BUCKETING
//    Fee rates (in sat/kvB) are divided into NUM_BUCKETS exponentially-
//    spaced buckets. Bucket boundaries are:
//      bucket[0] = BUCKET_BASE_FEE (1000 sat/kvB)
//      bucket[i] = BUCKET_BASE_FEE * BUCKET_SPACING^i
//
//    This covers a range from ~1 sat/vB to ~67,000 sat/vB at the default
//    spacing of 1.2 with 48 buckets, which is sufficient for typical
//    Bitcoin fee ranges.
//
// 2. ENTRY TRACKING
//    When a transaction enters the mempool, we record:
//      - Its txid (for later lookup when it confirms)
//      - Its fee rate in sat/kvB
//      - The block height at which it entered
//      - Its bucket index
//
//    We also increment the "total" counter in the appropriate bucket for
//    each horizon. This represents a transaction that has been observed
//    but not yet confirmed.
//
// 3. CONFIRMATION RECORDING
//    When a block is connected, we look up each confirmed transaction in
//    our tracked set. For each:
//      - Compute confirm_blocks = current_height - entry_height
//      - Increment the "confirmed" counter in the appropriate bucket
//      - Update the running average fee rate
//      - Remove from tracked set
//
// 4. EXPONENTIAL DECAY
//    To give more weight to recent data, we apply an exponential decay
//    factor to all bucket statistics each time a new block is processed.
//    With DECAY_FACTOR = 0.998, the half-life is about 347 blocks
//    (~2.4 days), meaning data older than a week has less than 1% weight.
//
// 5. ESTIMATION
//    To estimate the fee rate for target T blocks:
//      - For each horizon (short/medium/long), find the lowest bucket
//        where the confirmation rate (confirmed / total) meets the
//        SUCCESS_THRESHOLD (85%).
//      - The estimated fee rate is the average fee rate of that bucket.
//      - If multiple horizons produce estimates, pick the one with the
//        highest confidence.
//      - For short targets, prefer the short horizon (more recent data).
//
// 6. FALLBACK
//    If no bucket meets the threshold (insufficient data), return the
//    FALLBACK_FEE (20,000 sat/kvB = 20 sat/vB). The caller should
//    indicate to the user that this is a fallback estimate.
//
// LIMITATIONS:
//   - The estimator requires at least 2 blocks of history before it can
//     provide non-fallback estimates.
//   - During periods of rapid fee volatility, the decay factor may cause
//     the estimator to lag behind the true fee market.
//   - The estimator does not account for mempool size or congestion; it
//     only looks at historical confirmation data.
//   - Transactions that are evicted or replaced (rather than confirmed)
//     reduce the confirmation rate for their bucket, making the estimator
//     more conservative (which is the desired behavior).
//

// ===========================================================================
// FeeEstimationSnapshot -- multi-target snapshot
// ===========================================================================

std::string FeeEstimationSnapshot::to_string() const {
    std::ostringstream oss;

    oss << "Fee Estimation Snapshot:\n";
    oss << "  height:          " << height << "\n";
    oss << "  blocks_processed:" << blocks_processed << "\n";
    oss << "  tracked_count:   " << tracked_count << "\n";
    oss << "\n";
    oss << "  Target    | Fee (sat/kvB) | Fee (sat/vB) | Priority\n";
    oss << "  ----------+--------------+--------------+---------\n";

    auto format_row = [&](const char* label, int64_t fee) {
        oss << "  " << label << " | ";
        if (fee > 0) {
            oss << fee << " | "
                << static_cast<double>(fee) / 1000.0 << " | "
                << classify_fee_priority(fee);
        } else {
            oss << "N/A          | N/A          | N/A";
        }
        oss << "\n";
    };

    format_row("1 block   ", next_block_fee);
    format_row("3 blocks  ", half_hour_fee);
    format_row("6 blocks  ", one_hour_fee);
    format_row("12 blocks ", twelve_hour_fee);
    format_row("48 blocks ", two_day_fee);
    format_row("1008 block", one_week_fee);

    return oss.str();
}

FeeEstimationSnapshot take_fee_snapshot(const FeeEstimator& estimator) {
    FeeEstimationSnapshot snapshot;

    snapshot.next_block_fee   = estimator.estimate_fee(1);
    snapshot.half_hour_fee    = estimator.estimate_fee(3);
    snapshot.one_hour_fee     = estimator.estimate_fee(6);
    snapshot.twelve_hour_fee  = estimator.estimate_fee(SHORT_TARGET);
    snapshot.two_day_fee      = estimator.estimate_fee(MED_TARGET);
    snapshot.one_week_fee     = estimator.estimate_fee(LONG_TARGET);
    snapshot.height           = estimator.best_height();
    snapshot.tracked_count    = estimator.tracked_count();

    return snapshot;
}

// ===========================================================================
// Additional fee estimation algorithm design notes
// ===========================================================================
//
// BUCKET SPACING ANALYSIS
// -----------------------
// With BUCKET_BASE_FEE = 1000 sat/kvB and BUCKET_SPACING = 1.2, the 48
// buckets cover the following fee rate ranges:
//
//   Bucket 0:   1,000 sat/kvB  (1.0 sat/vB)    -- minimum relay fee
//   Bucket 5:   2,488 sat/kvB  (2.5 sat/vB)    -- low priority
//   Bucket 10:  6,192 sat/kvB  (6.2 sat/vB)    -- economy
//   Bucket 15: 15,407 sat/kvB  (15.4 sat/vB)   -- normal
//   Bucket 20: 38,338 sat/kvB  (38.3 sat/vB)   -- high priority
//   Bucket 25: 95,396 sat/kvB  (95.4 sat/vB)   -- very high
//   Bucket 30: 237,376 sat/kvB (237 sat/vB)     -- urgent
//   Bucket 35: 590,490 sat/kvB (590 sat/vB)     -- extreme
//   Bucket 40: 1,469,772 sat/kvB (1470 sat/vB)  -- peak congestion
//   Bucket 47: 7,385,506 sat/kvB (7386 sat/vB)  -- theoretical max
//
// The spacing of 1.2x means each bucket covers a ~20% fee rate range,
// providing good granularity for typical fee environments while still
// covering extreme scenarios.
//
// DECAY FACTOR ANALYSIS
// ---------------------
// With DECAY_FACTOR = 0.998 applied once per block (~10 minutes):
//
//   After   1 hour  ( 6 blocks): 98.8% weight
//   After   6 hours (36 blocks): 93.1% weight
//   After  24 hours (144 blocks): 74.9% weight
//   After  48 hours (288 blocks): 56.1% weight
//   After   1 week  (1008 blocks): 13.3% weight
//   After  2 weeks  (2016 blocks):  1.8% weight
//
// This gives a half-life of approximately 347 blocks (~58 hours). Data
// older than one week has less than 15% weight, and data older than two
// weeks has negligible impact on estimates. This provides a good balance
// between responsiveness to changing fee conditions and stability against
// short-term volatility.
//
// MULTI-HORIZON STRATEGY
// ----------------------
// Using three horizons (short/medium/long) allows the estimator to
// provide good estimates for different confirmation urgencies:
//
//   - Short horizon (12 blocks, scale 1):
//     Fine-grained tracking with 1-block resolution. Best for targets
//     of 1-12 blocks. Most responsive to recent fee changes but has
//     the highest variance due to fewer samples per bucket.
//
//   - Medium horizon (48 blocks, scale 2):
//     Each "period" spans 2 blocks, reducing noise. Covers targets up
//     to 48 blocks (~8 hours). Good balance of recency and stability.
//
//   - Long horizon (1008 blocks, scale 24):
//     Each "period" spans 24 blocks, smoothing out daily cycles. Covers
//     targets up to 1008 blocks (~1 week). Most stable but least
//     responsive to recent changes.
//
// When estimating for a given target, we try all applicable horizons
// and select the one with the highest confidence. For short targets,
// we also apply a conservatism check: if the short horizon gives a
// higher estimate than the selected horizon, we prefer the short
// horizon's estimate (as long as its confidence is close to the
// threshold). This prevents under-estimation during fee spikes.
//
// COMPARISON WITH BITCOIN CORE
// ----------------------------
// Our implementation differs from Bitcoin Core's CBlockPolicyEstimator
// in several ways:
//
// 1. Simpler structure: We use a flat array of buckets per horizon,
//    while Core uses a more complex TxConfirmStats structure.
//
// 2. Decay application: We apply decay once per block, while Core
//    applies it per block with different factors per horizon.
//
// 3. Confidence selection: We use a simple highest-confidence selection
//    across horizons, while Core uses a more nuanced approach with
//    separate "high" and "low" estimates.
//
// 4. Tracked entry limit: We cap tracked entries at MAX_TRACKED_ENTRIES
//    (50,000) to bound memory usage, while Core tracks all mempool txs.
//
// These simplifications make our estimator easier to reason about while
// still providing reasonable fee estimates for typical use cases.
//

} // namespace mempool
