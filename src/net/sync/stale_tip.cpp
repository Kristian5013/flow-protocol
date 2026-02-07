// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/sync/stale_tip.h"

#include "core/logging.h"

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <string>

namespace net::sync {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

StaleTipDetector::StaleTipDetector() = default;

// ---------------------------------------------------------------------------
// update
// ---------------------------------------------------------------------------
// Called periodically to inform the detector of the current chain state.
// This does NOT count as receiving a new block -- it merely records the
// tip metadata so that is_stale() can make its determination.
//
// The detector tracks two separate time signals:
//   1. last_new_block_time_: wall-clock time when we last received and
//      validated a new block (set by new_block_received()).
//   2. tip_time_: the timestamp encoded in the current tip block's header.
//
// Both are used by is_stale() to determine if the chain is progressing.
//
// If the chain height has increased since the last call, we treat this as
// an implicit new_block_received().  This handles blocks received through
// compact block relay, out-of-band mechanisms, or when the sync manager
// forgot to call new_block_received() explicitly.
// ---------------------------------------------------------------------------
void StaleTipDetector::update(int64_t now,
                               int chain_height,
                               int64_t tip_time) {
    std::unique_lock<std::mutex> lock(mutex_);

    // Detect if the chain has advanced since the last update.
    bool chain_advanced = (chain_height > chain_height_);

    int previous_height = chain_height_;
    chain_height_ = chain_height;
    tip_time_     = tip_time;

    // If this is the first update ever, initialize the last_new_block_time_
    // so that we don't immediately report a stale tip on startup.
    if (last_new_block_time_ == 0) {
        last_new_block_time_ = now;
        LOG_DEBUG(core::LogCategory::NET,
            "StaleTipDetector initialized: height "
            + std::to_string(chain_height)
            + ", tip time " + std::to_string(tip_time));
    }

    // If the chain advanced (height increased), treat it as a new block
    // even if new_block_received() wasn't called explicitly.
    if (chain_advanced) {
        last_new_block_time_ = now;
        consecutive_stale_count_ = 0;

        int blocks_advanced = chain_height - previous_height;
        if (blocks_advanced > 1) {
            // Multiple blocks advanced at once -- this can happen during
            // IBD or when processing a batch of blocks.
            LOG_DEBUG(core::LogCategory::NET,
                "Chain advanced " + std::to_string(blocks_advanced)
                + " blocks to height " + std::to_string(chain_height)
                + " (tip time: " + std::to_string(tip_time) + ")");
        } else {
            LOG_DEBUG(core::LogCategory::NET,
                "Chain advanced to height " + std::to_string(chain_height)
                + " (tip time: " + std::to_string(tip_time) + ")");
        }
    }
}

// ---------------------------------------------------------------------------
// is_stale
// ---------------------------------------------------------------------------
// Determines whether the tip is stale by checking two conditions:
//
//   Condition 1 (wall-clock staleness):
//     The time since we last received ANY new block exceeds
//     STALE_TIP_THRESHOLD.  This catches scenarios where the network
//     is producing blocks but we are not receiving them (eclipse attack,
//     network partition, etc.).
//
//   Condition 2 (tip age staleness):
//     The tip block's header timestamp is more than STALE_TIP_THRESHOLD
//     seconds behind the current wall-clock time.  This catches scenarios
//     where we are receiving blocks but the chain itself is not making
//     progress (we are on a dead fork, or the network is stalled).
//
// Both conditions must be satisfied for the tip to be declared stale.
// This avoids false positives:
//
//   - During IBD: the node is constantly receiving blocks (condition 1
//     fails) even though the tip timestamp is very old (condition 2 fires).
//     Result: NOT stale.
//
//   - After a reorg: a recently received block may carry a somewhat old
//     timestamp.  Condition 1 fails because we just received a block.
//     Result: NOT stale.
//
//   - After a brief network hiccup: the tip timestamp is recent (condition
//     2 fails) but we haven't received blocks for a while (condition 1
//     fires).  Result: NOT stale.
//
//   - True staleness (eclipse/partition): we haven't received blocks for
//     >30 minutes (condition 1 fires) AND the tip is >30 minutes old
//     (condition 2 fires).  Result: STALE.
// ---------------------------------------------------------------------------
bool StaleTipDetector::is_stale(int64_t now) const {
    std::unique_lock<std::mutex> lock(mutex_);

    // Not enough state to determine staleness.
    if (chain_height_ < 0 || last_new_block_time_ == 0) {
        return false;
    }

    // Condition 1: wall-clock time since last block received.
    int64_t since_last_block = now - last_new_block_time_;
    bool wall_clock_stale = (since_last_block > STALE_TIP_THRESHOLD);

    // Condition 2: tip block timestamp age.
    int64_t tip_age = now - tip_time_;
    bool tip_age_stale = (tip_age > STALE_TIP_THRESHOLD);

    return wall_clock_stale && tip_age_stale;
}

// ---------------------------------------------------------------------------
// new_block_received
// ---------------------------------------------------------------------------
// Called whenever a new block is successfully received and validated.
// Resets the wall-clock staleness timer and the consecutive stale check
// counter.  This is the primary signal that the chain is making progress.
//
// The sync manager should call this after each new block is validated,
// regardless of whether the block advanced the tip (it may have been on
// a side chain).  Receiving any valid block means we have network
// connectivity and peers are responding.
// ---------------------------------------------------------------------------
void StaleTipDetector::new_block_received(int64_t now) {
    std::unique_lock<std::mutex> lock(mutex_);

    int64_t elapsed = 0;
    if (last_new_block_time_ > 0) {
        elapsed = now - last_new_block_time_;
    }

    last_new_block_time_ = now;

    // Reset the consecutive stale check counter.
    if (consecutive_stale_count_ > 0) {
        LOG_INFO(core::LogCategory::NET,
            "New block received after " + std::to_string(elapsed)
            + "s -- stale tip condition resolved"
            + " (was stale for " + std::to_string(consecutive_stale_count_)
            + " check cycles)");
        consecutive_stale_count_ = 0;
    } else {
        LOG_DEBUG(core::LogCategory::NET,
            "New block received at time " + std::to_string(now)
            + " (chain height: " + std::to_string(chain_height_)
            + ", interval: " + std::to_string(elapsed) + "s)");
    }
}

// ---------------------------------------------------------------------------
// needs_more_peers
// ---------------------------------------------------------------------------
// Returns true if we should actively seek headers from additional peers
// to combat a potentially stale tip.  This is rate-limited by
// CHECK_INTERVAL to avoid excessive network chatter.
//
// The logic:
//   1. Check if the tip is stale (using is_stale logic inline to avoid
//      recursive locking).
//   2. If stale, check whether enough time has passed since the last
//      check to avoid flooding peers with requests.
//   3. If both conditions are met, increment the consecutive stale counter,
//      update last_check_time_, and return true.
//
// The consecutive_stale_count_ is incremented each time this returns true.
// The caller can use consecutive_stale_checks() to decide how aggressively
// to search for new peers:
//   - 1-5 checks: request headers from 1 additional peer.
//   - 5-10 checks: request from 2 additional peers + try new connections.
//   - 10+ checks: request from all peers + try DNS seeds.
//
// Note: This method updates mutable state through const_cast because
// the check interval tracking and consecutive counter are logically
// mutable (they do not affect the observable staleness state, only the
// rate and escalation of the response).
// ---------------------------------------------------------------------------
bool StaleTipDetector::needs_more_peers(int64_t now) const {
    std::unique_lock<std::mutex> lock(mutex_);

    // Not enough state.
    if (chain_height_ < 0 || last_new_block_time_ == 0) {
        return false;
    }

    // Check staleness conditions (inline to avoid recursive lock).
    int64_t since_last_block = now - last_new_block_time_;
    bool wall_clock_stale = (since_last_block > STALE_TIP_THRESHOLD);

    int64_t tip_age = now - tip_time_;
    bool tip_age_stale = (tip_age > STALE_TIP_THRESHOLD);

    if (!wall_clock_stale || !tip_age_stale) {
        return false;
    }

    // Rate-limit: don't request from more peers more often than
    // CHECK_INTERVAL seconds.
    if (last_check_time_ > 0 && (now - last_check_time_) < CHECK_INTERVAL) {
        return false;
    }

    // Update mutable state.
    auto* self = const_cast<StaleTipDetector*>(this);
    self->last_check_time_ = now;
    self->consecutive_stale_count_ += 1;

    // Calculate the number of expected missed blocks for the log message.
    int missed = static_cast<int>(since_last_block / BLOCK_INTERVAL);

    // Escalate log level after repeated stale checks.
    if (self->consecutive_stale_count_ >= WARN_AFTER_CHECKS) {
        LOG_WARN(core::LogCategory::NET,
            "Stale tip persists: requesting headers from additional peers"
            " (last block " + std::to_string(since_last_block)
            + "s ago, tip age " + std::to_string(tip_age)
            + "s, ~" + std::to_string(missed) + " blocks missed"
            + ", height " + std::to_string(chain_height_)
            + ", stale check #" + std::to_string(self->consecutive_stale_count_)
            + ")");
    } else {
        LOG_INFO(core::LogCategory::NET,
            "Stale tip detected: requesting headers from additional peers"
            " (last block " + std::to_string(since_last_block)
            + "s ago, tip age " + std::to_string(tip_age)
            + "s, ~" + std::to_string(missed) + " blocks missed"
            + ", height " + std::to_string(chain_height_)
            + ", stale check #" + std::to_string(self->consecutive_stale_count_)
            + ")");
    }

    return true;
}

// ---------------------------------------------------------------------------
// time_since_last_block
// ---------------------------------------------------------------------------
// Returns the number of seconds elapsed since we last received a new block.
// Returns 0 if no blocks have been received yet (i.e., the detector has
// not been initialized).
//
// This value can be displayed in RPC/debug output to help operators
// diagnose connectivity issues.
// ---------------------------------------------------------------------------
int64_t StaleTipDetector::time_since_last_block(int64_t now) const {
    std::unique_lock<std::mutex> lock(mutex_);

    if (last_new_block_time_ == 0) {
        return 0;
    }

    int64_t elapsed = now - last_new_block_time_;
    return std::max(int64_t{0}, elapsed);
}

// ---------------------------------------------------------------------------
// consecutive_stale_checks
// ---------------------------------------------------------------------------
// Returns the number of times needs_more_peers() has returned true
// consecutively without a new block being received.  Resets to zero
// when new_block_received() is called.
//
// The caller can use this to escalate their response:
//   - Low count: ask a few extra peers for headers.
//   - High count: try connecting to new peers, consult DNS seeds,
//     or alert the operator.
// ---------------------------------------------------------------------------
int StaleTipDetector::consecutive_stale_checks() const {
    std::unique_lock<std::mutex> lock(mutex_);
    return consecutive_stale_count_;
}

// ---------------------------------------------------------------------------
// expected_missed_blocks
// ---------------------------------------------------------------------------
// Estimates how many blocks the network should have produced in the time
// since our last received block.  This is a rough estimate based on the
// BLOCK_INTERVAL constant (600 seconds = 10 minutes).
//
// In practice, block production follows a Poisson process, so the actual
// number of blocks may vary significantly.  However, if the expected count
// is high (e.g., >10), it is very likely we are missing blocks rather than
// experiencing normal variance.
//
// Returns 0 if no blocks have been received yet.
// ---------------------------------------------------------------------------
int StaleTipDetector::expected_missed_blocks(int64_t now) const {
    std::unique_lock<std::mutex> lock(mutex_);

    if (last_new_block_time_ == 0 || BLOCK_INTERVAL <= 0) {
        return 0;
    }

    int64_t elapsed = now - last_new_block_time_;
    if (elapsed <= 0) {
        return 0;
    }

    return static_cast<int>(elapsed / BLOCK_INTERVAL);
}

// ---------------------------------------------------------------------------
// reset
// ---------------------------------------------------------------------------
// Clears all internal state.  After a reset, the detector behaves as if
// freshly constructed: is_stale() returns false, needs_more_peers() returns
// false, and time_since_last_block() returns 0.
//
// This is used when the sync manager wants to restart from scratch, for
// example after a configuration change or when the network interface
// is recycled.
// ---------------------------------------------------------------------------
void StaleTipDetector::reset() {
    std::unique_lock<std::mutex> lock(mutex_);

    if (chain_height_ >= 0) {
        LOG_INFO(core::LogCategory::NET,
            "StaleTipDetector reset (was at height "
            + std::to_string(chain_height_)
            + ", stale count: " + std::to_string(consecutive_stale_count_)
            + ")");
    }

    last_check_time_         = 0;
    last_new_block_time_     = 0;
    chain_height_            = -1;
    tip_time_                = 0;
    consecutive_stale_count_ = 0;
}

} // namespace net::sync
