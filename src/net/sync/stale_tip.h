#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Stale tip detection
// ---------------------------------------------------------------------------
// Monitors the blockchain tip and detects when it has become "stale" --
// meaning we haven't received a new block in longer than expected.  When
// the tip is stale, the sync manager should request headers from additional
// peers to ensure we haven't been isolated or eclipsed.
//
// The FTC block interval is 600 seconds (10 minutes).  A tip is considered
// stale if no new block has been received for STALE_TIP_THRESHOLD seconds
// (30 minutes, i.e., 3 block intervals).
//
// The detector uses two independent signals:
//   1. Wall-clock time since the last received block.
//   2. Age of the tip block's header timestamp relative to wall time.
// Both must exceed the threshold for the tip to be declared stale.  This
// prevents false positives during IBD (where the tip timestamp is old but
// blocks are flowing) and during reorgs (where a new block may carry an
// old timestamp).
//
// Thread safety: all public methods acquire the internal mutex and are safe
// to call from any thread.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <mutex>

namespace net::sync {

class StaleTipDetector {
public:
    /// Block interval in seconds (10 minutes).
    static constexpr int64_t BLOCK_INTERVAL = 600;

    /// A tip is considered stale if no block has been received for this
    /// many seconds (30 minutes = 3 block intervals).
    static constexpr int64_t STALE_TIP_THRESHOLD = 30 * 60;

    /// Minimum interval between stale tip checks in seconds.
    /// Prevents flooding the network with header requests.
    static constexpr int64_t CHECK_INTERVAL = 60;

    /// After this many consecutive stale checks, escalate logging to WARN
    /// level to alert the operator.
    static constexpr int WARN_AFTER_CHECKS = 5;

    /// Maximum number of extra peer requests per stale check cycle.
    /// Prevents requesting from too many peers at once.
    static constexpr int MAX_EXTRA_PEER_REQUESTS = 3;

    StaleTipDetector();

    /// Update the detector with the current chain state.
    /// Called periodically by the sync manager.
    /// @param now          Current time in seconds since epoch.
    /// @param chain_height Current best chain height.
    /// @param tip_time     Timestamp from the tip block's header.
    void update(int64_t now, int chain_height, int64_t tip_time);

    /// Returns true if the chain tip appears stale based on wall clock
    /// time since the last received block and the age of the tip block.
    /// @param now Current time in seconds since epoch.
    bool is_stale(int64_t now) const;

    /// Record that a new block has been received.  Resets the stale
    /// detection timer and consecutive check counter.
    /// @param now Current time in seconds since epoch.
    void new_block_received(int64_t now);

    /// Returns true if we should request headers from additional peers
    /// due to a potentially stale tip.  Rate-limited by CHECK_INTERVAL
    /// to avoid flooding the network with requests.
    /// @param now Current time in seconds since epoch.
    bool needs_more_peers(int64_t now) const;

    /// Returns how many seconds have elapsed since the last new block.
    /// @param now Current time in seconds since epoch.
    int64_t time_since_last_block(int64_t now) const;

    /// Returns the number of consecutive stale checks that have fired.
    /// Useful for escalating responses (e.g., trying more peers after
    /// prolonged staleness).
    int consecutive_stale_checks() const;

    /// Returns the number of expected blocks that should have been
    /// produced given the elapsed time since the last block.
    /// @param now Current time in seconds since epoch.
    int expected_missed_blocks(int64_t now) const;

    /// Reset all state.
    void reset();

private:
    int64_t last_check_time_         = 0;
    int64_t last_new_block_time_     = 0;
    int     chain_height_            = -1;
    int64_t tip_time_                = 0;
    int     consecutive_stale_count_ = 0;
    mutable std::mutex mutex_;
};

} // namespace net::sync
