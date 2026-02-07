#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Time-related consensus rules
// ---------------------------------------------------------------------------
// Provides the median-time-past (MTP) computation and block-time validity
// checks required by consensus.  A block's timestamp must be strictly
// greater than the median of the previous 11 blocks' timestamps and must
// not exceed the network-adjusted time by more than 2 hours.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <vector>

namespace consensus {

/// Number of previous block timestamps used to compute the median time past.
constexpr int MEDIAN_TIME_SPAN = 11;

/// Maximum amount of time (in seconds) a block timestamp may be ahead of
/// the node's network-adjusted clock.  Set to 2 hours (7,200 seconds).
constexpr int64_t MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60;

/// Computes the median time past (MTP) from the most recent block
/// timestamps.
///
/// @param timestamps  Up to MEDIAN_TIME_SPAN timestamps, ordered from
///                    most recent to oldest.  If fewer than
///                    MEDIAN_TIME_SPAN entries are provided (e.g. near
///                    the chain tip of a young chain), the median is
///                    computed over whatever is available.  An empty
///                    vector returns 0.
/// @returns           The median timestamp value.
[[nodiscard]] int64_t get_median_time_past(
    const std::vector<int64_t>& timestamps);

/// Checks whether a candidate block timestamp satisfies the two
/// consensus time rules:
///
///   1. block_time > median_time_past  (BIP113 -- strictly greater)
///   2. block_time <= adjusted_time + MAX_FUTURE_BLOCK_TIME
///
/// @param block_time        The timestamp in the candidate block header.
/// @param median_time_past  MTP of the 11 blocks preceding this one.
/// @param adjusted_time     The node's network-adjusted current time.
/// @returns                 true if both rules are satisfied.
[[nodiscard]] bool check_block_time(int64_t block_time,
                                    int64_t median_time_past,
                                    int64_t adjusted_time);

} // namespace consensus
