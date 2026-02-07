// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/time.h"

#include <algorithm>
#include <vector>

namespace consensus {

int64_t get_median_time_past(const std::vector<int64_t>& timestamps) {
    if (timestamps.empty()) {
        return 0;
    }

    // We only consider up to MEDIAN_TIME_SPAN entries.  The caller
    // typically provides the last 11 block timestamps (most-recent first),
    // but we handle any ordering by sorting a local copy.
    const size_t count = std::min(
        timestamps.size(),
        static_cast<size_t>(MEDIAN_TIME_SPAN));

    // Copy the relevant portion and sort ascending.
    std::vector<int64_t> sorted(timestamps.begin(),
                                timestamps.begin()
                                    + static_cast<std::ptrdiff_t>(count));
    std::sort(sorted.begin(), sorted.end());

    // Return the middle element.  For an even count the lower-median is
    // used (same convention as Bitcoin Core).
    return sorted[count / 2];
}

bool check_block_time(int64_t block_time,
                      int64_t median_time_past,
                      int64_t adjusted_time) {
    // Rule 1 (BIP113): block timestamp must be strictly greater than the
    // median time past of the previous 11 blocks.
    if (block_time <= median_time_past) {
        return false;
    }

    // Rule 2: block timestamp must not be more than MAX_FUTURE_BLOCK_TIME
    // seconds ahead of the node's network-adjusted clock.
    if (block_time > adjusted_time + MAX_FUTURE_BLOCK_TIME) {
        return false;
    }

    return true;
}

} // namespace consensus
