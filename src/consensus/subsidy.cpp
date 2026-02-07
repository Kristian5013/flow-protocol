// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/subsidy.h"

#include "consensus/amount.h"

namespace consensus {

primitives::Amount get_block_subsidy(int height,
                                     const ConsensusParams& params) {
    // The number of halvings that have occurred at this height.
    int halvings = height / params.subsidy_halving_interval;

    // After 64 right-shifts a 64-bit integer is guaranteed to be zero.
    // This also handles the degenerate case where halvings < 0 would be
    // impossible since height >= 0 and the interval is positive.
    if (halvings >= 64) {
        return primitives::Amount{0};
    }

    // Initial block reward: 50 FTC = 50 * COIN satoshis.
    int64_t subsidy = 50 * COIN;

    // Right-shift to halve the reward for each completed halving era.
    subsidy >>= halvings;

    return primitives::Amount{subsidy};
}

primitives::Amount get_block_reward(int height,
                                    primitives::Amount fees,
                                    const ConsensusParams& params) {
    int64_t subsidy = get_block_subsidy(height, params).value();
    int64_t total   = subsidy + fees.value();
    return primitives::Amount{total};
}

} // namespace consensus
