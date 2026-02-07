#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Block subsidy (reward) calculation
// ---------------------------------------------------------------------------
// Implements the deterministic coin-emission schedule: an initial reward
// of 50 FTC per block that halves every 210,000 blocks, converging to a
// maximum supply of 21,000,000 FTC.
// ---------------------------------------------------------------------------

#include "consensus/params.h"
#include "primitives/amount.h"

namespace consensus {

/// Computes the newly-created coin subsidy for the block at @p height.
///
/// The initial reward is 50 FTC (5,000,000,000 satoshis).  Every
/// @p params.subsidy_halving_interval blocks the reward is halved by a
/// right-shift.  After 64 halvings (or whenever the shift reduces the
/// reward to zero) no further coins are created.
///
/// @param height  Block height (genesis = 0).
/// @param params  Consensus parameters providing the halving interval.
/// @returns       The subsidy amount in base units (satoshis).
[[nodiscard]] primitives::Amount get_block_subsidy(
    int height,
    const ConsensusParams& params);

/// Computes the total block reward: subsidy plus collected transaction
/// fees.
///
/// @param height  Block height.
/// @param fees    Sum of all transaction fees in the block.
/// @param params  Consensus parameters.
/// @returns       subsidy + fees.
[[nodiscard]] primitives::Amount get_block_reward(
    int height,
    primitives::Amount fees,
    const ConsensusParams& params);

} // namespace consensus
