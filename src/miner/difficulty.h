#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Difficulty adjustment and compact target encoding for FTC mining.
//
// FTC uses Bitcoin-style compact "bits" encoding for difficulty targets.
// Difficulty adjusts every 2016 blocks to maintain a 10-minute block interval.
// ---------------------------------------------------------------------------

#include "chain/block_index.h"
#include "consensus/params.h"
#include "core/types.h"

#include <cstdint>

namespace miner {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of blocks between difficulty adjustments.
static constexpr int DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;

/// Target timespan for a full difficulty period (2016 * 600 seconds = 2 weeks).
static constexpr int64_t TARGET_TIMESPAN = 2016 * 600;

/// Minimum allowed actual timespan (TARGET_TIMESPAN / 4).
static constexpr int64_t MIN_ACTUAL_TIMESPAN = TARGET_TIMESPAN / 4;

/// Maximum allowed actual timespan (TARGET_TIMESPAN * 4).
static constexpr int64_t MAX_ACTUAL_TIMESPAN = TARGET_TIMESPAN * 4;

// ---------------------------------------------------------------------------
// Difficulty target encoding/decoding
// ---------------------------------------------------------------------------

/// Convert a compact "bits" representation to a full 256-bit target.
///
/// The compact format is a 32-bit value:
///   bits[31:24] = exponent (number of bytes in the target)
///   bits[23:0]  = mantissa (most significant 3 bytes of the target)
///
/// Target = mantissa * 2^(8 * (exponent - 3))
///
/// A negative sign bit (bit 23) is handled: if set, the mantissa is negated
/// and the target is zero (difficulty targets are always positive).
///
/// @param bits  The compact target representation.
/// @returns     The full 256-bit target value.
[[nodiscard]] core::uint256 bits_to_target(uint32_t bits);

/// Convert a full 256-bit target back to compact "bits" representation.
///
/// This is the inverse of bits_to_target(). The resulting compact value
/// encodes the target with at most 3 bytes of mantissa precision.
///
/// @param target  The full 256-bit target value.
/// @returns       The compact 32-bit representation.
[[nodiscard]] uint32_t target_to_bits(const core::uint256& target);

// ---------------------------------------------------------------------------
// Difficulty calculations
// ---------------------------------------------------------------------------

/// Calculate the next required work (compact target) after a difficulty
/// adjustment period.
///
/// Called at every block whose height is a multiple of 2016 (the adjustment
/// interval). Uses the timestamps of the first and last blocks in the period
/// to compute the actual timespan, clamps it to [TARGET_TIMESPAN/4,
/// TARGET_TIMESPAN*4], and scales the previous target proportionally.
///
/// @param last_block   The block index of the last block in the period
///                     (height % 2016 == 2015).
/// @param first_block  The block index of the first block in the period
///                     (height % 2016 == 0, i.e., 2016 blocks earlier).
/// @param params       Consensus parameters (provides pow_limit).
/// @returns            The new compact target (bits) for the next period.
[[nodiscard]] uint32_t calculate_next_work_required(
    const chain::BlockIndex& last_block,
    const chain::BlockIndex& first_block,
    const consensus::ConsensusParams& params);

/// Compute the human-readable difficulty from a compact target.
///
/// Difficulty is defined as: pow_limit_target / current_target.
/// The result represents how many times harder the current target is
/// compared to the easiest possible target. A difficulty of 1.0 means
/// the target equals the proof-of-work limit.
///
/// @param bits  The compact target representation.
/// @returns     The human-readable difficulty as a floating-point number.
[[nodiscard]] double get_difficulty(uint32_t bits);

/// Estimate the network hashrate from the current difficulty and the
/// average time between blocks.
///
/// hashrate = difficulty * 2^32 / block_time
///
/// This assumes the block time parameter represents the average observed
/// interval. For estimation purposes, the target block time (600 seconds)
/// is typically used.
///
/// @param difficulty  The human-readable difficulty value.
/// @param block_time  Average block interval in seconds.
/// @returns           Estimated hashes per second.
[[nodiscard]] double estimate_hashrate(double difficulty, double block_time);

/// Get the work (expected number of hashes) represented by a compact target.
///
/// Work is defined as: 2^256 / (target + 1).
///
/// @param bits  The compact target representation.
/// @returns     The work value as a uint256.
[[nodiscard]] core::uint256 get_block_proof(uint32_t bits);

/// Check whether a block hash meets the required difficulty target.
///
/// @param hash    The block hash to check.
/// @param bits    The required compact target.
/// @returns       true if hash <= target (i.e., meets difficulty).
[[nodiscard]] bool check_proof_of_work(
    const core::uint256& hash,
    uint32_t bits,
    const consensus::ConsensusParams& params);

} // namespace miner
