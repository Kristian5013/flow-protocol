#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Proof-of-work validation and difficulty adjustment
// ---------------------------------------------------------------------------
// FTC uses Equihash(200,9) as its memory-hard PoW algorithm with Keccak-256
// block hashing.  Difficulty retargets every 2016 blocks with a target block
// interval of 600 seconds.  The nBits compact format follows Bitcoin's
// convention.
// ---------------------------------------------------------------------------

#include "core/error.h"
#include "core/types.h"
#include "primitives/block_header.h"

#include <cstdint>

namespace consensus {

// Forward declaration -- full definition lives in consensus/params.h.
struct ConsensusParams;

// ---------------------------------------------------------------------------
// nBits <-> uint256 target conversion
// ---------------------------------------------------------------------------

/// Convert a compact nBits value to a full 256-bit target.
///
/// The compact format encodes a 256-bit unsigned integer as follows:
///   - Byte 0 (most significant byte of the uint32_t): the number of bytes
///     in the resulting target (the "exponent").
///   - Bytes 1-3: the mantissa in big-endian order.
///   - target = mantissa * 2^(8 * (exponent - 3))
///
/// If the mantissa has its high bit set and the exponent is greater than 0,
/// the value is considered negative (invalid for PoW targets); in that case
/// a zero uint256 is returned.
[[nodiscard]] core::uint256 nbits_to_target(uint32_t nbits);

/// Convert a full 256-bit target back to the compact nBits representation.
/// This is the inverse of nbits_to_target(), with the same semantics.
[[nodiscard]] uint32_t target_to_nbits(const core::uint256& target);

// ---------------------------------------------------------------------------
// Proof-of-work validation
// ---------------------------------------------------------------------------

/// Check that @p hash satisfies the proof-of-work requirement encoded in
/// @p nbits.  Specifically, verifies:
///   1. The target decoded from nbits does not exceed the network's pow_limit.
///   2. hash <= target.
///
/// @param hash    The block header hash (keccak256d of serialised header).
/// @param nbits   Compact difficulty target from the block header.
/// @param params  Consensus parameters (supplies pow_limit).
/// @returns true if the proof-of-work is valid.
[[nodiscard]] bool check_proof_of_work(const core::uint256& hash,
                                       uint32_t nbits,
                                       const ConsensusParams& params);

// ---------------------------------------------------------------------------
// Difficulty adjustment
// ---------------------------------------------------------------------------

/// Calculate the next required difficulty target.
///
/// @param height           Height of the block whose difficulty is being
///                         computed.
/// @param last_block_time  Timestamp of the previous block (height - 1).
/// @param first_block_time Timestamp of the block at the start of the
///                         retarget interval (height - 2016).
/// @param last_nbits       nBits of the previous block.
/// @param params           Consensus parameters.
/// @returns The compact nBits value for the new block.
///
/// If @p height is not on a retarget boundary (height % 2016 != 0), the
/// function simply returns @p last_nbits unchanged.
///
/// Otherwise the actual timespan of the previous 2016 blocks is computed and
/// clamped to [pow_target_timespan/4, pow_target_timespan*4].  The new target
/// is:
///   new_target = old_target * actual_timespan / pow_target_timespan
/// clamped to pow_limit.
[[nodiscard]] uint32_t get_next_work_required(int height,
                                              int64_t last_block_time,
                                              int64_t first_block_time,
                                              uint32_t last_nbits,
                                              const ConsensusParams& params);

// ---------------------------------------------------------------------------
// Equihash solution verification
// ---------------------------------------------------------------------------

/// Verify the Equihash(200,9) solution embedded in the block header.
///
/// Serialises the 80-byte header as the puzzle input and delegates to
/// crypto::equihash_verify().
///
/// @param header  The block header to validate.
/// @param params  Consensus parameters (supplies Equihash n, k).
/// @returns true if the Equihash solution is valid.
[[nodiscard]] bool check_equihash_solution(
    const primitives::BlockHeader& header,
    const ConsensusParams& params);

}  // namespace consensus
