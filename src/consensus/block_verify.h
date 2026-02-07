#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Block-level consensus validation
// ---------------------------------------------------------------------------
// check_block_header()     -- validate a block header in isolation
// check_block()            -- full block validation (header + transactions)
// check_witness_commitment() -- verify the segwit witness commitment
// ---------------------------------------------------------------------------

#include "core/error.h"
#include "primitives/block.h"
#include "primitives/block_header.h"

#include <cstdint>

namespace consensus {

struct ConsensusParams;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum total signature operation cost allowed in a single block.
constexpr int64_t MAX_BLOCK_SIGOPS_COST = 80'000;

/// Maximum allowed time offset from the adjusted network time for a new
/// block header (2 hours).
constexpr int64_t MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60;

/// The 4-byte witness commitment header that follows OP_RETURN (0x6a)
/// in the coinbase output.  Full prefix is: 0x6a 0x24 0xaa 0x21 0xa9 0xed.
/// The 0x24 is the push opcode for 36 bytes.
constexpr uint8_t WITNESS_COMMITMENT_HEADER[] = {0xaa, 0x21, 0xa9, 0xed};

// ---------------------------------------------------------------------------
// Block header validation
// ---------------------------------------------------------------------------

/// Validate a block header in isolation (no chain context beyond params).
///
/// Checks performed:
///   - Proof of work: the header hash must satisfy the target encoded
///     in the header's nBits field, and nBits must not exceed pow_limit.
///   - Timestamp: must not be more than MAX_FUTURE_BLOCK_TIME seconds in
///     the future relative to @p adjusted_time.
///
/// @param header         The block header to validate.
/// @param params         Consensus parameters (for pow_limit).
/// @param adjusted_time  The network-adjusted current time (Unix seconds).
///                        Pass 0 to skip the future-time check.
///
/// Returns core::make_ok() on success, or an appropriate error.
[[nodiscard]] core::Result<void> check_block_header(
    const primitives::BlockHeader& header,
    const ConsensusParams& params,
    int64_t adjusted_time = 0);

// ---------------------------------------------------------------------------
// Full block validation
// ---------------------------------------------------------------------------

/// Validate a complete block (header + transactions).
///
/// Checks performed:
///   - Block header validation (via check_block_header).
///   - Block must contain at least one transaction.
///   - First transaction must be coinbase.
///   - No other transaction may be coinbase.
///   - Merkle root must match the transactions.
///   - Each transaction must pass check_transaction().
///   - Total block weight must not exceed max_block_weight.
///   - Total signature operation cost must not exceed MAX_BLOCK_SIGOPS_COST.
///   - Witness commitment (if segwit active and witness data present).
///
/// @param block          The block to validate.
/// @param params         Consensus parameters.
/// @param adjusted_time  Network-adjusted time for header timestamp check.
///                        Pass 0 to skip.
///
/// Returns core::make_ok() on success, or an appropriate error.
[[nodiscard]] core::Result<void> check_block(
    const primitives::Block& block,
    const ConsensusParams& params,
    int64_t adjusted_time = 0);

// ---------------------------------------------------------------------------
// Witness commitment verification
// ---------------------------------------------------------------------------

/// Verify the segregated witness commitment in a block's coinbase.
///
/// The witness commitment is an OP_RETURN output in the coinbase whose
/// scriptPubKey begins with:
///   0x6a 0x24 0xaa21a9ed <32-byte witness commitment hash>
///
/// The commitment hash is:
///   Keccak256d( witness_merkle_root || witness_nonce )
///
/// where witness_nonce is the first item in the coinbase's witness stack
/// (must be exactly 32 bytes of zeros by convention) and the witness
/// merkle root is computed using wtxids (with the coinbase wtxid set to
/// all zeros).
///
/// @param block   The block whose witness commitment to verify.
/// @param params  Consensus parameters (for segwit_height).
///
/// Returns core::make_ok() on success, or an appropriate error.
[[nodiscard]] core::Result<void> check_witness_commitment(
    const primitives::Block& block,
    const ConsensusParams& params);

} // namespace consensus
