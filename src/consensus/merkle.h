#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Consensus-level merkle computation
// ---------------------------------------------------------------------------
// Provides functions for building the transaction merkle root and the
// witness merkle root used in block validation.  The underlying hash
// primitive is Keccak-256d (double Keccak-256), and the tree structure
// follows Bitcoin convention: when the leaf count at any level is odd,
// the last entry is duplicated before pairing.
// ---------------------------------------------------------------------------

#include "core/types.h"
#include "primitives/block.h"

#include <vector>

namespace consensus {

/// Computes a binary merkle root from a vector of 256-bit leaf hashes.
///
/// The algorithm hashes pairs of nodes with Keccak-256d (double
/// Keccak-256).  If the number of nodes at any level is odd, the last
/// node is duplicated so that every node has a partner (Bitcoin-style
/// merkle tree).
///
/// Returns a zero hash if @p leaves is empty.
///
/// @param leaves  Ordered leaf hashes.
/// @returns       The 256-bit merkle root.
[[nodiscard]] core::uint256 compute_merkle_root(
    const std::vector<core::uint256>& leaves);

/// Computes the witness merkle root for a block.
///
/// The witness merkle tree is built from the wtxid of each transaction,
/// except that the coinbase transaction (index 0) uses a zero hash
/// (32 zero bytes) in place of its wtxid.  This follows BIP141.
///
/// Returns a zero hash if the block contains no transactions.
///
/// @param block  The block whose witness merkle root to compute.
/// @returns      The 256-bit witness merkle root.
[[nodiscard]] core::uint256 compute_witness_merkle_root(
    const primitives::Block& block);

/// Verifies that the merkle_root field in the block header matches the
/// merkle root computed from the block's transactions (using their txid).
///
/// @param block  The block to validate.
/// @returns      true if the header's merkle_root matches the computed one.
[[nodiscard]] bool check_merkle_root(const primitives::Block& block);

} // namespace consensus
