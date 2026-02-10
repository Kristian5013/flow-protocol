#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Keccak256d proof-of-work solver for FTC mining.
//
// FTC uses keccak256d (double Keccak-256) as its proof-of-work hash
// function.  The solver iterates nonces, computes the block header hash
// via BlockHeader::hash(), and checks it against the difficulty target.
//
// The solver provides:
//   - Nonce iteration strategy
//   - Cooperative cancellation via atomic cancel token
//   - Difficulty checking (hash must be <= target)
//   - Header serialization utility
// ---------------------------------------------------------------------------

#include "core/error.h"
#include "core/types.h"
#include "miner/difficulty.h"
#include "primitives/block_header.h"

#include <atomic>
#include <cstdint>
#include <optional>
#include <vector>

namespace miner {

// ---------------------------------------------------------------------------
// SolverResult
// ---------------------------------------------------------------------------

/// The result of a successful solve attempt: contains the winning nonce.
struct SolverResult {
    /// The nonce that was used to find this solution.
    uint32_t nonce = 0;
};

// ---------------------------------------------------------------------------
// PowSolver
// ---------------------------------------------------------------------------

/// Finds valid keccak256d proof-of-work solutions for FTC block headers.
///
/// Usage:
///   PowSolver solver;
///   auto result = solver.solve(header, target, cancel_token);
///   if (result) {
///       // Found a valid solution.
///       header.nonce = result->nonce;
///   }
class PowSolver {
public:
    /// Construct a solver.
    PowSolver() = default;

    // -- Solving -----------------------------------------------------------

    /// Attempt to find a valid nonce for the given header.
    ///
    /// Iterates nonces starting from `header.nonce`, computing
    /// keccak256d(serialized_header) for each. Continues until a hash
    /// meeting the difficulty target is found, the nonce space is
    /// exhausted, or the cancel token is set.
    ///
    /// @param header       The block header to solve (nonce field is the
    ///                     starting nonce; will be iterated).
    /// @param target       The difficulty target: the block hash must be
    ///                     <= this value.
    /// @param cancel_token Atomic flag for cooperative cancellation.
    ///                     Set to true by the caller to abort.
    /// @returns            The winning nonce, or std::nullopt
    ///                     if cancelled or nonce space exhausted.
    [[nodiscard]] std::optional<SolverResult> solve(
        primitives::BlockHeader header,
        const core::uint256& target,
        std::atomic<bool>& cancel_token,
        std::atomic<uint64_t>* hash_counter = nullptr);

    // -- Utilities ---------------------------------------------------------

    /// Serialize a block header into bytes.
    ///
    /// @param header  The block header to serialize.
    /// @returns       The 80-byte serialized header.
    [[nodiscard]] static std::vector<uint8_t> serialize_header(
        const primitives::BlockHeader& header);
};

} // namespace miner
