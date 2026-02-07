#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Equihash proof-of-work solver for FTC mining.
//
// FTC uses Equihash with parameters n=200, k=9, the same parameter set
// as Zcash. This yields solutions of 512 indices (2^9) compressed into
// ~1344 bytes, and requires ~512 MB of working memory.
//
// The solver wraps the crypto::equihash module and adds:
//   - Nonce iteration strategy
//   - Cooperative cancellation via atomic cancel token
//   - Difficulty checking (solution must produce a hash <= target)
//   - Header serialization for Equihash input
// ---------------------------------------------------------------------------

#include "core/error.h"
#include "core/types.h"
#include "crypto/equihash.h"
#include "miner/difficulty.h"
#include "primitives/block_header.h"

#include <atomic>
#include <cstdint>
#include <optional>
#include <vector>

namespace miner {

// ---------------------------------------------------------------------------
// Equihash parameters for FTC
// ---------------------------------------------------------------------------

/// Default Equihash parameters: n=200, k=9.
static constexpr unsigned EQUIHASH_N = 200;
static constexpr unsigned EQUIHASH_K = 9;

/// Solution size in bytes for (200, 9) Equihash.
static constexpr size_t EQUIHASH_SOLUTION_SIZE = 1344;

/// Number of indices in a solution: 2^k = 512.
static constexpr size_t EQUIHASH_NUM_INDICES = 512;

// ---------------------------------------------------------------------------
// SolverResult
// ---------------------------------------------------------------------------

/// The result of a successful solve attempt: contains the winning nonce
/// and the Equihash solution bytes.
struct SolverResult {
    /// The nonce that was used to find this solution.
    uint32_t nonce = 0;

    /// The Equihash solution (compressed indices, ~1344 bytes).
    std::vector<uint8_t> solution;
};

// ---------------------------------------------------------------------------
// EquihashSolver
// ---------------------------------------------------------------------------

/// Finds valid Equihash solutions for FTC block headers.
///
/// Usage:
///   EquihashSolver solver;
///   auto result = solver.solve(header, target, cancel_token);
///   if (result) {
///       // Found a valid solution.
///       header.nonce = result->nonce;
///       // Attach result->solution to the block.
///   }
class EquihashSolver {
public:
    /// Construct a solver with the default FTC Equihash parameters.
    EquihashSolver();

    /// Construct a solver with custom Equihash parameters.
    /// @param n  Collision bit-length.
    /// @param k  Number of collision rounds.
    explicit EquihashSolver(unsigned n, unsigned k);

    // -- Solving -----------------------------------------------------------

    /// Attempt to find a valid Equihash solution for the given header.
    ///
    /// Iterates nonces starting from `header.nonce`, computing Equihash
    /// solutions for each. For each solution found, checks whether the
    /// resulting block hash meets the difficulty target. Continues until
    /// a valid solution is found, the nonce space is exhausted, or the
    /// cancel token is set.
    ///
    /// The input to the Equihash function is:
    ///   Keccak256(serialized_header_80_bytes)
    /// where the header includes the current nonce value.
    ///
    /// @param header       The block header to solve (nonce field is the
    ///                     starting nonce; will be iterated).
    /// @param target       The difficulty target: the block hash must be
    ///                     <= this value.
    /// @param cancel_token Atomic flag for cooperative cancellation.
    ///                     Set to true by the caller to abort.
    /// @returns            The winning nonce and solution, or std::nullopt
    ///                     if cancelled or nonce space exhausted.
    [[nodiscard]] std::optional<SolverResult> solve(
        primitives::BlockHeader header,
        const core::uint256& target,
        std::atomic<bool>& cancel_token,
        std::atomic<uint64_t>* hash_counter = nullptr);

    // -- Verification ------------------------------------------------------

    /// Verify that an Equihash solution is valid for the given header.
    ///
    /// Checks:
    ///   1. The solution decodes correctly for the (n, k) parameters.
    ///   2. The Equihash constraints are satisfied (partial collisions
    ///      at each level, full collision at the end).
    ///
    /// This does NOT check difficulty (block hash vs target). Use
    /// check_proof_of_work() for that.
    ///
    /// @param header    The block header (with nonce already set).
    /// @param solution  The Equihash solution bytes.
    /// @returns         true if the solution is cryptographically valid.
    [[nodiscard]] bool verify_solution(
        const primitives::BlockHeader& header,
        const std::vector<uint8_t>& solution) const;

    // -- Utilities ---------------------------------------------------------

    /// Serialize a block header into the format used as Equihash input.
    ///
    /// @param header  The block header to serialize.
    /// @returns       The 80-byte serialized header.
    [[nodiscard]] static std::vector<uint8_t> serialize_header(
        const primitives::BlockHeader& header);

    /// Compute the Equihash input hash from a serialized header.
    ///
    /// The Equihash function takes a variable-length input. For FTC,
    /// we use Keccak256(serialized_header) as the input.
    ///
    /// @param header  The block header.
    /// @returns       The 32-byte Equihash input.
    [[nodiscard]] static core::uint256 compute_equihash_input(
        const primitives::BlockHeader& header);

    /// Get the Equihash parameters used by this solver.
    [[nodiscard]] const crypto::EquihashParams& params() const {
        return params_;
    }

    /// Get the expected solution size in bytes.
    [[nodiscard]] size_t solution_size() const {
        return params_.solution_size();
    }

private:
    crypto::EquihashParams params_;
};

} // namespace miner
