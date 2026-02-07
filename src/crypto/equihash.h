#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Equihash -- memory-hard proof-of-work based on the generalised
// birthday problem (Wagner's algorithm).
//
// FTC uses Keccak-256 as its primary PoW hash function.  This module
// provides Equihash as an optional secondary PoW for potential future
// use (e.g. hybrid PoW, merge-mining, or difficulty-adjustment
// diversity).
//
// The implementation is correct but intentionally minimal -- a
// production miner would use the optimised Tromp solver.  The
// verifier, however, is fully production-grade.
//
// Parameters:
//   n -- collision bit length (default 200)
//   k -- number of Wagner rounds  (default 9)
//
// The default (200,9) yields solutions of 1344 bytes and requires
// ~512 MB of working memory during solving, making it meaningfully
// memory-hard.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace crypto {

// ===================================================================
// Equihash parameters
// ===================================================================

/// Describes the (n, k) parameter set for an Equihash instance.
struct EquihashParams {
    unsigned n = 200;  ///< collision bit length
    unsigned k = 9;    ///< number of collision rounds

    /// Number of bytes needed to store the collision bits at each
    /// round.  Each round reduces by n/(k+1) bits.
    [[nodiscard]] constexpr size_t collision_byte_length() const {
        return (n / (k + 1) + 7) / 8;
    }

    /// Total hash output length in bytes: ceil(n / 8).
    [[nodiscard]] constexpr size_t hash_output() const {
        return (n + 7) / 8;
    }

    /// Size of a single solution in bytes.
    /// Each solution contains 2^k indices; each index is encoded
    /// using ceil((n/(k+1) + 1) / 8) bits, packed tightly.
    [[nodiscard]] constexpr size_t indices_per_solution() const {
        return static_cast<size_t>(1u) << k;
    }

    /// Bit width of each index in the solution encoding.
    [[nodiscard]] constexpr unsigned index_bit_length() const {
        return n / (k + 1) + 1;
    }

    /// Total solution byte size (packed indices).
    [[nodiscard]] constexpr size_t solution_size() const {
        return (indices_per_solution() * index_bit_length() + 7) / 8;
    }
};

// ===================================================================
// Verification
// ===================================================================

/// Verify an Equihash solution against the given block header input.
///
/// Checks:
///   1. Solution decodes to 2^k indices in strictly ascending order
///      within each pair at every level (the "ordering constraint").
///   2. The XOR of all generated hash fragments equals zero.
///   3. At each intermediate level, the partial XOR is zero in the
///      appropriate number of leading bits.
///
/// @param params    Equihash (n, k) parameters.
/// @param input     Block header bytes (before nonce/solution).
/// @param solution  Packed solution bytes (solution_size() bytes).
/// @returns true if the solution is valid.
[[nodiscard]] bool equihash_verify(
    const EquihashParams& params,
    std::span<const uint8_t> input,
    std::span<const uint8_t> solution);

// ===================================================================
// Solver
// ===================================================================

/// Find Equihash solutions for the given input.
///
/// Implements Wagner's generalised birthday algorithm with a basic
/// in-memory collision search.  This is a reference solver -- not
/// optimised for mining speed.
///
/// @param params         Equihash (n, k) parameters.
/// @param input          Block header bytes.
/// @param max_solutions  Stop after finding this many solutions.
/// @returns Vector of solutions, each being solution_size() bytes.
[[nodiscard]] std::vector<std::vector<uint8_t>> equihash_solve(
    const EquihashParams& params,
    std::span<const uint8_t> input,
    size_t max_solutions = 1);

}  // namespace crypto
