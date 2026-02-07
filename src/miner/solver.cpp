// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner/solver.h"

#include "core/logging.h"
#include "core/stream.h"
#include "crypto/keccak.h"

#include <algorithm>
#include <cstring>

namespace miner {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

EquihashSolver::EquihashSolver()
    : params_{EQUIHASH_N, EQUIHASH_K} {}

EquihashSolver::EquihashSolver(unsigned n, unsigned k)
    : params_{n, k} {}

// ---------------------------------------------------------------------------
// serialize_header
// ---------------------------------------------------------------------------

std::vector<uint8_t> EquihashSolver::serialize_header(
    const primitives::BlockHeader& header) {

    // Serialize the 80-byte block header into a byte vector.
    core::DataStream stream;
    stream.reserve(primitives::BlockHeader::SERIALIZED_SIZE);
    header.serialize(stream);

    // Extract the serialized bytes.
    auto data = stream.release();
    return data;
}

// ---------------------------------------------------------------------------
// compute_equihash_input
// ---------------------------------------------------------------------------

core::uint256 EquihashSolver::compute_equihash_input(
    const primitives::BlockHeader& header) {

    auto serialized = serialize_header(header);
    return crypto::keccak256(
        std::span<const uint8_t>(serialized.data(), serialized.size()));
}

// ---------------------------------------------------------------------------
// solve
// ---------------------------------------------------------------------------

std::optional<SolverResult> EquihashSolver::solve(
    primitives::BlockHeader header,
    const core::uint256& target,
    std::atomic<bool>& cancel_token,
    std::atomic<uint64_t>* hash_counter) {

    // Iterate nonce values starting from header.nonce.
    // For each nonce, compute keccak256d(header) and check against target.
    // This matches BlockHeader::hash() which is what the consensus layer
    // uses for proof-of-work validation.

    uint32_t start_nonce = header.nonce;
    uint32_t nonce = start_nonce;

    LOG_DEBUG(core::LogCategory::MINING,
        "Solver starting at nonce " + std::to_string(nonce));

    uint64_t nonces_tried = 0;
    constexpr uint64_t LOG_INTERVAL = 100000;

    do {
        if (cancel_token.load(std::memory_order_relaxed)) {
            LOG_DEBUG(core::LogCategory::MINING,
                "Solver cancelled after " +
                std::to_string(nonces_tried) + " nonces");
            return std::nullopt;
        }

        header.nonce = nonce;

        // Compute block hash: keccak256d(serialized_80_byte_header).
        // This must match BlockHeader::hash() exactly.
        core::uint256 block_hash = header.hash();

        if (block_hash <= target) {
            LOG_INFO(core::LogCategory::MINING,
                "Found valid nonce " + std::to_string(nonce) +
                " after " + std::to_string(nonces_tried) + " attempts"
                " hash=" + block_hash.to_hex());

            SolverResult result;
            result.nonce = nonce;
            return result;
        }

        ++nonces_tried;
        if (hash_counter) {
            hash_counter->fetch_add(1, std::memory_order_relaxed);
        }

        if (nonces_tried % LOG_INTERVAL == 0) {
            LOG_DEBUG(core::LogCategory::MINING,
                "Solver: " + std::to_string(nonces_tried) + " nonces tried");
        }

        ++nonce;
    } while (nonce != start_nonce);

    LOG_WARN(core::LogCategory::MINING,
        "Solver exhausted nonce space (" +
        std::to_string(nonces_tried) + " nonces)");

    return std::nullopt;
}

// ---------------------------------------------------------------------------
// verify_solution
// ---------------------------------------------------------------------------

bool EquihashSolver::verify_solution(
    const primitives::BlockHeader& header,
    const std::vector<uint8_t>& solution) const {

    // Check solution size.
    if (solution.size() != params_.solution_size()) {
        LOG_DEBUG(core::LogCategory::MINING,
            "Solution size mismatch: expected " +
            std::to_string(params_.solution_size()) +
            " got " + std::to_string(solution.size()));
        return false;
    }

    // Serialize the header and compute the Equihash input.
    auto serialized = serialize_header(header);
    auto input_hash = crypto::keccak256(
        std::span<const uint8_t>(serialized.data(), serialized.size()));

    std::span<const uint8_t> input_span(
        input_hash.data(), input_hash.size());

    // Verify using the crypto::equihash_verify function.
    return crypto::equihash_verify(params_, input_span,
        std::span<const uint8_t>(solution.data(), solution.size()));
}

} // namespace miner
