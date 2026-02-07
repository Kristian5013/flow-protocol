// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/merkle.h"

#include "crypto/keccak.h"

#include <array>
#include <cstring>

namespace consensus {

namespace {

/// Concatenate two 32-byte hashes and double-keccak the result.
core::uint256 hash_pair(const core::uint256& left,
                        const core::uint256& right) {
    std::array<uint8_t, 64> combined{};
    std::memcpy(combined.data(), left.data(), 32);
    std::memcpy(combined.data() + 32, right.data(), 32);
    return crypto::keccak256d({combined.data(), combined.size()});
}

} // namespace

core::uint256 compute_merkle_root(
    const std::vector<core::uint256>& leaves) {
    if (leaves.empty()) {
        return core::uint256{};
    }

    // Work on a mutable copy so the caller's vector is untouched.
    std::vector<core::uint256> current = leaves;

    while (current.size() > 1) {
        // Bitcoin-style: if the level has an odd number of elements,
        // duplicate the last entry so every node has a partner.
        if (current.size() % 2 != 0) {
            current.push_back(current.back());
        }

        std::vector<core::uint256> next;
        next.reserve(current.size() / 2);

        for (size_t i = 0; i < current.size(); i += 2) {
            next.push_back(hash_pair(current[i], current[i + 1]));
        }

        current = std::move(next);
    }

    return current.front();
}

core::uint256 compute_witness_merkle_root(
    const primitives::Block& block) {
    const auto& txs = block.transactions();
    if (txs.empty()) {
        return core::uint256{};
    }

    std::vector<core::uint256> wtxids;
    wtxids.reserve(txs.size());

    for (size_t i = 0; i < txs.size(); ++i) {
        if (i == 0) {
            // BIP141: the coinbase entry in the witness merkle tree
            // uses a zero hash (32 zero bytes) instead of its wtxid.
            wtxids.emplace_back();
        } else {
            wtxids.push_back(txs[i].wtxid());
        }
    }

    return compute_merkle_root(wtxids);
}

bool check_merkle_root(const primitives::Block& block) {
    const auto& txs = block.transactions();
    if (txs.empty()) {
        // An empty block's merkle root must be the zero hash.
        return block.header().merkle_root.is_zero();
    }

    // Collect txids.
    std::vector<core::uint256> txids;
    txids.reserve(txs.size());
    for (const auto& tx : txs) {
        txids.push_back(tx.txid());
    }

    core::uint256 computed = compute_merkle_root(txids);

    return std::memcmp(computed.data(),
                       block.header().merkle_root.data(), 32) == 0;
}

} // namespace consensus
