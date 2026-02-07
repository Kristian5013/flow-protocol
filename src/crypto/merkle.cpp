#include "crypto/merkle.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>

#include "crypto/keccak.h"

namespace crypto {

namespace {

// Combine two 32-byte hashes by concatenating and double-hashing
core::uint256 combine_hashes(const core::uint256& left,
                             const core::uint256& right) {
    std::array<uint8_t, 64> combined{};
    std::memcpy(combined.data(), left.data(), 32);
    std::memcpy(combined.data() + 32, right.data(), 32);
    return keccak256d({combined.data(), combined.size()});
}

// Build one level of the merkle tree from the level below.
// Bitcoin-style: if the level has an odd number of entries,
// duplicate the last entry before pairing.
std::vector<core::uint256> build_next_level(
    const std::vector<core::uint256>& level) {
    std::vector<core::uint256> next;
    size_t count = level.size();
    // If odd, we will duplicate the last element
    size_t pairs = (count + 1) / 2;
    next.reserve(pairs);

    for (size_t i = 0; i < pairs; ++i) {
        size_t left_idx = i * 2;
        size_t right_idx = i * 2 + 1;
        const auto& left = level[left_idx];
        const auto& right =
            (right_idx < count) ? level[right_idx] : level[left_idx];
        next.push_back(combine_hashes(left, right));
    }
    return next;
}

} // namespace

MerkleTree::MerkleTree(std::vector<core::uint256> leaves)
    : leaves_(std::move(leaves)) {
    build();
}

void MerkleTree::build() {
    levels_.clear();
    if (leaves_.empty()) {
        return;
    }

    // Level 0 is the leaves themselves
    levels_.push_back(leaves_);

    // Build successive levels until we reach the root
    while (levels_.back().size() > 1) {
        levels_.push_back(build_next_level(levels_.back()));
    }
}

core::uint256 MerkleTree::root() const {
    if (levels_.empty()) {
        return core::uint256{};
    }
    return levels_.back().front();
}

std::vector<core::uint256> MerkleTree::proof(size_t index) const {
    if (leaves_.empty()) {
        return {};
    }
    if (index >= leaves_.size()) {
        throw std::out_of_range(
            "MerkleTree::proof: index out of range");
    }

    std::vector<core::uint256> result;
    // We don't include the root level in the proof
    size_t num_proof_levels = levels_.size() - 1;
    result.reserve(num_proof_levels);

    size_t idx = index;
    for (size_t level = 0; level < num_proof_levels; ++level) {
        const auto& current_level = levels_[level];
        size_t sibling_idx;
        if (idx % 2 == 0) {
            // We are a left child; sibling is to the right
            sibling_idx = idx + 1;
            if (sibling_idx >= current_level.size()) {
                // Odd count: sibling is a duplicate of ourselves
                sibling_idx = idx;
            }
        } else {
            // We are a right child; sibling is to the left
            sibling_idx = idx - 1;
        }
        result.push_back(current_level[sibling_idx]);
        idx /= 2;
    }

    return result;
}

bool MerkleTree::verify(const core::uint256& root,
                        const core::uint256& leaf,
                        const std::vector<core::uint256>& proof,
                        size_t index) {
    core::uint256 current = leaf;
    size_t idx = index;

    for (const auto& sibling : proof) {
        if (idx % 2 == 0) {
            current = combine_hashes(current, sibling);
        } else {
            current = combine_hashes(sibling, current);
        }
        idx /= 2;
    }

    return std::memcmp(current.data(), root.data(), 32) == 0;
}

size_t MerkleTree::leaf_count() const {
    return leaves_.size();
}

const std::vector<core::uint256>& MerkleTree::leaves() const {
    return leaves_;
}

core::uint256 compute_merkle_root(std::vector<core::uint256> hashes) {
    if (hashes.empty()) {
        return core::uint256{};
    }

    while (hashes.size() > 1) {
        // Bitcoin-style: duplicate last if odd count
        if (hashes.size() % 2 != 0) {
            hashes.push_back(hashes.back());
        }

        std::vector<core::uint256> next;
        next.reserve(hashes.size() / 2);

        for (size_t i = 0; i < hashes.size(); i += 2) {
            next.push_back(
                combine_hashes(hashes[i], hashes[i + 1]));
        }
        hashes = std::move(next);
    }

    return hashes.front();
}

core::uint256 compute_witness_merkle_root(
    std::vector<core::uint256> wtxids) {
    // Witness merkle root uses the same algorithm as the
    // regular merkle root, but operates on witness txids.
    // The first element (coinbase) should be set to zero hash
    // by the caller if following Bitcoin convention.
    return compute_merkle_root(std::move(wtxids));
}

} // namespace crypto
