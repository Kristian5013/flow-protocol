#pragma once

#include <cstddef>
#include <vector>

#include "core/types.h"

namespace crypto {

class MerkleTree {
public:
    MerkleTree() = default;
    explicit MerkleTree(std::vector<core::uint256> leaves);

    core::uint256 root() const;

    // Get proof for leaf at index (list of sibling hashes)
    std::vector<core::uint256> proof(size_t index) const;

    // Verify a proof
    static bool verify(const core::uint256& root,
                       const core::uint256& leaf,
                       const std::vector<core::uint256>& proof,
                       size_t index);

    size_t leaf_count() const;
    const std::vector<core::uint256>& leaves() const;

private:
    std::vector<core::uint256> leaves_;
    std::vector<std::vector<core::uint256>> levels_;

    void build();
};

// Compute merkle root from transaction hashes
// (Bitcoin-style: duplicate last if odd)
core::uint256 compute_merkle_root(std::vector<core::uint256> hashes);

// Compute witness merkle root
core::uint256 compute_witness_merkle_root(
    std::vector<core::uint256> wtxids);

} // namespace crypto
