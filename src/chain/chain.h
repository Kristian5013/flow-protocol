#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/block_index.h"
#include "core/types.h"

#include <cstdint>
#include <vector>

namespace chain {

// ---------------------------------------------------------------------------
// Chain -- the active best chain from genesis to tip
// ---------------------------------------------------------------------------
// Maintains a vector of BlockIndex pointers where index 0 is the genesis
// block and the last element is the current tip.  This is rebuilt whenever
// the tip changes (including reorgs) by walking `prev` pointers from the
// new tip back to genesis.
// ---------------------------------------------------------------------------
class Chain {
public:
    Chain() = default;

    /// Get the genesis block index.  Returns nullptr if the chain is empty.
    BlockIndex* genesis() const;

    /// Get the tip (highest block).  Returns nullptr if the chain is empty.
    BlockIndex* tip() const;

    /// Get the block index at the given height.
    /// Returns nullptr if the height is out of range.
    BlockIndex* at(int height) const;

    /// Convenience operator: equivalent to at(height).
    BlockIndex* operator[](int height) const { return at(height); }

    /// Height of the tip.  Returns -1 if the chain is empty.
    int height() const;

    /// Returns true if the given block index is part of this chain.
    /// A block is contained if its height is within range and the pointer
    /// stored at that height matches.
    bool contains(const BlockIndex* index) const;

    /// Find the fork point between this chain and the chain ending at
    /// `index`.  Returns the highest block that is in both chains, or
    /// nullptr if there is no common ancestor (including when either
    /// side is empty).
    const BlockIndex* find_fork(const BlockIndex* index) const;

    /// Set the tip to a new block.  Rebuilds the internal vector by walking
    /// `prev` pointers from `index` back to genesis.  Passing nullptr
    /// empties the chain.
    void set_tip(BlockIndex* index);

    /// Return a block locator: a sparse set of block hashes at
    /// exponentially increasing distances from the tip, used for peer
    /// synchronization.  The returned hashes are ordered from highest
    /// height to lowest.
    ///
    /// Step pattern: heights tip, tip-1, tip-2, ... tip-9, tip-11,
    /// tip-15, tip-23, tip-39, tip-71, ... (step doubles each time
    /// after the first 10 entries), and always includes genesis (height 0).
    std::vector<core::uint256> get_locator() const;

private:
    std::vector<BlockIndex*> chain_;  // index 0 = genesis
};

} // namespace chain
