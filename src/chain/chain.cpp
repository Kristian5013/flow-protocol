// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/chain.h"

#include "chain/block_index.h"
#include "core/types.h"

#include <algorithm>
#include <cstdint>
#include <vector>

namespace chain {

// ---------------------------------------------------------------------------
// genesis
// ---------------------------------------------------------------------------
BlockIndex* Chain::genesis() const {
    if (chain_.empty()) {
        return nullptr;
    }
    return chain_.front();
}

// ---------------------------------------------------------------------------
// tip
// ---------------------------------------------------------------------------
BlockIndex* Chain::tip() const {
    if (chain_.empty()) {
        return nullptr;
    }
    return chain_.back();
}

// ---------------------------------------------------------------------------
// at
// ---------------------------------------------------------------------------
BlockIndex* Chain::at(int height) const {
    if (height < 0 || static_cast<size_t>(height) >= chain_.size()) {
        return nullptr;
    }
    return chain_[static_cast<size_t>(height)];
}

// ---------------------------------------------------------------------------
// height
// ---------------------------------------------------------------------------
int Chain::height() const {
    if (chain_.empty()) {
        return -1;
    }
    return static_cast<int>(chain_.size()) - 1;
}

// ---------------------------------------------------------------------------
// contains
// ---------------------------------------------------------------------------
bool Chain::contains(const BlockIndex* index) const {
    if (index == nullptr) {
        return false;
    }
    if (index->height < 0 || static_cast<size_t>(index->height) >= chain_.size()) {
        return false;
    }
    return chain_[static_cast<size_t>(index->height)] == index;
}

// ---------------------------------------------------------------------------
// find_fork
// ---------------------------------------------------------------------------
const BlockIndex* Chain::find_fork(const BlockIndex* index) const {
    if (chain_.empty() || index == nullptr) {
        return nullptr;
    }

    // Walk down to the height of our tip if the candidate is taller.
    const BlockIndex* walk = index;
    while (walk != nullptr && walk->height > height()) {
        walk = walk->prev;
    }

    // Now walk down both chains in lockstep until we find the common block.
    while (walk != nullptr) {
        if (contains(walk)) {
            return walk;
        }
        walk = walk->prev;
    }

    return nullptr;
}

// ---------------------------------------------------------------------------
// set_tip
// ---------------------------------------------------------------------------
void Chain::set_tip(BlockIndex* index) {
    if (index == nullptr) {
        chain_.clear();
        return;
    }

    // Rebuild from genesis to tip.  First, determine the length.
    chain_.resize(static_cast<size_t>(index->height) + 1);

    // Walk backwards from the new tip, filling in the vector.
    BlockIndex* walk = index;
    while (walk != nullptr) {
        chain_[static_cast<size_t>(walk->height)] = walk;
        walk = walk->prev;
    }
}

// ---------------------------------------------------------------------------
// get_locator
// ---------------------------------------------------------------------------
// Returns block hashes at exponentially spaced heights.  The first 10
// entries are consecutive (step=1), then the step doubles each time.
// This gives O(log(height)) entries, providing efficient chain
// synchronization between peers.
//
// Example for a chain of height 100:
//   heights: 100, 99, 98, 97, 96, 95, 94, 93, 92, 91,
//            89, 85, 77, 61, 29, 0
// ---------------------------------------------------------------------------
std::vector<core::uint256> Chain::get_locator() const {
    std::vector<core::uint256> hashes;

    if (chain_.empty()) {
        return hashes;
    }

    int step = 1;
    int h = height();

    while (h >= 0) {
        hashes.push_back(chain_[static_cast<size_t>(h)]->block_hash);

        // If we have collected 10 entries, start doubling the step.
        if (hashes.size() >= 10) {
            step *= 2;
        }

        h -= step;
    }

    // Always include genesis if it was not already included.
    if (hashes.empty() || !(hashes.back() == chain_[0]->block_hash)) {
        hashes.push_back(chain_[0]->block_hash);
    }

    return hashes;
}

} // namespace chain
