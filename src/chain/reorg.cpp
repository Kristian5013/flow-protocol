// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/reorg.h"

#include "chain/block_index.h"
#include "chain/chain.h"
#include "core/logging.h"

#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

namespace chain {

// ---------------------------------------------------------------------------
// compute_reorg_path
// ---------------------------------------------------------------------------
// Algorithm:
//   1. Identify the two tips: the active chain tip and the proposed new tip.
//   2. Walk both pointers backwards until they converge on the same block
//      (the fork point).  At each step, advance whichever pointer is at a
//      greater height; record blocks passed by the active tip in
//      to_disconnect and blocks passed by the new tip in to_connect.
//   3. The to_disconnect list is naturally in newest-first order.
//   4. The to_connect list ends up in newest-first order from the walk, so
//      we reverse it to get oldest-first (the order in which blocks should
//      be applied).
// ---------------------------------------------------------------------------
ReorgPath compute_reorg_path(const Chain& active_chain, BlockIndex* new_tip) {
    ReorgPath path;

    BlockIndex* old_tip = active_chain.tip();

    // Degenerate cases.
    if (old_tip == nullptr && new_tip == nullptr) {
        return path;
    }
    if (old_tip == nullptr) {
        // No active chain -- only connect blocks.
        BlockIndex* walk = new_tip;
        while (walk != nullptr) {
            path.to_connect.push_back(walk);
            walk = walk->prev;
        }
        // Reverse so that genesis (oldest) is first.
        std::reverse(path.to_connect.begin(), path.to_connect.end());
        return path;
    }
    if (new_tip == nullptr) {
        // Disconnect everything (shouldn't happen in practice).
        BlockIndex* walk = old_tip;
        while (walk != nullptr) {
            path.to_disconnect.push_back(walk);
            walk = walk->prev;
        }
        return path;
    }

    // Walk both pointers backwards to find the fork point.
    BlockIndex* old_walk = old_tip;
    BlockIndex* new_walk = new_tip;

    // Equalise heights first, collecting blocks into the appropriate list.
    while (old_walk->height > new_walk->height) {
        path.to_disconnect.push_back(old_walk);
        old_walk = old_walk->prev;
    }
    while (new_walk->height > old_walk->height) {
        path.to_connect.push_back(new_walk);
        new_walk = new_walk->prev;
    }

    // Now both are at the same height.  Walk back in lockstep until they
    // meet at the fork point.
    while (old_walk != new_walk) {
        if (old_walk == nullptr || new_walk == nullptr) {
            // Disjoint trees -- no common ancestor.  This should never
            // happen on a properly configured network, but handle it
            // gracefully.
            path.fork_point = nullptr;
            // Reverse to_connect so it is oldest-first.
            std::reverse(path.to_connect.begin(), path.to_connect.end());
            return path;
        }
        path.to_disconnect.push_back(old_walk);
        path.to_connect.push_back(new_walk);
        old_walk = old_walk->prev;
        new_walk = new_walk->prev;
    }

    // old_walk == new_walk == fork point.
    path.fork_point = old_walk;

    // to_connect was built newest-first; reverse to oldest-first (connect
    // order).
    std::reverse(path.to_connect.begin(), path.to_connect.end());

    LOG_INFO(core::LogCategory::CHAIN,
             "Reorg path: disconnect " +
             std::to_string(path.to_disconnect.size()) + " blocks, connect " +
             std::to_string(path.to_connect.size()) + " blocks, fork at height " +
             std::to_string(path.fork_point ? path.fork_point->height : -1));

    return path;
}

// ---------------------------------------------------------------------------
// is_reorg_safe
// ---------------------------------------------------------------------------
bool is_reorg_safe(const ReorgPath& path) {
    return static_cast<int>(path.to_disconnect.size()) <= MAX_REORG_DEPTH;
}

} // namespace chain
