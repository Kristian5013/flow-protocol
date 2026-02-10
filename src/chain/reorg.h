#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Chain reorganization logic
// ---------------------------------------------------------------------------
// Provides utilities for computing the set of blocks to disconnect and
// connect when switching to a better chain tip, along with safety checks
// to prevent excessively deep reorganizations.
// ---------------------------------------------------------------------------

#include "chain/block_index.h"
#include "chain/chain.h"

#include <vector>

namespace chain {

// ---------------------------------------------------------------------------
// ReorgPath -- describes the blocks to disconnect and connect during a reorg
// ---------------------------------------------------------------------------
struct ReorgPath {
    /// Blocks to disconnect, ordered from the current tip backwards toward
    /// (but not including) the fork point.  Newest block first.
    std::vector<BlockIndex*> to_disconnect;

    /// Blocks to connect, ordered from the fork point forward toward the
    /// new tip.  Oldest block first.
    std::vector<BlockIndex*> to_connect;

    /// The common ancestor of the old and new chains.  nullptr when the
    /// chains share no common block (should not happen on a valid network).
    BlockIndex* fork_point = nullptr;
};

// ---------------------------------------------------------------------------
// Safety limit on reorganization depth
// ---------------------------------------------------------------------------

/// Maximum number of blocks that may be disconnected in a single
/// reorganization.  This protects against an attacker who constructs an
/// extremely long alternate chain designed to cause excessive I/O or
/// memory consumption.
constexpr int MAX_REORG_DEPTH = 100000;

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Compute the reorganization path from the current active chain to a new
/// tip.  Walks backwards from both the current tip and @p new_tip to
/// locate the fork point, then builds the disconnect and connect lists.
///
/// @param active_chain  The currently active chain.
/// @param new_tip       The BlockIndex at the tip of the competing chain.
/// @returns A ReorgPath describing the blocks to disconnect and connect.
ReorgPath compute_reorg_path(const Chain& active_chain, BlockIndex* new_tip);

/// Check whether a reorganization is within the safety depth limit.
/// Returns true if the number of blocks to disconnect does not exceed
/// MAX_REORG_DEPTH.
bool is_reorg_safe(const ReorgPath& path);

} // namespace chain
