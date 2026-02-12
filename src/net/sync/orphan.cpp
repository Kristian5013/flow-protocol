// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/sync/orphan.h"

#include "core/logging.h"
#include "core/types.h"
#include "primitives/block.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace net::sync {

// ---------------------------------------------------------------------------
// add
// ---------------------------------------------------------------------------
// Adds an orphan block to the pool.  The block is rejected if:
//   - A block with the same hash already exists in the pool.
//   - The block hash is the zero hash (clearly invalid).
//   - The prev_hash is the zero hash (genesis blocks should not be orphans;
//     there is only one genesis block and it has no parent).
//   - The serialized block size exceeds MAX_ORPHAN_BLOCK_SIZE (DoS protection).
//
// After adding, if the pool exceeds MAX_ORPHAN_BLOCKS, the oldest orphan
// is evicted to make room.  This ensures bounded memory usage even if the
// node is receiving orphan blocks at a high rate.
//
// The block data is copied (not moved) because the caller may still need
// the original block for error reporting or other purposes.
// ---------------------------------------------------------------------------
bool OrphanBlockPool::add(const primitives::Block& block,
                           uint64_t from_peer,
                           int64_t now) {
    std::unique_lock<std::mutex> lock(mutex_);

    core::uint256 hash = block.hash();
    core::uint256 prev_hash = block.header().prev_hash;

    // -----------------------------------------------------------------------
    // Reject invalid blocks
    // -----------------------------------------------------------------------

    // Reject zero hashes (clearly malformed).
    if (hash.is_zero()) {
        LOG_WARN(core::LogCategory::NET,
            "Rejecting orphan block with zero hash from peer "
            + std::to_string(from_peer));
        return false;
    }

    // Reject blocks that claim genesis as parent.  The genesis block has
    // prev_hash = 0x00...00 and is the only block allowed to do so.  An
    // orphan should never have a zero prev_hash because that would mean
    // it is a second genesis block, which is invalid.
    if (prev_hash.is_zero()) {
        LOG_WARN(core::LogCategory::NET,
            "Rejecting orphan block with zero prev_hash from peer "
            + std::to_string(from_peer)
            + " (hash: " + hash.to_hex().substr(0, 16) + "...)");
        return false;
    }

    // Reject oversized blocks to prevent DoS.  Full validation would catch
    // this later, but there is no reason to buffer massive blocks.
    size_t block_size = block.size();
    if (block_size > MAX_ORPHAN_BLOCK_SIZE) {
        LOG_WARN(core::LogCategory::NET,
            "Rejecting oversized orphan block from peer "
            + std::to_string(from_peer)
            + " (size: " + std::to_string(block_size)
            + ", max: " + std::to_string(MAX_ORPHAN_BLOCK_SIZE)
            + ", hash: " + hash.to_hex().substr(0, 16) + "...)");
        return false;
    }

    // Reject blocks with no transactions (malformed).
    if (block.tx_count() == 0) {
        LOG_WARN(core::LogCategory::NET,
            "Rejecting orphan block with zero transactions from peer "
            + std::to_string(from_peer)
            + " (hash: " + hash.to_hex().substr(0, 16) + "...)");
        return false;
    }

    // -----------------------------------------------------------------------
    // Check for duplicates
    // -----------------------------------------------------------------------

    if (orphans_.count(hash) > 0) {
        LOG_DEBUG(core::LogCategory::NET,
            "Duplicate orphan block ignored: "
            + hash.to_hex().substr(0, 16) + "...");
        return false;
    }

    // -----------------------------------------------------------------------
    // Insert into storage
    // -----------------------------------------------------------------------

    OrphanBlock orphan;
    orphan.block         = block;
    orphan.hash          = hash;
    orphan.prev_hash     = prev_hash;
    orphan.from_peer     = from_peer;
    orphan.received_time = now;

    // Insert into primary storage.
    orphans_.emplace(hash, std::move(orphan));

    // Update the parent index.
    by_parent_[prev_hash].push_back(hash);

    LOG_DEBUG(core::LogCategory::NET,
        "Added orphan block " + hash.to_hex().substr(0, 16)
        + "... (parent: " + prev_hash.to_hex().substr(0, 16)
        + "..., from peer " + std::to_string(from_peer)
        + ", size: " + std::to_string(block_size)
        + ", pool: " + std::to_string(orphans_.size())
        + "/" + std::to_string(MAX_ORPHAN_BLOCKS) + ")");

    // -----------------------------------------------------------------------
    // Enforce size limit
    // -----------------------------------------------------------------------

    if (orphans_.size() > MAX_ORPHAN_BLOCKS) {
        evict_oldest_locked();
    }

    return true;
}

// ---------------------------------------------------------------------------
// exists
// ---------------------------------------------------------------------------
bool OrphanBlockPool::exists(const core::uint256& hash) const {
    std::unique_lock<std::mutex> lock(mutex_);
    return orphans_.count(hash) > 0;
}

// ---------------------------------------------------------------------------
// get_children
// ---------------------------------------------------------------------------
// When a block arrives that might be the parent of orphan blocks, this
// method retrieves and removes all orphans that reference it.  The caller
// can then attempt to process those blocks in order.
//
// The returned vector may contain multiple orphans if there were competing
// blocks at the same height (a fork scenario).  The caller should handle
// fork resolution appropriately.
//
// Processing is recursive in concept: after processing one orphan, its
// hash should be passed to get_children again to resolve any deeper
// chains of orphans.  This is left to the caller to implement to avoid
// unbounded recursion within this method.
// ---------------------------------------------------------------------------
std::vector<OrphanBlockPool::OrphanBlock> OrphanBlockPool::get_children(
    const core::uint256& parent_hash) {

    std::unique_lock<std::mutex> lock(mutex_);

    std::vector<OrphanBlock> children;

    auto parent_it = by_parent_.find(parent_hash);
    if (parent_it == by_parent_.end()) {
        return children;
    }

    // Copy the list of child hashes (we'll modify the map during removal).
    std::vector<core::uint256> child_hashes = parent_it->second;

    // Remove the parent index entry first.
    by_parent_.erase(parent_it);

    // Retrieve and remove each child orphan.
    for (const auto& child_hash : child_hashes) {
        auto orphan_it = orphans_.find(child_hash);
        if (orphan_it != orphans_.end()) {
            children.push_back(std::move(orphan_it->second));
            orphans_.erase(orphan_it);
        }
    }

    if (!children.empty()) {
        LOG_DEBUG(core::LogCategory::NET,
            "Retrieved " + std::to_string(children.size())
            + " orphan children of block "
            + parent_hash.to_hex().substr(0, 16)
            + "... (pool size: " + std::to_string(orphans_.size()) + ")");

        // Log each child for detailed debugging.
        for (const auto& child : children) {
            LOG_DEBUG(core::LogCategory::NET,
                "  Orphan child: " + child.hash.to_hex().substr(0, 16)
                + "... from peer " + std::to_string(child.from_peer)
                + " (age: " + std::to_string(
                    children.empty() ? 0
                    : (children.front().received_time > 0
                       ? 0 : child.received_time))
                + "s)");
        }
    }

    return children;
}

// ---------------------------------------------------------------------------
// erase
// ---------------------------------------------------------------------------
void OrphanBlockPool::erase(const core::uint256& hash) {
    std::unique_lock<std::mutex> lock(mutex_);
    erase_locked(hash);
}

// ---------------------------------------------------------------------------
// erase_locked (internal)
// ---------------------------------------------------------------------------
// Remove an orphan from both the primary storage and the parent index.
// Must be called with mutex_ held.
//
// The parent index removal is careful to only remove the specific orphan
// hash from the parent's child list, not the entire entry.  This handles
// the case where multiple orphan blocks share the same parent (fork
// scenario).  If the child list becomes empty after removal, the parent
// entry itself is cleaned up.
// ---------------------------------------------------------------------------
void OrphanBlockPool::erase_locked(const core::uint256& hash) {
    auto it = orphans_.find(hash);
    if (it == orphans_.end()) {
        return;
    }

    core::uint256 prev_hash = it->second.prev_hash;

    // Remove from parent index.
    auto parent_it = by_parent_.find(prev_hash);
    if (parent_it != by_parent_.end()) {
        auto& siblings = parent_it->second;
        siblings.erase(
            std::remove_if(siblings.begin(), siblings.end(),
                [&hash](const core::uint256& h) { return h == hash; }),
            siblings.end());

        // Clean up empty parent entries to keep the index compact.
        if (siblings.empty()) {
            by_parent_.erase(parent_it);
        }
    }

    // Remove from primary storage.
    orphans_.erase(it);
}

// ---------------------------------------------------------------------------
// evict_oldest_locked (internal)
// ---------------------------------------------------------------------------
// Finds the orphan with the smallest received_time and removes it.
// This implements a simple LRU-like eviction policy.  Must be called
// with mutex_ held.
// ---------------------------------------------------------------------------
bool OrphanBlockPool::evict_oldest_locked() {
    if (orphans_.empty()) {
        return false;
    }

    // Linear scan to find the oldest.  This is O(n) but acceptable
    // because it only runs when the pool is full (at most MAX_ORPHAN_BLOCKS
    // entries, which is 750).
    auto oldest_it = orphans_.end();
    int64_t oldest_time = std::numeric_limits<int64_t>::max();

    for (auto it = orphans_.begin(); it != orphans_.end(); ++it) {
        if (it->second.received_time < oldest_time) {
            oldest_time = it->second.received_time;
            oldest_it = it;
        }
    }

    if (oldest_it == orphans_.end()) {
        return false;  // safety: should never happen
    }

    core::uint256 hash = oldest_it->first;

    LOG_DEBUG(core::LogCategory::NET,
        "Evicting oldest orphan block "
        + hash.to_hex().substr(0, 16)
        + "... from peer " + std::to_string(oldest_it->second.from_peer)
        + " (age: "
        + std::to_string(
            // We don't have "now" here, so just log the raw time.
            oldest_it->second.received_time)
        + ") to enforce size limit");

    erase_locked(hash);
    return true;
}

// ---------------------------------------------------------------------------
// erase_for_peer
// ---------------------------------------------------------------------------
// Remove all orphan blocks received from a specific peer.  This is called
// when a peer is banned or disconnected due to misbehavior, as we should
// not trust any data from that peer.
//
// Note: if a block was independently received from multiple peers, it
// would exist with the first peer's ID.  This means some blocks might
// survive peer eviction even though the same block was also sent by the
// banned peer.  This is acceptable for safety.
// ---------------------------------------------------------------------------
void OrphanBlockPool::erase_for_peer(uint64_t peer_id) {
    std::unique_lock<std::mutex> lock(mutex_);

    // Collect hashes of all orphans from this peer.
    std::vector<core::uint256> to_remove;
    to_remove.reserve(16);  // reasonable initial capacity

    for (const auto& [hash, orphan] : orphans_) {
        if (orphan.from_peer == peer_id) {
            to_remove.push_back(hash);
        }
    }

    // Remove them all.
    for (const auto& hash : to_remove) {
        erase_locked(hash);
    }

    if (!to_remove.empty()) {
        LOG_DEBUG(core::LogCategory::NET,
            "Removed " + std::to_string(to_remove.size())
            + " orphan blocks from peer " + std::to_string(peer_id)
            + " (pool size: " + std::to_string(orphans_.size())
            + "/" + std::to_string(MAX_ORPHAN_BLOCKS) + ")");
    }
}

// ---------------------------------------------------------------------------
// expire
// ---------------------------------------------------------------------------
// Removes all orphan blocks that are older than ORPHAN_BLOCK_EXPIRY
// seconds.  This prevents stale orphans from consuming memory indefinitely.
// Called periodically by the sync manager (typically every 60 seconds).
//
// The expiry threshold is ORPHAN_BLOCK_EXPIRY = 3600 seconds (1 hour).
// This is generous enough that most legitimate orphans will be resolved
// (their parent will arrive within a few minutes at most), but short
// enough that blocks from extended partitions or DoS attacks are cleaned
// up.
// ---------------------------------------------------------------------------
void OrphanBlockPool::expire(int64_t now) {
    std::unique_lock<std::mutex> lock(mutex_);

    int64_t cutoff = now - ORPHAN_BLOCK_EXPIRY;

    // Collect expired orphan hashes.
    std::vector<core::uint256> expired;
    for (const auto& [hash, orphan] : orphans_) {
        if (orphan.received_time < cutoff) {
            expired.push_back(hash);
        }
    }

    // Remove expired entries.
    for (const auto& hash : expired) {
        erase_locked(hash);
    }

    if (!expired.empty()) {
        LOG_DEBUG(core::LogCategory::NET,
            "Expired " + std::to_string(expired.size())
            + " orphan blocks older than "
            + std::to_string(ORPHAN_BLOCK_EXPIRY)
            + " seconds (pool size: "
            + std::to_string(orphans_.size())
            + "/" + std::to_string(MAX_ORPHAN_BLOCKS) + ")");
    }
}

// ---------------------------------------------------------------------------
// limit_size
// ---------------------------------------------------------------------------
// Enforces the MAX_ORPHAN_BLOCKS limit by repeatedly removing the oldest
// orphan block until the pool is at or below the limit.  This is a more
// aggressive version of the per-add eviction in add() and is useful when
// the limit has been lowered at runtime or after a batch of adds.
// ---------------------------------------------------------------------------
void OrphanBlockPool::limit_size() {
    std::unique_lock<std::mutex> lock(mutex_);

    size_t removed_count = 0;

    while (orphans_.size() > MAX_ORPHAN_BLOCKS) {
        if (!evict_oldest_locked()) {
            break;  // safety: pool is empty
        }
        ++removed_count;
    }

    if (removed_count > 0) {
        LOG_DEBUG(core::LogCategory::NET,
            "Orphan pool size limit enforced: removed "
            + std::to_string(removed_count) + " oldest orphans (pool size: "
            + std::to_string(orphans_.size()) + "/"
            + std::to_string(MAX_ORPHAN_BLOCKS) + ")");
    }
}

// ---------------------------------------------------------------------------
// size
// ---------------------------------------------------------------------------
size_t OrphanBlockPool::size() const {
    std::unique_lock<std::mutex> lock(mutex_);
    return orphans_.size();
}

// ---------------------------------------------------------------------------
// parent_count
// ---------------------------------------------------------------------------
// Returns the number of distinct parent hashes referenced by orphan blocks.
// A higher count relative to size() indicates many unrelated orphans (from
// different parts of the chain), while a count close to 1 indicates a
// chain of consecutive orphan blocks (common during IBD).
// ---------------------------------------------------------------------------
size_t OrphanBlockPool::parent_count() const {
    std::unique_lock<std::mutex> lock(mutex_);
    return by_parent_.size();
}

// ---------------------------------------------------------------------------
// missing_parents
// ---------------------------------------------------------------------------
// Returns a deduplicated list of all parent hashes that orphan blocks are
// waiting for.  The sync manager can use this to issue GETDATA requests
// for these blocks from available peers.
//
// Note: the returned hashes are not in any particular order.
// ---------------------------------------------------------------------------
std::vector<core::uint256> OrphanBlockPool::missing_parents() const {
    std::unique_lock<std::mutex> lock(mutex_);

    std::vector<core::uint256> parents;
    parents.reserve(by_parent_.size());

    for (const auto& [parent_hash, children] : by_parent_) {
        if (!children.empty()) {
            parents.push_back(parent_hash);
        }
    }

    return parents;
}

} // namespace net::sync
