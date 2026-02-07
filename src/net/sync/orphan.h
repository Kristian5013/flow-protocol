#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Network orphan block handling
// ---------------------------------------------------------------------------
// Manages blocks received from the network whose parent block is not yet
// known.  This is distinct from mempool/orphan.h which handles orphan
// transactions.  Orphan blocks are held temporarily until their parent
// arrives, at which point they can be processed in order.
//
// Size and age limits prevent memory exhaustion from misbehaving peers.
// A secondary index by parent hash enables efficient retrieval when a
// parent block becomes available.
//
// Thread safety: all public methods acquire the internal mutex and are safe
// to call from any thread.
// ---------------------------------------------------------------------------

#include "core/types.h"
#include "primitives/block.h"

#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace net::sync {

class OrphanBlockPool {
public:
    /// Maximum number of orphan blocks to hold in memory.
    static constexpr size_t MAX_ORPHAN_BLOCKS = 750;

    /// Maximum age of an orphan block in seconds before expiry (1 hour).
    static constexpr int64_t ORPHAN_BLOCK_EXPIRY = 3600;

    /// Maximum block size we will accept as an orphan (4 MB).
    /// Prevents DoS by very large invalid blocks.
    static constexpr size_t MAX_ORPHAN_BLOCK_SIZE = 4 * 1024 * 1024;

    /// Data associated with a single orphan block.
    struct OrphanBlock {
        primitives::Block block;       ///< The full block data.
        core::uint256     hash;        ///< Block hash (cached).
        core::uint256     prev_hash;   ///< Hash of the missing parent.
        uint64_t          from_peer;   ///< Peer that sent this block.
        int64_t           received_time; ///< When we received it (epoch secs).
    };

    /// Add an orphan block to the pool.
    /// @param block     The block whose parent is unknown.
    /// @param from_peer Peer that sent this block.
    /// @param now       Current time in seconds since epoch.
    /// @return true if the block was added, false if it already exists or
    ///         is otherwise rejected.
    bool add(const primitives::Block& block, uint64_t from_peer, int64_t now);

    /// Check whether an orphan with the given hash exists in the pool.
    bool exists(const core::uint256& hash) const;

    /// Retrieve all orphan blocks whose parent hash matches the given hash.
    /// The returned orphans are removed from the pool.
    /// @param parent_hash Hash of the parent block that is now available.
    std::vector<OrphanBlock> get_children(const core::uint256& parent_hash);

    /// Remove a specific orphan by hash.
    void erase(const core::uint256& hash);

    /// Remove all orphans received from a specific peer.
    void erase_for_peer(uint64_t peer_id);

    /// Remove orphan blocks older than ORPHAN_BLOCK_EXPIRY.
    /// @param now Current time in seconds since epoch.
    void expire(int64_t now);

    /// Enforce the MAX_ORPHAN_BLOCKS size limit by removing the oldest
    /// orphans until the pool is within bounds.
    void limit_size();

    /// Returns the current number of orphan blocks in the pool.
    size_t size() const;

    /// Returns the number of distinct parent hashes referenced by orphans.
    size_t parent_count() const;

    /// Returns a list of all unique parent hashes that orphan blocks are
    /// waiting for.  Useful for requesting missing blocks from peers.
    std::vector<core::uint256> missing_parents() const;

private:
    /// Hash functor for core::uint256 using the first sizeof(size_t) bytes.
    struct Uint256Hash {
        size_t operator()(const core::uint256& h) const noexcept {
            size_t result = 0;
            std::memcpy(&result, h.data(), sizeof(result));
            return result;
        }
    };

    /// Primary storage: block hash -> OrphanBlock.
    std::unordered_map<core::uint256, OrphanBlock, Uint256Hash> orphans_;

    /// Secondary index: parent hash -> list of orphan hashes that reference
    /// that parent.  Enables efficient lookup when a parent block arrives.
    std::unordered_map<core::uint256, std::vector<core::uint256>,
                       Uint256Hash> by_parent_;

    mutable std::mutex mutex_;

    /// Internal helper: remove an orphan from all indices.
    /// Must be called with mutex_ held.
    void erase_locked(const core::uint256& hash);

    /// Internal helper: find and remove the oldest orphan.
    /// Must be called with mutex_ held.  Returns true if an orphan was
    /// removed, false if the pool was empty.
    bool evict_oldest_locked();
};

} // namespace net::sync
