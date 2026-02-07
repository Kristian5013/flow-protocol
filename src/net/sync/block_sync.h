#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Block download manager
// ---------------------------------------------------------------------------
// Manages the download of full blocks from peers once headers have been
// validated.  Tracks in-flight requests, enforces per-peer limits, detects
// timeouts, and maintains the download queue ordered by block height.
//
// The download strategy prioritizes blocks in ascending height order so
// that validation can proceed without gaps.  When a peer disconnects or
// a request fails, blocks are moved back to the download queue for retry
// from a different peer.
//
// Thread safety: all public methods acquire the internal mutex and are safe
// to call from any thread.
// ---------------------------------------------------------------------------

#include "chain/block_index.h"
#include "chain/chain.h"
#include "core/types.h"

#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace net::sync {

class BlockSync {
public:
    /// Maximum number of blocks we will request simultaneously across all
    /// peers combined.
    static constexpr int MAX_BLOCKS_IN_TRANSIT = 16;

    /// Timeout in seconds for a single block request.  Equal to one block
    /// interval (600 seconds = 10 minutes).
    static constexpr int BLOCK_TIMEOUT = 600;

    /// Maximum number of blocks to request from a single peer at once.
    static constexpr int MAX_BLOCKS_PER_PEER = 16;

    /// If a peer has been stalling (not delivering the first in-flight
    /// block) for this many seconds, we may request from another peer.
    static constexpr int BLOCK_STALLING_TIMEOUT = 5;

    /// Maximum depth below the tip that we will request blocks for.
    /// Blocks deeper than this are ignored (prevents re-downloading
    /// very old blocks during reorgs).
    static constexpr int MAX_REORG_DEPTH = 288;

    BlockSync();

    /// A single pending block request.
    struct BlockRequest {
        core::uint256 hash;         ///< Hash of the requested block.
        int           height;       ///< Height in the chain.
        uint64_t      peer_id;      ///< Peer we sent the request to.
        int64_t       request_time; ///< Time the request was sent (epoch secs).
    };

    /// Determine which blocks should be downloaded next from the given peer.
    /// Walks the header chain from the active tip to best_header, skipping
    /// blocks that are already in-flight or already on disk.
    /// @param peer_id       The peer to assign downloads to.
    /// @param active_chain  The current best chain (blocks already validated).
    /// @param best_header   The tip of the validated header chain.
    /// @param max_blocks    Maximum blocks to request (default MAX_BLOCKS_PER_PEER).
    /// @return Vector of block hashes to request from this peer.
    std::vector<core::uint256> get_blocks_to_download(
        uint64_t peer_id,
        const chain::Chain& active_chain,
        const chain::BlockIndex* best_header,
        int max_blocks = MAX_BLOCKS_PER_PEER);

    /// Mark a block as successfully received.  Removes it from in-flight
    /// tracking.
    void block_received(const core::uint256& hash);

    /// Mark a block request as failed.  The block is removed from in-flight
    /// and placed back into the download queue for retry.
    void block_failed(const core::uint256& hash);

    /// Handle a peer disconnecting.  All in-flight requests assigned to
    /// that peer are moved back to the download queue.
    void peer_disconnected(uint64_t peer_id);

    /// Return all block requests that have exceeded BLOCK_TIMEOUT.
    /// @param now Current time in seconds since epoch.
    std::vector<BlockRequest> get_timed_out(int64_t now);

    /// Check if a specific peer appears to be stalling.  A peer is
    /// stalling if it has the lowest-height in-flight block and has not
    /// delivered it within BLOCK_STALLING_TIMEOUT seconds.
    /// @param peer_id Peer to check.
    /// @param now     Current time in seconds since epoch.
    bool is_peer_stalling(uint64_t peer_id, int64_t now) const;

    /// Returns true if the specified block hash is currently in-flight.
    bool is_in_flight(const core::uint256& hash) const;

    /// Returns the number of blocks currently in-flight for a specific peer.
    int blocks_in_flight(uint64_t peer_id) const;

    /// Returns the total number of blocks currently in-flight across all peers.
    int total_in_flight() const;

    /// Returns the number of blocks waiting in the download queue.
    int queue_size() const;

    /// Clear all state (in-flight and queued).
    void clear();

private:
    /// Hash functor for core::uint256 using the first sizeof(size_t) bytes.
    struct Uint256Hash {
        size_t operator()(const core::uint256& h) const noexcept {
            size_t result = 0;
            std::memcpy(&result, h.data(), sizeof(result));
            return result;
        }
    };

    /// Map from block hash to in-flight request metadata.
    std::unordered_map<core::uint256, BlockRequest, Uint256Hash> in_flight_;

    /// Ordered queue of block hashes waiting to be downloaded (by height).
    std::vector<core::uint256> download_queue_;

    /// Map from block hash to height for download queue entries (for O(1)
    /// height lookup when sorting).
    std::unordered_map<core::uint256, int, Uint256Hash> queue_heights_;

    mutable std::mutex mutex_;

    /// Internal: ensure the download queue is sorted by height (ascending).
    /// Must be called with mutex_ held.
    void sort_queue_locked();
};

} // namespace net::sync
