// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/sync/block_sync.h"

#include "chain/block_index.h"
#include "chain/chain.h"
#include "core/logging.h"
#include "core/types.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <mutex>
#include <string>
#include <vector>

namespace net::sync {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

BlockSync::BlockSync() = default;

// ---------------------------------------------------------------------------
// get_blocks_to_download
// ---------------------------------------------------------------------------
// Walks the header chain backwards from best_header to the active chain tip
// to find blocks that need downloading.  Blocks are assigned to the
// requesting peer up to the per-peer and global limits.
//
// The algorithm:
//   1. Determine how many slots are available both globally and for the
//      specific peer.
//   2. First, try to assign blocks from the existing download queue
//      (blocks that were previously queued due to peer disconnect or
//      failed request).
//   3. Then, walk from best_header backwards, collecting block indices
//      that don't have data on disk yet, are not already in-flight, and
//      are not already in the download queue.
//   4. Sort all candidates by height (ascending -- download low blocks
//      first for ordered validation).
//   5. Assign up to max_blocks to the peer, respecting the global
//      MAX_BLOCKS_IN_TRANSIT cap.
//   6. Each assigned block is recorded in in_flight_ with the current time.
//
// The MAX_REORG_DEPTH constant limits how far back we will look.  During
// a large reorg, we do not want to re-download hundreds of blocks if
// they are deeper than 288 blocks below the best header.
// ---------------------------------------------------------------------------
std::vector<core::uint256> BlockSync::get_blocks_to_download(
    uint64_t peer_id,
    const chain::Chain& active_chain,
    const chain::BlockIndex* best_header,
    int max_blocks) {

    std::unique_lock<std::mutex> lock(mutex_);

    std::vector<core::uint256> to_download;

    if (best_header == nullptr) {
        return to_download;
    }

    // -----------------------------------------------------------------------
    // Determine available slots
    // -----------------------------------------------------------------------

    int global_slots = MAX_BLOCKS_IN_TRANSIT
                       - static_cast<int>(in_flight_.size());
    if (global_slots <= 0) {
        LOG_DEBUG(core::LogCategory::NET,
            "Block download: global in-flight limit reached ("
            + std::to_string(in_flight_.size()) + "/"
            + std::to_string(MAX_BLOCKS_IN_TRANSIT) + ")");
        return to_download;
    }

    // Count how many blocks are already in flight for this peer.
    int peer_in_flight = 0;
    for (const auto& [hash, req] : in_flight_) {
        if (req.peer_id == peer_id) {
            ++peer_in_flight;
        }
    }

    int peer_slots = max_blocks - peer_in_flight;
    if (peer_slots <= 0) {
        LOG_DEBUG(core::LogCategory::NET,
            "Block download: per-peer limit reached for peer "
            + std::to_string(peer_id) + " ("
            + std::to_string(peer_in_flight) + "/"
            + std::to_string(max_blocks) + ")");
        return to_download;
    }

    // Effective maximum for this call.
    int effective_max = std::min(global_slots, peer_slots);

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    // -----------------------------------------------------------------------
    // Phase 1: drain the existing download queue
    // -----------------------------------------------------------------------
    // Blocks in the queue are from previous failed attempts or disconnected
    // peers.  They should be retried before requesting new blocks.

    int assigned_from_queue = 0;

    if (!download_queue_.empty()) {
        // Sort the queue so lowest-height blocks are tried first.
        sort_queue_locked();

        std::vector<core::uint256> remaining_queue;
        remaining_queue.reserve(download_queue_.size());

        for (const auto& queued_hash : download_queue_) {
            if (assigned_from_queue >= effective_max) {
                remaining_queue.push_back(queued_hash);
                continue;
            }

            // Skip if it somehow got into in-flight already.
            if (in_flight_.count(queued_hash) > 0) {
                continue;
            }

            // Look up the height from queue_heights_.
            int height = 0;
            auto height_it = queue_heights_.find(queued_hash);
            if (height_it != queue_heights_.end()) {
                height = height_it->second;
            }

            BlockRequest request;
            request.hash         = queued_hash;
            request.height       = height;
            request.peer_id      = peer_id;
            request.request_time = now;

            in_flight_.emplace(queued_hash, request);
            to_download.push_back(queued_hash);
            queue_heights_.erase(queued_hash);
            ++assigned_from_queue;
        }

        download_queue_ = std::move(remaining_queue);
    }

    if (assigned_from_queue > 0) {
        LOG_DEBUG(core::LogCategory::NET,
            "Assigned " + std::to_string(assigned_from_queue)
            + " blocks from retry queue to peer "
            + std::to_string(peer_id));
    }

    // Adjust remaining slots.
    effective_max -= assigned_from_queue;
    if (effective_max <= 0) {
        return to_download;
    }

    // -----------------------------------------------------------------------
    // Phase 2: walk the header chain for new blocks to download
    // -----------------------------------------------------------------------

    struct Candidate {
        core::uint256 hash;
        int height;
    };
    std::vector<Candidate> candidates;

    // Compute the minimum height we're willing to download (prevents
    // deep reorg re-downloads).
    int min_height = 0;
    if (best_header->height > MAX_REORG_DEPTH) {
        min_height = best_header->height - MAX_REORG_DEPTH;
    }

    const chain::BlockIndex* walk = best_header;
    int walk_count = 0;
    static constexpr int MAX_WALK_DISTANCE = 1024;

    while (walk != nullptr
           && !active_chain.contains(walk)
           && walk->height >= min_height
           && walk_count < MAX_WALK_DISTANCE) {

        ++walk_count;

        // Skip blocks that already have data on disk.
        if (walk->has_data()) {
            walk = walk->prev;
            continue;
        }

        // Skip blocks already in flight.
        if (in_flight_.count(walk->block_hash) > 0) {
            walk = walk->prev;
            continue;
        }

        // Skip blocks already in the download queue.
        if (queue_heights_.count(walk->block_hash) > 0) {
            walk = walk->prev;
            continue;
        }

        // Skip failed blocks.
        if (walk->is_failed()) {
            walk = walk->prev;
            continue;
        }

        candidates.push_back({walk->block_hash, walk->height});
        walk = walk->prev;
    }

    if (candidates.empty()) {
        return to_download;
    }

    // Sort by height ascending so we download blocks in order.
    // This allows the validation pipeline to process blocks sequentially
    // without having to wait for out-of-order deliveries.
    std::sort(candidates.begin(), candidates.end(),
        [](const Candidate& a, const Candidate& b) {
            return a.height < b.height;
        });

    // -----------------------------------------------------------------------
    // Phase 3: assign candidates to the peer
    // -----------------------------------------------------------------------

    int assigned_new = 0;
    for (const auto& candidate : candidates) {
        if (assigned_new >= effective_max) {
            break;
        }

        BlockRequest request;
        request.hash         = candidate.hash;
        request.height       = candidate.height;
        request.peer_id      = peer_id;
        request.request_time = now;

        in_flight_.emplace(candidate.hash, request);
        to_download.push_back(candidate.hash);
        ++assigned_new;
    }

    // -----------------------------------------------------------------------
    // Log the assignment
    // -----------------------------------------------------------------------

    int total_assigned = assigned_from_queue + assigned_new;
    if (total_assigned > 0) {
        // Determine the height range of assigned blocks for logging.
        int min_assigned_height = std::numeric_limits<int>::max();
        int max_assigned_height = std::numeric_limits<int>::min();
        for (const auto& hash : to_download) {
            auto it = in_flight_.find(hash);
            if (it != in_flight_.end()) {
                min_assigned_height = std::min(min_assigned_height,
                                               it->second.height);
                max_assigned_height = std::max(max_assigned_height,
                                               it->second.height);
            }
        }

        LOG_DEBUG(core::LogCategory::NET,
            "Requesting " + std::to_string(total_assigned)
            + " blocks from peer " + std::to_string(peer_id)
            + " (heights " + std::to_string(min_assigned_height)
            + ".." + std::to_string(max_assigned_height)
            + ", " + std::to_string(assigned_from_queue) + " from queue"
            + ", " + std::to_string(assigned_new) + " new"
            + ", total in-flight: "
            + std::to_string(in_flight_.size()) + ")");
    }

    return to_download;
}

// ---------------------------------------------------------------------------
// block_received
// ---------------------------------------------------------------------------
// A block was successfully received and validated.  Remove it from the
// in-flight set.  Also remove from the download queue if it was queued
// (e.g., after a failed attempt was re-queued and then completed via a
// different path).
// ---------------------------------------------------------------------------
void BlockSync::block_received(const core::uint256& hash) {
    std::unique_lock<std::mutex> lock(mutex_);

    auto it = in_flight_.find(hash);
    if (it != in_flight_.end()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()
            - it->second.request_time;

        LOG_DEBUG(core::LogCategory::NET,
            "Block received: height " + std::to_string(it->second.height)
            + " from peer " + std::to_string(it->second.peer_id)
            + " in " + std::to_string(elapsed) + "s"
            + " (" + hash.to_hex().substr(0, 16) + "...)");
        in_flight_.erase(it);
    }

    // Also remove from the download queue if present.
    auto queue_it = std::find_if(
        download_queue_.begin(), download_queue_.end(),
        [&hash](const core::uint256& queued) {
            return queued == hash;
        });

    if (queue_it != download_queue_.end()) {
        download_queue_.erase(queue_it);
    }

    queue_heights_.erase(hash);
}

// ---------------------------------------------------------------------------
// block_failed
// ---------------------------------------------------------------------------
// A block request failed (e.g., peer sent invalid data, or NOTFOUND).
// Remove from in-flight and push back onto the download queue so it can
// be retried from a different peer.
// ---------------------------------------------------------------------------
void BlockSync::block_failed(const core::uint256& hash) {
    std::unique_lock<std::mutex> lock(mutex_);

    auto it = in_flight_.find(hash);
    if (it != in_flight_.end()) {
        LOG_WARN(core::LogCategory::NET,
            "Block request failed: height "
            + std::to_string(it->second.height)
            + " from peer " + std::to_string(it->second.peer_id)
            + " (" + hash.to_hex().substr(0, 16) + "...)");

        // Record the height before erasing.
        int height = it->second.height;

        // Re-queue for download from a different peer.
        download_queue_.push_back(hash);
        queue_heights_[hash] = height;
        in_flight_.erase(it);
    }
}

// ---------------------------------------------------------------------------
// peer_disconnected
// ---------------------------------------------------------------------------
// All blocks in-flight from this peer need to be re-queued so they can be
// downloaded from other peers.  We preserve the height information so the
// queue maintains its ordering.
// ---------------------------------------------------------------------------
void BlockSync::peer_disconnected(uint64_t peer_id) {
    std::unique_lock<std::mutex> lock(mutex_);

    std::vector<core::uint256> to_requeue;

    for (const auto& [hash, req] : in_flight_) {
        if (req.peer_id == peer_id) {
            to_requeue.push_back(hash);
        }
    }

    for (const auto& hash : to_requeue) {
        auto it = in_flight_.find(hash);
        if (it != in_flight_.end()) {
            queue_heights_[hash] = it->second.height;
            download_queue_.push_back(hash);
            in_flight_.erase(it);
        }
    }

    if (!to_requeue.empty()) {
        LOG_DEBUG(core::LogCategory::NET,
            "Peer " + std::to_string(peer_id)
            + " disconnected: re-queued "
            + std::to_string(to_requeue.size())
            + " in-flight blocks for download"
            + " (queue size: " + std::to_string(download_queue_.size())
            + ", in-flight: " + std::to_string(in_flight_.size()) + ")");
    }
}

// ---------------------------------------------------------------------------
// get_timed_out
// ---------------------------------------------------------------------------
// Scan all in-flight requests and return those that have exceeded the
// BLOCK_TIMEOUT.  Timed-out requests are removed from in-flight and
// added back to the download queue for retry from a different peer.
//
// The caller should use the returned list to:
//   1. Log the timeout and potentially penalize the peer.
//   2. Request the blocks from alternative peers.
// ---------------------------------------------------------------------------
std::vector<BlockSync::BlockRequest> BlockSync::get_timed_out(int64_t now) {
    std::unique_lock<std::mutex> lock(mutex_);

    std::vector<BlockRequest> timed_out;
    std::vector<core::uint256> to_remove;

    for (const auto& [hash, req] : in_flight_) {
        int64_t elapsed = now - req.request_time;
        if (elapsed > BLOCK_TIMEOUT) {
            timed_out.push_back(req);
            to_remove.push_back(hash);
        }
    }

    // Move timed-out entries back to the download queue.
    for (const auto& hash : to_remove) {
        auto it = in_flight_.find(hash);
        if (it != in_flight_.end()) {
            queue_heights_[hash] = it->second.height;
            download_queue_.push_back(hash);
            in_flight_.erase(it);
        }
    }

    if (!timed_out.empty()) {
        LOG_WARN(core::LogCategory::NET,
            std::to_string(timed_out.size())
            + " block requests timed out after "
            + std::to_string(BLOCK_TIMEOUT)
            + " seconds -- re-queued for download");

        for (const auto& req : timed_out) {
            LOG_DEBUG(core::LogCategory::NET,
                "  Timed out: height " + std::to_string(req.height)
                + " from peer " + std::to_string(req.peer_id)
                + " (waited " + std::to_string(now - req.request_time) + "s"
                + ", " + req.hash.to_hex().substr(0, 16) + "...)");
        }
    }

    return timed_out;
}

// ---------------------------------------------------------------------------
// is_peer_stalling
// ---------------------------------------------------------------------------
// A peer is considered stalling if:
//   1. It has at least one block in-flight.
//   2. The block with the lowest height assigned to this peer is also the
//      lowest-height block across ALL in-flight blocks (i.e., this peer
//      is blocking the pipeline).
//   3. That block has been in-flight for more than BLOCK_STALLING_TIMEOUT
//      seconds.
//
// This detection helps avoid situations where one slow peer holds up the
// entire block validation pipeline.  When a stalling peer is detected,
// the sync manager can request the same block from another peer.
// ---------------------------------------------------------------------------
bool BlockSync::is_peer_stalling(uint64_t peer_id, int64_t now) const {
    std::unique_lock<std::mutex> lock(mutex_);

    if (in_flight_.empty()) {
        return false;
    }

    // Find the globally lowest-height in-flight block.
    int global_min_height = std::numeric_limits<int>::max();
    for (const auto& [hash, req] : in_flight_) {
        if (req.height < global_min_height) {
            global_min_height = req.height;
        }
    }

    // Find the lowest-height block for this specific peer.
    int peer_min_height = std::numeric_limits<int>::max();
    int64_t peer_min_request_time = 0;
    bool has_peer_blocks = false;

    for (const auto& [hash, req] : in_flight_) {
        if (req.peer_id == peer_id) {
            has_peer_blocks = true;
            if (req.height < peer_min_height) {
                peer_min_height = req.height;
                peer_min_request_time = req.request_time;
            }
        }
    }

    if (!has_peer_blocks) {
        return false;
    }

    // This peer is only "stalling" if it holds the globally lowest block.
    if (peer_min_height != global_min_height) {
        return false;
    }

    // Check if it has been too long.
    int64_t elapsed = now - peer_min_request_time;
    if (elapsed > BLOCK_STALLING_TIMEOUT) {
        LOG_DEBUG(core::LogCategory::NET,
            "Peer " + std::to_string(peer_id)
            + " is stalling: block at height "
            + std::to_string(peer_min_height)
            + " has been in-flight for "
            + std::to_string(elapsed) + "s"
            + " (threshold: "
            + std::to_string(BLOCK_STALLING_TIMEOUT) + "s)");
        return true;
    }

    return false;
}

// ---------------------------------------------------------------------------
// is_in_flight
// ---------------------------------------------------------------------------
bool BlockSync::is_in_flight(const core::uint256& hash) const {
    std::unique_lock<std::mutex> lock(mutex_);
    return in_flight_.count(hash) > 0;
}

// ---------------------------------------------------------------------------
// blocks_in_flight
// ---------------------------------------------------------------------------
int BlockSync::blocks_in_flight(uint64_t peer_id) const {
    std::unique_lock<std::mutex> lock(mutex_);

    int count = 0;
    for (const auto& [hash, req] : in_flight_) {
        if (req.peer_id == peer_id) {
            ++count;
        }
    }
    return count;
}

// ---------------------------------------------------------------------------
// total_in_flight
// ---------------------------------------------------------------------------
int BlockSync::total_in_flight() const {
    std::unique_lock<std::mutex> lock(mutex_);
    return static_cast<int>(in_flight_.size());
}

// ---------------------------------------------------------------------------
// queue_size
// ---------------------------------------------------------------------------
int BlockSync::queue_size() const {
    std::unique_lock<std::mutex> lock(mutex_);
    return static_cast<int>(download_queue_.size());
}

// ---------------------------------------------------------------------------
// clear
// ---------------------------------------------------------------------------
void BlockSync::clear() {
    std::unique_lock<std::mutex> lock(mutex_);

    if (!in_flight_.empty() || !download_queue_.empty()) {
        LOG_DEBUG(core::LogCategory::NET,
            "Clearing block sync state: "
            + std::to_string(in_flight_.size()) + " in-flight, "
            + std::to_string(download_queue_.size()) + " queued");
    }

    in_flight_.clear();
    download_queue_.clear();
    queue_heights_.clear();
}

// ---------------------------------------------------------------------------
// sort_queue_locked (private)
// ---------------------------------------------------------------------------
// Sorts the download queue by block height in ascending order using the
// queue_heights_ lookup table.  Blocks with unknown height (missing from
// the map) are placed at the end.  Must be called with mutex_ held.
// ---------------------------------------------------------------------------
void BlockSync::sort_queue_locked() {
    std::sort(download_queue_.begin(), download_queue_.end(),
        [this](const core::uint256& a, const core::uint256& b) {
            int ha = 0;
            int hb = 0;

            auto it_a = queue_heights_.find(a);
            if (it_a != queue_heights_.end()) {
                ha = it_a->second;
            } else {
                ha = std::numeric_limits<int>::max();
            }

            auto it_b = queue_heights_.find(b);
            if (it_b != queue_heights_.end()) {
                hb = it_b->second;
            } else {
                hb = std::numeric_limits<int>::max();
            }

            return ha < hb;
        });
}

} // namespace net::sync
