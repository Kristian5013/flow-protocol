#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Headers-first synchronization
// ---------------------------------------------------------------------------
// Manages the process of downloading block headers from a selected sync peer.
// Implements headers-first IBD (Initial Block Download) where headers are
// fetched before block data, allowing the node to validate the chain of
// proof-of-work before committing to downloading full blocks.
//
// Thread safety: all public methods acquire the internal mutex and are safe
// to call from any thread.
// ---------------------------------------------------------------------------

#include "chain/chain.h"
#include "core/error.h"
#include "core/types.h"
#include "primitives/block_header.h"

#include <cstdint>
#include <mutex>
#include <vector>

namespace net::sync {

class HeadersSync {
public:
    /// Maximum headers a peer may send in a single HEADERS message.
    static constexpr int MAX_HEADERS_PER_REQUEST = 2000;

    /// Maximum number of consecutive headers that fail to connect to our
    /// chain before we disconnect the peer.
    static constexpr int MAX_UNCONNECTING_HEADERS = 10;

    /// Timeout in seconds for a GETHEADERS request before we consider
    /// the sync stalled.
    static constexpr int HEADERS_TIMEOUT = 120;

    /// Minimum time between log messages about sync progress (seconds).
    static constexpr int PROGRESS_LOG_INTERVAL = 10;

    HeadersSync();

    /// Begin syncing headers from the specified peer.
    /// @param peer_id     Identifier of the peer to sync from.
    /// @param peer_height Best height reported by the peer.
    void start_sync(uint64_t peer_id, int32_t peer_height);

    /// Process a received HEADERS message from a peer.
    /// Validates that headers connect to the chain and returns the list
    /// of new headers accepted.  Returns an error if headers are invalid
    /// or from the wrong peer.
    /// @param peer_id        Peer that sent the headers.
    /// @param headers        The block headers received.
    /// @param current_height Our current best chain height.
    core::Result<std::vector<primitives::BlockHeader>> process_headers(
        uint64_t peer_id,
        const std::vector<primitives::BlockHeader>& headers,
        int current_height);

    /// Build a block locator for a GETHEADERS request from the active chain.
    /// Returns the locator hashes to include in the message.
    std::vector<core::uint256> get_locator(
        const chain::Chain& active_chain) const;

    /// Returns true if a header sync is currently in progress.
    bool is_syncing() const;

    /// Returns the peer ID we are currently syncing from.
    uint64_t sync_peer() const;

    /// Returns the height reported by the sync peer.
    int32_t peer_height() const;

    /// Returns the total number of headers received during this sync session.
    int64_t total_headers_received() const;

    /// Handle disconnection of a peer.  If the disconnected peer is our
    /// sync peer, the sync state is reset.
    void peer_disconnected(uint64_t peer_id);

    /// Returns true if the current sync has timed out.
    /// @param now Current time in seconds since epoch.
    bool is_timed_out(int64_t now) const;

    /// Returns the estimated sync progress as a fraction [0.0, 1.0].
    /// Based on the difference between current_height and peer_height.
    double estimated_progress(int current_height) const;

    /// Reset all sync state, allowing a fresh sync to begin.
    void reset();

private:
    uint64_t      sync_peer_              = 0;
    int32_t       peer_height_            = 0;
    int64_t       last_request_time_      = 0;
    int64_t       sync_start_time_        = 0;
    int32_t       sync_start_height_      = 0;
    core::uint256 last_header_hash_;
    int           unconnecting_count_     = 0;
    int64_t       total_headers_received_ = 0;
    int64_t       last_progress_log_time_ = 0;
    bool          syncing_                = false;
    mutable std::mutex mutex_;

    /// Log periodic sync progress.  Must be called with mutex_ held.
    void log_progress_locked(int current_height, int64_t now);
};

} // namespace net::sync
