// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/sync/headers_sync.h"

#include "chain/chain.h"
#include "core/error.h"
#include "core/logging.h"
#include "core/types.h"
#include "primitives/block_header.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace net::sync {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

HeadersSync::HeadersSync() = default;

// ---------------------------------------------------------------------------
// start_sync
// ---------------------------------------------------------------------------
// Begin syncing headers from the specified peer.  Only one peer may be the
// active sync peer at a time.  If a sync is already in progress, it is
// silently replaced (the caller is expected to check is_syncing() first
// and handle the previous sync peer appropriately).
//
// The sync starts by recording the peer's reported best height, which is
// used both for progress estimation and for detecting when the sync is
// complete.  The actual download begins when get_locator() is called and
// the resulting GETHEADERS message is sent to the peer.
// ---------------------------------------------------------------------------
void HeadersSync::start_sync(uint64_t peer_id, int32_t peer_height) {
    std::unique_lock<std::mutex> lock(mutex_);

    // Log if we are replacing an existing sync peer.
    if (syncing_ && sync_peer_ != peer_id) {
        LOG_INFO(core::LogCategory::NET,
            "Replacing sync peer " + std::to_string(sync_peer_)
            + " with peer " + std::to_string(peer_id));
    }

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    sync_peer_              = peer_id;
    peer_height_            = peer_height;
    last_request_time_      = 0;    // will be set when get_locator is called
    sync_start_time_        = now;
    sync_start_height_      = 0;    // will be set on first process_headers call
    last_header_hash_       = core::uint256{};
    unconnecting_count_     = 0;
    total_headers_received_ = 0;
    last_progress_log_time_ = 0;
    syncing_                = true;

    LOG_INFO(core::LogCategory::NET,
        "Starting headers sync from peer " + std::to_string(peer_id)
        + " (reported height " + std::to_string(peer_height) + ")");
}

// ---------------------------------------------------------------------------
// process_headers
// ---------------------------------------------------------------------------
// Validates a batch of received headers.  The logic enforces:
//
//   1. Only accept headers from the current sync peer.
//   2. Headers must form a connected chain internally (each header's
//      prev_hash must equal the hash of the preceding header in the batch).
//   3. The first header in the batch must connect to either:
//      (a) our last received header hash, or
//      (b) have a prev_hash that is the zero hash (genesis), or
//      (c) at least match a hash we already know about (allowing for
//          overlap when peers re-send headers we already have).
//      If none of those, it is an "unconnecting" header.
//   4. An empty headers message signals that the peer has no more headers
//      to send, so we complete the sync.
//   5. If we get MAX_HEADERS_PER_REQUEST headers, the peer likely has more.
//   6. Basic sanity checks on header timestamps are performed to reject
//      obviously invalid data.
//
// On success, returns the accepted headers (which may be a subset if we
// need to skip already-known ones).
// ---------------------------------------------------------------------------
core::Result<std::vector<primitives::BlockHeader>> HeadersSync::process_headers(
    uint64_t peer_id,
    const std::vector<primitives::BlockHeader>& headers,
    int current_height) {

    std::unique_lock<std::mutex> lock(mutex_);

    // -----------------------------------------------------------------------
    // Pre-condition checks
    // -----------------------------------------------------------------------

    // Must be syncing and from the correct peer.
    if (!syncing_) {
        return core::Error(core::ErrorCode::NETWORK_ERROR,
            "Received headers but not in syncing state");
    }

    if (peer_id != sync_peer_) {
        return core::Error(core::ErrorCode::NETWORK_ERROR,
            "Received headers from unexpected peer "
            + std::to_string(peer_id)
            + " (expected " + std::to_string(sync_peer_) + ")");
    }

    // Record the start height if this is the first batch.
    if (sync_start_height_ == 0 && current_height > 0) {
        sync_start_height_ = current_height;
    }

    // -----------------------------------------------------------------------
    // Handle empty headers (sync complete signal)
    // -----------------------------------------------------------------------

    // An empty headers message means the peer has nothing more to send.
    // This can happen when we are fully synced with the peer, or when
    // the peer's chain is shorter than ours.
    if (headers.empty()) {
        LOG_INFO(core::LogCategory::NET,
            "Peer " + std::to_string(peer_id)
            + " sent empty headers -- sync complete at height "
            + std::to_string(current_height)
            + " (received " + std::to_string(total_headers_received_)
            + " headers total)");
        syncing_ = false;
        return std::vector<primitives::BlockHeader>{};
    }

    // -----------------------------------------------------------------------
    // Reject oversized batches
    // -----------------------------------------------------------------------

    if (static_cast<int>(headers.size()) > MAX_HEADERS_PER_REQUEST) {
        syncing_ = false;
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Peer " + std::to_string(peer_id)
            + " sent " + std::to_string(headers.size())
            + " headers, exceeding maximum of "
            + std::to_string(MAX_HEADERS_PER_REQUEST));
    }

    // -----------------------------------------------------------------------
    // Validate internal chain connectivity
    // -----------------------------------------------------------------------
    // Each header's prev_hash must match the hash of the header before it.
    // This ensures the batch forms a contiguous chain.

    for (size_t i = 1; i < headers.size(); ++i) {
        core::uint256 expected_prev = headers[i - 1].hash();
        if (!(headers[i].prev_hash == expected_prev)) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "Headers at index " + std::to_string(i)
                + " do not form a connected chain: prev_hash "
                + headers[i].prev_hash.to_hex().substr(0, 16)
                + "... does not match preceding header hash "
                + expected_prev.to_hex().substr(0, 16) + "...");
        }
    }

    // -----------------------------------------------------------------------
    // Validate timestamp ordering within the batch
    // -----------------------------------------------------------------------
    // While block timestamps do not need to be strictly increasing (they
    // only need to exceed the median of the prior 11 blocks), a batch where
    // timestamps jump backwards by more than 2 hours is suspicious.

    static constexpr uint32_t MAX_TIMESTAMP_REWIND = 7200;  // 2 hours

    for (size_t i = 1; i < headers.size(); ++i) {
        if (headers[i].timestamp + MAX_TIMESTAMP_REWIND
            < headers[i - 1].timestamp) {
            LOG_WARN(core::LogCategory::NET,
                "Header at index " + std::to_string(i)
                + " has timestamp " + std::to_string(headers[i].timestamp)
                + " which is more than " + std::to_string(MAX_TIMESTAMP_REWIND)
                + "s before prior header timestamp "
                + std::to_string(headers[i - 1].timestamp));
            // Not a fatal error -- consensus validation will catch truly
            // invalid timestamps.  Just log the anomaly.
        }
    }

    // -----------------------------------------------------------------------
    // Check that the first header connects to our known chain
    // -----------------------------------------------------------------------

    std::vector<primitives::BlockHeader> accepted;
    accepted.reserve(headers.size());

    bool first_connects = false;

    if (last_header_hash_.is_zero()) {
        // This is the very first batch.  The first header should connect
        // to genesis or to a block we already know about.  We trust the
        // caller (sync manager) to have set up the locator correctly.
        first_connects = true;
    } else if (headers[0].prev_hash == last_header_hash_) {
        // Perfect continuation from where we left off.
        first_connects = true;
    } else {
        // Check if the first header itself is one we already have (overlap).
        // Some peers may re-send the last header we already received, which
        // is harmless and expected.
        core::uint256 first_hash = headers[0].hash();
        if (first_hash == last_header_hash_) {
            // The first header is one we already have.  Skip it and check
            // if the rest connects.
            if (headers.size() > 1) {
                first_connects = true;
                // We will skip this header below.
            } else {
                // Single duplicate header.  Treat as end of sync.
                LOG_DEBUG(core::LogCategory::NET,
                    "Peer " + std::to_string(peer_id)
                    + " sent duplicate header -- nothing new");
                return std::vector<primitives::BlockHeader>{};
            }
        }
    }

    // -----------------------------------------------------------------------
    // Handle unconnecting headers
    // -----------------------------------------------------------------------

    if (!first_connects) {
        ++unconnecting_count_;

        LOG_WARN(core::LogCategory::NET,
            "Unconnecting headers from peer " + std::to_string(peer_id)
            + ": first header prev_hash "
            + headers[0].prev_hash.to_hex().substr(0, 16)
            + "... does not match last_header_hash "
            + last_header_hash_.to_hex().substr(0, 16)
            + "... (count " + std::to_string(unconnecting_count_)
            + "/" + std::to_string(MAX_UNCONNECTING_HEADERS) + ")");

        if (unconnecting_count_ >= MAX_UNCONNECTING_HEADERS) {
            syncing_ = false;
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "Too many unconnecting headers from peer "
                + std::to_string(peer_id)
                + " (" + std::to_string(unconnecting_count_)
                + " consecutive failures)");
        }

        // Return empty -- the caller should re-request with a better locator
        // or choose a different sync peer.
        return std::vector<primitives::BlockHeader>{};
    }

    // -----------------------------------------------------------------------
    // Build the accepted headers list
    // -----------------------------------------------------------------------

    // Reset unconnecting counter on successful connection.
    unconnecting_count_ = 0;

    // Filter out any headers we already have (overlap at the start).
    bool skip_first = (!last_header_hash_.is_zero()
                       && headers[0].hash() == last_header_hash_);
    size_t start_idx = skip_first ? 1 : 0;

    for (size_t i = start_idx; i < headers.size(); ++i) {
        accepted.push_back(headers[i]);
    }

    // Update the last header hash to the tip of the received batch.
    if (!headers.empty()) {
        last_header_hash_ = headers.back().hash();
    }

    // Track total headers received for progress reporting.
    total_headers_received_ += static_cast<int64_t>(accepted.size());

    // Update the request time so the timeout counter resets.
    last_request_time_ = 0;  // reset; will be set on next get_locator call

    // -----------------------------------------------------------------------
    // Log progress
    // -----------------------------------------------------------------------

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    log_progress_locked(current_height + static_cast<int>(accepted.size()),
                        now);

    // -----------------------------------------------------------------------
    // Check if sync is complete
    // -----------------------------------------------------------------------

    // If the peer sent a full batch, there are likely more headers to fetch.
    // If fewer, the peer has sent everything it knows about.
    if (static_cast<int>(headers.size()) < MAX_HEADERS_PER_REQUEST) {
        int expected_new_height = current_height
            + static_cast<int>(accepted.size());

        if (expected_new_height >= peer_height_) {
            auto elapsed = now - sync_start_time_;
            double rate = (elapsed > 0)
                ? static_cast<double>(total_headers_received_)
                  / static_cast<double>(elapsed)
                : 0.0;

            LOG_INFO(core::LogCategory::NET,
                "Headers sync complete with peer "
                + std::to_string(peer_id)
                + " at height " + std::to_string(expected_new_height)
                + " (" + std::to_string(total_headers_received_)
                + " headers in " + std::to_string(elapsed) + "s"
                + ", " + std::to_string(static_cast<int>(rate))
                + " headers/s)");
            syncing_ = false;
        } else {
            // Peer sent fewer than MAX but we haven't reached their height.
            // They may have been temporarily slow.  We will re-request.
            LOG_DEBUG(core::LogCategory::NET,
                "Peer " + std::to_string(peer_id)
                + " sent partial batch (" + std::to_string(headers.size())
                + " headers), expected height "
                + std::to_string(peer_height_)
                + " but at " + std::to_string(expected_new_height));
        }
    }

    return accepted;
}

// ---------------------------------------------------------------------------
// get_locator
// ---------------------------------------------------------------------------
// Builds a block locator from the active chain.  The locator is a sparse
// set of block hashes at exponentially increasing distances from the tip,
// as defined by Chain::get_locator().  If we have a last_header_hash_ that
// extends beyond the active chain, we prepend it to the locator so that
// the peer can send headers starting from where we left off.
//
// The locator structure ensures that even if our chain diverges from the
// peer's, the peer can find the common ancestor efficiently.
// ---------------------------------------------------------------------------
std::vector<core::uint256> HeadersSync::get_locator(
    const chain::Chain& active_chain) const {

    std::unique_lock<std::mutex> lock(mutex_);

    std::vector<core::uint256> locator = active_chain.get_locator();

    // If we have received headers beyond what the active chain knows about,
    // prepend the last known header hash.  This helps the peer start sending
    // from the right position rather than re-sending headers we already have.
    if (!last_header_hash_.is_zero()) {
        // Check whether the last header hash is already in the locator.
        bool already_present = false;
        for (const auto& hash : locator) {
            if (hash == last_header_hash_) {
                already_present = true;
                break;
            }
        }

        if (!already_present) {
            locator.insert(locator.begin(), last_header_hash_);
        }
    }

    // Record the time of this request for timeout tracking.
    // (const_cast is acceptable here: last_request_time_ is logically
    // mutable state protected by the mutex, used only for timeout checks.)
    const_cast<HeadersSync*>(this)->last_request_time_ =
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();

    LOG_DEBUG(core::LogCategory::NET,
        "Built GETHEADERS locator with " + std::to_string(locator.size())
        + " hashes for peer " + std::to_string(sync_peer_));

    return locator;
}

// ---------------------------------------------------------------------------
// is_syncing
// ---------------------------------------------------------------------------
bool HeadersSync::is_syncing() const {
    std::unique_lock<std::mutex> lock(mutex_);
    return syncing_;
}

// ---------------------------------------------------------------------------
// sync_peer
// ---------------------------------------------------------------------------
uint64_t HeadersSync::sync_peer() const {
    std::unique_lock<std::mutex> lock(mutex_);
    return sync_peer_;
}

// ---------------------------------------------------------------------------
// peer_height
// ---------------------------------------------------------------------------
int32_t HeadersSync::peer_height() const {
    std::unique_lock<std::mutex> lock(mutex_);
    return peer_height_;
}

// ---------------------------------------------------------------------------
// total_headers_received
// ---------------------------------------------------------------------------
int64_t HeadersSync::total_headers_received() const {
    std::unique_lock<std::mutex> lock(mutex_);
    return total_headers_received_;
}

// ---------------------------------------------------------------------------
// peer_disconnected
// ---------------------------------------------------------------------------
// If the peer that disconnected is our sync peer, abort the current sync
// so a new sync peer can be selected.  This is critical because a sync
// in progress to a disconnected peer will never complete, and the timeout
// could take up to HEADERS_TIMEOUT seconds to fire.
// ---------------------------------------------------------------------------
void HeadersSync::peer_disconnected(uint64_t peer_id) {
    std::unique_lock<std::mutex> lock(mutex_);

    if (syncing_ && peer_id == sync_peer_) {
        LOG_INFO(core::LogCategory::NET,
            "Sync peer " + std::to_string(peer_id)
            + " disconnected -- resetting header sync"
            + " (had received " + std::to_string(total_headers_received_)
            + " headers)");

        sync_peer_              = 0;
        peer_height_            = 0;
        last_request_time_      = 0;
        sync_start_time_        = 0;
        sync_start_height_      = 0;
        last_header_hash_       = core::uint256{};
        unconnecting_count_     = 0;
        total_headers_received_ = 0;
        last_progress_log_time_ = 0;
        syncing_                = false;
    }
}

// ---------------------------------------------------------------------------
// is_timed_out
// ---------------------------------------------------------------------------
// Returns true if we have been waiting longer than HEADERS_TIMEOUT for a
// response from the sync peer.  The caller passes the current time.
//
// Note that we only consider a timeout if a request has actually been sent
// (last_request_time_ > 0).  If get_locator() has not been called yet,
// there is nothing to time out on.
// ---------------------------------------------------------------------------
bool HeadersSync::is_timed_out(int64_t now) const {
    std::unique_lock<std::mutex> lock(mutex_);

    if (!syncing_) {
        return false;
    }

    // If no request has been made yet, there is nothing to time out.
    if (last_request_time_ == 0) {
        return false;
    }

    int64_t elapsed = now - last_request_time_;
    if (elapsed > HEADERS_TIMEOUT) {
        LOG_DEBUG(core::LogCategory::NET,
            "Headers sync timed out: waiting "
            + std::to_string(elapsed) + "s for peer "
            + std::to_string(sync_peer_)
            + " (timeout " + std::to_string(HEADERS_TIMEOUT) + "s)");
        return true;
    }

    return false;
}

// ---------------------------------------------------------------------------
// estimated_progress
// ---------------------------------------------------------------------------
// Returns a progress estimate as a fraction [0.0, 1.0].
//   - 0.0 means we are at the start height when sync began.
//   - 1.0 means we have reached (or exceeded) the peer's reported height.
//
// This is an estimate because:
//   - The peer's height may have increased since sync started.
//   - Headers may not have been fully validated yet.
//   - Peer may have lied about their height.
// ---------------------------------------------------------------------------
double HeadersSync::estimated_progress(int current_height) const {
    std::unique_lock<std::mutex> lock(mutex_);

    if (!syncing_ || peer_height_ <= 0) {
        return 0.0;
    }

    int start = sync_start_height_;
    int target = peer_height_;

    if (target <= start) {
        return 1.0;
    }

    double progress = static_cast<double>(current_height - start)
                    / static_cast<double>(target - start);

    // Clamp to [0.0, 1.0].
    if (progress < 0.0) return 0.0;
    if (progress > 1.0) return 1.0;
    return progress;
}

// ---------------------------------------------------------------------------
// reset
// ---------------------------------------------------------------------------
void HeadersSync::reset() {
    std::unique_lock<std::mutex> lock(mutex_);

    if (syncing_) {
        LOG_INFO(core::LogCategory::NET,
            "Resetting header sync (was syncing from peer "
            + std::to_string(sync_peer_)
            + ", received " + std::to_string(total_headers_received_)
            + " headers)");
    }

    sync_peer_              = 0;
    peer_height_            = 0;
    last_request_time_      = 0;
    sync_start_time_        = 0;
    sync_start_height_      = 0;
    last_header_hash_       = core::uint256{};
    unconnecting_count_     = 0;
    total_headers_received_ = 0;
    last_progress_log_time_ = 0;
    syncing_                = false;
}

// ---------------------------------------------------------------------------
// log_progress_locked (private)
// ---------------------------------------------------------------------------
// Logs sync progress at most once every PROGRESS_LOG_INTERVAL seconds.
// Reports the current height, estimated progress percentage, and download
// rate.  Must be called with mutex_ held.
// ---------------------------------------------------------------------------
void HeadersSync::log_progress_locked(int current_height, int64_t now) {
    if (now - last_progress_log_time_ < PROGRESS_LOG_INTERVAL) {
        return;
    }

    last_progress_log_time_ = now;

    // Calculate progress percentage.
    double pct = 0.0;
    if (peer_height_ > sync_start_height_) {
        pct = 100.0 * static_cast<double>(current_height - sync_start_height_)
            / static_cast<double>(peer_height_ - sync_start_height_);
        if (pct < 0.0) pct = 0.0;
        if (pct > 100.0) pct = 100.0;
    }

    // Calculate headers per second.
    int64_t elapsed = now - sync_start_time_;
    double rate = (elapsed > 0)
        ? static_cast<double>(total_headers_received_)
          / static_cast<double>(elapsed)
        : 0.0;

    // Estimate time remaining.
    int64_t remaining_headers = static_cast<int64_t>(peer_height_)
                              - static_cast<int64_t>(current_height);
    int64_t eta_seconds = (rate > 0.1)
        ? static_cast<int64_t>(static_cast<double>(remaining_headers) / rate)
        : 0;

    LOG_INFO(core::LogCategory::NET,
        "Headers sync progress: height " + std::to_string(current_height)
        + "/" + std::to_string(peer_height_)
        + " (" + std::to_string(static_cast<int>(pct)) + "%"
        + ", " + std::to_string(static_cast<int>(rate)) + " hdrs/s"
        + ", ETA " + std::to_string(eta_seconds) + "s)");
}

} // namespace net::sync
