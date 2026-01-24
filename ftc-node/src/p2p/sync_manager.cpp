/**
 * FTC Node - Adaptive Sync Manager Implementation
 */

#include "sync_manager.h"
#include "peer_manager.h"
#include "chain/chain.h"
#include "util/logging.h"

#include <algorithm>
#include <numeric>

namespace ftc::p2p {

using namespace std::chrono;
using Chain = ftc::chain::Chain;

SyncManager::SyncManager(Chain* chain, PeerManager* peer_manager, const Config& config)
    : chain_(chain)
    , peer_manager_(peer_manager)
    , config_(config)
    , target_in_flight_(config.initial_blocks_in_flight)
{
}

SyncManager::~SyncManager() {
    stop();
}

void SyncManager::start() {
    if (running_.exchange(true)) return;

    sync_start_time_ = Clock::now();
    last_adjustment_time_ = sync_start_time_;
    last_tick_time_ = sync_start_time_;

    LOG_INFO("SyncManager started with target={} blocks in flight", target_in_flight_.load());
}

void SyncManager::stop() {
    running_ = false;
}

void SyncManager::queueBlocks(const std::vector<Hash256>& hashes) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    for (const auto& hash : hashes) {
        if (!chain_->hasBlockData(hash)) {
            download_queue_.push_back(hash);
        }
    }
    LOG_DEBUG("SyncManager: queued {} blocks, total queue={}", hashes.size(), download_queue_.size());
}

void SyncManager::queueBlock(const Hash256& hash) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    if (!chain_->hasBlockData(hash)) {
        download_queue_.push_back(hash);
    }
}

void SyncManager::onBlockReceived(Connection::Id peer_id, const Hash256& hash, size_t bytes) {
    auto now = Clock::now();

    // Remove from in-flight
    {
        std::lock_guard<std::mutex> lock(flight_mutex_);
        in_flight_.erase(hash);
    }

    // Update peer stats
    updatePeerStats(peer_id, bytes, true);

    // Update global stats
    total_blocks_++;
    total_bytes_ += bytes;

    // Add to throughput samples
    {
        std::lock_guard<std::mutex> lock(samples_mutex_);
        throughput_samples_.push_back({now, bytes});

        // Remove old samples
        auto cutoff = now - config_.measurement_window;
        while (!throughput_samples_.empty() && throughput_samples_.front().first < cutoff) {
            throughput_samples_.pop_front();
        }
    }

    // Remove from recently failed
    recently_failed_.erase(hash);

    // Request more blocks to fill the pipeline
    requestBlocks();
}

void SyncManager::onBlockTimeout(const Hash256& hash) {
    BlockRequest req;

    {
        std::lock_guard<std::mutex> lock(flight_mutex_);
        auto it = in_flight_.find(hash);
        if (it == in_flight_.end()) return;
        req = it->second;
        in_flight_.erase(it);
    }

    // Update peer stats
    updatePeerStats(req.peer_id, 0, false);

    // Retry or give up
    if (req.retry_count < config_.max_retries) {
        LOG_DEBUG("SyncManager: block timeout, retry {} of {}", req.retry_count + 1, config_.max_retries);

        // Re-queue with higher retry count
        std::lock_guard<std::mutex> lock(queue_mutex_);
        download_queue_.push_front(hash);  // Priority retry
    } else {
        LOG_WARN("SyncManager: block failed after {} retries", config_.max_retries);
        recently_failed_.insert(hash);
    }
}

void SyncManager::onPeerDisconnected(Connection::Id peer_id) {
    std::vector<Hash256> to_requeue;

    {
        std::lock_guard<std::mutex> lock(flight_mutex_);
        for (auto it = in_flight_.begin(); it != in_flight_.end();) {
            if (it->second.peer_id == peer_id) {
                to_requeue.push_back(it->first);
                it = in_flight_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Re-queue blocks from disconnected peer
    if (!to_requeue.empty()) {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        for (const auto& hash : to_requeue) {
            download_queue_.push_front(hash);  // Priority retry
        }
        LOG_DEBUG("SyncManager: re-queued {} blocks from disconnected peer {}", to_requeue.size(), peer_id);
    }

    // Remove peer stats
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        peer_stats_.erase(peer_id);
    }
}

void SyncManager::tick() {
    if (!running_) return;

    auto now = Clock::now();
    auto elapsed = duration_cast<milliseconds>(now - last_tick_time_);

    // Tick every 100ms
    if (elapsed < milliseconds(100)) return;
    last_tick_time_ = now;

    // Check for timeouts
    checkTimeouts();

    // Calculate current throughput
    calculateThroughput();

    // Adjust target based on performance
    if (duration_cast<seconds>(now - last_adjustment_time_) >= seconds(2)) {
        adjustTarget();
        last_adjustment_time_ = now;
    }

    // Request more blocks
    requestBlocks();
}

void SyncManager::requestBlocks() {
    if (!running_) return;

    std::vector<std::pair<Connection::Id, std::vector<Hash256>>> requests;

    {
        std::lock_guard<std::mutex> lock1(queue_mutex_);
        std::lock_guard<std::mutex> lock2(flight_mutex_);

        size_t current_in_flight = in_flight_.size();
        size_t target = target_in_flight_.load();

        if (current_in_flight >= target || download_queue_.empty()) {
            return;
        }

        size_t to_request = target - current_in_flight;

        // Group requests by peer
        std::unordered_map<Connection::Id, std::vector<Hash256>> peer_requests;

        while (to_request > 0 && !download_queue_.empty()) {
            Hash256 hash = download_queue_.front();
            download_queue_.pop_front();

            // Skip if already in flight or recently failed
            if (in_flight_.count(hash) || recently_failed_.count(hash)) {
                continue;
            }

            // Skip if we already have it
            if (chain_->hasBlockData(hash)) {
                continue;
            }

            // Select peer
            Connection::Id peer = selectPeerForBlock(hash);
            if (peer == 0) {
                // No available peer, put back in queue
                download_queue_.push_front(hash);
                break;
            }

            // Check per-peer limit
            if (peer_requests[peer].size() >= config_.blocks_per_peer) {
                // Try another peer or put back
                download_queue_.push_front(hash);
                continue;
            }

            // Add to peer's batch
            peer_requests[peer].push_back(hash);

            // Track in-flight
            BlockRequest req;
            req.hash = hash;
            req.peer_id = peer;
            req.request_time = Clock::now();
            req.retry_count = 0;
            in_flight_[hash] = req;

            to_request--;
        }

        // Convert to vector for callback
        for (auto it = peer_requests.begin(); it != peer_requests.end(); ++it) {
            if (!it->second.empty()) {
                requests.push_back({it->first, std::move(it->second)});
            }
        }
    }

    // Send requests (outside locks)
    for (size_t i = 0; i < requests.size(); ++i) {
        if (on_block_request_) {
            on_block_request_(requests[i].first, requests[i].second);
        }
        LOG_DEBUG("SyncManager: requesting {} blocks from peer {}", requests[i].second.size(), requests[i].first);
    }
}

Connection::Id SyncManager::selectPeerForBlock(const Hash256& /* hash */) {
    // Get connected peers
    auto peer_info = peer_manager_->getPeerInfo();
    if (peer_info.empty()) return 0;

    std::lock_guard<std::mutex> lock(stats_mutex_);

    Connection::Id best_peer = 0;
    double best_score = -1.0;
    size_t min_in_flight = SIZE_MAX;

    for (size_t i = 0; i < peer_info.size(); ++i) {
        Connection::Id peer = peer_info[i].id;
        // Get peer stats
        auto it = peer_stats_.find(peer);
        double score = 1.0;  // Default score for new peers
        size_t peer_in_flight = 0;

        if (it != peer_stats_.end()) {
            score = it->second.getScore();
            // Count in-flight for this peer
            for (auto fit = in_flight_.begin(); fit != in_flight_.end(); ++fit) {
                if (fit->second.peer_id == peer) peer_in_flight++;
            }
        }

        // Prefer peers with fewer in-flight requests
        if (peer_in_flight < min_in_flight || (peer_in_flight == min_in_flight && score > best_score)) {
            best_peer = peer;
            best_score = score;
            min_in_flight = peer_in_flight;
        }
    }

    return best_peer;
}

void SyncManager::updatePeerStats(Connection::Id peer_id, size_t bytes, bool success) {
    auto now = Clock::now();

    std::lock_guard<std::mutex> lock(stats_mutex_);

    PeerSyncStats& pstats = peer_stats_[peer_id];
    pstats.peer_id = peer_id;

    if (success) {
        pstats.blocks_received++;
        pstats.bytes_received += bytes;
        pstats.recent_blocks.push_back(std::make_pair(now, bytes));
        pstats.last_block_time = now;

        // Remove old samples
        auto cutoff = now - config_.measurement_window;
        while (!pstats.recent_blocks.empty() && pstats.recent_blocks.front().first < cutoff) {
            pstats.recent_blocks.pop_front();
        }

        // Calculate throughput
        if (pstats.recent_blocks.size() >= 2) {
            auto dur = duration_cast<milliseconds>(
                pstats.recent_blocks.back().first - pstats.recent_blocks.front().first
            );
            if (dur.count() > 0) {
                pstats.blocks_per_second = static_cast<double>(pstats.recent_blocks.size()) * 1000.0 / dur.count();
                size_t total_bytes = 0;
                for (const auto& sample : pstats.recent_blocks) {
                    total_bytes += sample.second;
                }
                pstats.bytes_per_second = static_cast<double>(total_bytes) * 1000.0 / dur.count();
            }
        }
    } else {
        pstats.timeouts++;
    }
}

void SyncManager::adjustTarget() {
    std::lock_guard<std::mutex> lock(stats_mutex_);

    // Calculate success rate from all peers
    size_t total_received = 0;
    size_t total_timeouts = 0;

    for (auto it = peer_stats_.begin(); it != peer_stats_.end(); ++it) {
        total_received += it->second.blocks_received;
        total_timeouts += it->second.timeouts;
    }

    if (total_received + total_timeouts == 0) return;

    double success_rate = static_cast<double>(total_received) / (total_received + total_timeouts);
    size_t current_target = target_in_flight_.load();
    size_t new_target = current_target;

    if (success_rate >= config_.scale_up_threshold && current_throughput_ > 10.0) {
        // Scale up
        new_target = static_cast<size_t>(current_target * config_.scale_factor);
        new_target = std::min(new_target, config_.max_blocks_in_flight);
    } else if (success_rate < config_.scale_down_threshold) {
        // Scale down
        new_target = static_cast<size_t>(current_target / config_.scale_factor);
        new_target = std::max(new_target, config_.min_blocks_in_flight);
    }

    if (new_target != current_target) {
        target_in_flight_ = new_target;
        LOG_INFO("SyncManager: adjusted target {} -> {} (success_rate={:.1f}%, throughput={:.1f} blk/s)",
                 current_target, new_target, success_rate * 100.0, current_throughput_.load());
    }
}

void SyncManager::checkTimeouts() {
    auto now = Clock::now();
    std::vector<Hash256> timed_out;

    {
        std::lock_guard<std::mutex> lock(flight_mutex_);
        for (auto it = in_flight_.begin(); it != in_flight_.end(); ++it) {
            if (now - it->second.request_time > config_.block_timeout) {
                timed_out.push_back(it->first);
            }
        }
    }

    for (const auto& hash : timed_out) {
        onBlockTimeout(hash);
    }
}

void SyncManager::calculateThroughput() {
    auto now = Clock::now();

    std::lock_guard<std::mutex> lock(samples_mutex_);

    if (throughput_samples_.size() < 2) {
        current_throughput_ = 0.0;
        current_bandwidth_ = 0.0;
        return;
    }

    auto duration = duration_cast<milliseconds>(
        throughput_samples_.back().first - throughput_samples_.front().first
    );

    if (duration.count() > 0) {
        current_throughput_ = static_cast<double>(throughput_samples_.size()) * 1000.0 / duration.count();

        size_t total_bytes = 0;
        for (const auto& sample : throughput_samples_) {
            total_bytes += sample.second;
        }
        current_bandwidth_ = static_cast<double>(total_bytes) * 1000.0 / duration.count();
    }
}

void SyncManager::rebalanceWork() {
    // Move blocks from slow/failed peers to faster ones
    // TODO: Implement if needed
}

SyncManager::Stats SyncManager::getStats() const {
    Stats s;
    s.blocks_downloaded = total_blocks_;
    s.bytes_downloaded = total_bytes_;
    s.current_throughput = current_throughput_;
    s.current_bandwidth = current_bandwidth_;
    s.target_in_flight = target_in_flight_;
    s.sync_start_time = sync_start_time_;
    s.is_syncing = running_;

    {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(flight_mutex_));
        s.current_in_flight = in_flight_.size();
    }
    {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(queue_mutex_));
        s.queue_size = download_queue_.size();
    }
    {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(stats_mutex_));
        s.active_peers = peer_stats_.size();
    }

    return s;
}

} // namespace ftc::p2p
