/**
 * FTC Node - Adaptive Sync Manager
 * Production-grade blockchain synchronization
 *
 * Features:
 * - Dynamic blocks_in_flight based on throughput
 * - Multi-peer parallel download
 * - Bandwidth measurement and peer scoring
 * - Automatic retry and failover
 */

#pragma once

#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <vector>

#include "protocol.h"
#include "connection.h"
#include "crypto/keccak256.h"

namespace ftc::chain {
class Chain;  // Forward declare in ftc::chain namespace
}

namespace ftc::p2p {

using Hash256 = crypto::Hash256;
using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

class PeerManager;

/**
 * Per-peer sync statistics
 */
struct PeerSyncStats {
    Connection::Id peer_id = 0;
    uint64_t blocks_received = 0;
    uint64_t bytes_received = 0;
    double blocks_per_second = 0.0;
    double bytes_per_second = 0.0;
    uint32_t timeouts = 0;
    uint32_t failures = 0;
    std::chrono::milliseconds avg_latency{0};
    TimePoint last_block_time;
    bool is_syncing = false;

    // Sliding window for throughput calculation
    std::deque<std::pair<TimePoint, size_t>> recent_blocks;  // time, bytes

    double getScore() const {
        // Higher score = better peer
        if (timeouts > 5 || failures > 3) return 0.0;
        return blocks_per_second * 10.0 - timeouts * 5.0 - failures * 10.0;
    }
};

/**
 * Block download request
 */
struct BlockRequest {
    Hash256 hash;
    Connection::Id peer_id = 0;
    TimePoint request_time;
    uint32_t retry_count = 0;
    size_t expected_size = 0;  // Estimated from header
};

/**
 * Sync Manager Configuration
 */
struct SyncConfig {
    // Initial settings
    size_t initial_blocks_in_flight = 32;
    size_t min_blocks_in_flight = 8;
    size_t max_blocks_in_flight = 512;

    // Adaptive thresholds
    double scale_up_threshold = 0.9;    // Scale up if 90%+ success rate
    double scale_down_threshold = 0.7;  // Scale down if <70% success rate
    double scale_factor = 1.5;          // Multiply/divide by this

    // Timeouts
    std::chrono::seconds block_timeout{30};
    std::chrono::seconds peer_timeout{60};
    std::chrono::milliseconds measurement_window{5000};  // 5 sec window

    // Multi-peer
    size_t max_peers_for_sync = 8;
    size_t blocks_per_peer = 64;  // Max blocks to request from one peer

    // Retry
    uint32_t max_retries = 3;
};

/**
 * Adaptive Sync Manager
 * Dynamically adjusts sync parameters based on network conditions
 */
class SyncManager {
public:
    using Config = SyncConfig;

    explicit SyncManager(ftc::chain::Chain* chain, PeerManager* peer_manager, const Config& config = Config{});
    ~SyncManager();

    // Control
    void start();
    void stop();
    bool isRunning() const { return running_; }

    // Add blocks to download queue
    void queueBlocks(const std::vector<Hash256>& hashes);
    void queueBlock(const Hash256& hash);

    // Called when block is received
    void onBlockReceived(Connection::Id peer_id, const Hash256& hash, size_t bytes);

    // Called on timeout or failure
    void onBlockTimeout(const Hash256& hash);
    void onPeerDisconnected(Connection::Id peer_id);

    // Periodic update (call from main loop)
    void tick();

    // Statistics
    struct Stats {
        uint64_t blocks_downloaded = 0;
        uint64_t bytes_downloaded = 0;
        double current_throughput = 0.0;  // blocks/sec
        double current_bandwidth = 0.0;   // bytes/sec
        size_t current_in_flight = 0;
        size_t target_in_flight = 0;
        size_t queue_size = 0;
        size_t active_peers = 0;
        TimePoint sync_start_time;
        bool is_syncing = false;
    };

    Stats getStats() const;

    // Callbacks
    using BlockRequestCallback = std::function<void(Connection::Id peer_id, const std::vector<Hash256>& hashes)>;
    void setOnBlockRequest(BlockRequestCallback cb) { on_block_request_ = std::move(cb); }

private:
    // Request blocks from peers
    void requestBlocks();

    // Select best peer for downloading
    Connection::Id selectPeerForBlock(const Hash256& hash);

    // Update peer statistics
    void updatePeerStats(Connection::Id peer_id, size_t bytes, bool success);

    // Adjust in_flight target based on performance
    void adjustTarget();

    // Check for timeouts
    void checkTimeouts();

    // Calculate current throughput
    void calculateThroughput();

    // Redistribute work from slow/failed peers
    void rebalanceWork();

    ftc::chain::Chain* chain_;
    PeerManager* peer_manager_;
    Config config_;

    std::atomic<bool> running_{false};

    // Download queue (blocks we need)
    std::deque<Hash256> download_queue_;
    std::mutex queue_mutex_;

    // In-flight requests
    std::map<Hash256, BlockRequest> in_flight_;
    std::mutex flight_mutex_;

    // Per-peer statistics
    std::map<Connection::Id, PeerSyncStats> peer_stats_;
    std::mutex stats_mutex_;

    // Adaptive target
    std::atomic<size_t> target_in_flight_;

    // Global statistics
    std::atomic<uint64_t> total_blocks_{0};
    std::atomic<uint64_t> total_bytes_{0};
    std::atomic<double> current_throughput_{0.0};
    std::atomic<double> current_bandwidth_{0.0};

    // Measurement window
    std::deque<std::pair<TimePoint, size_t>> throughput_samples_;
    std::mutex samples_mutex_;

    TimePoint sync_start_time_;
    TimePoint last_adjustment_time_;
    TimePoint last_tick_time_;

    // Recently failed blocks (avoid immediate retry)
    std::set<Hash256> recently_failed_;

    BlockRequestCallback on_block_request_;
};

} // namespace ftc::p2p
