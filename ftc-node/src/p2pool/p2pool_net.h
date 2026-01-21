#ifndef FTC_P2POOL_NET_H
#define FTC_P2POOL_NET_H

#include "p2pool/sharechain.h"
#include "p2p/connection.h"
#include "p2p/peer_manager.h"
#include "chain/chain.h"

#include <map>
#include <set>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>

namespace ftc {
namespace p2pool {

// ============================================================================
// P2Pool Protocol Messages
// ============================================================================

enum class P2PoolMessageType : uint8_t {
    // Share messages
    SHARE = 0x01,           // Announce new share
    GETSHARES = 0x02,       // Request shares
    SHARES = 0x03,          // Response with shares

    // Sync messages
    GETSHAREHASHES = 0x04,  // Get share hashes from tip
    SHAREHASHES = 0x05,     // List of share hashes
    GETSHARE = 0x06,        // Request specific share

    // Pool state
    POOLSTATUS = 0x10,      // Pool status update
    GETPOOLSTATUS = 0x11,

    // Ping/pong
    PING = 0x20,
    PONG = 0x21,
};

struct P2PoolMessage {
    P2PoolMessageType type;
    std::vector<uint8_t> payload;

    std::vector<uint8_t> serialize() const;
    bool deserialize(const std::vector<uint8_t>& data);
};

// Share announcement
struct ShareMessage {
    Share share;

    std::vector<uint8_t> serialize() const;
    bool deserialize(const std::vector<uint8_t>& data);
};

// Request shares from a starting hash
struct GetSharesMessage {
    crypto::Hash256 start_hash;  // Start from this share
    uint32_t count;              // Number of shares to request

    std::vector<uint8_t> serialize() const;
    bool deserialize(const std::vector<uint8_t>& data);
};

// Response with multiple shares
struct SharesMessage {
    std::vector<Share> shares;

    std::vector<uint8_t> serialize() const;
    bool deserialize(const std::vector<uint8_t>& data);
};

// Request share hash list (for sync)
struct GetShareHashesMessage {
    crypto::Hash256 locator_hash;  // Known share hash
    crypto::Hash256 stop_hash;     // Stop at this hash (zero = get all)
    uint32_t max_hashes;

    std::vector<uint8_t> serialize() const;
    bool deserialize(const std::vector<uint8_t>& data);
};

// List of share hashes
struct ShareHashesMessage {
    std::vector<crypto::Hash256> hashes;

    std::vector<uint8_t> serialize() const;
    bool deserialize(const std::vector<uint8_t>& data);
};

// Pool status
struct PoolStatusMessage {
    uint32_t share_height;
    crypto::Hash256 share_tip;
    uint32_t main_height;
    crypto::Hash256 main_tip;
    uint64_t pool_hashrate;
    uint32_t miner_count;
    uint64_t shares_per_minute;

    std::vector<uint8_t> serialize() const;
    bool deserialize(const std::vector<uint8_t>& data);
};

// ============================================================================
// P2Pool Peer
// ============================================================================

struct P2PoolPeer {
    p2p::Connection::Id id;
    p2p::NetAddr addr;

    // State
    bool handshake_complete = false;
    uint32_t share_height = 0;
    crypto::Hash256 share_tip;

    // Sync state
    bool syncing = false;
    std::set<crypto::Hash256> requested_shares;
    std::chrono::steady_clock::time_point last_request_time;

    // Statistics
    uint64_t shares_received = 0;
    uint64_t shares_sent = 0;
    uint64_t bytes_sent = 0;
    uint64_t bytes_recv = 0;
};

// ============================================================================
// P2Pool Network Manager
// ============================================================================

/**
 * P2PoolNet manages the P2Pool peer-to-peer network.
 *
 * Responsibilities:
 * - Connect to other P2Pool nodes (via --addnode or known peers)
 * - Propagate shares to/from other nodes
 * - Synchronize sharechain with network
 * - Handle pool-specific protocol messages
 */
class P2PoolNet {
public:
    struct Config {
        uint16_t port = 17320;              // P2Pool listen port
        size_t max_peers = 30;              // Max P2Pool peers
        size_t target_peers = 8;            // Target outbound peers
        std::chrono::seconds sync_interval{30};
        std::chrono::seconds ping_interval{60};
        std::chrono::seconds share_timeout{5};

        Config() = default;
    };

    P2PoolNet(Sharechain* sharechain, chain::Chain* mainchain);
    P2PoolNet(Sharechain* sharechain, chain::Chain* mainchain, const Config& config);
    ~P2PoolNet();

    // Non-copyable
    P2PoolNet(const P2PoolNet&) = delete;
    P2PoolNet& operator=(const P2PoolNet&) = delete;

    // Lifecycle
    bool start();
    void stop();
    bool isRunning() const { return running_; }

    // Share propagation
    void broadcastShare(const Share& share);
    void requestShare(const crypto::Hash256& hash);

    // Peer management
    bool connectTo(const p2p::NetAddr& addr);
    void disconnect(p2p::Connection::Id id, const std::string& reason);
    size_t getPeerCount() const;
    std::vector<P2PoolPeer> getPeerInfo() const;

    // Sync
    void startSync();
    void stopSync();
    bool isSyncing() const { return syncing_; }

    // Statistics
    struct Stats {
        uint64_t peers_connected = 0;
        uint64_t shares_propagated = 0;
        uint64_t shares_received = 0;
        uint64_t sync_progress = 0;
        uint64_t bytes_sent = 0;
        uint64_t bytes_recv = 0;
    };
    Stats getStats() const;

private:
    Config config_;
    Sharechain* sharechain_;
    chain::Chain* mainchain_;

    // State
    std::atomic<bool> running_{false};
    std::atomic<bool> syncing_{false};

    // Peers
    std::map<p2p::Connection::Id, P2PoolPeer> peers_;
    mutable std::mutex peers_mutex_;

    // Listener
    p2p::Listener listener_;

    // Pending connections
    std::set<p2p::NetAddr> connecting_;
    std::mutex connecting_mutex_;

    // Share relay
    std::set<crypto::Hash256> recently_seen_;
    std::mutex seen_mutex_;
    std::queue<crypto::Hash256> seen_queue_;

    // Requested shares
    std::map<crypto::Hash256, std::chrono::steady_clock::time_point> pending_shares_;
    std::mutex pending_mutex_;

    // Threads
    std::thread network_thread_;
    std::thread maintenance_thread_;

    // Statistics
    mutable std::atomic<uint64_t> stats_propagated_{0};
    mutable std::atomic<uint64_t> stats_received_{0};
    mutable std::atomic<uint64_t> stats_bytes_sent_{0};
    mutable std::atomic<uint64_t> stats_bytes_recv_{0};

    // Thread functions
    void networkThread();
    void maintenanceThread();

    // Connection handling
    void onNewConnection(std::shared_ptr<p2p::Connection> conn);
    void onDisconnect(p2p::Connection::Id id, const std::string& reason);

    // Message handling
    void onMessage(p2p::Connection::Id id, const P2PoolMessage& msg);
    void handleShare(p2p::Connection::Id id, const ShareMessage& msg);
    void handleGetShares(p2p::Connection::Id id, const GetSharesMessage& msg);
    void handleShares(p2p::Connection::Id id, const SharesMessage& msg);
    void handleGetShareHashes(p2p::Connection::Id id, const GetShareHashesMessage& msg);
    void handleShareHashes(p2p::Connection::Id id, const ShareHashesMessage& msg);
    void handleGetShare(p2p::Connection::Id id, const crypto::Hash256& hash);
    void handlePoolStatus(p2p::Connection::Id id, const PoolStatusMessage& msg);
    void handlePing(p2p::Connection::Id id, uint64_t nonce);

    // Helpers
    void sendMessage(p2p::Connection::Id id, const P2PoolMessage& msg);
    void sendShare(p2p::Connection::Id id, const Share& share);
    void sendPoolStatus(p2p::Connection::Id id);
    void requestMoreShares(P2PoolPeer& peer);

    // Maintenance
    void tryConnectPeers();
    void sendPings();
    void checkTimeouts();
    void cleanupSeen();
};

// ============================================================================
// P2Pool Manager - main integration point
// ============================================================================

/**
 * P2Pool - main entry point for P2Pool functionality
 *
 * Combines:
 * - Sharechain management
 * - P2Pool networking
 * - Work generation for miners
 * - Payout tracking
 */
class P2Pool {
public:
    struct Config {
        std::string data_dir = "./p2pool";
        uint16_t port = 17320;
        bool enabled = true;

        // Pool identity
        std::vector<uint8_t> pool_script;  // Default payout script

        // Mining
        uint32_t work_restart_seconds = 15;

        Config() = default;
    };

    explicit P2Pool(chain::Chain* mainchain);
    P2Pool(chain::Chain* mainchain, const Config& config);
    ~P2Pool();

    // Lifecycle
    bool start();
    void stop();
    bool isRunning() const { return running_; }

    // Components
    Sharechain* getSharechain() { return sharechain_.get(); }
    P2PoolNet* getNetwork() { return network_.get(); }

    // Mining interface
    Share getWorkTemplate(const std::vector<uint8_t>& payout_script) const;
    bool submitShare(const Share& share, std::string& error);
    bool submitWork(uint32_t nonce, const std::vector<uint8_t>& extra_nonce);

    // Payout info
    std::map<std::vector<uint8_t>, uint64_t> getEstimatedPayouts() const;
    std::map<std::vector<uint8_t>, uint64_t> getPayouts() const { return getEstimatedPayouts(); }
    uint64_t getPoolHashrate() const;
    uint32_t getMinerCount() const;

    // Register a miner's share contribution
    void registerMinerShare(const std::vector<uint8_t>& payout_script);

    // Statistics
    struct Stats {
        uint32_t sharechain_height;
        crypto::Hash256 sharechain_tip;
        uint64_t pool_hashrate;
        uint32_t active_miners;
        uint64_t total_shares;
        uint64_t total_blocks;
        double shares_per_minute;
        size_t peer_count;
    };
    Stats getStats() const;

    // Callbacks
    using BlockFoundCallback = std::function<void(const chain::Block&)>;
    void setBlockFoundCallback(BlockFoundCallback cb) { on_block_found_ = cb; }

    // Callback to get connected miner count from Stratum server (for instant disconnect detection)
    using GetConnectedMinersCallback = std::function<size_t()>;
    void setGetConnectedMinersCallback(GetConnectedMinersCallback cb) { get_connected_miners_ = cb; }

private:
    Config config_;
    chain::Chain* mainchain_;

    std::atomic<bool> running_{false};

    // Components
    std::unique_ptr<Sharechain> sharechain_;
    std::unique_ptr<P2PoolNet> network_;

    // Callbacks
    BlockFoundCallback on_block_found_;
    GetConnectedMinersCallback get_connected_miners_;

    // Current work template
    mutable std::mutex work_mutex_;
    mutable Share current_work_;
    mutable std::chrono::steady_clock::time_point work_time_;

    // Simple miner tracking for PPLNS (work contributions)
    mutable std::mutex miner_mutex_;
    std::map<std::vector<uint8_t>, uint64_t> miner_work_count_;  // script -> work count
    std::map<std::vector<uint8_t>, std::chrono::steady_clock::time_point> miner_last_seen_;  // script -> last activity

    static constexpr int MINER_TIMEOUT_SECONDS = 15;  // 15 seconds (miners poll every 2-3 sec)

    // Internal
    void onShareAccepted(const Share& share, bool accepted);
    void onNewBlock(const chain::Block& block);
    void updateWork();
};

} // namespace p2pool
} // namespace ftc

#endif // FTC_P2POOL_NET_H
