#ifndef FTC_NODE_H
#define FTC_NODE_H

#include "util/config.h"
#include "chain/chain.h"
#include "chain/mempool.h"
#include "chain/utxo_set.h"
#include "chain/consensus.h"
#include "chain/snapshot.h"
#include "p2p/peer_manager.h"
#include "p2p/message_handler.h"
#include "api/server.h"
#include "p2pool/p2pool_net.h"
#include "p2pool/sharechain.h"
#include "dht/dht.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <thread>

namespace ftc {

/**
 * Main FTC Node - fully integrated
 *
 * Coordinates all node components:
 * - P2P Protocol (TCP connections, block/tx propagation)
 * - Blockchain (validation, storage, UTXO)
 * - Mempool (transaction pool)
 * - Consensus (validation rules)
 * - Localhost API (wallet/miner interface)
 *
 * Peer discovery:
 * - BitTorrent DHT (Kademlia) for automatic peer discovery
 * - P2P addr message exchange between connected nodes
 * - IPv6 only network
 *
 * "Kristian Pilatovich 20091227 - First Real P2P"
 */
class Node {
public:
    explicit Node(const util::Config& config);
    ~Node();

    // Non-copyable
    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;

    // Lifecycle
    bool start();
    void stop();
    bool isRunning() const { return running_.load(); }

    // Wait for shutdown signal
    void waitForShutdown();

    // Signal shutdown
    void requestShutdown();

    // Check if shutdown was requested
    bool isShutdownRequested() const { return shutdown_requested_; }

    // Print live status line (updates in place)
    void printStatusLine();

    // Get components (for external access if needed)
    chain::Chain* getChain() { return chain_.get(); }
    chain::Mempool* getMempool() { return mempool_.get(); }
    chain::UTXOSet* getUTXOSet() { return utxo_set_.get(); }
    p2p::PeerManager* getPeerManager() { return peer_manager_.get(); }
    p2p::MessageHandler* getMessageHandler() { return message_handler_.get(); }
    api::Server* getAPIServer() { return api_server_.get(); }
    p2pool::P2Pool* getP2Pool() { return p2pool_.get(); }
    ::dht::DHT* getDHT() { return dht_.get(); }

    // Get config
    const util::Config& getConfig() const { return config_; }

    // Get node ID
    const uint8_t* getNodeId() const { return node_id_; }

    // Statistics
    struct Stats {
        uint64_t uptime_seconds;
        int32_t chain_height;
        uint64_t peer_count;
        uint64_t mempool_size;
        uint64_t mempool_bytes;
        uint64_t known_addresses;
        uint64_t blocks_received;
        uint64_t txs_received;
        double bandwidth_in;   // bytes/sec average
        double bandwidth_out;  // bytes/sec average
        double sync_progress;
    };
    Stats getStats() const;

    // Record bandwidth (called by P2P layer)
    void recordBytesIn(uint64_t bytes) { bytes_in_.fetch_add(bytes, std::memory_order_relaxed); }
    void recordBytesOut(uint64_t bytes) { bytes_out_.fetch_add(bytes, std::memory_order_relaxed); }

private:
    util::Config config_;
    std::atomic<bool> running_{false};
    std::chrono::steady_clock::time_point start_time_;

    // Shutdown synchronization
    std::mutex shutdown_mutex_;
    std::condition_variable shutdown_cv_;
    bool shutdown_requested_ = false;

    // Bandwidth tracking (atomic for lock-free updates from P2P threads)
    std::atomic<uint64_t> bytes_in_{0};
    std::atomic<uint64_t> bytes_out_{0};
    uint64_t last_bytes_in_ = 0;
    uint64_t last_bytes_out_ = 0;
    std::chrono::steady_clock::time_point last_bandwidth_check_;

    // Heartbeat thread
    std::thread heartbeat_thread_;
    void heartbeatLoop();

    // Node identity (20 bytes, derived from random + hash)
    uint8_t node_id_[20];

    // =========================================================================
    // Mining Work Cache (for Stratum block submission)
    // =========================================================================
    struct MiningWork {
        chain::Block block_template;
        crypto::Hash256 prev_hash;
        uint32_t height = 0;
        uint32_t bits = 0;
        bool valid = false;
    };
    mutable std::mutex mining_work_mutex_;
    MiningWork current_mining_work_;

    // =========================================================================
    // Core Components (in initialization order)
    // =========================================================================

    // 1. Consensus rules
    std::unique_ptr<chain::Consensus> consensus_;

    // 2. UTXO Set (unspent transaction outputs)
    std::unique_ptr<chain::UTXOSet> utxo_set_;

    // 3. Blockchain (block storage and chain management)
    std::unique_ptr<chain::Chain> chain_;

    // 4. Mempool (pending transactions)
    std::unique_ptr<chain::Mempool> mempool_;

    // 5. P2P Peer Manager (TCP connections)
    std::unique_ptr<p2p::PeerManager> peer_manager_;

    // 6. Message Handler (processes P2P messages)
    std::unique_ptr<p2p::MessageHandler> message_handler_;

    // 7. HTTP API Server (localhost only)
    std::unique_ptr<api::Server> api_server_;

    // 8. P2Pool - Decentralized Mining Pool
    std::unique_ptr<p2pool::P2Pool> p2pool_;

    // 9. DHT - BitTorrent-style peer discovery
    std::unique_ptr<::dht::DHT> dht_;

    // =========================================================================
    // Initialization
    // =========================================================================
    void generateNodeId();
    bool initDataDir();
    bool initConsensus();
    bool initUTXOSet();
    bool initChain();
    bool initMempool();
    bool initP2P();
    bool addPeerAddress(const std::string& addr_str, const std::string& source);  // Parse and add peer
    bool initAPI();
    bool initP2Pool();
    bool initDHT();     // Initialize BitTorrent DHT for peer discovery

    // Rebuild UTXO set from blocks (--reindex)
    bool reindexUTXO();

    // Check if node is accessible from outside (before joining P2P network)
    bool checkExternalAccessibility();

    // Snapshot support
    bool loadSnapshot();    // Load UTXO snapshot at startup
    bool exportSnapshot();  // Export UTXO snapshot to file
    std::string getSnapshotPath() const;

    // =========================================================================
    // Event Handlers
    // =========================================================================

    // P2P callbacks
    void onNewPeer(p2p::Connection::Id peer_id);
    void onPeerDisconnect(p2p::Connection::Id peer_id, const std::string& reason);
    void onP2PMessage(p2p::Connection::Id peer_id, const p2p::Message& msg);

    // Chain callbacks
    void onNewTip(const chain::BlockIndex* tip);
    void onBlockConnected(const chain::Block& block, const chain::BlockIndex* index);
    void onBlockDisconnected(const chain::Block& block, const chain::BlockIndex* index);

    // Mempool callbacks
    void onTxAdded(const chain::Transaction& tx);
    void onTxRemoved(const crypto::Hash256& txid, const std::string& reason);
};

} // namespace ftc

#endif // FTC_NODE_H
