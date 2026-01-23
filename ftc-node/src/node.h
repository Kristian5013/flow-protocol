#ifndef FTC_NODE_H
#define FTC_NODE_H

#include "util/config.h"
#include "chain/chain.h"
#include "chain/mempool.h"
#include "chain/utxo_set.h"
#include "chain/consensus.h"
#include "p2p/peer_manager.h"
#include "p2p/message_handler.h"
#include "api/server.h"
#include "stratum/stratum_server.h"
#include "p2pool/p2pool_net.h"
#include "p2pool/sharechain.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <condition_variable>

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
 * - Load seed nodes from peers.dat file
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
    };
    Stats getStats() const;

private:
    util::Config config_;
    std::atomic<bool> running_{false};
    std::chrono::steady_clock::time_point start_time_;

    // Shutdown synchronization
    std::mutex shutdown_mutex_;
    std::condition_variable shutdown_cv_;
    bool shutdown_requested_ = false;

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

    // 8. Stratum Server (for GPU miners)
    std::unique_ptr<stratum::StratumServer> stratum_server_;

    // 9. P2Pool - Decentralized Mining Pool
    std::unique_ptr<p2pool::P2Pool> p2pool_;

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
    bool loadSeedPeers();  // Load peers from peers.dat
    bool savePeers();      // Save peers to peers.dat
    bool initAPI();
    bool initStratum();
    bool initP2Pool();

    // Rebuild UTXO set from blocks (--reindex)
    bool reindexUTXO();

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
