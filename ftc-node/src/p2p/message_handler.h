#ifndef FTC_P2P_MESSAGE_HANDLER_H
#define FTC_P2P_MESSAGE_HANDLER_H

#include "p2p/protocol.h"
#include "p2p/peer_manager.h"
#include "chain/chain.h"
#include "chain/mempool.h"
#include "chain/utxo_set.h"
#include "crypto/keccak256.h"

#include <map>
#include <set>
#include <queue>
#include <mutex>
#include <atomic>
#include <thread>
#include <condition_variable>
#include <functional>
#include <chrono>

namespace ftc {
namespace p2p {

// Forward declarations
class PeerManager;

// Block request entry
struct BlockRequest {
    crypto::Hash256 hash;
    Connection::Id peer_id;
    std::chrono::steady_clock::time_point request_time;
    int attempts;
};

// Sync state
enum class SyncState {
    IDLE,           // Not syncing
    HEADERS,        // Downloading headers
    BLOCKS,         // Downloading blocks
    COMPLETE        // Sync complete
};

/**
 * MessageHandler - processes blockchain-related P2P messages
 *
 * Responsibilities:
 * - Process INV/GETDATA messages for blocks and transactions
 * - Handle block and header downloads
 * - Manage initial block download (IBD)
 * - Validate and relay transactions
 * - Validate and relay blocks
 */
class MessageHandler {
public:
    // Configuration
    struct Config {
        size_t max_blocks_in_flight = 128;          // Max concurrent block downloads
        size_t max_headers_in_flight = 2000;        // Max headers per request
        size_t max_inv_per_message = 50000;         // Max INV items per message
        std::chrono::seconds block_request_timeout{60};
        std::chrono::seconds headers_request_timeout{30};
        size_t max_orphan_txs = 100;
        size_t max_orphan_blocks = 750;
        bool relay_txs = true;
        bool relay_blocks = true;

        Config() = default;
    };

    MessageHandler(chain::Chain* chain,
                   chain::Mempool* mempool,
                   chain::UTXOSet* utxo_set,
                   PeerManager* peer_manager);
    MessageHandler(chain::Chain* chain,
                   chain::Mempool* mempool,
                   chain::UTXOSet* utxo_set,
                   PeerManager* peer_manager,
                   const Config& config);
    ~MessageHandler();

    // Non-copyable
    MessageHandler(const MessageHandler&) = delete;
    MessageHandler& operator=(const MessageHandler&) = delete;

    // Lifecycle
    bool start();
    void stop();
    bool isRunning() const { return running_; }

    // Process incoming message (called by PeerManager)
    void processMessage(Connection::Id peer_id, const Message& msg);

    // Sync control
    void startSync();
    void stopSync();
    bool isSyncing() const { return sync_state_ != SyncState::IDLE && sync_state_ != SyncState::COMPLETE; }
    SyncState getSyncState() const { return sync_state_; }
    double getSyncProgress() const;

    // Manual operations
    void requestBlock(const crypto::Hash256& hash);
    void requestHeaders(Connection::Id peer_id);
    void announceBlock(const chain::Block& block);
    void announceTx(const chain::Transaction& tx);

    // Callbacks for validated items
    using BlockCallback = std::function<void(const chain::Block&, bool accepted)>;
    using TxCallback = std::function<void(const chain::Transaction&, bool accepted)>;

    void setBlockCallback(BlockCallback cb) { on_block_ = cb; }
    void setTxCallback(TxCallback cb) { on_tx_ = cb; }

    // Statistics
    struct Stats {
        uint64_t blocks_received = 0;
        uint64_t blocks_validated = 0;
        uint64_t blocks_rejected = 0;
        uint64_t txs_received = 0;
        uint64_t txs_validated = 0;
        uint64_t txs_rejected = 0;
        uint64_t headers_received = 0;
        uint64_t inv_received = 0;
        uint64_t getdata_sent = 0;
    };

    Stats getStats() const;

    // Sync statistics (for API)
    struct SyncStats {
        SyncState state = SyncState::IDLE;
        uint64_t current_height = 0;
        uint64_t target_height = 0;
        double progress = 0.0;              // 0.0 - 1.0
        double blocks_per_second = 0.0;
        double bytes_per_second = 0.0;
        size_t blocks_in_flight = 0;
        size_t blocks_in_queue = 0;
        size_t active_peers = 0;
        uint64_t total_downloaded = 0;
        std::chrono::seconds eta{0};        // Estimated time remaining
    };

    SyncStats getSyncStats() const;

private:
    // Message handlers
    void handleInv(Connection::Id peer_id, const InvMessage& msg);
    void handleGetData(Connection::Id peer_id, const InvMessage& msg);
    void handleNotFound(Connection::Id peer_id, const InvMessage& msg);
    void handleGetBlocks(Connection::Id peer_id, const GetBlocksMessage& msg);
    void handleGetHeaders(Connection::Id peer_id, const GetHeadersMessage& msg);
    void handleHeaders(Connection::Id peer_id, const HeadersMessage& msg);
    void handleBlock(Connection::Id peer_id, const BlockMessage& msg);
    void handleTx(Connection::Id peer_id, const TxMessage& msg);
    void handleMempool(Connection::Id peer_id);

    // Block processing
    void processBlock(const chain::Block& block, Connection::Id from_peer);
    void processOrphanBlocks(const crypto::Hash256& parent_hash);
    bool validateBlock(const chain::Block& block, std::string& error);
    void relayBlock(const crypto::Hash256& hash, const chain::Block& block, Connection::Id exclude);

    // Transaction processing
    void processTx(const chain::Transaction& tx, Connection::Id from_peer);
    void processOrphanTxs(const crypto::Hash256& parent_txid);
    bool validateTx(const chain::Transaction& tx, std::string& error);
    void relayTx(const crypto::Hash256& txid, const chain::Transaction& tx, Connection::Id exclude);

    // Header processing
    void processHeaders(const std::vector<chain::BlockHeader>& headers, Connection::Id from_peer);
    bool validateHeader(const chain::BlockHeader& header, std::string& error);

    // Sync helpers
    void selectSyncPeer();
    void requestMoreHeaders();
    void requestMoreBlocks();
    void checkSyncProgress();
    void completeSyncPhase();

    // Block download management
    void addBlockRequest(const crypto::Hash256& hash, Connection::Id peer_id);
    void removeBlockRequest(const crypto::Hash256& hash);
    bool isBlockInFlight(const crypto::Hash256& hash) const;
    void checkBlockTimeouts();

    // Inventory management
    void sendInv(Connection::Id peer_id, const std::vector<InvItem>& items);
    void sendGetData(Connection::Id peer_id, const std::vector<InvItem>& items);
    void sendHeaders(Connection::Id peer_id, const std::vector<chain::BlockHeader>& headers);
    void sendBlock(Connection::Id peer_id, const chain::Block& block);
    void sendTx(Connection::Id peer_id, const chain::Transaction& tx);
    void sendNotFound(Connection::Id peer_id, const std::vector<InvItem>& items);

    // Locator helpers
    std::vector<crypto::Hash256> buildLocator() const;
    crypto::Hash256 findForkPoint(const std::vector<crypto::Hash256>& locator) const;

    // Worker thread
    void workerThread();

    // Configuration
    Config config_;

    // Chain components
    chain::Chain* chain_;
    chain::Mempool* mempool_;
    chain::UTXOSet* utxo_set_;
    PeerManager* peer_manager_;

    // State
    std::atomic<bool> running_{false};
    std::atomic<SyncState> sync_state_{SyncState::IDLE};
    Connection::Id sync_peer_{0};
    std::chrono::steady_clock::time_point sync_start_;

    // Block download state
    std::map<crypto::Hash256, BlockRequest> blocks_in_flight_;
    std::set<crypto::Hash256> blocks_requested_;
    std::queue<crypto::Hash256> download_queue_;
    mutable std::mutex blocks_mutex_;

    // Header sync state
    std::vector<crypto::Hash256> headers_chain_;
    crypto::Hash256 last_header_hash_;
    std::chrono::steady_clock::time_point last_headers_request_;
    bool headers_sync_complete_{false};

    // Orphan management
    struct OrphanBlock {
        chain::Block block;
        Connection::Id from_peer;
        std::chrono::steady_clock::time_point received_time;
    };
    std::map<crypto::Hash256, OrphanBlock> orphan_blocks_;
    std::multimap<crypto::Hash256, crypto::Hash256> orphan_blocks_by_prev_;  // prev_hash -> orphan_hash

    struct OrphanTx {
        chain::Transaction tx;
        Connection::Id from_peer;
        std::chrono::steady_clock::time_point received_time;
    };
    std::map<crypto::Hash256, OrphanTx> orphan_txs_;
    std::multimap<crypto::Hash256, crypto::Hash256> orphan_txs_by_prev_;  // prev_txid -> orphan_txid
    mutable std::mutex orphans_mutex_;

    // Recent rejects (to avoid re-requesting)
    std::set<crypto::Hash256> recent_rejects_;
    mutable std::mutex rejects_mutex_;

    // Worker thread
    std::thread worker_thread_;
    std::condition_variable worker_cv_;
    std::mutex worker_mutex_;
    std::queue<std::function<void()>> work_queue_;

    // Callbacks
    BlockCallback on_block_;
    TxCallback on_tx_;

    // Statistics
    mutable Stats stats_;
    mutable std::mutex stats_mutex_;
};

} // namespace p2p
} // namespace ftc

#endif // FTC_P2P_MESSAGE_HANDLER_H
