#include "p2p/message_handler.h"
#include "chain/consensus.h"
#include "util/logging.h"
#include <algorithm>
#include <cstring>

namespace ftc {
namespace p2p {

using namespace crypto;
using namespace chain;
using namespace std::chrono;

//-----------------------------------------------------------------------------
// Constructor / Destructor
//-----------------------------------------------------------------------------

MessageHandler::MessageHandler(Chain* chain,
                               Mempool* mempool,
                               UTXOSet* utxo_set,
                               PeerManager* peer_manager)
    : MessageHandler(chain, mempool, utxo_set, peer_manager, Config{}) {
}

MessageHandler::MessageHandler(Chain* chain,
                               Mempool* mempool,
                               UTXOSet* utxo_set,
                               PeerManager* peer_manager,
                               const Config& config)
    : config_(config)
    , chain_(chain)
    , mempool_(mempool)
    , utxo_set_(utxo_set)
    , peer_manager_(peer_manager) {
}

MessageHandler::~MessageHandler() {
    stop();
}

//-----------------------------------------------------------------------------
// Lifecycle
//-----------------------------------------------------------------------------

bool MessageHandler::start() {
    if (running_) return true;

    running_ = true;
    sync_state_ = SyncState::IDLE;

    // Start worker thread
    worker_thread_ = std::thread(&MessageHandler::workerThread, this);

    return true;
}

void MessageHandler::stop() {
    if (!running_) return;

    running_ = false;
    sync_state_ = SyncState::IDLE;

    // Wake up worker thread
    {
        std::lock_guard<std::mutex> lock(worker_mutex_);
        worker_cv_.notify_all();
    }

    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

//-----------------------------------------------------------------------------
// Message Dispatch
//-----------------------------------------------------------------------------

void MessageHandler::processMessage(Connection::Id peer_id, const Message& msg) {
    if (!running_) return;

    LOG_DEBUG("processMessage: from peer {} type={}", peer_id, static_cast<int>(msg.type));

    // Dispatch based on message type
    switch (msg.type) {
        case MessageType::INV:
            if (auto* inv = std::get_if<InvMessage>(&msg.payload)) {
                handleInv(peer_id, *inv);
            }
            break;

        case MessageType::GETDATA:
            if (auto* getdata = std::get_if<InvMessage>(&msg.payload)) {
                handleGetData(peer_id, *getdata);
            }
            break;

        case MessageType::NOTFOUND:
            if (auto* notfound = std::get_if<InvMessage>(&msg.payload)) {
                handleNotFound(peer_id, *notfound);
            }
            break;

        case MessageType::GETBLOCKS:
            if (auto* getblocks = std::get_if<GetBlocksMessage>(&msg.payload)) {
                handleGetBlocks(peer_id, *getblocks);
            }
            break;

        case MessageType::GETHEADERS:
            if (auto* getheaders = std::get_if<GetHeadersMessage>(&msg.payload)) {
                handleGetHeaders(peer_id, *getheaders);
            }
            break;

        case MessageType::HEADERS:
            if (auto* headers = std::get_if<HeadersMessage>(&msg.payload)) {
                handleHeaders(peer_id, *headers);
            }
            break;

        case MessageType::BLOCK:
            if (auto* block = std::get_if<BlockMessage>(&msg.payload)) {
                handleBlock(peer_id, *block);
            }
            break;

        case MessageType::TX:
            if (auto* tx = std::get_if<TxMessage>(&msg.payload)) {
                handleTx(peer_id, *tx);
            }
            break;

        case MessageType::MEMPOOL:
            handleMempool(peer_id);
            break;

        default:
            // Other messages handled by PeerManager
            break;
    }
}

//-----------------------------------------------------------------------------
// INV Handler
//-----------------------------------------------------------------------------

void MessageHandler::handleInv(Connection::Id peer_id, const InvMessage& msg) {
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.inv_received++;
    }

    std::vector<InvItem> blocks_to_request;
    std::vector<InvItem> txs_to_request;

    for (const auto& item : msg.items) {
        // Check if already rejected
        {
            std::lock_guard<std::mutex> rlock(rejects_mutex_);
            if (recent_rejects_.count(item.hash)) {
                continue;
            }
        }

        if (item.type == InvType::BLOCK) {
            // Check if we already have this block
            if (chain_->hasBlock(item.hash)) {
                peer_manager_->addKnownBlock(peer_id, item.hash);
                continue;
            }

            // Check if already in flight
            if (!isBlockInFlight(item.hash)) {
                blocks_to_request.push_back(item);
            }
        } else if (item.type == InvType::TX) {
            // Check if we already have this transaction
            if (mempool_->has(item.hash) || chain_->hasTx(item.hash)) {
                peer_manager_->addKnownTx(peer_id, item.hash);
                continue;
            }

            txs_to_request.push_back(item);
        }
    }

    // Request blocks
    if (!blocks_to_request.empty()) {
        sendGetData(peer_id, blocks_to_request);

        std::lock_guard<std::mutex> block_lock(blocks_mutex_);
        for (const auto& item : blocks_to_request) {
            addBlockRequest(item.hash, peer_id);
        }
    }

    // Request transactions
    if (!txs_to_request.empty()) {
        sendGetData(peer_id, txs_to_request);
    }
}

//-----------------------------------------------------------------------------
// GETDATA Handler
//-----------------------------------------------------------------------------

void MessageHandler::handleGetData(Connection::Id peer_id, const InvMessage& msg) {
    LOG_DEBUG("handleGetData: from peer {} with {} items", peer_id, msg.items.size());

    std::vector<InvItem> not_found;

    for (const auto& item : msg.items) {
        if (item.type == InvType::BLOCK) {
            LOG_DEBUG("handleGetData: looking for block {:02x}{:02x}...",
                      item.hash[0], item.hash[1]);
            // Try to get block from chain
            auto block = chain_->getBlock(item.hash);
            if (block) {
                LOG_DEBUG("handleGetData: found block, sending to peer {}", peer_id);
                sendBlock(peer_id, *block);
            } else {
                LOG_DEBUG("handleGetData: block not found");
                not_found.push_back(item);
            }
        } else if (item.type == InvType::TX) {
            // Try to get transaction from mempool or chain
            auto tx = mempool_->get(item.hash);
            if (tx) {
                sendTx(peer_id, *tx);
            } else {
                tx = chain_->getTx(item.hash);
                if (tx) {
                    sendTx(peer_id, *tx);
                } else {
                    not_found.push_back(item);
                }
            }
        }
    }

    if (!not_found.empty()) {
        sendNotFound(peer_id, not_found);
    }
}

//-----------------------------------------------------------------------------
// NOTFOUND Handler
//-----------------------------------------------------------------------------

void MessageHandler::handleNotFound(Connection::Id peer_id, const InvMessage& msg) {
    std::lock_guard<std::mutex> lock(blocks_mutex_);

    for (const auto& item : msg.items) {
        if (item.type == InvType::BLOCK) {
            // Remove from in-flight and try another peer
            removeBlockRequest(item.hash);

            // Re-queue for download from another peer
            download_queue_.push(item.hash);
        }
    }
}

//-----------------------------------------------------------------------------
// GETBLOCKS Handler
//-----------------------------------------------------------------------------

void MessageHandler::handleGetBlocks(Connection::Id peer_id, const GetBlocksMessage& msg) {
    // Find the fork point using the locator
    Hash256 fork_hash = findForkPoint(msg.locator);

    // Get block hashes after the fork point
    std::vector<InvItem> inv_items;
    auto height_opt = chain_->getBlockHeight(fork_hash);
    int32_t height = height_opt.value_or(0);

    // Send up to 500 block hashes
    for (size_t i = 0; i < 500 && height < chain_->getHeight(); i++) {
        height++;
        auto hash_opt = chain_->getBlockHashAtHeight(height);
        if (!hash_opt) break;

        Hash256 hash = *hash_opt;
        if (hash == msg.hash_stop) break;

        InvItem item;
        item.type = InvType::BLOCK;
        item.hash = hash;
        inv_items.push_back(item);
    }

    if (!inv_items.empty()) {
        sendInv(peer_id, inv_items);
    }
}

//-----------------------------------------------------------------------------
// GETHEADERS Handler
//-----------------------------------------------------------------------------

void MessageHandler::handleGetHeaders(Connection::Id peer_id, const GetHeadersMessage& msg) {
    LOG_DEBUG("handleGetHeaders: from peer {} with {} locator hashes", peer_id, msg.locator.size());

    // Find the fork point using the locator
    Hash256 fork_hash = findForkPoint(msg.locator);
    // Log first few bytes of fork hash
    LOG_DEBUG("handleGetHeaders: fork point {:02x}{:02x}{:02x}{:02x}...",
              fork_hash[0], fork_hash[1], fork_hash[2], fork_hash[3]);

    // Get headers after the fork point
    std::vector<BlockHeader> headers;
    auto height_opt = chain_->getBlockHeight(fork_hash);
    int32_t height = height_opt.value_or(0);
    LOG_DEBUG("handleGetHeaders: starting from height {}, chain height is {}",
              height, chain_->getHeight());

    // Send up to 2000 headers
    for (size_t i = 0; i < MAX_HEADERS_SIZE && height < chain_->getHeight(); i++) {
        height++;
        auto hash_opt = chain_->getBlockHashAtHeight(height);
        if (!hash_opt) break;

        auto header = chain_->getBlockHeader(*hash_opt);
        if (!header) break;

        if (header->getHash() == msg.hash_stop) {
            headers.push_back(*header);
            break;
        }

        headers.push_back(*header);
    }

    LOG_DEBUG("handleGetHeaders: sending {} headers to peer {}", headers.size(), peer_id);
    if (!headers.empty()) {
        sendHeaders(peer_id, headers);
    }
}

//-----------------------------------------------------------------------------
// HEADERS Handler
//-----------------------------------------------------------------------------

void MessageHandler::handleHeaders(Connection::Id peer_id, const HeadersMessage& msg) {
    LOG_DEBUG("handleHeaders: from peer {} with {} headers", peer_id, msg.headers.size());

    if (msg.headers.empty()) {
        LOG_DEBUG("handleHeaders: empty headers, completing sync phase");
        // No more headers, move to block download phase
        if (sync_state_ == SyncState::HEADERS && peer_id == sync_peer_) {
            headers_sync_complete_ = true;
            completeSyncPhase();
        }
        return;
    }

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.headers_received += msg.headers.size();
    }

    LOG_INFO("Received {} headers from peer {}", msg.headers.size(), peer_id);
    processHeaders(msg.headers, peer_id);

    // Request more headers if in sync mode
    LOG_DEBUG("handleHeaders: checking sync state={}, sync_peer={}, this peer={}",
              static_cast<int>(sync_state_.load()), sync_peer_, peer_id);

    if (sync_state_ == SyncState::HEADERS && peer_id == sync_peer_) {
        if (msg.headers.size() >= MAX_HEADERS_SIZE) {
            LOG_DEBUG("handleHeaders: requesting more headers");
            requestMoreHeaders();
        } else {
            LOG_DEBUG("handleHeaders: headers sync complete, moving to block download");
            headers_sync_complete_ = true;
            completeSyncPhase();
        }
    } else {
        LOG_DEBUG("handleHeaders: not in sync mode or different peer");
    }
}

//-----------------------------------------------------------------------------
// BLOCK Handler
//-----------------------------------------------------------------------------

void MessageHandler::handleBlock(Connection::Id peer_id, const BlockMessage& msg) {
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.blocks_received++;
    }

    Hash256 hash = msg.block.getHash();

    // Remove from in-flight
    {
        std::lock_guard<std::mutex> lock(blocks_mutex_);
        removeBlockRequest(hash);
    }

    // Mark peer as knowing this block
    peer_manager_->addKnownBlock(peer_id, hash);

    // Process the block
    processBlock(msg.block, peer_id);

    // Request more blocks if syncing
    if (sync_state_ == SyncState::BLOCKS) {
        requestMoreBlocks();
    }
}

//-----------------------------------------------------------------------------
// TX Handler
//-----------------------------------------------------------------------------

void MessageHandler::handleTx(Connection::Id peer_id, const TxMessage& msg) {
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.txs_received++;
    }

    Hash256 txid = msg.tx.getTxId();

    // Mark peer as knowing this transaction
    peer_manager_->addKnownTx(peer_id, txid);

    // Process the transaction
    processTx(msg.tx, peer_id);
}

//-----------------------------------------------------------------------------
// MEMPOOL Handler
//-----------------------------------------------------------------------------

void MessageHandler::handleMempool(Connection::Id peer_id) {
    // Send INV for all mempool transactions
    auto txids = mempool_->getAllTxids();

    if (txids.empty()) return;

    std::vector<InvItem> items;
    for (const auto& txid : txids) {
        // Don't send if peer already knows
        if (peer_manager_->hasKnownTx(peer_id, txid)) {
            continue;
        }

        InvItem item;
        item.type = InvType::TX;
        item.hash = txid;
        items.push_back(item);

        if (items.size() >= config_.max_inv_per_message) {
            break;
        }
    }

    if (!items.empty()) {
        sendInv(peer_id, items);
    }
}

//-----------------------------------------------------------------------------
// Block Processing
//-----------------------------------------------------------------------------

void MessageHandler::processBlock(const Block& block, Connection::Id from_peer) {
    Hash256 hash = block.getHash();
    Hash256 prev_hash = block.header.prev_hash;

    // Check if we already have this block
    if (chain_->hasBlock(hash)) {
        return;
    }

    // Validate the block
    std::string error;
    if (!validateBlock(block, error)) {
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.blocks_rejected++;
        }
        {
            std::lock_guard<std::mutex> lock(rejects_mutex_);
            recent_rejects_.insert(hash);
        }

        if (on_block_) {
            on_block_(block, false);
        }
        return;
    }

    // Check if parent exists
    if (!chain_->hasBlock(prev_hash)) {
        // Store as orphan
        std::lock_guard<std::mutex> lock(orphans_mutex_);

        if (orphan_blocks_.size() < config_.max_orphan_blocks) {
            OrphanBlock orphan;
            orphan.block = block;
            orphan.from_peer = from_peer;
            orphan.received_time = steady_clock::now();

            orphan_blocks_[hash] = orphan;
            orphan_blocks_by_prev_.insert({prev_hash, hash});
        }
        return;
    }

    // Add block to chain
    if (chain_->addBlock(block) != ValidationResult::VALID) {
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.blocks_rejected++;
        }
        return;
    }

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.blocks_validated++;
    }

    if (on_block_) {
        on_block_(block, true);
    }

    // Relay to other peers
    if (config_.relay_blocks) {
        relayBlock(hash, block, from_peer);
    }

    // Process any orphan blocks that were waiting for this one
    processOrphanBlocks(hash);
}

void MessageHandler::processOrphanBlocks(const Hash256& parent_hash) {
    std::vector<Block> to_process;

    {
        std::lock_guard<std::mutex> lock(orphans_mutex_);

        auto range = orphan_blocks_by_prev_.equal_range(parent_hash);
        for (auto it = range.first; it != range.second; ++it) {
            auto orphan_it = orphan_blocks_.find(it->second);
            if (orphan_it != orphan_blocks_.end()) {
                to_process.push_back(orphan_it->second.block);
                orphan_blocks_.erase(orphan_it);
            }
        }

        orphan_blocks_by_prev_.erase(parent_hash);
    }

    for (const auto& block : to_process) {
        processBlock(block, 0);
    }
}

bool MessageHandler::validateBlock(const Block& block, std::string& error) {
    // Basic validation
    if (block.transactions.empty()) {
        error = "Block has no transactions";
        return false;
    }

    // Validate header
    if (!validateHeader(block.header, error)) {
        return false;
    }

    // Validate merkle root
    auto computed_root = block.calculateMerkleRoot();
    if (computed_root != block.header.merkle_root) {
        error = "Merkle root mismatch";
        return false;
    }

    // Validate transactions
    for (size_t i = 0; i < block.transactions.size(); i++) {
        const auto& tx = block.transactions[i];

        // First transaction must be coinbase
        if (i == 0) {
            if (!tx.isCoinbase()) {
                error = "First transaction is not coinbase";
                return false;
            }
        } else {
            if (tx.isCoinbase()) {
                error = "Multiple coinbase transactions";
                return false;
            }
        }
    }

    // Full validation delegated to consensus rules
    // This is just basic structural checks
    return true;
}

void MessageHandler::relayBlock(const Hash256& hash, const Block& block, Connection::Id exclude) {
    // Create INV message
    InvItem item;
    item.type = InvType::BLOCK;
    item.hash = hash;

    std::vector<InvItem> items = {item};

    // Send to all connected peers except the one we got it from
    auto peers = peer_manager_->getPeerInfo();
    for (const auto& peer : peers) {
        if (peer.id == exclude) continue;
        if (peer_manager_->hasKnownBlock(peer.id, hash)) continue;

        sendInv(peer.id, items);
    }
}

//-----------------------------------------------------------------------------
// Transaction Processing
//-----------------------------------------------------------------------------

void MessageHandler::processTx(const Transaction& tx, Connection::Id from_peer) {
    Hash256 txid = tx.getTxId();

    // Check if we already have this transaction
    if (mempool_->has(txid) || chain_->hasTx(txid)) {
        return;
    }

    // Validate the transaction
    std::string error;
    if (!validateTx(tx, error)) {
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.txs_rejected++;
        }
        {
            std::lock_guard<std::mutex> lock(rejects_mutex_);
            recent_rejects_.insert(txid);
        }

        if (on_tx_) {
            on_tx_(tx, false);
        }
        return;
    }

    // Check if all inputs are available
    bool inputs_available = true;
    for (const auto& input : tx.inputs) {
        if (!input.prevout.isNull()) {
            if (!utxo_set_->has(input.prevout) && !mempool_->has(input.prevout.txid)) {
                inputs_available = false;
                break;
            }
        }
    }

    if (!inputs_available) {
        // Store as orphan
        std::lock_guard<std::mutex> lock(orphans_mutex_);

        if (orphan_txs_.size() < config_.max_orphan_txs) {
            OrphanTx orphan;
            orphan.tx = tx;
            orphan.from_peer = from_peer;
            orphan.received_time = steady_clock::now();

            orphan_txs_[txid] = orphan;

            // Track by prev txid for each input
            for (const auto& input : tx.inputs) {
                if (!input.prevout.isNull()) {
                    orphan_txs_by_prev_.insert({input.prevout.txid, txid});
                }
            }
        }
        return;
    }

    // Add to mempool
    if (mempool_->add(tx, chain_->getHeight()) != MempoolReject::VALID) {
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.txs_rejected++;
        }
        return;
    }

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.txs_validated++;
    }

    if (on_tx_) {
        on_tx_(tx, true);
    }

    // Relay to other peers
    if (config_.relay_txs) {
        relayTx(txid, tx, from_peer);
    }

    // Process any orphan transactions waiting for this one
    processOrphanTxs(txid);
}

void MessageHandler::processOrphanTxs(const Hash256& parent_txid) {
    std::vector<Transaction> to_process;

    {
        std::lock_guard<std::mutex> lock(orphans_mutex_);

        auto range = orphan_txs_by_prev_.equal_range(parent_txid);
        for (auto it = range.first; it != range.second; ++it) {
            auto orphan_it = orphan_txs_.find(it->second);
            if (orphan_it != orphan_txs_.end()) {
                to_process.push_back(orphan_it->second.tx);
                orphan_txs_.erase(orphan_it);
            }
        }

        orphan_txs_by_prev_.erase(parent_txid);
    }

    for (const auto& tx : to_process) {
        processTx(tx, 0);
    }
}

bool MessageHandler::validateTx(const Transaction& tx, std::string& error) {
    // Basic structural validation
    if (tx.inputs.empty()) {
        error = "Transaction has no inputs";
        return false;
    }

    if (tx.outputs.empty()) {
        error = "Transaction has no outputs";
        return false;
    }

    // Check for duplicate inputs
    std::set<OutPoint> seen_inputs;
    for (const auto& input : tx.inputs) {
        if (seen_inputs.count(input.prevout)) {
            error = "Duplicate input";
            return false;
        }
        seen_inputs.insert(input.prevout);
    }

    // Check output values
    uint64_t total_output = 0;
    for (const auto& output : tx.outputs) {
        if (output.value > 21000000ULL * 100000000ULL) {
            error = "Output value too high";
            return false;
        }
        total_output += output.value;
        if (total_output > 21000000ULL * 100000000ULL) {
            error = "Total output value overflow";
            return false;
        }
    }

    // Size check
    if (tx.getSize() > 1000000) {  // 1 MB max tx size
        error = "Transaction too large";
        return false;
    }

    return true;
}

void MessageHandler::relayTx(const Hash256& txid, const Transaction& tx, Connection::Id exclude) {
    // Create INV message
    InvItem item;
    item.type = InvType::TX;
    item.hash = txid;

    std::vector<InvItem> items = {item};

    // Send to all connected peers except the one we got it from
    auto peers = peer_manager_->getPeerInfo();
    for (const auto& peer : peers) {
        if (peer.id == exclude) continue;
        if (!peer.relay) continue;
        if (peer_manager_->hasKnownTx(peer.id, txid)) continue;

        sendInv(peer.id, items);
    }
}

//-----------------------------------------------------------------------------
// Header Processing
//-----------------------------------------------------------------------------

void MessageHandler::processHeaders(const std::vector<BlockHeader>& headers, Connection::Id from_peer) {
    for (const auto& header : headers) {
        std::string error;
        if (!validateHeader(header, error)) {
            // Invalid header, disconnect peer
            peer_manager_->disconnect(from_peer, "Invalid header: " + error);
            return;
        }

        Hash256 hash = header.getHash();

        // Store in headers chain for later block download
        if (!chain_->hasBlock(hash)) {
            headers_chain_.push_back(hash);
            last_header_hash_ = hash;
        }
    }
}

bool MessageHandler::validateHeader(const BlockHeader& header, std::string& error) {
    // Check proof of work
    Hash256 hash = header.getHash();

    // The hash should be below the target (simplified check)
    // In full implementation, compare against difficulty target

    // Check timestamp (not too far in the future)
    auto now = std::chrono::system_clock::now();
    auto max_time = now + std::chrono::hours(2);
    auto header_time = std::chrono::system_clock::from_time_t(header.timestamp);

    if (header_time > max_time) {
        error = "Timestamp too far in future";
        return false;
    }

    return true;
}

//-----------------------------------------------------------------------------
// Sync Control
//-----------------------------------------------------------------------------

void MessageHandler::startSync() {
    // Allow starting sync if IDLE or COMPLETE (to handle late-connecting higher peers)
    auto current_state = sync_state_.load();
    LOG_DEBUG("startSync called, current state={}", static_cast<int>(current_state));

    if (current_state != SyncState::IDLE && current_state != SyncState::COMPLETE) {
        LOG_DEBUG("startSync: skipping, state is not IDLE or COMPLETE");
        return;
    }

    sync_start_ = steady_clock::now();
    headers_sync_complete_ = false;
    headers_chain_.clear();

    selectSyncPeer();
    LOG_DEBUG("startSync: selected sync_peer={}", sync_peer_);

    if (sync_peer_ != 0) {
        sync_state_ = SyncState::HEADERS;
        LOG_INFO("Starting headers sync from peer {}", sync_peer_);
        requestMoreHeaders();
    } else {
        // No peer with higher height - we're already synced
        LOG_DEBUG("startSync: no peer with higher height, marking complete");
        sync_state_ = SyncState::COMPLETE;
    }
}

void MessageHandler::stopSync() {
    sync_state_ = SyncState::IDLE;
    sync_peer_ = 0;

    std::lock_guard<std::mutex> lock(blocks_mutex_);
    blocks_in_flight_.clear();
    blocks_requested_.clear();
    while (!download_queue_.empty()) {
        download_queue_.pop();
    }
}

double MessageHandler::getSyncProgress() const {
    if (sync_state_ == SyncState::IDLE) return 1.0;
    if (sync_state_ == SyncState::COMPLETE) return 1.0;

    // Estimate progress based on headers and blocks downloaded
    uint64_t current_height = chain_->getHeight();
    uint64_t target_height = headers_chain_.size() + current_height;

    if (target_height == 0) return 0.0;

    return static_cast<double>(current_height) / static_cast<double>(target_height);
}

void MessageHandler::selectSyncPeer() {
    // Select peer with highest reported height that's higher than our chain
    Connection::Id best_peer = 0;
    int32_t our_height = chain_ ? chain_->getHeight() : 0;
    int32_t best_height = our_height;  // Start from our height, only select peers higher

    auto peers = peer_manager_->getPeerInfo();
    LOG_DEBUG("selectSyncPeer: our_height={}, checking {} peers", our_height, peers.size());

    for (const auto& peer : peers) {
        LOG_DEBUG("  peer {} state={} best_height={}",
                  peer.id, static_cast<int>(peer.state), peer.best_height);
        if (peer.state != PeerState::ESTABLISHED) continue;
        if (peer.best_height > best_height) {
            best_height = peer.best_height;
            best_peer = peer.id;
        }
    }

    LOG_DEBUG("selectSyncPeer: selected peer={} with height={}", best_peer, best_height);
    sync_peer_ = best_peer;
}

void MessageHandler::requestMoreHeaders() {
    if (sync_peer_ == 0) {
        LOG_DEBUG("requestMoreHeaders: no sync_peer, returning");
        return;
    }

    GetHeadersMessage msg;
    msg.version = PROTOCOL_VERSION;
    msg.locator = buildLocator();
    msg.hash_stop = ZERO_HASH;

    LOG_DEBUG("requestMoreHeaders: sending GETHEADERS to peer {} with {} locator hashes",
              sync_peer_, msg.locator.size());

    Message message;
    message.type = MessageType::GETHEADERS;
    message.payload = msg;

    bool sent = peer_manager_->sendTo(sync_peer_, message);
    LOG_DEBUG("requestMoreHeaders: sendTo returned {}", sent);
    last_headers_request_ = steady_clock::now();
}

void MessageHandler::requestMoreBlocks() {
    LOG_DEBUG("requestMoreBlocks: headers_chain size={}", headers_chain_.size());

    std::lock_guard<std::mutex> lock(blocks_mutex_);

    // Fill up block download queue
    while (!headers_chain_.empty() && download_queue_.size() < config_.max_blocks_in_flight) {
        Hash256 hash = headers_chain_.front();
        headers_chain_.erase(headers_chain_.begin());

        if (!chain_->hasBlock(hash) && !blocks_requested_.count(hash)) {
            download_queue_.push(hash);
            LOG_DEBUG("requestMoreBlocks: queued block {:02x}{:02x}...",
                      hash[0], hash[1]);
        }
    }

    // Request blocks from queue
    std::vector<InvItem> to_request;

    LOG_DEBUG("requestMoreBlocks: download_queue size={}, blocks_in_flight={}",
              download_queue_.size(), blocks_in_flight_.size());

    while (!download_queue_.empty() && blocks_in_flight_.size() < config_.max_blocks_in_flight) {
        Hash256 hash = download_queue_.front();
        download_queue_.pop();

        if (chain_->hasBlock(hash) || blocks_requested_.count(hash)) {
            LOG_DEBUG("requestMoreBlocks: skipping block (already have or requested)");
            continue;
        }

        InvItem item;
        item.type = InvType::BLOCK;
        item.hash = hash;
        to_request.push_back(item);

        addBlockRequest(hash, sync_peer_);
    }

    LOG_DEBUG("requestMoreBlocks: to_request size={}, sync_peer={}",
              to_request.size(), sync_peer_);

    if (!to_request.empty() && sync_peer_ != 0) {
        LOG_INFO("Requesting {} blocks from peer {}", to_request.size(), sync_peer_);
        sendGetData(sync_peer_, to_request);
    }

    // Check if sync is complete
    if (download_queue_.empty() && blocks_in_flight_.empty() && headers_sync_complete_) {
        LOG_DEBUG("requestMoreBlocks: sync complete (all queues empty)");
        sync_state_ = SyncState::COMPLETE;
    }
}

void MessageHandler::completeSyncPhase() {
    LOG_DEBUG("completeSyncPhase: sync_state={}, headers_chain size={}",
              static_cast<int>(sync_state_.load()), headers_chain_.size());

    if (sync_state_ == SyncState::HEADERS) {
        // Move to block download phase
        LOG_INFO("Headers sync complete with {} blocks to download", headers_chain_.size());
        sync_state_ = SyncState::BLOCKS;
        requestMoreBlocks();
    }
}

void MessageHandler::checkSyncProgress() {
    if (sync_state_ == SyncState::HEADERS) {
        auto now = steady_clock::now();
        if (now - last_headers_request_ > config_.headers_request_timeout) {
            // Headers request timed out, try another peer
            selectSyncPeer();
            if (sync_peer_ != 0) {
                requestMoreHeaders();
            }
        }
    }

    checkBlockTimeouts();
}

//-----------------------------------------------------------------------------
// Block Download Management
//-----------------------------------------------------------------------------

void MessageHandler::addBlockRequest(const Hash256& hash, Connection::Id peer_id) {
    BlockRequest req;
    req.hash = hash;
    req.peer_id = peer_id;
    req.request_time = steady_clock::now();
    req.attempts = 1;

    blocks_in_flight_[hash] = req;
    blocks_requested_.insert(hash);
}

void MessageHandler::removeBlockRequest(const Hash256& hash) {
    blocks_in_flight_.erase(hash);
    // Keep in blocks_requested_ to prevent re-requesting
}

bool MessageHandler::isBlockInFlight(const Hash256& hash) const {
    std::lock_guard<std::mutex> lock(blocks_mutex_);
    return blocks_in_flight_.count(hash) > 0;
}

void MessageHandler::checkBlockTimeouts() {
    std::lock_guard<std::mutex> lock(blocks_mutex_);

    auto now = steady_clock::now();
    std::vector<Hash256> timed_out;

    for (const auto& [hash, req] : blocks_in_flight_) {
        if (now - req.request_time > config_.block_request_timeout) {
            timed_out.push_back(hash);
        }
    }

    for (const auto& hash : timed_out) {
        // Remove and re-queue
        blocks_in_flight_.erase(hash);
        blocks_requested_.erase(hash);
        download_queue_.push(hash);
    }
}

//-----------------------------------------------------------------------------
// Message Sending
//-----------------------------------------------------------------------------

void MessageHandler::sendInv(Connection::Id peer_id, const std::vector<InvItem>& items) {
    if (items.empty()) return;

    InvMessage inv;
    inv.items = items;

    Message msg;
    msg.type = MessageType::INV;
    msg.payload = inv;

    peer_manager_->sendTo(peer_id, msg);
}

void MessageHandler::sendGetData(Connection::Id peer_id, const std::vector<InvItem>& items) {
    if (items.empty()) return;

    InvMessage getdata;
    getdata.items = items;

    Message msg;
    msg.type = MessageType::GETDATA;
    msg.payload = getdata;

    peer_manager_->sendTo(peer_id, msg);

    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.getdata_sent++;
}

void MessageHandler::sendHeaders(Connection::Id peer_id, const std::vector<BlockHeader>& headers) {
    if (headers.empty()) {
        LOG_DEBUG("sendHeaders: empty headers, not sending");
        return;
    }

    LOG_DEBUG("sendHeaders: preparing {} headers for peer {}", headers.size(), peer_id);

    HeadersMessage hdr_msg;
    hdr_msg.headers = headers;

    Message msg;
    msg.type = MessageType::HEADERS;
    msg.payload = hdr_msg;

    bool sent = peer_manager_->sendTo(peer_id, msg);
    LOG_DEBUG("sendHeaders: sendTo returned {}", sent);
}

void MessageHandler::sendBlock(Connection::Id peer_id, const Block& block) {
    BlockMessage blk_msg;
    blk_msg.block = block;

    Message msg;
    msg.type = MessageType::BLOCK;
    msg.payload = blk_msg;

    peer_manager_->sendTo(peer_id, msg);
}

void MessageHandler::sendTx(Connection::Id peer_id, const Transaction& tx) {
    TxMessage tx_msg;
    tx_msg.tx = tx;

    Message msg;
    msg.type = MessageType::TX;
    msg.payload = tx_msg;

    peer_manager_->sendTo(peer_id, msg);
}

void MessageHandler::sendNotFound(Connection::Id peer_id, const std::vector<InvItem>& items) {
    if (items.empty()) return;

    InvMessage notfound;
    notfound.items = items;

    Message msg;
    msg.type = MessageType::NOTFOUND;
    msg.payload = notfound;

    peer_manager_->sendTo(peer_id, msg);
}

//-----------------------------------------------------------------------------
// Locator Helpers
//-----------------------------------------------------------------------------

std::vector<Hash256> MessageHandler::buildLocator() const {
    std::vector<Hash256> locator;

    uint64_t height = chain_->getHeight();
    int step = 1;

    while (height > 0) {
        auto hash = chain_->getBlockHashAtHeight(static_cast<int32_t>(height));
        if (hash && *hash != ZERO_HASH) {
            locator.push_back(*hash);
        }

        if (locator.size() >= 10) {
            step *= 2;
        }

        if (height < static_cast<uint64_t>(step)) {
            break;
        }
        height -= step;
    }

    // Always include genesis
    auto genesis = chain_->getBlockHashAtHeight(0);
    if (genesis && *genesis != ZERO_HASH) {
        locator.push_back(*genesis);
    }

    return locator;
}

Hash256 MessageHandler::findForkPoint(const std::vector<Hash256>& locator) const {
    for (const auto& hash : locator) {
        if (chain_->hasBlock(hash)) {
            return hash;
        }
    }

    // Return genesis if none found
    auto genesis = chain_->getBlockHashAtHeight(0);
    return genesis.value_or(ZERO_HASH);
}

//-----------------------------------------------------------------------------
// Public Operations
//-----------------------------------------------------------------------------

void MessageHandler::requestBlock(const Hash256& hash) {
    std::lock_guard<std::mutex> lock(blocks_mutex_);
    download_queue_.push(hash);
}

void MessageHandler::requestHeaders(Connection::Id peer_id) {
    GetHeadersMessage msg;
    msg.version = PROTOCOL_VERSION;
    msg.locator = buildLocator();
    msg.hash_stop = ZERO_HASH;

    Message message;
    message.type = MessageType::GETHEADERS;
    message.payload = msg;

    peer_manager_->sendTo(peer_id, message);
}

void MessageHandler::announceBlock(const Block& block) {
    Hash256 hash = block.getHash();

    InvItem item;
    item.type = InvType::BLOCK;
    item.hash = hash;

    std::vector<InvItem> items = {item};

    auto peers = peer_manager_->getPeerInfo();
    for (const auto& peer : peers) {
        if (peer_manager_->hasKnownBlock(peer.id, hash)) continue;
        sendInv(peer.id, items);
    }
}

void MessageHandler::announceTx(const Transaction& tx) {
    Hash256 txid = tx.getTxId();

    InvItem item;
    item.type = InvType::TX;
    item.hash = txid;

    std::vector<InvItem> items = {item};

    auto peers = peer_manager_->getPeerInfo();
    for (const auto& peer : peers) {
        if (!peer.relay) continue;
        if (peer_manager_->hasKnownTx(peer.id, txid)) continue;
        sendInv(peer.id, items);
    }
}

MessageHandler::Stats MessageHandler::getStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

//-----------------------------------------------------------------------------
// Worker Thread
//-----------------------------------------------------------------------------

void MessageHandler::workerThread() {
    while (running_) {
        std::function<void()> task;

        {
            std::unique_lock<std::mutex> lock(worker_mutex_);
            worker_cv_.wait_for(lock, seconds(1), [this] {
                return !running_ || !work_queue_.empty();
            });

            if (!running_ && work_queue_.empty()) {
                break;
            }

            if (!work_queue_.empty()) {
                task = std::move(work_queue_.front());
                work_queue_.pop();
            }
        }

        if (task) {
            task();
        }

        // Periodic maintenance
        if (running_) {
            checkSyncProgress();

            // Clean up old orphans
            auto now = steady_clock::now();

            {
                std::lock_guard<std::mutex> lock(orphans_mutex_);

                // Remove old orphan blocks (older than 20 minutes)
                for (auto it = orphan_blocks_.begin(); it != orphan_blocks_.end(); ) {
                    if (now - it->second.received_time > minutes(20)) {
                        orphan_blocks_by_prev_.erase(it->second.block.header.prev_hash);
                        it = orphan_blocks_.erase(it);
                    } else {
                        ++it;
                    }
                }

                // Remove old orphan transactions (older than 10 minutes)
                for (auto it = orphan_txs_.begin(); it != orphan_txs_.end(); ) {
                    if (now - it->second.received_time > minutes(10)) {
                        // Remove from prev index
                        for (const auto& input : it->second.tx.inputs) {
                            if (!input.prevout.isNull()) {
                                auto range = orphan_txs_by_prev_.equal_range(input.prevout.txid);
                                for (auto pit = range.first; pit != range.second; ) {
                                    if (pit->second == it->first) {
                                        pit = orphan_txs_by_prev_.erase(pit);
                                    } else {
                                        ++pit;
                                    }
                                }
                            }
                        }
                        it = orphan_txs_.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

            // Clean up old rejects (older than 15 minutes)
            {
                std::lock_guard<std::mutex> lock(rejects_mutex_);
                // In a production system, we'd track timestamps
                // For now, just limit the size
                if (recent_rejects_.size() > 10000) {
                    recent_rejects_.clear();
                }
            }
        }
    }
}

} // namespace p2p
} // namespace ftc
