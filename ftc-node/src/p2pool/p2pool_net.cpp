/**
 * FTC P2Pool Network Implementation
 *
 * Handles P2P communication for the decentralized mining pool.
 * Shares are propagated between all P2Pool nodes for PPLNS payouts.
 */

#include "p2pool/p2pool_net.h"
#include "util/logging.h"

#include <algorithm>
#include <cstring>

namespace ftc {
namespace p2pool {

// Helper functions for Hash256
static bool isZeroHash(const crypto::Hash256& hash) {
    for (const auto& byte : hash) {
        if (byte != 0) return false;
    }
    return true;
}

static std::string hashToHex(const crypto::Hash256& hash) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (const auto& byte : hash) {
        result += hex_chars[(byte >> 4) & 0x0F];
        result += hex_chars[byte & 0x0F];
    }
    return result;
}

// ============================================================================
// Message Serialization
// ============================================================================

std::vector<uint8_t> P2PoolMessage::serialize() const {
    std::vector<uint8_t> data;
    data.push_back(static_cast<uint8_t>(type));

    // Payload length (4 bytes)
    uint32_t len = payload.size();
    data.push_back(len & 0xFF);
    data.push_back((len >> 8) & 0xFF);
    data.push_back((len >> 16) & 0xFF);
    data.push_back((len >> 24) & 0xFF);

    data.insert(data.end(), payload.begin(), payload.end());
    return data;
}

bool P2PoolMessage::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 5) return false;

    type = static_cast<P2PoolMessageType>(data[0]);

    uint32_t len = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24);
    if (data.size() < 5 + len) return false;

    payload.assign(data.begin() + 5, data.begin() + 5 + len);
    return true;
}

std::vector<uint8_t> ShareMessage::serialize() const {
    return share.serialize();
}

bool ShareMessage::deserialize(const std::vector<uint8_t>& data) {
    return share.deserialize(data);
}

std::vector<uint8_t> GetSharesMessage::serialize() const {
    std::vector<uint8_t> data;
    data.insert(data.end(), start_hash.begin(), start_hash.end());
    data.push_back(count & 0xFF);
    data.push_back((count >> 8) & 0xFF);
    data.push_back((count >> 16) & 0xFF);
    data.push_back((count >> 24) & 0xFF);
    return data;
}

bool GetSharesMessage::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 36) return false;
    std::copy(data.begin(), data.begin() + 32, start_hash.begin());
    count = data[32] | (data[33] << 8) | (data[34] << 16) | (data[35] << 24);
    return true;
}

std::vector<uint8_t> SharesMessage::serialize() const {
    std::vector<uint8_t> data;

    // Count
    uint32_t count = shares.size();
    data.push_back(count & 0xFF);
    data.push_back((count >> 8) & 0xFF);
    data.push_back((count >> 16) & 0xFF);
    data.push_back((count >> 24) & 0xFF);

    // Each share
    for (const auto& share : shares) {
        auto share_data = share.serialize();
        uint32_t len = share_data.size();
        data.push_back(len & 0xFF);
        data.push_back((len >> 8) & 0xFF);
        data.push_back((len >> 16) & 0xFF);
        data.push_back((len >> 24) & 0xFF);
        data.insert(data.end(), share_data.begin(), share_data.end());
    }

    return data;
}

bool SharesMessage::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 4) return false;

    size_t pos = 0;
    uint32_t count = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
    pos = 4;

    shares.clear();
    shares.reserve(count);

    for (uint32_t i = 0; i < count && pos + 4 <= data.size(); i++) {
        uint32_t len = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
        pos += 4;

        if (pos + len > data.size()) break;

        Share share;
        if (share.deserialize(std::vector<uint8_t>(data.begin() + pos, data.begin() + pos + len))) {
            shares.push_back(share);
        }
        pos += len;
    }

    return true;
}

std::vector<uint8_t> GetShareHashesMessage::serialize() const {
    std::vector<uint8_t> data;
    data.insert(data.end(), locator_hash.begin(), locator_hash.end());
    data.insert(data.end(), stop_hash.begin(), stop_hash.end());
    data.push_back(max_hashes & 0xFF);
    data.push_back((max_hashes >> 8) & 0xFF);
    data.push_back((max_hashes >> 16) & 0xFF);
    data.push_back((max_hashes >> 24) & 0xFF);
    return data;
}

bool GetShareHashesMessage::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 68) return false;
    std::copy(data.begin(), data.begin() + 32, locator_hash.begin());
    std::copy(data.begin() + 32, data.begin() + 64, stop_hash.begin());
    max_hashes = data[64] | (data[65] << 8) | (data[66] << 16) | (data[67] << 24);
    return true;
}

std::vector<uint8_t> ShareHashesMessage::serialize() const {
    std::vector<uint8_t> data;

    uint32_t count = hashes.size();
    data.push_back(count & 0xFF);
    data.push_back((count >> 8) & 0xFF);
    data.push_back((count >> 16) & 0xFF);
    data.push_back((count >> 24) & 0xFF);

    for (const auto& hash : hashes) {
        data.insert(data.end(), hash.begin(), hash.end());
    }

    return data;
}

bool ShareHashesMessage::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 4) return false;

    uint32_t count = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);

    if (data.size() < 4 + count * 32) return false;

    hashes.clear();
    hashes.reserve(count);

    for (uint32_t i = 0; i < count; i++) {
        crypto::Hash256 hash;
        std::copy(data.begin() + 4 + i * 32, data.begin() + 4 + (i + 1) * 32, hash.begin());
        hashes.push_back(hash);
    }

    return true;
}

std::vector<uint8_t> PoolStatusMessage::serialize() const {
    std::vector<uint8_t> data;

    // Share info
    data.push_back(share_height & 0xFF);
    data.push_back((share_height >> 8) & 0xFF);
    data.push_back((share_height >> 16) & 0xFF);
    data.push_back((share_height >> 24) & 0xFF);
    data.insert(data.end(), share_tip.begin(), share_tip.end());

    // Main chain info
    data.push_back(main_height & 0xFF);
    data.push_back((main_height >> 8) & 0xFF);
    data.push_back((main_height >> 16) & 0xFF);
    data.push_back((main_height >> 24) & 0xFF);
    data.insert(data.end(), main_tip.begin(), main_tip.end());

    // Pool stats
    for (int i = 0; i < 8; i++) {
        data.push_back((pool_hashrate >> (i * 8)) & 0xFF);
    }
    data.push_back(miner_count & 0xFF);
    data.push_back((miner_count >> 8) & 0xFF);
    data.push_back((miner_count >> 16) & 0xFF);
    data.push_back((miner_count >> 24) & 0xFF);
    for (int i = 0; i < 8; i++) {
        data.push_back((shares_per_minute >> (i * 8)) & 0xFF);
    }

    return data;
}

bool PoolStatusMessage::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 92) return false;

    size_t pos = 0;

    share_height = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
    pos += 4;

    std::copy(data.begin() + pos, data.begin() + pos + 32, share_tip.begin());
    pos += 32;

    main_height = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
    pos += 4;

    std::copy(data.begin() + pos, data.begin() + pos + 32, main_tip.begin());
    pos += 32;

    pool_hashrate = 0;
    for (int i = 0; i < 8; i++) {
        pool_hashrate |= static_cast<uint64_t>(data[pos + i]) << (i * 8);
    }
    pos += 8;

    miner_count = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
    pos += 4;

    shares_per_minute = 0;
    for (int i = 0; i < 8; i++) {
        shares_per_minute |= static_cast<uint64_t>(data[pos + i]) << (i * 8);
    }

    return true;
}

// ============================================================================
// P2PoolNet Implementation
// ============================================================================

P2PoolNet::P2PoolNet(Sharechain* sharechain, chain::Chain* mainchain)
    : P2PoolNet(sharechain, mainchain, Config{}) {
}

P2PoolNet::P2PoolNet(Sharechain* sharechain, chain::Chain* mainchain, const Config& config)
    : config_(config)
    , sharechain_(sharechain)
    , mainchain_(mainchain) {
}

P2PoolNet::~P2PoolNet() {
    stop();
}

bool P2PoolNet::start() {
    if (running_) return true;

    LOG_INFO("Starting P2Pool network on port {}...", config_.port);

    // Bind listener
    if (!listener_.bind(config_.port, true)) {
        LOG_ERROR("Failed to bind P2Pool port {}", config_.port);
        return false;
    }

    if (!listener_.listen()) {
        LOG_ERROR("Failed to listen on P2Pool port");
        return false;
    }

    running_ = true;

    // Start threads
    network_thread_ = std::thread(&P2PoolNet::networkThread, this);
    maintenance_thread_ = std::thread(&P2PoolNet::maintenanceThread, this);

    LOG_INFO("P2Pool network started");
    return true;
}

void P2PoolNet::stop() {
    if (!running_) return;

    LOG_INFO("Stopping P2Pool network...");
    running_ = false;

    listener_.close();

    // Disconnect all peers
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        peers_.clear();
    }

    if (network_thread_.joinable()) {
        network_thread_.join();
    }
    if (maintenance_thread_.joinable()) {
        maintenance_thread_.join();
    }

    LOG_INFO("P2Pool network stopped");
}

void P2PoolNet::networkThread() {
    LOG_DEBUG("P2Pool network thread started");

    while (running_) {
        // Accept new connections
        while (auto conn = listener_.accept()) {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            if (peers_.size() < config_.max_peers) {
                onNewConnection(conn);
            } else {
                conn->disconnect("peer limit reached");
            }
        }

        // Process peer I/O
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            for (auto& [id, peer] : peers_) {
                // Read data
                std::vector<uint8_t> data;
                // ... read from connection
                // Parse messages and handle
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    LOG_DEBUG("P2Pool network thread stopped");
}

void P2PoolNet::maintenanceThread() {
    LOG_DEBUG("P2Pool maintenance thread started");

    auto last_connect = std::chrono::steady_clock::now();
    auto last_ping = std::chrono::steady_clock::now();
    auto last_cleanup = std::chrono::steady_clock::now();

    while (running_) {
        auto now = std::chrono::steady_clock::now();

        // Try to connect to more peers
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_connect).count() >= 10) {
            tryConnectPeers();
            last_connect = now;
        }

        // Send pings
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_ping).count() >= 60) {
            sendPings();
            last_ping = now;
        }

        // Cleanup
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_cleanup).count() >= 30) {
            checkTimeouts();
            cleanupSeen();
            last_cleanup = now;
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    LOG_DEBUG("P2Pool maintenance thread stopped");
}

void P2PoolNet::onNewConnection(std::shared_ptr<p2p::Connection> conn) {
    P2PoolPeer peer;
    peer.id = conn->getId();
    peer.addr = conn->getAddress();

    peers_[peer.id] = peer;

    LOG_INFO("P2Pool: new peer {}", peer.addr.toString());

    // Send our status
    sendPoolStatus(peer.id);
}

void P2PoolNet::onDisconnect(p2p::Connection::Id id, const std::string& reason) {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    auto it = peers_.find(id);
    if (it != peers_.end()) {
        LOG_INFO("P2Pool: peer {} disconnected: {}",
                 it->second.addr.toString(), reason);
        peers_.erase(it);
    }
}

void P2PoolNet::broadcastShare(const Share& share) {
    crypto::Hash256 hash = share.hash();

    // Check if already seen
    {
        std::lock_guard<std::mutex> lock(seen_mutex_);
        if (recently_seen_.count(hash) > 0) {
            return;
        }
        recently_seen_.insert(hash);
        seen_queue_.push(hash);
    }

    // Broadcast to all peers
    P2PoolMessage msg;
    msg.type = P2PoolMessageType::SHARE;

    ShareMessage share_msg;
    share_msg.share = share;
    msg.payload = share_msg.serialize();

    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (auto& [id, peer] : peers_) {
            if (peer.handshake_complete) {
                sendMessage(id, msg);
                peer.shares_sent++;
            }
        }
    }

    stats_propagated_++;
    LOG_DEBUG("P2Pool: broadcast share {}", hashToHex(hash).substr(0, 16));
}

void P2PoolNet::requestShare(const crypto::Hash256& hash) {
    // Check if already pending
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        if (pending_shares_.count(hash) > 0) {
            return;
        }
        pending_shares_[hash] = std::chrono::steady_clock::now();
    }

    // Request from a peer
    P2PoolMessage msg;
    msg.type = P2PoolMessageType::GETSHARE;
    msg.payload.assign(hash.begin(), hash.end());

    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (auto& [id, peer] : peers_) {
        if (peer.handshake_complete) {
            sendMessage(id, msg);
            break;
        }
    }
}

void P2PoolNet::handleShare(p2p::Connection::Id id, const ShareMessage& msg) {
    stats_received_++;

    crypto::Hash256 hash = msg.share.hash();

    // Mark as seen
    {
        std::lock_guard<std::mutex> lock(seen_mutex_);
        if (recently_seen_.count(hash) > 0) {
            return;  // Already seen
        }
        recently_seen_.insert(hash);
        seen_queue_.push(hash);
    }

    // Remove from pending
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        pending_shares_.erase(hash);
    }

    // Process share
    std::string error;
    if (sharechain_->processShare(msg.share, error)) {
        LOG_DEBUG("P2Pool: accepted share {} from peer {}",
                  hashToHex(hash).substr(0, 16), id);

        // Relay to other peers
        broadcastShare(msg.share);

        // Update peer state
        std::lock_guard<std::mutex> lock(peers_mutex_);
        auto it = peers_.find(id);
        if (it != peers_.end()) {
            it->second.shares_received++;
        }
    } else {
        LOG_DEBUG("P2Pool: rejected share from peer {}: {}",
                  id, error);
    }
}

void P2PoolNet::handleGetShares(p2p::Connection::Id id, const GetSharesMessage& msg) {
    SharesMessage response;

    // Get shares starting from hash
    ShareIndex* start = sharechain_->getShareIndex(msg.start_hash);
    if (!start) {
        start = sharechain_->getTip();
    }

    // Collect shares
    ShareIndex* current = start;
    for (uint32_t i = 0; i < msg.count && current; i++) {
        auto share = sharechain_->getShare(current->hash);
        if (share) {
            response.shares.push_back(*share);
        }
        current = current->prev;
    }

    // Send response
    P2PoolMessage reply;
    reply.type = P2PoolMessageType::SHARES;
    reply.payload = response.serialize();
    sendMessage(id, reply);
}

void P2PoolNet::handleShares(p2p::Connection::Id id, const SharesMessage& msg) {
    for (const auto& share : msg.shares) {
        std::string error;
        sharechain_->processShare(share, error);
    }

    // Update peer state
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = peers_.find(id);
    if (it != peers_.end()) {
        it->second.syncing = false;
        it->second.shares_received += msg.shares.size();
    }
}

void P2PoolNet::handleGetShareHashes(p2p::Connection::Id id, const GetShareHashesMessage& msg) {
    ShareHashesMessage response;

    // Find starting point
    ShareIndex* start = nullptr;
    if (!isZeroHash(msg.locator_hash)) {
        start = sharechain_->getShareIndex(msg.locator_hash);
    }
    if (!start) {
        start = sharechain_->getTip();
    }

    // Collect hashes going backwards
    ShareIndex* current = start;
    while (current && response.hashes.size() < msg.max_hashes) {
        if (!isZeroHash(msg.stop_hash) && current->hash == msg.stop_hash) {
            break;
        }
        response.hashes.push_back(current->hash);
        current = current->prev;
    }

    // Send response
    P2PoolMessage reply;
    reply.type = P2PoolMessageType::SHAREHASHES;
    reply.payload = response.serialize();
    sendMessage(id, reply);
}

void P2PoolNet::handleShareHashes(p2p::Connection::Id id, const ShareHashesMessage& msg) {
    // Request any shares we don't have
    for (const auto& hash : msg.hashes) {
        if (!sharechain_->getShareIndex(hash)) {
            requestShare(hash);
        }
    }
}

void P2PoolNet::handlePoolStatus(p2p::Connection::Id id, const PoolStatusMessage& msg) {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    auto it = peers_.find(id);
    if (it != peers_.end()) {
        it->second.handshake_complete = true;
        it->second.share_height = msg.share_height;
        it->second.share_tip = msg.share_tip;

        LOG_DEBUG("P2Pool: peer {} status: height={} hashrate={}",
                  it->second.addr.toString(),
                  msg.share_height, msg.pool_hashrate);

        // If they have more shares, sync
        if (msg.share_height > sharechain_->getHeight()) {
            requestMoreShares(it->second);
        }
    }
}

void P2PoolNet::handlePing(p2p::Connection::Id id, uint64_t nonce) {
    P2PoolMessage pong;
    pong.type = P2PoolMessageType::PONG;
    pong.payload.resize(8);
    for (int i = 0; i < 8; i++) {
        pong.payload[i] = (nonce >> (i * 8)) & 0xFF;
    }
    sendMessage(id, pong);
}

void P2PoolNet::sendMessage(p2p::Connection::Id id, const P2PoolMessage& msg) {
    auto data = msg.serialize();
    stats_bytes_sent_ += data.size();

    // Send via connection
    // ... implementation depends on connection interface
}

void P2PoolNet::sendPoolStatus(p2p::Connection::Id id) {
    PoolStatusMessage status;
    status.share_height = sharechain_->getHeight();
    status.share_tip = sharechain_->getTipHash();

    if (mainchain_) {
        auto tip = mainchain_->getTip();
        if (tip) {
            status.main_height = tip->height;
            status.main_tip = tip->hash;
        }
    }

    auto sc_stats = sharechain_->getStats();
    status.shares_per_minute = static_cast<uint64_t>(sc_stats.share_rate);

    P2PoolMessage msg;
    msg.type = P2PoolMessageType::POOLSTATUS;
    msg.payload = status.serialize();
    sendMessage(id, msg);
}

void P2PoolNet::requestMoreShares(P2PoolPeer& peer) {
    if (peer.syncing) return;

    peer.syncing = true;
    peer.last_request_time = std::chrono::steady_clock::now();

    GetSharesMessage req;
    req.start_hash = sharechain_->getTipHash();
    req.count = 100;

    P2PoolMessage msg;
    msg.type = P2PoolMessageType::GETSHARES;
    msg.payload = req.serialize();
    sendMessage(peer.id, msg);
}

bool P2PoolNet::connectTo(const p2p::NetAddr& addr) {
    {
        std::lock_guard<std::mutex> lock(connecting_mutex_);
        if (connecting_.count(addr) > 0) {
            return false;
        }
        connecting_.insert(addr);
    }

    // Create connection
    auto conn = p2p::Connection::connect(addr, [this, addr](bool success) {
        std::lock_guard<std::mutex> lock(connecting_mutex_);
        connecting_.erase(addr);

        if (!success) {
            LOG_DEBUG("P2Pool: failed to connect to {}", addr.toString());
        }
    });

    if (conn) {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        onNewConnection(conn);
        return true;
    }

    return false;
}

void P2PoolNet::disconnect(p2p::Connection::Id id, const std::string& reason) {
    onDisconnect(id, reason);
}

size_t P2PoolNet::getPeerCount() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    return peers_.size();
}

std::vector<P2PoolPeer> P2PoolNet::getPeerInfo() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    std::vector<P2PoolPeer> result;
    result.reserve(peers_.size());
    for (const auto& [id, peer] : peers_) {
        result.push_back(peer);
    }
    return result;
}

void P2PoolNet::startSync() {
    syncing_ = true;

    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (auto& [id, peer] : peers_) {
        if (peer.handshake_complete && !peer.syncing) {
            requestMoreShares(peer);
        }
    }
}

void P2PoolNet::stopSync() {
    syncing_ = false;
}

void P2PoolNet::addPeerAddress(const p2p::NetAddr& addr) {
    // Convert to P2Pool port (17320)
    p2p::NetAddr p2pool_addr = addr;
    p2pool_addr.port = config_.port;

    // Don't add if already connected or connecting
    {
        std::lock_guard<std::mutex> plock(peers_mutex_);
        for (const auto& [id, peer] : peers_) {
            if (peer.addr.ip == p2pool_addr.ip) {
                return;
            }
        }
    }
    {
        std::lock_guard<std::mutex> clock(connecting_mutex_);
        if (connecting_.count(p2pool_addr) > 0) {
            return;
        }
    }

    std::lock_guard<std::mutex> lock(candidates_mutex_);
    candidate_addrs_.insert(p2pool_addr);
}

void P2PoolNet::tryConnectPeers() {
    size_t current = getPeerCount();
    if (current >= config_.target_peers) {
        return;
    }

    // Get candidates to try
    std::vector<p2p::NetAddr> to_try;
    {
        std::lock_guard<std::mutex> lock(candidates_mutex_);
        for (const auto& addr : candidate_addrs_) {
            if (to_try.size() >= 3) break;  // Try max 3 at a time
            to_try.push_back(addr);
        }
    }

    // Try connecting to candidates
    for (const auto& addr : to_try) {
        if (getPeerCount() >= config_.target_peers) break;

        LOG_DEBUG("P2Pool: trying to connect to {}", addr.toString());
        connectTo(addr);

        // Remove from candidates after attempting
        {
            std::lock_guard<std::mutex> lock(candidates_mutex_);
            candidate_addrs_.erase(addr);
        }
    }
}

void P2PoolNet::sendPings() {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    uint64_t nonce = std::chrono::steady_clock::now().time_since_epoch().count();

    P2PoolMessage ping;
    ping.type = P2PoolMessageType::PING;
    ping.payload.resize(8);
    for (int i = 0; i < 8; i++) {
        ping.payload[i] = (nonce >> (i * 8)) & 0xFF;
    }

    for (auto& [id, peer] : peers_) {
        sendMessage(id, ping);
    }
}

void P2PoolNet::checkTimeouts() {
    auto now = std::chrono::steady_clock::now();

    // Check pending share requests
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        for (auto it = pending_shares_.begin(); it != pending_shares_.end();) {
            if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count() > 30) {
                it = pending_shares_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Check syncing peers
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (auto& [id, peer] : peers_) {
            if (peer.syncing) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - peer.last_request_time).count();
                if (elapsed > 60) {
                    peer.syncing = false;
                }
            }
        }
    }
}

void P2PoolNet::cleanupSeen() {
    std::lock_guard<std::mutex> lock(seen_mutex_);

    // Keep only last 10000 seen hashes
    while (seen_queue_.size() > 10000) {
        recently_seen_.erase(seen_queue_.front());
        seen_queue_.pop();
    }
}

P2PoolNet::Stats P2PoolNet::getStats() const {
    Stats stats;
    stats.peers_connected = getPeerCount();
    stats.shares_propagated = stats_propagated_.load();
    stats.shares_received = stats_received_.load();
    stats.bytes_sent = stats_bytes_sent_.load();
    stats.bytes_recv = stats_bytes_recv_.load();
    return stats;
}

// ============================================================================
// P2Pool Implementation
// ============================================================================

P2Pool::P2Pool(chain::Chain* mainchain)
    : P2Pool(mainchain, Config{}) {
}

P2Pool::P2Pool(chain::Chain* mainchain, const Config& config)
    : config_(config)
    , mainchain_(mainchain) {
}

P2Pool::~P2Pool() {
    stop();
}

bool P2Pool::start() {
    if (!config_.enabled) {
        LOG_INFO("P2Pool is disabled");
        return true;
    }

    LOG_INFO("Starting P2Pool...");

    // Create sharechain
    Sharechain::Config sc_config;
    sc_config.data_dir = config_.data_dir + "/sharechain";

    sharechain_ = std::make_unique<Sharechain>(sc_config);

    // Set callbacks
    sharechain_->setShareCallback([this](const Share& share, bool accepted) {
        onShareAccepted(share, accepted);
    });

    sharechain_->setNewBlockCallback([this](const chain::Block& block) {
        onNewBlock(block);
    });

    if (!sharechain_->initialize()) {
        LOG_ERROR("Failed to initialize sharechain");
        return false;
    }

    // Create network
    P2PoolNet::Config net_config;
    net_config.port = config_.port;

    network_ = std::make_unique<P2PoolNet>(
        sharechain_.get(),
        mainchain_,
        net_config
    );

    if (!network_->start()) {
        LOG_ERROR("Failed to start P2Pool network");
        return false;
    }

    running_ = true;

    LOG_INFO("P2Pool started: sharechain height={}", sharechain_->getHeight());
    return true;
}

void P2Pool::stop() {
    if (!running_) return;

    LOG_INFO("Stopping P2Pool...");

    running_ = false;

    if (network_) {
        network_->stop();
    }

    if (sharechain_) {
        sharechain_->shutdown();
    }

    LOG_INFO("P2Pool stopped");
}

Share P2Pool::getWorkTemplate(const std::vector<uint8_t>& payout_script) const {
    std::lock_guard<std::mutex> lock(work_mutex_);

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - work_time_).count();

    // Regenerate work if stale
    if (elapsed > config_.work_restart_seconds || current_work_.payouts.empty()) {
        ShareBuilder builder(sharechain_.get(), mainchain_);

        // Get transactions from main chain mempool
        std::vector<chain::Transaction> txs;
        // ... would get from mempool

        uint64_t block_reward = 50ULL * 100000000ULL;  // 50 FTC
        uint64_t fees = 0;

        if (mainchain_) {
            auto tip = mainchain_->getTip();
            if (tip) {
                block_reward = mainchain_->getBlockReward(tip->height + 1);
            }
        }

        current_work_ = builder.buildShareTemplate(payout_script, txs, block_reward, fees);
        work_time_ = now;
    }

    return current_work_;
}

bool P2Pool::submitShare(const Share& share, std::string& error) {
    if (!sharechain_->processShare(share, error)) {
        return false;
    }

    // Broadcast to network
    if (network_) {
        network_->broadcastShare(share);
    }

    return true;
}

bool P2Pool::submitWork(uint32_t nonce, const std::vector<uint8_t>& extra_nonce) {
    std::lock_guard<std::mutex> lock(work_mutex_);

    if (current_work_.payouts.empty()) {
        LOG_WARN("No current work template available");
        return false;
    }

    // Update the nonce in the current work
    Share share = current_work_;
    share.header.nonce = nonce;

    // TODO: Update extra_nonce in generation transaction if needed

    // Check if share meets P2Pool difficulty
    if (!sharechain_->checkSharePoW(share)) {
        LOG_DEBUG("Share does not meet P2Pool difficulty target");
        return false;
    }

    // Submit the share
    std::string error;
    if (!submitShare(share, error)) {
        LOG_WARN("Share submission failed: {}", error);
        return false;
    }

    LOG_INFO("Share accepted! Hash: {}", hashToHex(share.hash()).substr(0, 16));

    // Check if share meets main chain target
    if (share.meetsBlockTarget()) {
        LOG_NOTICE("Share meets main chain difficulty - block found!");
        // The sharechain callback will handle block propagation
    }

    return true;
}

std::map<std::vector<uint8_t>, uint64_t> P2Pool::getEstimatedPayouts() const {
    uint64_t next_reward = 50ULL * 100000000ULL;  // 50 FTC default
    if (mainchain_) {
        auto tip = mainchain_->getTip();
        if (tip) {
            next_reward = mainchain_->getBlockReward(tip->height + 1);
        }
    }

    // First try sharechain-based payouts
    if (sharechain_) {
        auto payouts = sharechain_->calculatePayouts(next_reward);
        if (!payouts.empty()) {
            return payouts;
        }
    }

    // Fall back to simple work tracking - only active miners
    std::lock_guard<std::mutex> lock(miner_mutex_);
    if (miner_work_count_.empty()) {
        return {};
    }

    auto now = std::chrono::steady_clock::now();

    // Calculate total work from active miners only
    uint64_t total_work = 0;
    for (const auto& [script, count] : miner_work_count_) {
        auto it = miner_last_seen_.find(script);
        if (it != miner_last_seen_.end()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
            if (elapsed < MINER_TIMEOUT_SECONDS) {
                total_work += count;
            }
        }
    }

    if (total_work == 0) return {};

    // Split reward proportionally among active miners
    std::map<std::vector<uint8_t>, uint64_t> payouts;
    uint64_t distributed = 0;

    for (const auto& [script, count] : miner_work_count_) {
        auto it = miner_last_seen_.find(script);
        if (it != miner_last_seen_.end()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
            if (elapsed < MINER_TIMEOUT_SECONDS) {
                uint64_t share = (next_reward * count) / total_work;
                if (share > 0) {
                    payouts[script] = share;
                    distributed += share;
                }
            }
        }
    }

    // Add any rounding remainder to first miner
    if (!payouts.empty() && distributed < next_reward) {
        payouts.begin()->second += (next_reward - distributed);
    }

    return payouts;
}

uint64_t P2Pool::getPoolHashrate() const {
    if (!sharechain_) return 0;

    auto stats = sharechain_->getStats();
    // Rough estimate: shares_per_minute * share_difficulty * 2^32 / 60
    uint64_t difficulty = sharechain_->getTip() ? sharechain_->getTip()->difficulty : 1;
    return static_cast<uint64_t>(stats.share_rate * difficulty * 4294967296.0 / 60.0);
}

uint32_t P2Pool::getMinerCount() const {
    // Count unique miners from sharechain PPLNS window (network-wide)
    if (sharechain_) {
        uint32_t sharechain_miners = sharechain_->getUniqueMinerCount();
        if (sharechain_miners > 0) {
            return sharechain_miners;
        }
    }

    // Fallback: HTTP API miners tracked with timeout (local only)
    std::lock_guard<std::mutex> lock(miner_mutex_);
    auto now = std::chrono::steady_clock::now();
    uint32_t active_count = 0;

    for (const auto& [script, last_seen] : miner_last_seen_) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_seen).count();
        if (elapsed < MINER_TIMEOUT_SECONDS) {
            active_count++;
        }
    }

    return active_count;
}

P2Pool::Stats P2Pool::getStats() const {
    Stats stats;

    if (sharechain_) {
        auto sc_stats = sharechain_->getStats();
        stats.sharechain_height = sharechain_->getHeight();
        stats.sharechain_tip = sharechain_->getTipHash();
        stats.total_shares = sc_stats.shares_accepted;
        stats.total_blocks = sc_stats.blocks_found;
        stats.shares_per_minute = sc_stats.share_rate;
    }

    stats.pool_hashrate = getPoolHashrate();
    stats.active_miners = getMinerCount();

    if (network_) {
        stats.peer_count = network_->getPeerCount();
    }

    return stats;
}

void P2Pool::registerMinerShare(const std::vector<uint8_t>& payout_script) {
    if (payout_script.empty()) return;

    // Track work requests per miner for PPLNS
    {
        std::lock_guard<std::mutex> lock(miner_mutex_);
        miner_work_count_[payout_script]++;
        miner_last_seen_[payout_script] = std::chrono::steady_clock::now();
    }

    // Also try to add to sharechain if available (for proper P2Pool)
    if (sharechain_) {
        Share share;
        share.header.version = 1;
        share.header.timestamp = static_cast<uint32_t>(std::time(nullptr));

        Share::PayoutEntry payout;
        payout.script_pubkey = payout_script;
        payout.weight = 1;
        share.payouts.push_back(payout);

        auto tip = sharechain_->getTip();
        if (tip) {
            share.header.prev_share = tip->hash;
            share.header.bits = sharechain_->getShareTarget();
        } else {
            std::memset(share.header.prev_share.data(), 0, 32);
            share.header.bits = 0x1f00ffff;
        }

        if (mainchain_) {
            auto main_tip = mainchain_->getTip();
            if (main_tip) {
                share.header.block_prev_hash = main_tip->hash;
                share.header.block_height = main_tip->height + 1;
            }
        }

        std::string error;
        sharechain_->processShare(share, error);
    }
}

void P2Pool::onShareAccepted(const Share& share, bool accepted) {
    if (!accepted) return;

    // Check if share found a block
    if (share.meetsBlockTarget()) {
        LOG_NOTICE("P2Pool found block! Share: {}", hashToHex(share.hash()).substr(0, 16));
    }
}

void P2Pool::onNewBlock(const chain::Block& block) {
    LOG_NOTICE("P2Pool block found: {}", hashToHex(block.getHash()).substr(0, 16));

    if (on_block_found_) {
        on_block_found_(block);
    }
}

} // namespace p2pool
} // namespace ftc
