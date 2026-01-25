/**
 * FTC Peer Manager Implementation
 * Full peer lifecycle management with address and ban tracking
 */

#include "p2p/peer_manager.h"
#include "util/logging.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <ctime>
#include <set>

#ifdef _WIN32
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <ifaddrs.h>
#endif

namespace ftc {
namespace p2p {

// ============================================================================
// AddrInfo implementation
// ============================================================================

double AddrInfo::getScore(int64_t now) const {
    double score = 0.0;

    // Favor recently successful addresses
    if (last_success > 0) {
        int64_t age = now - last_success;
        // Decay score over time (half-life of 8 hours)
        score += 100.0 * std::exp(-age / (8.0 * 3600.0));
    }

    // Favor addresses we've heard about recently
    if (last_seen > 0) {
        int64_t age = now - last_seen;
        score += 10.0 * std::exp(-age / (24.0 * 3600.0));
    }

    // Penalize failed attempts
    if (attempts > success_count) {
        int failures = attempts - success_count;
        score -= failures * 5.0;
    }

    // Bonus for services
    if (services & 1) score += 5.0;  // NODE_NETWORK

    return score;
}

// ============================================================================
// PeerManager implementation
// ============================================================================

PeerManager::PeerManager() : PeerManager(Config{}) {}

PeerManager::PeerManager(const Config& config)
    : config_(config) {
    // Initialize RNG
    std::random_device rd;
    rng_.seed(rd());
}

PeerManager::~PeerManager() {
    stop();
}

bool PeerManager::start() {
    if (running_) return true;

    LOG_INFO("Starting peer manager...");

    // Initialize networking
    if (!initNetworking()) {
        LOG_ERROR("Failed to initialize networking");
        return false;
    }

    // Detect local IPs to avoid self-connection
    detectLocalIPs();

    // Start listener
    if (!listener_.bind(config_.listen_port, true)) {
        LOG_ERROR("Failed to bind to port {}", config_.listen_port);
        return false;
    }

    if (!listener_.listen()) {
        LOG_ERROR("Failed to start listening");
        return false;
    }

    running_ = true;
    stopping_ = false;

    // Start threads
    network_thread_ = std::thread(&PeerManager::networkThread, this);
    maintenance_thread_ = std::thread(&PeerManager::maintenanceThread, this);

    LOG_INFO("Peer manager started");
    return true;
}

void PeerManager::stop() {
    if (!running_) return;

    LOG_INFO("Stopping peer manager...");
    stopping_ = true;

    // Close listener
    listener_.close();

    // Disconnect all peers
    disconnectAll("shutdown");

    // Wait for threads
    if (network_thread_.joinable()) {
        network_thread_.join();
    }
    if (maintenance_thread_.joinable()) {
        maintenance_thread_.join();
    }

    running_ = false;
    shutdownNetworking();

    LOG_INFO("Peer manager stopped");
}

void PeerManager::networkThread() {
    LOG_DEBUG("Network thread started");

    try {
        while (!stopping_) {
            // Accept new connections
            while (auto conn = listener_.accept()) {
                // Check inbound limit
                if (getInboundCount() >= static_cast<size_t>(config_.max_inbound)) {
                    LOG_DEBUG("Inbound limit reached, rejecting {}", conn->getAddress().toString());
                    conn->disconnect("inbound limit");
                    continue;
                }

                // Check ban
                if (isBanned(conn->getAddress())) {
                    LOG_DEBUG("Rejecting banned address {}", conn->getAddress().toString());
                    conn->disconnect("banned");
                    continue;
                }

                // Check self-connection (hairpin NAT)
                if (isLocalIP(conn->getAddress().ip)) {
                    LOG_DEBUG("Rejecting self-connection from {}", conn->getAddress().toString());
                    conn->disconnect("self-connection");
                    continue;
                }

                onNewConnection(conn);
            }

            // Process I/O
            auto ready = socket_set_.wait(std::chrono::milliseconds(100));

            // Handle errors
            for (auto& conn : ready.errors) {
                onDisconnect(conn->getId(), "socket error");
            }

            // Handle readable sockets
            for (auto& conn : ready.readable) {
                if (!conn->processRead()) {
                    onDisconnect(conn->getId(), "read error");
                }
            }

            // Handle writable sockets
            for (auto& conn : ready.writable) {
                if (!conn->processWrite()) {
                    onDisconnect(conn->getId(), "write error");
                }
            }
        }
    } catch (const std::exception& e) {
        LOG_ERR("Network thread exception: {}", e.what());
    } catch (...) {
        LOG_ERR("Network thread unknown exception");
    }

    LOG_DEBUG("Network thread stopped");
}

void PeerManager::maintenanceThread() {
    LOG_DEBUG("Maintenance thread started");

    try {
        auto last_try_connect = std::chrono::steady_clock::now();
        auto last_ping = std::chrono::steady_clock::now();
        auto last_cleanup = std::chrono::steady_clock::now();

        while (!stopping_) {
            auto now = std::chrono::steady_clock::now();

            // Try to connect to more peers
            auto since_connect = std::chrono::duration_cast<std::chrono::seconds>(now - last_try_connect);
            if (since_connect.count() >= 5) {
                tryConnect();
                last_try_connect = now;
            }

            // Send pings
            auto since_ping = std::chrono::duration_cast<std::chrono::seconds>(now - last_ping);
            if (since_ping.count() >= 30) {
                sendPings();
                last_ping = now;
            }

            // Check timeouts and cleanup
            auto since_cleanup = std::chrono::duration_cast<std::chrono::seconds>(now - last_cleanup);
            if (since_cleanup.count() >= 10) {
                checkTimeouts();
                cleanupBans();
                last_cleanup = now;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    } catch (const std::exception& e) {
        LOG_ERR("Maintenance thread exception: {}", e.what());
    } catch (...) {
        LOG_ERR("Maintenance thread unknown exception");
    }

    LOG_DEBUG("Maintenance thread stopped");
}

void PeerManager::onNewConnection(std::shared_ptr<Connection> conn) {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);

    Connection::Id id = conn->getId();

    Peer peer;
    peer.conn = conn;
    peer.state = PeerState::CONNECTED;
    peer.info.id = id;
    peer.info.addr = conn->getAddress();
    peer.info.direction = conn->getDirection();
    peer.info.connect_time = std::chrono::steady_clock::now();

    // Set up callbacks
    conn->setMessageCallback([this, id](const Message& msg) {
        onMessage(id, msg);
    });

    conn->setDisconnectCallback([this, id](const std::string& reason) {
        onDisconnect(id, reason);
    });

    // Add to socket set
    socket_set_.add(conn);

    peers_[id] = std::move(peer);
    total_connections_++;

    LOG_INFO("New {} connection: {} (total: {})",
             conn->getDirection() == ConnectionDir::INBOUND ? "inbound" : "outbound",
             conn->getAddress().toString(), peers_.size());

    // Start handshake (outbound sends VERSION first)
    if (conn->getDirection() == ConnectionDir::OUTBOUND) {
        sendVersion(peers_[id]);
    }
}

void PeerManager::onConnectionFailed(const NetAddr& addr) {
    // Update address info
    {
        std::lock_guard<std::mutex> lock(addr_mutex_);
        auto it = addresses_.find(addr);
        if (it != addresses_.end()) {
            it->second.attempts++;
            it->second.last_try = std::time(nullptr);
        }
    }

    // Remove from connecting set
    {
        std::lock_guard<std::mutex> lock(connecting_mutex_);
        connecting_.erase(addr);
    }
}

void PeerManager::onMessage(Connection::Id id, const Message& msg) {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);

    auto it = peers_.find(id);
    if (it == peers_.end()) return;

    Peer& peer = it->second;

    // Handle protocol messages
    switch (msg.type) {
        case MessageType::VERSION:
            if (auto* ver = std::get_if<VersionMessage>(&msg.payload)) {
                handleVersion(peer, *ver);
            }
            break;

        case MessageType::VERACK:
            handleVerack(peer);
            break;

        case MessageType::PING:
            if (auto* ping = std::get_if<PingMessage>(&msg.payload)) {
                handlePing(peer, *ping);
            }
            break;

        case MessageType::PONG:
            if (auto* pong = std::get_if<PongMessage>(&msg.payload)) {
                handlePong(peer, *pong);
            }
            break;

        case MessageType::GETADDR:
            handleGetAddr(peer);
            break;

        case MessageType::ADDR:
            if (auto* addr = std::get_if<AddrMessage>(&msg.payload)) {
                handleAddr(peer, *addr);
            }
            break;

        case MessageType::REJECT:
            if (auto* rej = std::get_if<RejectMessage>(&msg.payload)) {
                handleReject(peer, *rej);
            }
            break;

        default:
            // Forward to application callback only if handshake complete
            if (peer.state == PeerState::ESTABLISHED && on_message_) {
                // Release lock before callback
                peers_mutex_.unlock();
                on_message_(id, msg);
                peers_mutex_.lock();
            }
            break;
    }
}

void PeerManager::onDisconnect(Connection::Id id, const std::string& reason) {
    NetAddr addr;
    {
        std::lock_guard<std::recursive_mutex> lock(peers_mutex_);

        auto it = peers_.find(id);
        if (it == peers_.end()) return;

        addr = it->second.info.addr;

        // Remove from socket set
        socket_set_.remove(id);

        peers_.erase(it);
    }

    // Remove from connecting set
    {
        std::lock_guard<std::mutex> lock(connecting_mutex_);
        connecting_.erase(addr);
    }

    LOG_INFO("Peer disconnected: {} - {} (remaining: {})",
             addr.toString(), reason, peers_.size());

    if (on_peer_disconnect_) {
        on_peer_disconnect_(id, reason);
    }
}

void PeerManager::handleVersion(Peer& peer, const VersionMessage& ver) {
    if (peer.version_received) {
        LOG_WARN("Duplicate VERSION from {}", peer.info.addr.toString());
        peer.conn->addBanScore(10, "duplicate version");
        return;
    }

    // Check protocol version
    if (ver.version < 70001) {
        LOG_DEBUG("Peer {} has old protocol version: {}",
                  peer.info.addr.toString(), ver.version);
        peer.conn->disconnect("obsolete version");
        return;
    }

    // Check for self-connection (same node_id as us)
    if (std::memcmp(ver.node_id, our_node_id_, 20) == 0) {
        LOG_DEBUG("Self-connection detected from {}", peer.info.addr.toString());
        peer.conn->disconnect("self-connection");
        return;
    }

    // Check for duplicate connection (same node_id, different IP)
    // Only check if node_id is not all zeros (old clients)
    bool has_node_id = false;
    for (int i = 0; i < 20; i++) {
        if (ver.node_id[i] != 0) { has_node_id = true; break; }
    }

    if (has_node_id) {
        std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
        for (const auto& [id, other] : peers_) {
            if (id == peer.info.id) continue;  // Skip self
            if (other.version_received && std::memcmp(other.info.node_id, ver.node_id, 20) == 0) {
                LOG_DEBUG("Duplicate connection from {} (same node as {})",
                          peer.info.addr.toString(), other.info.addr.toString());
                peer.conn->disconnect("duplicate node connection");
                return;
            }
        }
    }

    peer.version_received = true;
    peer.conn->setPeerVersion(ver);

    peer.info.version = ver.version;
    peer.info.services = ver.services;
    peer.info.user_agent = ver.user_agent;
    peer.info.start_height = ver.start_height;
    peer.info.relay = ver.relay;
    peer.info.best_height = ver.start_height;
    std::memcpy(peer.info.node_id, ver.node_id, 20);  // Store node_id

    LOG_DEBUG("VERSION from {}: v{} \"{}\" height={}",
              peer.info.addr.toString(), ver.version,
              ver.user_agent, ver.start_height);

    // Inbound connections send VERSION after receiving
    if (peer.info.direction == ConnectionDir::INBOUND && !peer.version_sent) {
        sendVersion(peer);
    }

    // Send VERACK
    sendVerack(peer);

    // Check if handshake is complete
    if (peer.verack_received) {
        completeHandshake(peer);
    }
}

void PeerManager::handleVerack(Peer& peer) {
    if (peer.verack_received) {
        LOG_WARN("Duplicate VERACK from {}", peer.info.addr.toString());
        peer.conn->addBanScore(10, "duplicate verack");
        return;
    }

    peer.verack_received = true;

    LOG_DEBUG("VERACK from {}", peer.info.addr.toString());

    // Check if handshake is complete
    if (peer.version_received) {
        completeHandshake(peer);
    }
}

void PeerManager::handlePing(Peer& peer, const PingMessage& msg) {
    // Reply with PONG
    Message pong;
    pong.type = MessageType::PONG;
    pong.payload = PongMessage{msg.nonce};
    peer.conn->send(pong);
}

void PeerManager::handlePong(Peer& peer, const PongMessage& msg) {
    if (msg.nonce != peer.ping_nonce) {
        LOG_DEBUG("PONG nonce mismatch from {}", peer.info.addr.toString());
        return;
    }

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        now - peer.ping_start
    );

    peer.info.ping_usec = elapsed.count();
    peer.conn->recordPingTime(elapsed.count());

    LOG_DEBUG("PONG from {}: {} ms",
              peer.info.addr.toString(), elapsed.count() / 1000.0);
}

void PeerManager::handleGetAddr(Peer& peer) {
    // DHT handles peer discovery - no address exchange needed
    (void)peer;
}

void PeerManager::handleAddr(Peer& peer, const AddrMessage& msg) {
    // DHT handles peer discovery - ignore ADDR messages
    (void)peer;
    (void)msg;
}

void PeerManager::handleReject(Peer& peer, const RejectMessage& msg) {
    // Silent - reject messages are expected in normal operation
    (void)peer;
    (void)msg;
}

void PeerManager::sendVersion(Peer& peer) {
    VersionMessage ver;
    ver.version = our_version_;
    ver.services = our_services_;
    ver.timestamp = std::time(nullptr);

    // Receiver address
    ver.addr_recv.services = peer.info.services;
    memcpy(ver.addr_recv.ip, peer.info.addr.ip, 16);
    ver.addr_recv.port = peer.info.addr.port;

    // Our address (we don't know our external IP, use zeros)
    ver.addr_from.services = our_services_;
    ver.addr_from.port = config_.listen_port;

    // Nonce
    {
        std::lock_guard<std::mutex> lock(rng_mutex_);
        ver.nonce = rng_();
    }

    ver.user_agent = our_user_agent_;
    ver.start_height = our_height_;
    ver.relay = true;
    std::memcpy(ver.node_id, our_node_id_, 20);  // Include our node ID

    Message msg;
    msg.type = MessageType::VERSION;
    msg.payload = ver;

    peer.conn->send(msg);
    peer.version_sent = true;
    peer.state = PeerState::VERSION_SENT;

    LOG_DEBUG("Sent VERSION to {}", peer.info.addr.toString());
}

void PeerManager::sendVerack(Peer& peer) {
    Message msg;
    msg.type = MessageType::VERACK;

    peer.conn->send(msg);
    peer.verack_sent = true;

    LOG_DEBUG("Sent VERACK to {}", peer.info.addr.toString());
}

void PeerManager::completeHandshake(Peer& peer) {
    peer.state = PeerState::ESTABLISHED;

    // Update address info
    {
        std::lock_guard<std::mutex> lock(addr_mutex_);
        auto it = addresses_.find(peer.info.addr);
        if (it != addresses_.end()) {
            it->second.last_success = std::time(nullptr);
            it->second.success_count++;
            it->second.services = peer.info.services;
        }
    }

    LOG_INFO("Handshake complete: {} \"{}\" height={}",
             peer.info.addr.toString(), peer.info.user_agent, peer.info.start_height);

    // DHT handles peer discovery - no GETADDR needed

    if (on_new_peer_) {
        on_new_peer_(peer.info.id);
    }
}

bool PeerManager::connectTo(const NetAddr& addr) {
    // Check ban
    if (isBanned(addr)) {
        LOG_DEBUG("Not connecting to banned address: {}", addr.toString());
        return false;
    }

    // Check if this is our own IP (avoid self-connection)
    if (isLocalIP(addr.ip)) {
        LOG_DEBUG("Not connecting to own IP: {}", addr.toString());
        return false;
    }

    // Check if already connected or connecting
    {
        std::lock_guard<std::mutex> lock(connecting_mutex_);
        if (connecting_.count(addr) > 0) {
            return false;
        }
        connecting_.insert(addr);
    }

    {
        std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
        for (auto& p : peers_) {
            if (p.second.info.addr == addr) {
                std::lock_guard<std::mutex> lock2(connecting_mutex_);
                connecting_.erase(addr);
                return false;
            }
        }
    }

    // Update address info (only for routable addresses)
    if (addr.isRoutable()) {
        std::lock_guard<std::mutex> lock(addr_mutex_);
        auto& info = addresses_[addr];
        info.addr = addr;
        info.last_try = std::time(nullptr);
        info.attempts++;
    }

    // Create connection
    auto conn = Connection::connect(addr, [this, addr](bool success) {
        if (success) {
            // Will be handled by onNewConnection
        } else {
            onConnectionFailed(addr);
        }
    });

    if (!conn) {
        std::lock_guard<std::mutex> lock(connecting_mutex_);
        connecting_.erase(addr);
        return false;
    }

    onNewConnection(conn);
    return true;
}

void PeerManager::disconnect(Connection::Id id, const std::string& reason) {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);

    auto it = peers_.find(id);
    if (it != peers_.end()) {
        it->second.conn->disconnect(reason);
    }
}

void PeerManager::disconnectAll(const std::string& reason) {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);

    for (auto& p : peers_) {
        p.second.conn->disconnect(reason);
    }
}

void PeerManager::addAddress(const NetAddr& addr, const std::string& source) {
    if (!addr.isRoutable()) return;

    std::lock_guard<std::mutex> lock(addr_mutex_);

    auto& info = addresses_[addr];
    info.addr = addr;
    info.last_seen = std::time(nullptr);
    if (info.source.empty()) {
        info.source = source;
    }
}

void PeerManager::addAddresses(const std::vector<NetAddrTime>& addrs, const std::string& source) {
    std::lock_guard<std::mutex> lock(addr_mutex_);

    int64_t now = std::time(nullptr);

    for (auto& a : addrs) {
        NetAddr addr;
        addr.services = a.services;
        memcpy(addr.ip, a.ip, 16);
        addr.port = a.port;

        if (!addr.isRoutable()) continue;

        auto& info = addresses_[addr];
        info.addr = addr;
        info.services = a.services;
        info.last_seen = std::min(static_cast<int64_t>(a.timestamp), now);
        if (info.source.empty()) {
            info.source = source;
        }
    }
}

std::vector<NetAddrTime> PeerManager::getAddresses(size_t max_count) const {
    std::lock_guard<std::mutex> lock(addr_mutex_);

    std::vector<NetAddrTime> result;
    result.reserve(std::min(max_count, addresses_.size()));

    int64_t now = std::time(nullptr);

    // Score and sort addresses
    std::vector<std::pair<double, const AddrInfo*>> scored;
    for (auto& p : addresses_) {
        scored.emplace_back(p.second.getScore(now), &p.second);
    }

    std::sort(scored.begin(), scored.end(), [](auto& a, auto& b) {
        return a.first > b.first;
    });

    for (size_t i = 0; i < std::min(max_count, scored.size()); i++) {
        const AddrInfo* info = scored[i].second;
        NetAddrTime a;
        a.timestamp = static_cast<uint32_t>(info->last_seen);
        a.services = info->services;
        memcpy(a.ip, info->addr.ip, 16);
        a.port = info->addr.port;
        result.push_back(a);
    }

    return result;
}

size_t PeerManager::getAddressCount() const {
    // DHT handles peer discovery - address database not used
    return 0;
}

std::vector<NetAddrTime> PeerManager::getGoodAddresses(size_t max_count, double min_score) const {
    std::lock_guard<std::mutex> lock(addr_mutex_);

    std::vector<NetAddrTime> result;
    int64_t now = std::time(nullptr);

    // Score and filter addresses
    std::vector<std::pair<double, const AddrInfo*>> scored;
    for (auto& p : addresses_) {
        double score = p.second.getScore(now);
        if (score >= min_score) {
            scored.emplace_back(score, &p.second);
        }
    }

    // Sort by score (highest first)
    std::sort(scored.begin(), scored.end(), [](auto& a, auto& b) {
        return a.first > b.first;
    });

    // Return top addresses
    for (size_t i = 0; i < std::min(max_count, scored.size()); i++) {
        const AddrInfo* info = scored[i].second;
        NetAddrTime a;
        a.timestamp = static_cast<uint32_t>(info->last_seen);
        a.services = info->services;
        memcpy(a.ip, info->addr.ip, 16);
        a.port = info->addr.port;
        result.push_back(a);
    }

    return result;
}

void PeerManager::pruneDeadAddresses(double min_score) {
    std::lock_guard<std::mutex> lock(addr_mutex_);

    int64_t now = std::time(nullptr);
    size_t before = addresses_.size();

    auto it = addresses_.begin();
    while (it != addresses_.end()) {
        double score = it->second.getScore(now);
        if (score < min_score) {
            LOG_DEBUG("Pruning dead address {} (score: {:.1f})", it->first.toString(), score);
            it = addresses_.erase(it);
        } else {
            ++it;
        }
    }

    size_t pruned = before - addresses_.size();
    if (pruned > 0) {
        LOG_INFO("[Peers] Pruned {} dead addresses (score < {:.1f})", pruned, min_score);
    }
}

void PeerManager::addLocalIP(const uint8_t ip[16]) {
    std::lock_guard<std::mutex> lock(local_ips_mutex_);
    std::array<uint8_t, 16> arr;
    std::memcpy(arr.data(), ip, 16);
    local_ips_.insert(arr);
}

bool PeerManager::isLocalIP(const uint8_t ip[16]) const {
    std::lock_guard<std::mutex> lock(local_ips_mutex_);
    std::array<uint8_t, 16> arr;
    std::memcpy(arr.data(), ip, 16);
    return local_ips_.count(arr) > 0;
}

std::vector<std::string> PeerManager::getLocalIPs() const {
    std::lock_guard<std::mutex> lock(local_ips_mutex_);
    std::vector<std::string> result;
    char buf[INET6_ADDRSTRLEN];
    for (const auto& ip : local_ips_) {
        if (inet_ntop(AF_INET6, ip.data(), buf, sizeof(buf))) {
            result.push_back(buf);
        }
    }
    return result;
}

void PeerManager::detectLocalIPs() {
    // Add loopback
    uint8_t loopback[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1};
    addLocalIP(loopback);

#ifdef _WIN32
    // Windows: use GetAdaptersAddresses
    ULONG bufLen = 15000;
    std::vector<uint8_t> buffer(bufLen);
    PIP_ADAPTER_ADDRESSES addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

    ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    if (GetAdaptersAddresses(AF_INET6, flags, nullptr, addrs, &bufLen) == NO_ERROR) {
        for (auto* adapter = addrs; adapter; adapter = adapter->Next) {
            for (auto* ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
                if (ua->Address.lpSockaddr->sa_family == AF_INET6) {
                    auto* sin6 = reinterpret_cast<sockaddr_in6*>(ua->Address.lpSockaddr);
                    addLocalIP(reinterpret_cast<uint8_t*>(&sin6->sin6_addr));

                    char ip_str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));
                    LOG_DEBUG("[P2P] Local IP detected: {}", ip_str);
                }
            }
        }
    }
#else
    // Linux/macOS: use getifaddrs
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == 0) {
        for (auto* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6) {
                auto* sin6 = reinterpret_cast<sockaddr_in6*>(ifa->ifa_addr);
                addLocalIP(reinterpret_cast<uint8_t*>(&sin6->sin6_addr));

                char ip_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));
                LOG_DEBUG("[P2P] Local IP detected: {}", ip_str);
            }
        }
        freeifaddrs(ifaddr);
    }
#endif
}

void PeerManager::ban(const NetAddr& addr, const std::string& reason,
                      std::chrono::seconds duration) {
    std::lock_guard<std::mutex> lock(ban_mutex_);

    int64_t now = std::time(nullptr);

    BanEntry entry;
    entry.addr = addr;
    entry.ban_time = now;
    entry.unban_time = now + duration.count();
    entry.reason = reason;

    bans_[addr] = entry;

    LOG_INFO("Banned {} for {}: {}", addr.toString(), duration.count(), reason);

    // Disconnect if connected
    std::lock_guard<std::recursive_mutex> lock2(peers_mutex_);
    for (auto& p : peers_) {
        if (p.second.info.addr == addr) {
            p.second.conn->disconnect("banned: " + reason);
        }
    }
}

void PeerManager::unban(const NetAddr& addr) {
    std::lock_guard<std::mutex> lock(ban_mutex_);
    bans_.erase(addr);
    LOG_INFO("Unbanned {}", addr.toString());
}

bool PeerManager::isBanned(const NetAddr& addr) const {
    std::lock_guard<std::mutex> lock(ban_mutex_);

    auto it = bans_.find(addr);
    if (it == bans_.end()) return false;

    int64_t now = std::time(nullptr);
    return now < it->second.unban_time;
}

std::vector<BanEntry> PeerManager::getBanList() const {
    std::lock_guard<std::mutex> lock(ban_mutex_);

    std::vector<BanEntry> result;
    result.reserve(bans_.size());
    for (auto& p : bans_) {
        result.push_back(p.second);
    }
    return result;
}

void PeerManager::clearBans() {
    std::lock_guard<std::mutex> lock(ban_mutex_);
    bans_.clear();
}

std::shared_ptr<Connection> PeerManager::getConnection(Connection::Id id) {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
    auto it = peers_.find(id);
    return it != peers_.end() ? it->second.conn : nullptr;
}

std::vector<PeerInfo> PeerManager::getPeerInfo() const {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);

    std::vector<PeerInfo> result;
    result.reserve(peers_.size());
    for (auto& p : peers_) {
        PeerInfo info = p.second.info;
        info.state = p.second.state;  // Use actual peer state, not info's copy
        info.known_blocks = p.second.known_blocks;
        info.known_txs = p.second.known_txs;

        auto& stats = p.second.conn->getStats();
        info.bytes_sent = stats.bytes_sent;
        info.bytes_recv = stats.bytes_received;

        result.push_back(info);
    }
    return result;
}

size_t PeerManager::getPeerCount() const {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
    // Count unique nodes by IP (not connections)
    std::set<std::array<uint8_t, 16>> unique_ips;
    for (const auto& p : peers_) {
        std::array<uint8_t, 16> ip;
        std::memcpy(ip.data(), p.second.info.addr.ip, 16);
        unique_ips.insert(ip);
    }
    return unique_ips.size();
}

size_t PeerManager::getConnectionCount() const {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
    return peers_.size();
}

size_t PeerManager::getInboundCount() const {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
    size_t count = 0;
    for (auto& p : peers_) {
        if (p.second.info.direction == ConnectionDir::INBOUND) {
            count++;
        }
    }
    return count;
}

size_t PeerManager::getOutboundCount() const {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
    size_t count = 0;
    for (auto& p : peers_) {
        if (p.second.info.direction == ConnectionDir::OUTBOUND) {
            count++;
        }
    }
    return count;
}

bool PeerManager::sendTo(Connection::Id id, const Message& msg) {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);

    auto it = peers_.find(id);
    if (it == peers_.end()) return false;

    return it->second.conn->send(msg);
}

void PeerManager::broadcast(const Message& msg, Connection::Id exclude) {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);

    for (auto& p : peers_) {
        if (p.first != exclude && p.second.state == PeerState::ESTABLISHED) {
            p.second.conn->send(msg);
        }
    }
}

void PeerManager::broadcastBlock(const Hash256& hash, const Block& block) {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);

    // Create INV message
    Message inv_msg;
    inv_msg.type = MessageType::INV;
    InvMessage inv;
    inv.items.push_back(InvItem{InvType::BLOCK, hash});
    inv_msg.payload = inv;

    for (auto& p : peers_) {
        if (p.second.state != PeerState::ESTABLISHED) continue;
        if (p.second.known_blocks.count(hash) > 0) continue;

        p.second.known_blocks.insert(hash);
        p.second.conn->send(inv_msg);
    }
}

void PeerManager::broadcastTx(const Hash256& txid, const Transaction& tx) {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);

    // Create INV message
    Message inv_msg;
    inv_msg.type = MessageType::INV;
    InvMessage inv;
    inv.items.push_back(InvItem{InvType::TX, txid});
    inv_msg.payload = inv;

    for (auto& p : peers_) {
        if (p.second.state != PeerState::ESTABLISHED) continue;
        if (!p.second.info.relay) continue;
        if (p.second.known_txs.count(txid) > 0) continue;

        p.second.known_txs.insert(txid);
        p.second.conn->send(inv_msg);
    }
}

Connection::Id PeerManager::selectSyncPeer() const {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);

    Connection::Id best_id = 0;
    int32_t best_height = -1;
    int64_t best_ping = INT64_MAX;

    for (auto& p : peers_) {
        if (p.second.state != PeerState::ESTABLISHED) continue;
        if (p.second.info.syncing) continue;

        // Prefer peers with higher height
        if (p.second.info.best_height > best_height ||
            (p.second.info.best_height == best_height && p.second.info.ping_usec < best_ping)) {
            best_id = p.first;
            best_height = p.second.info.best_height;
            best_ping = p.second.info.ping_usec;
        }
    }

    return best_id;
}

std::vector<Connection::Id> PeerManager::selectRelayPeers(size_t count) const {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);

    std::vector<Connection::Id> result;

    for (auto& p : peers_) {
        if (p.second.state == PeerState::ESTABLISHED && p.second.info.relay) {
            result.push_back(p.first);
        }
    }

    // Shuffle and truncate
    if (result.size() > count) {
        std::lock_guard<std::mutex> rng_lock(rng_mutex_);
        std::shuffle(result.begin(), result.end(), rng_);
        result.resize(count);
    }

    return result;
}

void PeerManager::addKnownBlock(Connection::Id id, const Hash256& hash) {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
    auto it = peers_.find(id);
    if (it != peers_.end()) {
        it->second.known_blocks.insert(hash);
    }
}

void PeerManager::addKnownTx(Connection::Id id, const Hash256& txid) {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
    auto it = peers_.find(id);
    if (it != peers_.end()) {
        it->second.known_txs.insert(txid);
    }
}

bool PeerManager::hasKnownBlock(Connection::Id id, const Hash256& hash) const {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
    auto it = peers_.find(id);
    return it != peers_.end() && it->second.known_blocks.count(hash) > 0;
}

bool PeerManager::hasKnownTx(Connection::Id id, const Hash256& txid) const {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
    auto it = peers_.find(id);
    return it != peers_.end() && it->second.known_txs.count(txid) > 0;
}

void PeerManager::updatePeerHeight(Connection::Id id, int32_t height, const Hash256& hash) {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
    auto it = peers_.find(id);
    if (it != peers_.end()) {
        it->second.info.best_height = height;
        it->second.info.best_hash = hash;
    }
}

void PeerManager::markSyncing(Connection::Id id, bool syncing) {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
    auto it = peers_.find(id);
    if (it != peers_.end()) {
        it->second.info.syncing = syncing;
    }
}

NetAddr PeerManager::selectAddressToConnect() {
    std::lock_guard<std::mutex> lock(addr_mutex_);

    if (addresses_.empty()) {
        return NetAddr{};
    }

    int64_t now = std::time(nullptr);

    // Score addresses
    std::vector<std::pair<double, NetAddr>> scored;
    for (auto& p : addresses_) {
        // Skip recently tried
        if (now - p.second.last_try < 60) continue;

        // Skip if we're already connecting
        {
            std::lock_guard<std::mutex> lock2(connecting_mutex_);
            if (connecting_.count(p.first) > 0) continue;
        }

        // Skip if already connected
        bool connected = false;
        {
            std::lock_guard<std::recursive_mutex> lock2(peers_mutex_);
            for (auto& peer : peers_) {
                if (peer.second.info.addr == p.first) {
                    connected = true;
                    break;
                }
            }
        }
        if (connected) continue;

        double score = p.second.getScore(now);
        if (score > -100) {  // Filter out heavily penalized addresses
            scored.emplace_back(score, p.first);
        }
    }

    if (scored.empty()) {
        return NetAddr{};
    }

    // Sort by score and pick from top candidates with some randomness
    std::sort(scored.begin(), scored.end(), [](auto& a, auto& b) {
        return a.first > b.first;
    });

    // Pick randomly from top 10% (at least 1)
    size_t top_n = std::max(size_t(1), scored.size() / 10);
    std::lock_guard<std::mutex> rng_lock(rng_mutex_);
    std::uniform_int_distribution<size_t> dist(0, top_n - 1);

    return scored[dist(rng_)].second;
}

void PeerManager::tryConnect() {
    size_t outbound = getOutboundCount();
    if (outbound >= static_cast<size_t>(config_.target_outbound)) {
        return;
    }

    size_t needed = config_.target_outbound - outbound;

    for (size_t i = 0; i < needed; i++) {
        NetAddr addr = selectAddressToConnect();
        if (addr.port == 0) break;  // No more addresses

        connectTo(addr);
    }
}

void PeerManager::checkTimeouts() {
    std::vector<Connection::Id> to_disconnect;

    {
        std::lock_guard<std::recursive_mutex> lock(peers_mutex_);

        for (auto& p : peers_) {
            // Check connection timeout
            if (p.second.state == PeerState::CONNECTING ||
                p.second.state == PeerState::VERSION_SENT) {
                if (!p.second.conn->checkTimeout(config_.connect_timeout)) {
                    to_disconnect.push_back(p.first);
                    continue;
                }
            }

            // Check inactivity timeout
            if (!p.second.conn->checkTimeout(config_.inactivity_timeout)) {
                to_disconnect.push_back(p.first);
                continue;
            }

            // Check ban score
            if (p.second.conn->getBanScore() >= config_.ban_threshold) {
                ban(p.second.info.addr, "ban score exceeded");
                to_disconnect.push_back(p.first);
            }
        }
    }

    for (auto id : to_disconnect) {
        disconnect(id, "timeout");
    }
}

void PeerManager::sendPings() {
    std::lock_guard<std::recursive_mutex> lock(peers_mutex_);

    auto now = std::chrono::steady_clock::now();

    for (auto& p : peers_) {
        if (p.second.state != PeerState::ESTABLISHED) continue;

        auto since_last = std::chrono::duration_cast<std::chrono::seconds>(
            now - p.second.last_ping_sent
        );

        if (since_last >= config_.ping_interval) {
            // Generate nonce
            {
                std::lock_guard<std::mutex> rng_lock(rng_mutex_);
                p.second.ping_nonce = rng_();
            }
            p.second.ping_start = now;
            p.second.last_ping_sent = now;

            Message msg;
            msg.type = MessageType::PING;
            msg.payload = PingMessage{p.second.ping_nonce};
            p.second.conn->send(msg);
        }
    }
}

void PeerManager::cleanupBans() {
    std::lock_guard<std::mutex> lock(ban_mutex_);

    int64_t now = std::time(nullptr);

    auto it = bans_.begin();
    while (it != bans_.end()) {
        if (now >= it->second.unban_time) {
            LOG_DEBUG("Ban expired: {}", it->first.toString());
            it = bans_.erase(it);
        } else {
            ++it;
        }
    }
}

void PeerManager::requestAddresses() {
    // DHT handles peer discovery - no GETADDR needed
}

} // namespace p2p
} // namespace ftc
