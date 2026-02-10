// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/manager/conn_manager.h"
#include "core/logging.h"
#include "core/time.h"
#include "core/random.h"

#include <algorithm>
#include <chrono>
#include <limits>
#include <utility>

namespace net {

// ===========================================================================
// Peer implementation
// ===========================================================================

Peer::Peer(uint64_t id, Connection conn, bool inbound)
    : id(id)
    , conn(std::move(conn))
    , inbound(inbound)
    , state(PeerState::CONNECTED)
{
    stats.connected_time = core::get_time();
}

Peer::~Peer() {
    // If the read thread is still joinable, request a stop.
    // The jthread destructor will join automatically.
    if (read_thread.joinable()) {
        read_thread.request_stop();
    }
}

// ===========================================================================
// ConnManager construction / destruction
// ===========================================================================

ConnManager::ConnManager(Config config,
                         core::Channel<PeerEvent>& event_channel)
    : config_(std::move(config))
    , event_channel_(event_channel)
{
}

ConnManager::~ConnManager() {
    stop();
}

// ===========================================================================
// Lifecycle
// ===========================================================================

core::Result<void> ConnManager::start() {
    if (running_.load(std::memory_order_relaxed)) {
        return core::Error(core::ErrorCode::INTERNAL_ERROR,
                           "ConnManager already running");
    }

    // Bind and listen if configured.
    if (config_.listen) {
        auto bind_result = listen_socket_.bind_listen(
            config_.bind_address, config_.port);
        if (!bind_result.ok()) {
            return core::Error(core::ErrorCode::NETWORK_ERROR,
                               "Failed to bind listener on " +
                               config_.bind_address + ":" +
                               std::to_string(config_.port) + ": " +
                               bind_result.error().message());
        }

        LOG_INFO(core::LogCategory::NET,
                 "P2P listener bound to " + config_.bind_address +
                 ":" + std::to_string(config_.port));
    }

    running_.store(true, std::memory_order_release);

    // Start the listen thread.
    if (config_.listen) {
        listen_thread_ = std::jthread([this](std::stop_token stoken) {
            listen_loop(stoken);
        });
    }

    LOG_INFO(core::LogCategory::NET, "Connection manager started");
    return core::make_ok();
}

void ConnManager::stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return;  // Already stopped.
    }

    LOG_INFO(core::LogCategory::NET, "Connection manager stopping...");

    // Close the listen socket to unblock accept().
    listen_socket_.close();

    // Request stop on the listen thread.
    if (listen_thread_.joinable()) {
        listen_thread_.request_stop();
        listen_thread_.join();
    }

    // Disconnect all peers and stop their read threads.
    // We collect peer IDs first to avoid holding the lock while destroying.
    std::vector<uint64_t> ids;
    {
        std::lock_guard lock(peers_mutex_);
        ids.reserve(peers_.size());
        for (const auto& [id, _] : peers_) {
            ids.push_back(id);
        }
    }

    for (uint64_t id : ids) {
        disconnect(id, DisconnectReason::USER_REQUESTED);
    }

    // Move all peers out under the lock, then destroy them outside
    // so that the jthread joins happen without holding peers_mutex_.
    std::unordered_map<uint64_t, std::unique_ptr<Peer>> peers_to_destroy;
    {
        std::lock_guard lock(peers_mutex_);
        peers_to_destroy = std::move(peers_);
        peers_.clear();
    }
    // ~Peer destructors join read threads here, without the lock.
    peers_to_destroy.clear();

    LOG_INFO(core::LogCategory::NET, "Connection manager stopped");
}

// ===========================================================================
// Connection management
// ===========================================================================

core::Result<uint64_t> ConnManager::connect_to(const std::string& host,
                                                uint16_t port) {
    if (!running_.load(std::memory_order_relaxed)) {
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "ConnManager is not running");
    }

    // Check outbound slot availability.
    if (static_cast<int>(outbound_count()) >= config_.max_outbound) {
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "Maximum outbound connections reached (" +
                           std::to_string(config_.max_outbound) + ")");
    }

    // Check total connection limit.
    if (static_cast<int>(peer_count()) >= DEFAULT_MAX_TOTAL) {
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "Maximum total connections reached (" +
                           std::to_string(DEFAULT_MAX_TOTAL) + ")");
    }

    // Check for duplicate outbound connections to the same host:port.
    {
        std::lock_guard lock(peers_mutex_);
        for (const auto& [_, peer] : peers_) {
            if (!peer->inbound &&
                peer->conn.remote_address() == host &&
                peer->conn.remote_port() == port) {
                return core::Error(core::ErrorCode::NETWORK_ERROR,
                                   "Already connected to " + host +
                                   ":" + std::to_string(port));
            }
        }
    }

    // Skip known self-addresses (detected via nonce during prior handshakes).
    if (is_self_address(host)) {
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "Skipping self-address " + host);
    }

    // Validate the host string is not empty.
    if (host.empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "Empty host address");
    }

    // Validate port is non-zero.
    if (port == 0) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "Invalid port number 0");
    }

    LOG_INFO(core::LogCategory::NET,
             "Connecting to " + host + ":" + std::to_string(port));

    // Create socket and connect with a 5-second timeout.
    net::Socket socket;
    auto connect_result = socket.connect(host, port, 5000);
    if (!connect_result.ok()) {
        LOG_WARN(core::LogCategory::NET,
                 "Failed to connect to " + host + ":" +
                 std::to_string(port) + ": " +
                 connect_result.error().message());
        return core::Error(core::ErrorCode::NETWORK_REFUSED,
                           "Connection to " + host + ":" +
                           std::to_string(port) + " failed: " +
                           connect_result.error().message());
    }

    // Set socket options for the new connection.
    socket.set_nodelay(true);
    socket.set_keepalive(true);
    socket.set_send_timeout(5000); // 5s send timeout prevents event loop stalls

    uint64_t peer_id = allocate_peer_id();
    std::string remote = host + ":" + std::to_string(port);

    // Create the Connection and Peer objects.
    Connection conn(std::move(socket), ConnDir::OUTBOUND, peer_id);
    conn.set_state(ConnState::CONNECTED);

    auto peer = std::make_unique<Peer>(peer_id, std::move(conn), false);

    // Start the per-peer read loop thread.
    uint64_t captured_id = peer_id;
    peer->read_thread = std::jthread([this, captured_id](std::stop_token stoken) {
        peer_read_loop(stoken, captured_id);
    });

    // Insert into the peer map.
    {
        std::lock_guard lock(peers_mutex_);
        peers_.emplace(peer_id, std::move(peer));
    }

    // Notify the event loop about the new connection.
    PeerEvent event;
    event.type = PeerEventType::CONNECTED;
    event.peer_id = peer_id;
    event.remote_addr = remote;
    event.inbound = false;
    push_event(std::move(event));

    LOG_INFO(core::LogCategory::NET,
             "Outbound connection established: peer " +
             std::to_string(peer_id) + " (" + remote + ")");

    return peer_id;
}

void ConnManager::disconnect(uint64_t peer_id, DisconnectReason reason) {
    std::lock_guard lock(peers_mutex_);

    auto it = peers_.find(peer_id);
    if (it == peers_.end()) {
        return;  // Already disconnected or unknown.
    }

    Peer& peer = *it->second;

    // Skip if already disconnecting.
    if (peer.state == PeerState::DISCONNECTING ||
        peer.state == PeerState::DISCONNECTED) {
        return;
    }

    LOG_INFO(core::LogCategory::NET,
             "Disconnecting peer " + std::to_string(peer_id) +
             " (" + peer.conn.remote_address() +
             "): " + std::string(disconnect_reason_name(reason)));

    peer.state = PeerState::DISCONNECTING;

    // Close the socket to unblock any blocking I/O in the read loop.
    peer.conn.socket().close();

    // The read loop thread will detect the closed socket, push a
    // DISCONNECTED event, and exit.  We do not remove the peer from
    // the map here -- that happens in remove_peer() after the event
    // loop processes the DISCONNECTED event.
}

// ===========================================================================
// Peer lookup
// ===========================================================================

Peer* ConnManager::get_peer(uint64_t peer_id) {
    std::lock_guard lock(peers_mutex_);
    auto it = peers_.find(peer_id);
    if (it == peers_.end()) return nullptr;
    return it->second.get();
}

const Peer* ConnManager::get_peer(uint64_t peer_id) const {
    std::lock_guard lock(peers_mutex_);
    auto it = peers_.find(peer_id);
    if (it == peers_.end()) return nullptr;
    return it->second.get();
}

std::vector<uint64_t> ConnManager::get_peer_ids() const {
    std::lock_guard lock(peers_mutex_);
    std::vector<uint64_t> ids;
    ids.reserve(peers_.size());
    for (const auto& [id, _] : peers_) {
        ids.push_back(id);
    }
    return ids;
}

size_t ConnManager::peer_count() const {
    std::lock_guard lock(peers_mutex_);
    return peers_.size();
}

size_t ConnManager::outbound_count() const {
    std::lock_guard lock(peers_mutex_);
    size_t count = 0;
    for (const auto& [_, peer] : peers_) {
        if (!peer->inbound &&
            peer->state != PeerState::DISCONNECTING &&
            peer->state != PeerState::DISCONNECTED) {
            ++count;
        }
    }
    return count;
}

size_t ConnManager::inbound_count() const {
    std::lock_guard lock(peers_mutex_);
    size_t count = 0;
    for (const auto& [_, peer] : peers_) {
        if (peer->inbound &&
            peer->state != PeerState::DISCONNECTING &&
            peer->state != PeerState::DISCONNECTED) {
            ++count;
        }
    }
    return count;
}

// ===========================================================================
// Message sending
// ===========================================================================

void ConnManager::send_to(uint64_t peer_id, net::Message msg) {
    std::lock_guard lock(peers_mutex_);

    auto it = peers_.find(peer_id);
    if (it == peers_.end()) {
        return;  // Peer gone.
    }

    Peer& peer = *it->second;

    // Only send if the connection is still operational.
    if (peer.state == PeerState::DISCONNECTING ||
        peer.state == PeerState::DISCONNECTED) {
        return;
    }

    auto result = peer.conn.send_message(msg);
    if (!result.ok()) {
        LOG_WARN(core::LogCategory::NET,
                 "Failed to send " + msg.header.get_command() +
                 " to peer " + std::to_string(peer_id) + ": " +
                 result.error().message());
        // Schedule disconnect outside the lock to avoid recursion.
        // We set the state and close the socket; the read loop will
        // detect the closure and emit the DISCONNECTED event.
        peer.state = PeerState::DISCONNECTING;
        peer.conn.socket().close();
        return;
    }

    // Update send stats.
    peer.stats.last_send = core::get_time();
    peer.stats.msgs_sent++;
    peer.stats.bytes_sent += msg.payload.size() + MessageHeader::HEADER_SIZE;

    LOG_TRACE(core::LogCategory::NET,
              "Sent " + msg.header.get_command() +
              " (" + std::to_string(msg.payload.size()) + " bytes) to peer " +
              std::to_string(peer_id));
}

void ConnManager::broadcast(const net::Message& msg) {
    std::lock_guard lock(peers_mutex_);

    for (auto& [peer_id, peer] : peers_) {
        if (peer->state == PeerState::DISCONNECTING ||
            peer->state == PeerState::DISCONNECTED) {
            continue;
        }
        // Only broadcast to peers that have completed the handshake.
        if (!peer_state_is_operational(peer->state)) {
            continue;
        }

        auto result = peer->conn.send_message(msg);
        if (result.ok()) {
            peer->stats.last_send = core::get_time();
            peer->stats.msgs_sent++;
            peer->stats.bytes_sent +=
                msg.payload.size() + MessageHeader::HEADER_SIZE;
        } else {
            LOG_WARN(core::LogCategory::NET,
                     "Broadcast send failed to peer " +
                     std::to_string(peer_id));
            peer->state = PeerState::DISCONNECTING;
            peer->conn.socket().close();
        }
    }
}

void ConnManager::broadcast_if(
    const net::Message& msg,
    std::function<bool(const Peer&)> predicate)
{
    std::lock_guard lock(peers_mutex_);

    for (auto& [peer_id, peer] : peers_) {
        if (peer->state == PeerState::DISCONNECTING ||
            peer->state == PeerState::DISCONNECTED) {
            continue;
        }
        if (!peer_state_is_operational(peer->state)) {
            continue;
        }
        if (!predicate(*peer)) {
            continue;
        }

        auto result = peer->conn.send_message(msg);
        if (result.ok()) {
            peer->stats.last_send = core::get_time();
            peer->stats.msgs_sent++;
            peer->stats.bytes_sent +=
                msg.payload.size() + MessageHeader::HEADER_SIZE;
        } else {
            LOG_WARN(core::LogCategory::NET,
                     "Broadcast send failed to peer " +
                     std::to_string(peer_id));
            peer->state = PeerState::DISCONNECTING;
            peer->conn.socket().close();
        }
    }
}

// ===========================================================================
// Listen loop
// ===========================================================================

void ConnManager::listen_loop(std::stop_token stoken) {
    LOG_INFO(core::LogCategory::NET, "Listen thread started");

    while (!stoken.stop_requested() &&
           running_.load(std::memory_order_relaxed)) {
        // Accept blocks until a connection arrives or the socket is closed.
        auto result = listen_socket_.accept();

        if (stoken.stop_requested() ||
            !running_.load(std::memory_order_relaxed)) {
            break;
        }

        if (!result.ok()) {
            // If the listen socket was closed (during shutdown), exit cleanly.
            if (!listen_socket_.is_open()) {
                break;
            }
            LOG_WARN(core::LogCategory::NET,
                     "Accept failed: " + result.error().message());
            // Brief sleep to avoid a tight error loop.
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        handle_accept(std::move(result).value());
    }

    LOG_INFO(core::LogCategory::NET, "Listen thread exiting");
}

void ConnManager::handle_accept(net::Socket socket) {
    std::string remote_addr = socket.remote_address();
    uint16_t remote_port = socket.remote_port();
    std::string remote = remote_addr + ":" + std::to_string(remote_port);

    // 1) Rate limiting: max N new inbound connections per minute.
    {
        std::lock_guard lock(rate_mutex_);
        int64_t now = core::get_time();
        // Prune timestamps older than the window.
        std::erase_if(inbound_timestamps_, [&](int64_t ts) {
            return (now - ts) > RATE_LIMIT_WINDOW;
        });
        if (static_cast<int>(inbound_timestamps_.size()) >=
            MAX_INBOUND_PER_MINUTE) {
            LOG_DEBUG(core::LogCategory::NET,
                      "Rejecting inbound from " + remote +
                      ": rate limit exceeded (" +
                      std::to_string(MAX_INBOUND_PER_MINUTE) + "/min)");
            socket.close();
            return;
        }
        inbound_timestamps_.push_back(now);
    }

    // 2) Per-IP limit: max 1 inbound connection per IP (like Bitcoin Core).
    {
        std::lock_guard lock(peers_mutex_);
        for (const auto& [_, peer] : peers_) {
            if (peer->inbound &&
                peer->conn.remote_address() == remote_addr) {
                LOG_DEBUG(core::LogCategory::NET,
                          "Rejecting inbound from " + remote +
                          ": already connected from this IP");
                socket.close();
                return;
            }
        }
    }

    // 3) Check inbound slot availability.  If full, try to evict the
    //    worst inbound peer (highest banscore, then oldest with least
    //    bytes transferred) to make room — like Bitcoin Core eviction.
    if (static_cast<int>(inbound_count()) >= config_.max_inbound) {
        uint64_t evict_id = 0;
        {
            std::lock_guard lock(peers_mutex_);
            int worst_score = -1;
            int64_t worst_bytes = std::numeric_limits<int64_t>::max();
            for (const auto& [id, peer] : peers_) {
                if (!peer->inbound) continue;
                int score = peer->stats.misbehavior_score;
                int64_t bytes = peer->stats.bytes_recv + peer->stats.bytes_sent;
                if (score > worst_score ||
                    (score == worst_score && bytes < worst_bytes)) {
                    worst_score = score;
                    worst_bytes = bytes;
                    evict_id = id;
                }
            }
        }
        if (evict_id != 0) {
            LOG_INFO(core::LogCategory::NET,
                     "Evicting inbound peer " + std::to_string(evict_id) +
                     " to make room for " + remote);
            disconnect(evict_id, DisconnectReason::TOO_MANY_CONNECTIONS);
        } else {
            LOG_WARN(core::LogCategory::NET,
                     "Rejecting inbound from " + remote +
                     ": max inbound reached, no eviction candidate");
            socket.close();
            return;
        }
    }

    // 4) Check total connection limit.
    if (static_cast<int>(peer_count()) >= DEFAULT_MAX_TOTAL) {
        LOG_WARN(core::LogCategory::NET,
                 "Rejecting inbound from " + remote + ": max total reached");
        socket.close();
        return;
    }

    LOG_INFO(core::LogCategory::NET,
             "Accepted inbound connection from " + remote);

    // Set socket options.
    socket.set_nodelay(true);
    socket.set_keepalive(true);
    socket.set_send_timeout(5000); // 5s send timeout prevents event loop stalls

    uint64_t peer_id = allocate_peer_id();

    // Create the Connection and Peer.
    Connection conn(std::move(socket), ConnDir::INBOUND, peer_id);
    conn.set_state(ConnState::CONNECTED);

    auto peer = std::make_unique<Peer>(peer_id, std::move(conn), true);

    // Start the per-peer read loop.
    uint64_t captured_id = peer_id;
    peer->read_thread = std::jthread([this, captured_id](std::stop_token stoken) {
        peer_read_loop(stoken, captured_id);
    });

    // Insert into the map.
    {
        std::lock_guard lock(peers_mutex_);
        peers_.emplace(peer_id, std::move(peer));
    }

    // Notify the event loop.
    PeerEvent event;
    event.type = PeerEventType::CONNECTED;
    event.peer_id = peer_id;
    event.remote_addr = remote;
    event.inbound = true;
    push_event(std::move(event));
}

// ===========================================================================
// Per-peer read loop
// ===========================================================================

void ConnManager::peer_read_loop(std::stop_token stoken, uint64_t peer_id) {
    LOG_DEBUG(core::LogCategory::NET,
              "Read loop started for peer " + std::to_string(peer_id));

    // Get a stable pointer to the peer's Connection.  This pointer
    // remains valid for the lifetime of the read loop because
    // remove_peer() closes the socket first (unblocking recv), then
    // joins this thread before destroying the Peer.
    Connection* conn_ptr = nullptr;
    {
        std::lock_guard lock(peers_mutex_);
        auto it = peers_.find(peer_id);
        if (it == peers_.end()) return;
        conn_ptr = &it->second->conn;
    }

    while (!stoken.stop_requested() &&
           running_.load(std::memory_order_relaxed)) {
        // Read message WITHOUT holding peers_mutex_ so that other
        // threads (RPC, event loop) can access the peer map while
        // this thread blocks on recv().
        auto msg_result = conn_ptr->read_message();

        if (!msg_result.ok()) {
            // Connection closed or error -- push disconnect event.
            if (!stoken.stop_requested()) {
                PeerEvent event;
                event.type = PeerEventType::DISCONNECTED;
                event.peer_id = peer_id;
                event.disconnect_reason = DisconnectReason::PROTOCOL_ERROR;
                push_event(std::move(event));
            }
            break;
        }

        Message msg = std::move(msg_result).value();

        // Validate checksum.
        if (!msg.verify_checksum()) {
            LOG_WARN(core::LogCategory::NET,
                     "Checksum mismatch from peer " +
                     std::to_string(peer_id) + " for " +
                     msg.header.get_command());

            PeerEvent event;
            event.type = PeerEventType::MISBEHAVIOR;
            event.peer_id = peer_id;
            event.misbehavior_score = 10;
            push_event(std::move(event));
            continue;
        }

        // Update receive stats.
        {
            std::lock_guard lock(peers_mutex_);
            auto it = peers_.find(peer_id);
            if (it != peers_.end()) {
                auto& peer = *it->second;
                peer.stats.last_recv = core::get_time();
                peer.stats.msgs_recv++;
                peer.stats.bytes_recv +=
                    msg.payload.size() + MessageHeader::HEADER_SIZE;
            }
        }

        // Push the message event.
        PeerEvent event;
        event.type = PeerEventType::MESSAGE;
        event.peer_id = peer_id;
        event.msg = std::move(msg);
        push_event(std::move(event));
    }

    LOG_DEBUG(core::LogCategory::NET,
              "Read loop exiting for peer " + std::to_string(peer_id));
}

// ===========================================================================
// Internal helpers
// ===========================================================================

uint64_t ConnManager::allocate_peer_id() {
    return next_peer_id_.fetch_add(1, std::memory_order_relaxed);
}

void ConnManager::remove_peer(uint64_t peer_id) {
    std::unique_ptr<Peer> removed_peer;
    {
        std::lock_guard lock(peers_mutex_);
        auto it = peers_.find(peer_id);
        if (it == peers_.end()) return;

        auto& peer = *it->second;
        peer.state = PeerState::DISCONNECTED;
        peer.conn.socket().close();

        if (peer.read_thread.joinable()) {
            peer.read_thread.request_stop();
        }

        // Move out of the map so that the Peer destructor (which
        // joins the read thread) runs OUTSIDE the lock.
        removed_peer = std::move(it->second);
        peers_.erase(it);
    }
    // ~Peer joins the read thread here, without holding peers_mutex_.
}

void ConnManager::push_event(PeerEvent event) {
    event_channel_.send(std::move(event));
}

// ===========================================================================
// Self-connection prevention
// ===========================================================================

void ConnManager::mark_self_address(const std::string& addr) {
    std::lock_guard lock(self_addr_mutex_);
    self_addresses_.insert(addr);
    LOG_INFO(core::LogCategory::NET,
             "Marked " + addr + " as self-address");
}

bool ConnManager::is_self_address(const std::string& addr) const {
    std::lock_guard lock(self_addr_mutex_);
    return self_addresses_.count(addr) > 0;
}

// ===========================================================================
// Connection statistics (for RPC / logging)
// ===========================================================================

} // namespace net
