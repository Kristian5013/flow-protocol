/**
 * FTC Connection Implementation
 * Full TCP connection management with non-blocking I/O
 */

#include "p2p/connection.h"
#include "util/logging.h"
#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <thread>

#ifdef _WIN32
    #pragma comment(lib, "ws2_32.lib")
#endif

namespace ftc {
namespace p2p {

// Static member initialization
std::atomic<Connection::Id> Connection::next_id_{1};

// ============================================================================
// Networking initialization
// ============================================================================

bool initNetworking() {
#ifdef _WIN32
    WSADATA wsa_data;
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0) {
        LOG_ERROR("WSAStartup failed: {}", result);
        return false;
    }
    LOG_DEBUG("Winsock initialized");
#endif
    return true;
}

void shutdownNetworking() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// Connection implementation
// ============================================================================

Connection::Connection(socket_t sock, const NetAddr& addr, ConnectionDir dir)
    : id_(next_id_++), sock_(sock), addr_(addr), direction_(dir) {
    stats_.connect_time = std::chrono::steady_clock::now();
    stats_.last_recv = stats_.connect_time;
    stats_.last_send = stats_.connect_time;
    recv_buffer_.reserve(RECV_CHUNK_SIZE);
}

Connection::~Connection() {
    disconnect("destructor");
}

std::shared_ptr<Connection> Connection::connect(const NetAddr& addr, ConnectCallback on_connect) {
    // Create IPv6 socket (handles IPv4-mapped addresses via dual-stack)
    socket_t sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

    if (sock == INVALID_SOCK) {
        LOG_ERROR("Failed to create socket: {}", SOCKET_ERROR_CODE);
        if (on_connect) on_connect(false);
        return nullptr;
    }

    // Disable IPV6_V6ONLY to allow IPv4-mapped addresses
    int v6only = 0;
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&v6only, sizeof(v6only));

    auto conn = std::shared_ptr<Connection>(
        new Connection(sock, addr, ConnectionDir::OUTBOUND)
    );

    conn->on_connect_ = on_connect;

    if (!conn->setNonBlocking() || !conn->setSocketOptions()) {
        if (on_connect) on_connect(false);
        return nullptr;
    }

    // Initiate connection (always IPv6)
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(addr.port);
    memcpy(&sa.sin6_addr, addr.ip, 16);
    int result = ::connect(sock, (struct sockaddr*)&sa, sizeof(sa));

    if (result == 0) {
        conn->state_ = ConnectionState::CONNECTED;
        if (on_connect) on_connect(true);
    } else {
        int err = SOCKET_ERROR_CODE;
        if (err == WOULD_BLOCK || err == IN_PROGRESS) {
            conn->state_ = ConnectionState::CONNECTING;
        } else {
            LOG_DEBUG("Connect to {} failed: {}", addr.toString(), err);
            if (on_connect) on_connect(false);
            return nullptr;
        }
    }

    LOG_DEBUG("Connecting to {}", addr.toString());
    return conn;
}

std::shared_ptr<Connection> Connection::fromSocket(socket_t sock, const NetAddr& addr) {
    auto conn = std::shared_ptr<Connection>(
        new Connection(sock, addr, ConnectionDir::INBOUND)
    );

    if (!conn->setNonBlocking() || !conn->setSocketOptions()) {
        return nullptr;
    }

    conn->state_ = ConnectionState::CONNECTED;
    LOG_DEBUG("Accepted connection from {}", addr.toString());
    return conn;
}

bool Connection::setNonBlocking() {
#ifdef _WIN32
    u_long mode = 1;
    if (ioctlsocket(sock_, FIONBIO, &mode) != 0) {
        LOG_ERROR("Failed to set non-blocking: {}", SOCKET_ERROR_CODE);
        return false;
    }
#else
    int flags = fcntl(sock_, F_GETFL, 0);
    if (flags == -1 || fcntl(sock_, F_SETFL, flags | O_NONBLOCK) == -1) {
        LOG_ERROR("Failed to set non-blocking: {}", SOCKET_ERROR_CODE);
        return false;
    }
#endif
    return true;
}

bool Connection::setSocketOptions() {
    // Disable Nagle's algorithm for lower latency
    int flag = 1;
    if (setsockopt(sock_, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag)) != 0) {
        LOG_WARN("Failed to set TCP_NODELAY");
    }

    // Set send/receive buffer sizes
    int bufsize = 256 * 1024;  // 256 KB
    setsockopt(sock_, SOL_SOCKET, SO_SNDBUF, (char*)&bufsize, sizeof(bufsize));
    setsockopt(sock_, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(bufsize));

    // Enable keep-alive
    flag = 1;
    setsockopt(sock_, SOL_SOCKET, SO_KEEPALIVE, (char*)&flag, sizeof(flag));

    return true;
}

void Connection::closeSocket() {
    if (sock_ != INVALID_SOCK) {
#ifdef _WIN32
        closesocket(sock_);
#else
        ::close(sock_);
#endif
        sock_ = INVALID_SOCK;
    }
}

void Connection::disconnect(const std::string& reason) {
    ConnectionState expected = state_.load();
    if (expected == ConnectionState::DISCONNECTED ||
        expected == ConnectionState::DISCONNECTING) {
        return;
    }

    state_ = ConnectionState::DISCONNECTING;

    LOG_DEBUG("Disconnecting from {}: {}", addr_.toString(),
              reason.empty() ? "no reason" : reason);

    closeSocket();
    state_ = ConnectionState::DISCONNECTED;

    if (on_disconnect_) {
        on_disconnect_(reason);
    }
}

bool Connection::send(const Message& msg) {
    if (state_ == ConnectionState::DISCONNECTED ||
        state_ == ConnectionState::DISCONNECTING) {
        return false;
    }

    std::vector<uint8_t> data = msg.serialize(NETWORK_MAGIC);

    {
        std::lock_guard<std::mutex> lock(send_mutex_);
        send_queue_.push_back(std::move(data));
    }

    stats_.messages_sent++;
    return true;
}

bool Connection::processRead() {
    if (sock_ == INVALID_SOCK) return false;

    uint8_t buffer[RECV_CHUNK_SIZE];

    while (true) {
        int bytes = recv(sock_, (char*)buffer, sizeof(buffer), 0);

        if (bytes > 0) {
            // Check buffer size limit
            if (recv_buffer_.size() + bytes > MAX_RECV_BUFFER) {
                addBanScore(10, "buffer overflow");
                return false;
            }

            recv_buffer_.insert(recv_buffer_.end(), buffer, buffer + bytes);
            stats_.bytes_received += bytes;
            stats_.last_recv = std::chrono::steady_clock::now();

            // Parse complete messages
            if (!parseMessages()) {
                return false;
            }
        } else if (bytes == 0) {
            // Connection closed
            LOG_DEBUG("Connection closed by peer: {}", addr_.toString());
            return false;
        } else {
            int err = SOCKET_ERROR_CODE;
            if (err == WOULD_BLOCK) {
                // No more data available
                break;
            }
            LOG_DEBUG("Receive error from {}: {}", addr_.toString(), err);
            return false;
        }
    }

    return true;
}

bool Connection::parseMessages() {
    while (recv_buffer_.size() >= MessageHeader::HEADER_SIZE) {
        // Parse header
        MessageHeader header;
        if (!header.deserialize(recv_buffer_.data(), MessageHeader::HEADER_SIZE)) {
            addBanScore(20, "invalid header");
            return false;
        }

        // Validate magic
        if (header.magic != NETWORK_MAGIC) {
            addBanScore(100, "wrong network");
            return false;
        }

        // Check message size
        if (header.payload_size > MAX_MESSAGE_SIZE) {
            addBanScore(50, "oversized message");
            return false;
        }

        // Check if we have the full message
        size_t total_size = MessageHeader::HEADER_SIZE + header.payload_size;
        if (recv_buffer_.size() < total_size) {
            // Need more data
            break;
        }

        // Verify checksum
        const uint8_t* payload = recv_buffer_.data() + MessageHeader::HEADER_SIZE;
        auto computed = calculateChecksum(payload, header.payload_size);
        if (std::memcmp(computed.data(), header.checksum, 4) != 0) {
            addBanScore(10, "bad checksum");
            recv_buffer_.erase(recv_buffer_.begin(), recv_buffer_.begin() + total_size);
            continue;
        }

        // Deserialize message
        Message msg;
        msg.type = static_cast<MessageType>(header.type);

        if (header.payload_size > 0) {
            if (!msg.deserializePayload(payload, header.payload_size)) {
                addBanScore(10, "bad payload");
                recv_buffer_.erase(recv_buffer_.begin(), recv_buffer_.begin() + total_size);
                continue;
            }
        }

        // Remove processed data from buffer
        recv_buffer_.erase(recv_buffer_.begin(), recv_buffer_.begin() + total_size);
        stats_.messages_received++;

        // Dispatch message
        if (on_message_) {
            on_message_(msg);
        }
    }

    return true;
}

bool Connection::processWrite() {
    if (sock_ == INVALID_SOCK) return false;

    // Check if connecting
    if (state_ == ConnectionState::CONNECTING) {
        // Check if connection completed
        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(sock_, SOL_SOCKET, SO_ERROR, (char*)&error, &len) != 0) {
            return false;
        }
        if (error != 0) {
            LOG_DEBUG("Connection to {} failed: {}", addr_.toString(), error);
            if (on_connect_) on_connect_(false);
            return false;
        }
        state_ = ConnectionState::CONNECTED;
        LOG_DEBUG("Connected to {}", addr_.toString());
        if (on_connect_) on_connect_(true);
    }

    std::lock_guard<std::mutex> lock(send_mutex_);

    while (!send_queue_.empty()) {
        auto& data = send_queue_.front();
        size_t remaining = data.size() - send_offset_;

        int bytes = ::send(sock_, (char*)data.data() + send_offset_, (int)remaining, 0);

        if (bytes > 0) {
            stats_.bytes_sent += bytes;
            stats_.last_send = std::chrono::steady_clock::now();
            send_offset_ += bytes;

            if (send_offset_ >= data.size()) {
                send_queue_.pop_front();
                send_offset_ = 0;
            }
        } else if (bytes == 0) {
            return false;
        } else {
            int err = SOCKET_ERROR_CODE;
            if (err == WOULD_BLOCK) {
                // Socket buffer full, try again later
                break;
            }
            LOG_DEBUG("Send error to {}: {}", addr_.toString(), err);
            return false;
        }
    }

    return true;
}

bool Connection::checkTimeout(std::chrono::seconds timeout) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - stats_.last_recv
    );

    if (elapsed > timeout) {
        LOG_DEBUG("Connection timeout: {}", addr_.toString());
        return false;
    }

    return true;
}

void Connection::setPeerVersion(const VersionMessage& ver) {
    peer_version_ = ver.version;
    peer_services_ = ver.services;
    peer_user_agent_ = ver.user_agent;
    peer_start_height_ = ver.start_height;
    peer_relay_ = ver.relay;
}

void Connection::addBanScore(int score, const std::string& reason) {
    ban_score_ += score;
    LOG_DEBUG("Ban score +{} for {}: {} (total: {})",
              score, addr_.toString(), reason, ban_score_.load());
}

bool Connection::hasPendingData() const {
    std::lock_guard<std::mutex> lock(send_mutex_);
    return !send_queue_.empty();
}

void Connection::setPingNonce(uint64_t nonce) {
    ping_nonce_ = nonce;
    ping_start_ = std::chrono::steady_clock::now();
}

bool Connection::checkPingNonce(uint64_t nonce) {
    return nonce == ping_nonce_;
}

void Connection::recordPingTime(int64_t usec) {
    stats_.ping_time_usec = usec;
    if (stats_.min_ping_usec < 0 || usec < stats_.min_ping_usec) {
        stats_.min_ping_usec = usec;
    }
}

std::string Connection::toString() const {
    std::ostringstream ss;
    ss << "Connection[" << id_ << " " << addr_.toString();
    ss << " " << (direction_ == ConnectionDir::INBOUND ? "in" : "out");
    ss << " v" << peer_version_;
    if (!peer_user_agent_.empty()) {
        ss << " \"" << peer_user_agent_ << "\"";
    }
    ss << "]";
    return ss.str();
}

// ============================================================================
// SocketSet implementation
// ============================================================================

void SocketSet::add(std::shared_ptr<Connection> conn) {
    std::lock_guard<std::mutex> lock(mutex_);
    connections_[conn->getId()] = conn;
}

void SocketSet::remove(Connection::Id id) {
    std::lock_guard<std::mutex> lock(mutex_);
    connections_.erase(id);
}

void SocketSet::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    connections_.clear();
}

size_t SocketSet::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return connections_.size();
}

std::shared_ptr<Connection> SocketSet::get(Connection::Id id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(id);
    return it != connections_.end() ? it->second : nullptr;
}

std::vector<std::shared_ptr<Connection>> SocketSet::getAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<Connection>> result;
    result.reserve(connections_.size());
    for (auto& p : connections_) {
        result.push_back(p.second);
    }
    return result;
}

SocketSet::ReadySet SocketSet::wait(std::chrono::milliseconds timeout) {
    ReadySet result;

    std::vector<std::shared_ptr<Connection>> conns;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        conns.reserve(connections_.size());
        for (auto& p : connections_) {
            conns.push_back(p.second);
        }
    }

    if (conns.empty()) {
        std::this_thread::sleep_for(timeout);
        return result;
    }

    fd_set read_set, write_set, error_set;
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    FD_ZERO(&error_set);

    socket_t max_fd = 0;

    for (auto& conn : conns) {
        socket_t s = conn->getSocket();
        if (s == INVALID_SOCK) continue;

        FD_SET(s, &read_set);
        FD_SET(s, &error_set);

        // Add to write set if connecting or has data to send
        if (conn->getState() == ConnectionState::CONNECTING || conn->hasPendingData()) {
            FD_SET(s, &write_set);
        }

        if (s > max_fd) max_fd = s;
    }

    struct timeval tv;
    tv.tv_sec = static_cast<long>(timeout.count() / 1000);
    tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);

    int ready = select(static_cast<int>(max_fd + 1), &read_set, &write_set, &error_set, &tv);

    if (ready <= 0) {
        return result;
    }

    for (auto& conn : conns) {
        socket_t s = conn->getSocket();
        if (s == INVALID_SOCK) continue;

        if (FD_ISSET(s, &error_set)) {
            result.errors.push_back(conn);
        } else {
            if (FD_ISSET(s, &read_set)) {
                result.readable.push_back(conn);
            }
            if (FD_ISSET(s, &write_set)) {
                result.writable.push_back(conn);
            }
        }
    }

    return result;
}

// ============================================================================
// Listener implementation
// ============================================================================

Listener::Listener() {}

Listener::~Listener() {
    close();
}

bool Listener::bind(uint16_t port, bool /* ipv6 parameter ignored - always IPv6 */) {
    ipv6_ = true;  // Always IPv6
    port_ = port;

    // IPv6-only socket
    sock_ = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

    if (sock_ == INVALID_SOCK) {
        LOG_ERROR("Failed to create listener socket: {}", SOCKET_ERROR_CODE);
        return false;
    }

    // Allow address reuse
    int flag = 1;
    setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, (char*)&flag, sizeof(flag));

    // Disable IPV6_V6ONLY to accept IPv4-mapped addresses (dual-stack)
    int v6only = 0;
    setsockopt(sock_, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&v6only, sizeof(v6only));

    // Bind to IPv6 any address
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    sa.sin6_addr = in6addr_any;

    int result = ::bind(sock_, (struct sockaddr*)&sa, sizeof(sa));

    if (result != 0) {
        LOG_ERROR("Failed to bind to port {}: {}", port, SOCKET_ERROR_CODE);
        close();
        return false;
    }

    return true;
}

bool Listener::listen(int backlog) {
    if (sock_ == INVALID_SOCK) return false;

    if (::listen(sock_, backlog) != 0) {
        LOG_ERROR("Failed to listen: {}", SOCKET_ERROR_CODE);
        return false;
    }

    // Set non-blocking
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock_, FIONBIO, &mode);
#else
    int flags = fcntl(sock_, F_GETFL, 0);
    fcntl(sock_, F_SETFL, flags | O_NONBLOCK);
#endif

    listening_ = true;
    LOG_INFO("Listening on port {}", port_);
    return true;
}

std::shared_ptr<Connection> Listener::accept() {
    if (!listening_) return nullptr;

    struct sockaddr_in6 client_addr;
    socklen_t addr_len = sizeof(client_addr);

    socket_t client_sock = ::accept(sock_, (struct sockaddr*)&client_addr, &addr_len);

    if (client_sock == INVALID_SOCK) {
        int err = SOCKET_ERROR_CODE;
        if (err != WOULD_BLOCK) {
            LOG_DEBUG("Accept error: {}", err);
        }
        return nullptr;
    }

    // Extract IPv6 address (handles IPv4-mapped addresses via dual-stack)
    NetAddr addr = NetAddr::fromIPv6((uint8_t*)&client_addr.sin6_addr, ntohs(client_addr.sin6_port));

    return Connection::fromSocket(client_sock, addr);
}

void Listener::close() {
    if (sock_ != INVALID_SOCK) {
#ifdef _WIN32
        closesocket(sock_);
#else
        ::close(sock_);
#endif
        sock_ = INVALID_SOCK;
    }
    listening_ = false;
}

} // namespace p2p
} // namespace ftc
