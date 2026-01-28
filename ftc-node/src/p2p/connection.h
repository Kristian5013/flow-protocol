#ifndef FTC_P2P_CONNECTION_H
#define FTC_P2P_CONNECTION_H

#include "p2p/protocol.h"
#include <string>
#include <cstdint>
#include <memory>
#include <vector>
#include <map>
#include <deque>
#include <mutex>
#include <atomic>
#include <functional>
#include <chrono>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET socket_t;
    #define INVALID_SOCK INVALID_SOCKET
    #define SOCKET_ERROR_CODE WSAGetLastError()
    #define WOULD_BLOCK WSAEWOULDBLOCK
    #define IN_PROGRESS WSAEWOULDBLOCK
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    typedef int socket_t;
    #define INVALID_SOCK -1
    #define SOCKET_ERROR_CODE errno
    #define WOULD_BLOCK EWOULDBLOCK
    #define IN_PROGRESS EINPROGRESS
#endif

namespace ftc {
namespace p2p {

// Forward declarations
class PeerManager;

// NetAddr is defined in protocol.h (included above)
// Provides: ip[16], port, services, timestamp, factory methods, serialization

// Connection state
enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    VERSION_SENT,
    VERSION_RECEIVED,
    ESTABLISHED,      // Handshake complete
    DISCONNECTING
};

// Connection direction
enum class ConnectionDir {
    INBOUND,
    OUTBOUND
};

// Connection statistics
struct ConnectionStats {
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t messages_sent = 0;
    uint64_t messages_received = 0;
    std::chrono::steady_clock::time_point connect_time;
    std::chrono::steady_clock::time_point last_send;
    std::chrono::steady_clock::time_point last_recv;
    int64_t ping_time_usec = -1;    // Last ping RTT in microseconds
    int64_t min_ping_usec = -1;     // Minimum observed ping
};

// Callback types
using MessageCallback = std::function<void(const Message&)>;
using DisconnectCallback = std::function<void(const std::string& reason)>;
using ConnectCallback = std::function<void(bool success)>;

/**
 * Connection - manages a single TCP connection to a peer
 *
 * Handles:
 * - Non-blocking socket I/O
 * - Message framing (header + payload)
 * - Send/receive buffering
 * - Timeout detection
 * - Graceful disconnection
 */
class Connection : public std::enable_shared_from_this<Connection> {
public:
    // Unique connection ID
    using Id = uint64_t;

    // Create outbound connection
    static std::shared_ptr<Connection> connect(
        const NetAddr& addr,
        ConnectCallback on_connect = nullptr
    );

    // Create from accepted socket (inbound)
    static std::shared_ptr<Connection> fromSocket(
        socket_t sock,
        const NetAddr& addr
    );

    ~Connection();

    // Non-copyable
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    // Getters
    Id getId() const { return id_; }
    ConnectionState getState() const { return state_; }
    ConnectionDir getDirection() const { return direction_; }
    const NetAddr& getAddress() const { return addr_; }
    const ConnectionStats& getStats() const { return stats_; }
    socket_t getSocket() const { return sock_; }

    // Peer info (set after VERSION exchange)
    void setPeerVersion(const VersionMessage& ver);
    int32_t getPeerVersion() const { return peer_version_; }
    uint64_t getPeerServices() const { return peer_services_; }
    const std::string& getPeerUserAgent() const { return peer_user_agent_; }
    int32_t getPeerStartHeight() const { return peer_start_height_; }
    bool getPeerRelay() const { return peer_relay_; }

    // Set callbacks
    void setMessageCallback(MessageCallback cb) { on_message_ = cb; }
    void setDisconnectCallback(DisconnectCallback cb) { on_disconnect_ = cb; }

    // Send a message
    bool send(const Message& msg);

    // Process socket I/O (call from event loop)
    // Returns false if connection should be closed
    bool processRead();
    bool processWrite();

    // Check timeouts
    bool checkTimeout(std::chrono::seconds timeout);

    // Disconnect
    void disconnect(const std::string& reason = "");

    // Ban score management
    void addBanScore(int score, const std::string& reason);
    int getBanScore() const { return ban_score_; }

    // Check if there's pending data to send
    bool hasPendingData() const;

    // Ping tracking
    void setPingNonce(uint64_t nonce);
    bool checkPingNonce(uint64_t nonce);
    void recordPingTime(int64_t usec);

    // String representation
    std::string toString() const;

private:
    Connection(socket_t sock, const NetAddr& addr, ConnectionDir dir);

    bool setNonBlocking();
    bool setSocketOptions();
    void closeSocket();
    bool parseMessages();

    // Connection identity
    Id id_;
    static std::atomic<Id> next_id_;

    // Socket
    socket_t sock_ = INVALID_SOCK;
    NetAddr addr_;
    ConnectionDir direction_;
    std::atomic<ConnectionState> state_{ConnectionState::DISCONNECTED};

    // Buffers
    std::vector<uint8_t> recv_buffer_;
    std::deque<std::vector<uint8_t>> send_queue_;
    size_t send_offset_ = 0;
    mutable std::mutex send_mutex_;

    // Peer info
    int32_t peer_version_ = 0;
    uint64_t peer_services_ = 0;
    std::string peer_user_agent_;
    int32_t peer_start_height_ = 0;
    bool peer_relay_ = true;

    // Statistics
    ConnectionStats stats_;

    // Ban score
    std::atomic<int> ban_score_{0};

    // Ping tracking
    uint64_t ping_nonce_ = 0;
    std::chrono::steady_clock::time_point ping_start_;

    // Callbacks
    MessageCallback on_message_;
    DisconnectCallback on_disconnect_;
    ConnectCallback on_connect_;

    // Buffer size constants
    static constexpr size_t MAX_RECV_BUFFER = 4 * 1024 * 1024;   // 4 MB
    static constexpr size_t MAX_MESSAGE_SIZE = 32 * 1024 * 1024;  // 32 MB
    static constexpr size_t RECV_CHUNK_SIZE = 64 * 1024;          // 64 KB
};

/**
 * SocketSet - manages a set of connections for select/poll
 */
class SocketSet {
public:
    SocketSet() = default;

    void add(std::shared_ptr<Connection> conn);
    void remove(Connection::Id id);
    void clear();

    // Wait for I/O events, returns connections that are ready
    struct ReadySet {
        std::vector<std::shared_ptr<Connection>> readable;
        std::vector<std::shared_ptr<Connection>> writable;
        std::vector<std::shared_ptr<Connection>> errors;
    };

    ReadySet wait(std::chrono::milliseconds timeout);

    size_t size() const;
    std::shared_ptr<Connection> get(Connection::Id id);
    std::vector<std::shared_ptr<Connection>> getAll();

private:
    std::map<Connection::Id, std::shared_ptr<Connection>> connections_;
    mutable std::mutex mutex_;
};

/**
 * Listener - TCP server socket for accepting inbound connections
 */
class Listener {
public:
    Listener();
    ~Listener();

    // Bind and listen
    bool bind(uint16_t port, bool ipv6 = false);
    bool listen(int backlog = 128);

    // Accept incoming connection (non-blocking)
    std::shared_ptr<Connection> accept();

    // Close listener
    void close();

    socket_t getSocket() const { return sock_; }
    uint16_t getPort() const { return port_; }
    bool isListening() const { return listening_; }
    bool isIPv6() const { return ipv6_; }
    bool isIPv4() const { return !ipv6_; }

private:
    socket_t sock_ = INVALID_SOCK;
    uint16_t port_ = 0;
    bool ipv6_ = false;
    bool listening_ = false;
};

// Initialize networking (call once at startup)
bool initNetworking();
void shutdownNetworking();

} // namespace p2p
} // namespace ftc

#endif // FTC_P2P_CONNECTION_H
