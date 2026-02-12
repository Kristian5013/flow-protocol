// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/transport/socket.h"
#include "core/logging.h"

#include <chrono>
#include <cstring>
#include <string>

// ---------------------------------------------------------------------------
// Platform headers -- Winsock2 on Windows, POSIX sockets elsewhere.
// ---------------------------------------------------------------------------
#ifdef _WIN32
#   ifndef WIN32_LEAN_AND_MEAN
#       define WIN32_LEAN_AND_MEAN
#   endif
#   include <winsock2.h>
#   include <ws2tcpip.h>
#   include <mstcpip.h>   // For SIO_KEEPALIVE_VALS on older SDKs
#   pragma comment(lib, "ws2_32.lib")
#else
#   include <arpa/inet.h>
#   include <cerrno>
#   include <fcntl.h>
#   include <netdb.h>
#   include <netinet/in.h>
#   include <netinet/tcp.h>
#   include <signal.h>
#   include <sys/socket.h>
#   include <sys/types.h>
#   include <unistd.h>
#   define INVALID_SOCKET  static_cast<uintptr_t>(~0)
#   define SOCKET_ERROR    (-1)
#   define closesocket(s)  ::close(static_cast<int>(s))
#   define WSAGetLastError() errno
    using SOCKET = int;
#endif

namespace {

// ---------------------------------------------------------------------------
// Winsock global init / cleanup (reference counted via static local)
// ---------------------------------------------------------------------------
#ifdef _WIN32

struct WinsockInit {
    WinsockInit() {
        WSADATA wsa_data{};
        int rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
        if (rc != 0) {
            // Cannot use LOG_ERROR before the logger might be initialized,
            // but in practice the logger singleton is constructed first.
            LOG_ERROR(core::LogCategory::NET,
                      "WSAStartup failed with error code " +
                      std::to_string(rc));
        } else {
            LOG_DEBUG(core::LogCategory::NET,
                      "Winsock 2.2 initialized (version " +
                      std::to_string(LOBYTE(wsa_data.wVersion)) + "." +
                      std::to_string(HIBYTE(wsa_data.wVersion)) + ")");
        }
    }

    ~WinsockInit() {
        WSACleanup();
    }
};

/// Ensure WSAStartup is called exactly once before any socket operation.
/// The static local guarantees thread-safe initialization (C++11 magic
/// statics) and cleanup at program exit.
static WinsockInit& winsock_init() {
    static WinsockInit instance;
    return instance;
}

#else // !_WIN32

/// On POSIX, ignore SIGPIPE globally so that send() on a broken pipe
/// returns EPIPE instead of killing the process.
struct SigpipeGuard {
    SigpipeGuard() {
        ::signal(SIGPIPE, SIG_IGN);
    }
};

static SigpipeGuard& sigpipe_guard() {
    static SigpipeGuard instance;
    return instance;
}

#endif // _WIN32

// ---------------------------------------------------------------------------
// Helper: get last socket error as a human-readable string
// ---------------------------------------------------------------------------
std::string last_error_string() {
#ifdef _WIN32
    int err = WSAGetLastError();
    char buf[256]{};
    FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, static_cast<DWORD>(err),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buf, sizeof(buf), nullptr);

    // Trim trailing \r\n that Windows adds to FormatMessage output.
    size_t len = std::strlen(buf);
    while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n')) {
        buf[--len] = '\0';
    }
    return std::string(buf) + " (WSA " + std::to_string(err) + ")";
#else
    int err = errno;
    return std::string(std::strerror(err)) + " (errno " +
           std::to_string(err) + ")";
#endif
}

// ---------------------------------------------------------------------------
// Helper: get last socket error code (numeric)
// ---------------------------------------------------------------------------
int last_error_code() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

// ---------------------------------------------------------------------------
// Helper: check if a socket error code indicates "would block"
// ---------------------------------------------------------------------------
bool is_would_block(int err) {
#ifdef _WIN32
    return err == WSAEWOULDBLOCK;
#else
    return err == EAGAIN || err == EWOULDBLOCK;
#endif
}

// ---------------------------------------------------------------------------
// Helper: check if a socket error code indicates "connection reset"
// ---------------------------------------------------------------------------
bool is_connection_reset(int err) {
#ifdef _WIN32
    return err == WSAECONNRESET || err == WSAECONNABORTED ||
           err == WSAENETRESET;
#else
    return err == ECONNRESET || err == EPIPE || err == ENOTCONN;
#endif
}

// ---------------------------------------------------------------------------
// Helper: check if a socket error code indicates "in progress"
// ---------------------------------------------------------------------------
bool is_connect_in_progress(int err) {
#ifdef _WIN32
    return err == WSAEWOULDBLOCK;
#else
    return err == EINPROGRESS || err == EALREADY;
#endif
}

// ---------------------------------------------------------------------------
// Helper: portable non-blocking mode
// ---------------------------------------------------------------------------
void set_nonblocking_impl(uintptr_t fd, bool enable) {
#ifdef _WIN32
    u_long mode = enable ? 1 : 0;
    int rc = ::ioctlsocket(static_cast<SOCKET>(fd), FIONBIO, &mode);
    if (rc == SOCKET_ERROR) {
        LOG_WARN(core::LogCategory::NET,
                 "ioctlsocket(FIONBIO) failed: " + last_error_string());
    }
#else
    int flags = ::fcntl(static_cast<int>(fd), F_GETFL, 0);
    if (flags == -1) {
        return;
    }
    if (enable) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    ::fcntl(static_cast<int>(fd), F_SETFL, flags);
#endif
}

// ---------------------------------------------------------------------------
// Helper: wait for socket to become writable (used for connect timeout)
// ---------------------------------------------------------------------------
bool wait_writable(uintptr_t fd, int timeout_ms) {
    if (timeout_ms < 0) {
        timeout_ms = 0;
    }

    fd_set write_set;
    fd_set error_set;
    FD_ZERO(&write_set);
    FD_ZERO(&error_set);
    FD_SET(static_cast<SOCKET>(fd), &write_set);
    FD_SET(static_cast<SOCKET>(fd), &error_set);

    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

#ifdef _WIN32
    // On Windows the first parameter (nfds) is ignored.
    int rc = ::select(0, nullptr, &write_set, &error_set, &tv);
#else
    int nfds = static_cast<int>(fd) + 1;
    int rc = ::select(nfds, nullptr, &write_set, &error_set, &tv);
#endif

    if (rc <= 0) {
        return false; // timeout (rc==0) or error (rc<0)
    }

    // If the socket is in the error set, the connect failed.
    if (FD_ISSET(static_cast<SOCKET>(fd), &error_set)) {
        return false;
    }

    return FD_ISSET(static_cast<SOCKET>(fd), &write_set) != 0;
}

// ---------------------------------------------------------------------------
// Helper: wait for socket to become readable (used for recv timeout)
// ---------------------------------------------------------------------------
bool wait_readable(uintptr_t fd, int timeout_ms) {
    if (timeout_ms <= 0) {
        return false;
    }

    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(static_cast<SOCKET>(fd), &read_set);

    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

#ifdef _WIN32
    int rc = ::select(0, &read_set, nullptr, nullptr, &tv);
#else
    int nfds = static_cast<int>(fd) + 1;
    int rc = ::select(nfds, &read_set, nullptr, nullptr, &tv);
#endif

    return rc > 0 && FD_ISSET(static_cast<SOCKET>(fd), &read_set);
}

// ---------------------------------------------------------------------------
// Helper: set a generic integer socket option
// ---------------------------------------------------------------------------
void set_int_sockopt(uintptr_t fd, int level, int optname, int value) {
    ::setsockopt(static_cast<SOCKET>(fd), level, optname,
                 reinterpret_cast<const char*>(&value),
                 static_cast<int>(sizeof(value)));
}

// ---------------------------------------------------------------------------
// Helper: set a timeval socket option (SO_SNDTIMEO / SO_RCVTIMEO)
// ---------------------------------------------------------------------------
void set_timeval_sockopt(uintptr_t fd, int optname, int timeout_ms) {
#ifdef _WIN32
    // On Windows, SO_SNDTIMEO / SO_RCVTIMEO take a DWORD in milliseconds.
    DWORD ms = static_cast<DWORD>(timeout_ms > 0 ? timeout_ms : 0);
    ::setsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, optname,
                 reinterpret_cast<const char*>(&ms),
                 static_cast<int>(sizeof(ms)));
#else
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ::setsockopt(static_cast<int>(fd), SOL_SOCKET, optname,
                 &tv, sizeof(tv));
#endif
}

// ---------------------------------------------------------------------------
// Helper: extract an address string and port from a sockaddr_storage
// ---------------------------------------------------------------------------
void parse_sockaddr(const struct sockaddr_storage& addr,
                    std::string& out_ip, uint16_t& out_port) {
    char ip_buf[INET6_ADDRSTRLEN]{};
    out_ip.clear();
    out_port = 0;

    if (addr.ss_family == AF_INET) {
        const auto* sin = reinterpret_cast<const struct sockaddr_in*>(&addr);
        if (::inet_ntop(AF_INET, &sin->sin_addr, ip_buf, sizeof(ip_buf))) {
            out_ip = ip_buf;
        }
        out_port = ntohs(sin->sin_port);
    } else if (addr.ss_family == AF_INET6) {
        const auto* sin6 = reinterpret_cast<const struct sockaddr_in6*>(&addr);
        if (::inet_ntop(AF_INET6, &sin6->sin6_addr, ip_buf, sizeof(ip_buf))) {
            out_ip = ip_buf;
        }
        out_port = ntohs(sin6->sin6_port);
    }
}

// ---------------------------------------------------------------------------
// Helper: query peer or local address from a socket
// ---------------------------------------------------------------------------
bool get_sock_name(uintptr_t fd, bool peer,
                   std::string& out_ip, uint16_t& out_port) {
    struct sockaddr_storage addr{};
    socklen_t addr_len = static_cast<socklen_t>(sizeof(addr));
    int rc;

    if (peer) {
        rc = ::getpeername(static_cast<SOCKET>(fd),
                           reinterpret_cast<struct sockaddr*>(&addr),
                           &addr_len);
    } else {
        rc = ::getsockname(static_cast<SOCKET>(fd),
                           reinterpret_cast<struct sockaddr*>(&addr),
                           &addr_len);
    }

    if (rc == SOCKET_ERROR) {
        out_ip.clear();
        out_port = 0;
        return false;
    }

    parse_sockaddr(addr, out_ip, out_port);
    return true;
}

/// Maximum bytes to request in a single recv() system call.
constexpr int MAX_RECV_CHUNK = 65536;

/// Maximum bytes to send in a single send() system call.
/// Winsock can handle large sends but we cap to avoid int overflow.
constexpr int MAX_SEND_CHUNK = 1024 * 1024;

} // anonymous namespace

namespace net {

// ===================================================================
// Construction / Destruction
// ===================================================================

Socket::Socket() {
#ifdef _WIN32
    (void)winsock_init();
#else
    (void)sigpipe_guard();
#endif
}

Socket::Socket(uintptr_t raw_fd) : fd_(raw_fd) {
#ifdef _WIN32
    (void)winsock_init();
#else
    (void)sigpipe_guard();
#endif
}

Socket::~Socket() {
    close();
}

Socket::Socket(Socket&& other) noexcept : fd_(other.fd_) {
    other.fd_ = ~uintptr_t(0);
}

Socket& Socket::operator=(Socket&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        other.fd_ = ~uintptr_t(0);
    }
    return *this;
}

// ===================================================================
// connect
// ===================================================================

core::Result<void> Socket::connect(const std::string& host, uint16_t port,
                                   int timeout_ms) {
    if (host.empty()) {
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "connect: empty host name");
    }
    if (port == 0) {
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "connect: port must be non-zero");
    }

    // Resolve the host address using getaddrinfo (supports both
    // DNS names and numeric IP addresses).
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;     // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;   // TCP
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(port);
    struct addrinfo* result = nullptr;
    int rc = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (rc != 0 || result == nullptr) {
        std::string detail;
#ifdef _WIN32
        detail = last_error_string();
#else
        detail = gai_strerror(rc);
#endif
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "getaddrinfo failed for " + host + ":" +
                           port_str + " - " + detail);
    }

    // Try each resolved address in order until one succeeds.
    core::Error last_err(core::ErrorCode::NETWORK_ERROR,
                         "no addresses could be resolved for " + host);
    int attempt = 0;

    for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
        ++attempt;

        // Close any socket left from a previous failed attempt.
        close();

        // Create a new TCP socket matching this address family.
        SOCKET sock = ::socket(rp->ai_family, rp->ai_socktype,
                               rp->ai_protocol);
        if (sock == static_cast<SOCKET>(INVALID_SOCKET)) {
            last_err = core::Error(core::ErrorCode::NETWORK_ERROR,
                                   "socket() failed (attempt " +
                                   std::to_string(attempt) + "): " +
                                   last_error_string());
            continue;
        }
        fd_ = static_cast<uintptr_t>(sock);

        // Put the socket into non-blocking mode so that connect()
        // returns immediately, allowing us to enforce a timeout via
        // select().
        set_nonblocking_impl(fd_, true);

        rc = ::connect(sock, rp->ai_addr,
                       static_cast<int>(rp->ai_addrlen));

        if (rc == 0) {
            // Immediate success (rare for non-blocking but possible for
            // loopback connections on some platforms).
            set_nonblocking_impl(fd_, false);
            ::freeaddrinfo(result);

            LOG_DEBUG(core::LogCategory::NET,
                     "connected to " + host + ":" + port_str +
                     " (immediate)");
            return core::make_ok();
        }

        // Expect "in progress" for a non-blocking connect.
        int err = last_error_code();
        if (!is_connect_in_progress(err)) {
            last_err = core::Error(core::ErrorCode::NETWORK_ERROR,
                                   "connect() failed (attempt " +
                                   std::to_string(attempt) + "): " +
                                   last_error_string());
            continue;
        }

        // Wait for the connection to complete or timeout.
        if (!wait_writable(fd_, timeout_ms)) {
            last_err = core::Error(core::ErrorCode::NETWORK_TIMEOUT,
                                   "connect to " + host + ":" + port_str +
                                   " timed out after " +
                                   std::to_string(timeout_ms) + " ms " +
                                   "(attempt " + std::to_string(attempt) +
                                   ")");
            continue;
        }

        // The socket became writable -- check SO_ERROR to see if the
        // connection actually succeeded or was refused.
        int sock_err = 0;
        socklen_t opt_len = static_cast<socklen_t>(sizeof(sock_err));
        ::getsockopt(sock, SOL_SOCKET, SO_ERROR,
                     reinterpret_cast<char*>(&sock_err), &opt_len);
        if (sock_err != 0) {
            last_err = core::Error(core::ErrorCode::NETWORK_REFUSED,
                                   "connect to " + host + ":" + port_str +
                                   " refused (SO_ERROR=" +
                                   std::to_string(sock_err) + ", attempt " +
                                   std::to_string(attempt) + ")");
            continue;
        }

        // Connected -- restore blocking mode for normal I/O.
        set_nonblocking_impl(fd_, false);
        ::freeaddrinfo(result);

        LOG_DEBUG(core::LogCategory::NET,
                 "connected to " + host + ":" + port_str +
                 " (attempt " + std::to_string(attempt) + ")");
        return core::make_ok();
    }

    // All attempts exhausted.
    ::freeaddrinfo(result);
    close();
    return last_err;
}

// ===================================================================
// bind_listen
// ===================================================================

core::Result<void> Socket::bind_listen(const std::string& host,
                                       uint16_t port,
                                       int backlog) {
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags    = AI_PASSIVE;  // Suitable for bind

    std::string port_str = std::to_string(port);
    const char* node = host.empty() ? nullptr : host.c_str();

    struct addrinfo* result = nullptr;
    int rc = ::getaddrinfo(node, port_str.c_str(), &hints, &result);
    if (rc != 0 || result == nullptr) {
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "getaddrinfo failed for bind on " +
                           (host.empty() ? std::string("*") : host) +
                           ":" + port_str + " - " + last_error_string());
    }

    core::Error last_err(core::ErrorCode::NETWORK_ERROR,
                         "failed to bind on any address");

    for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
        close();

        SOCKET sock = ::socket(rp->ai_family, rp->ai_socktype,
                               rp->ai_protocol);
        if (sock == static_cast<SOCKET>(INVALID_SOCKET)) {
            last_err = core::Error(core::ErrorCode::NETWORK_ERROR,
                                   "socket() for listen failed: " +
                                   last_error_string());
            continue;
        }
        fd_ = static_cast<uintptr_t>(sock);

        // SO_REUSEADDR -- allow the address to be reused immediately
        // after a previous listener on the same port exits.  Critical
        // for quick restarts during development and node operation.
        set_int_sockopt(fd_, SOL_SOCKET, SO_REUSEADDR, 1);

        // For IPv6 sockets, disable IPV6_V6ONLY so we can accept both
        // IPv4-mapped and native IPv6 connections on a single socket.
        if (rp->ai_family == AF_INET6) {
            set_int_sockopt(fd_, IPPROTO_IPV6, IPV6_V6ONLY, 0);
        }

        rc = ::bind(sock, rp->ai_addr,
                    static_cast<int>(rp->ai_addrlen));
        if (rc == SOCKET_ERROR) {
            last_err = core::Error(core::ErrorCode::NETWORK_ERROR,
                                   "bind() failed on " +
                                   (host.empty() ? std::string("*") : host) +
                                   ":" + port_str + " - " +
                                   last_error_string());
            continue;
        }

        rc = ::listen(sock, backlog);
        if (rc == SOCKET_ERROR) {
            last_err = core::Error(core::ErrorCode::NETWORK_ERROR,
                                   "listen() failed: " +
                                   last_error_string());
            continue;
        }

        ::freeaddrinfo(result);

        LOG_DEBUG(core::LogCategory::NET,
                 "listening on " +
                 (host.empty() ? std::string("0.0.0.0") : host) +
                 ":" + port_str + " (backlog=" +
                 std::to_string(backlog) + ")");
        return core::make_ok();
    }

    ::freeaddrinfo(result);
    close();
    return last_err;
}

// ===================================================================
// accept
// ===================================================================

core::Result<Socket> Socket::accept() {
    if (!is_open()) {
        return core::Error(core::ErrorCode::NETWORK_CLOSED,
                           "accept() called on closed listener socket");
    }

    struct sockaddr_storage peer_addr{};
    socklen_t addr_len = static_cast<socklen_t>(sizeof(peer_addr));

    SOCKET client = ::accept(static_cast<SOCKET>(fd_),
                             reinterpret_cast<struct sockaddr*>(&peer_addr),
                             &addr_len);
    if (client == static_cast<SOCKET>(INVALID_SOCKET)) {
        int err = last_error_code();
        // On Windows, WSAEWOULDBLOCK means no pending connections
        // (if the listener is non-blocking).
        if (is_would_block(err)) {
            return core::Error(core::ErrorCode::NETWORK_ERROR,
                               "accept() would block (no pending connections)");
        }
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "accept() failed: " + last_error_string());
    }

    Socket accepted(static_cast<uintptr_t>(client));

    std::string peer_ip;
    uint16_t peer_port = 0;
    parse_sockaddr(peer_addr, peer_ip, peer_port);

    LOG_DEBUG(core::LogCategory::NET,
              "accepted connection from " + peer_ip + ":" +
              std::to_string(peer_port));

    return accepted;
}

// ===================================================================
// send (single call)
// ===================================================================

core::Result<size_t> Socket::send(std::span<const uint8_t> data) {
    if (!is_open()) {
        return core::Error(core::ErrorCode::NETWORK_CLOSED,
                           "send() called on closed socket");
    }
    if (data.empty()) {
        return size_t{0};
    }

    // Cap the send size to avoid int overflow on Windows where
    // send() takes an int length parameter.
    int to_send = static_cast<int>(
        std::min(data.size(), static_cast<size_t>(MAX_SEND_CHUNK)));

    int rc = ::send(static_cast<SOCKET>(fd_),
                    reinterpret_cast<const char*>(data.data()),
                    to_send, 0);
    if (rc == SOCKET_ERROR) {
        int err = last_error_code();
        if (is_connection_reset(err)) {
            return core::Error(core::ErrorCode::NETWORK_CLOSED,
                               "connection reset by peer on send");
        }
        if (is_would_block(err)) {
            // Non-blocking socket with full send buffer.
            return size_t{0};
        }
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "send() failed: " + last_error_string());
    }

    return static_cast<size_t>(rc);
}

// ===================================================================
// recv (single call)
// ===================================================================

core::Result<size_t> Socket::recv(std::span<uint8_t> buf) {
    if (!is_open()) {
        return core::Error(core::ErrorCode::NETWORK_CLOSED,
                           "recv() called on closed socket");
    }
    if (buf.empty()) {
        return size_t{0};
    }

    int to_recv = static_cast<int>(
        std::min(buf.size(), static_cast<size_t>(MAX_RECV_CHUNK)));

    int rc = ::recv(static_cast<SOCKET>(fd_),
                    reinterpret_cast<char*>(buf.data()),
                    to_recv, 0);
    if (rc == SOCKET_ERROR) {
        int err = last_error_code();
        if (is_connection_reset(err)) {
            return core::Error(core::ErrorCode::NETWORK_CLOSED,
                               "connection reset by peer on recv");
        }
        if (is_would_block(err)) {
            // Non-blocking socket, nothing available yet.
            return size_t{0};
        }
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "recv() failed: " + last_error_string());
    }

    // rc == 0 means the peer performed an orderly shutdown.
    return static_cast<size_t>(rc);
}

// ===================================================================
// send_all (loop until complete)
// ===================================================================

core::Result<void> Socket::send_all(std::span<const uint8_t> data) {
    size_t total_sent = 0;

    while (total_sent < data.size()) {
        auto result = send(data.subspan(total_sent));
        if (!result.ok()) {
            return result.error();
        }

        size_t n = result.value();
        if (n == 0) {
            // Zero bytes sent usually means the connection is gone
            // or the non-blocking buffer is full.  For a blocking
            // socket this should not happen, so treat it as an error.
            return core::Error(core::ErrorCode::NETWORK_CLOSED,
                               "send_all: connection closed after " +
                               std::to_string(total_sent) + " of " +
                               std::to_string(data.size()) + " bytes");
        }

        total_sent += n;
    }

    return core::make_ok();
}

// ===================================================================
// recv_all (loop with timeout)
// ===================================================================

core::Result<size_t> Socket::recv_all(std::span<uint8_t> buf,
                                      int timeout_ms) {
    if (!is_open()) {
        return core::Error(core::ErrorCode::NETWORK_CLOSED,
                           "recv_all() called on closed socket");
    }
    if (buf.empty()) {
        return size_t{0};
    }

    size_t total_recv = 0;
    int remaining_ms  = timeout_ms;

    while (total_recv < buf.size()) {
        // Wait for data with the remaining timeout budget.
        auto t0 = std::chrono::steady_clock::now();

        if (!wait_readable(fd_, remaining_ms)) {
            // Timeout elapsed.
            if (total_recv == 0) {
                return core::Error(core::ErrorCode::NETWORK_TIMEOUT,
                                   "recv_all: timed out after " +
                                   std::to_string(timeout_ms) +
                                   " ms with no data");
            }
            // Partial data received before timeout.
            LOG_DEBUG(core::LogCategory::NET,
                      "recv_all: timeout with " +
                      std::to_string(total_recv) + " of " +
                      std::to_string(buf.size()) + " bytes received");
            return total_recv;
        }

        // Socket is readable -- perform the actual read.
        auto result = recv(buf.subspan(total_recv));
        if (!result.ok()) {
            // If we already have some data, return it rather than
            // propagating the error.
            if (total_recv > 0) {
                LOG_DEBUG(core::LogCategory::NET,
                          "recv_all: error after " +
                          std::to_string(total_recv) +
                          " bytes, returning partial data");
                return total_recv;
            }
            return result.error();
        }

        size_t n = result.value();
        if (n == 0) {
            // Graceful peer shutdown.
            if (total_recv > 0) {
                return total_recv;
            }
            return core::Error(core::ErrorCode::NETWORK_CLOSED,
                               "recv_all: peer closed connection");
        }

        total_recv += n;

        // Subtract the wall-clock time consumed by this iteration
        // from the remaining timeout budget.
        auto t1 = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<
            std::chrono::milliseconds>(t1 - t0).count();
        remaining_ms -= static_cast<int>(elapsed_ms);
        if (remaining_ms <= 0) {
            if (total_recv < buf.size()) {
                LOG_DEBUG(core::LogCategory::NET,
                          "recv_all: timeout budget exhausted with " +
                          std::to_string(total_recv) + " of " +
                          std::to_string(buf.size()) + " bytes");
            }
            break;
        }
    }

    return total_recv;
}

// ===================================================================
// close / shutdown_send / is_open
// ===================================================================

void Socket::close() {
    if (is_open()) {
        LOG_TRACE(core::LogCategory::NET,
                  "closing socket fd=" + std::to_string(fd_));
        // Shutdown both directions first to unblock any recv()/send()
        // on other threads.  Without this, close() on Linux may not
        // wake a thread blocked in recv(), causing join() to hang.
#ifdef _WIN32
        ::shutdown(static_cast<SOCKET>(fd_), SD_BOTH);
#else
        ::shutdown(static_cast<int>(fd_), SHUT_RDWR);
#endif
        closesocket(static_cast<SOCKET>(fd_));
        fd_ = ~uintptr_t(0);
    }
}

void Socket::shutdown_send() {
    if (is_open()) {
#ifdef _WIN32
        ::shutdown(static_cast<SOCKET>(fd_), SD_SEND);
#else
        ::shutdown(static_cast<int>(fd_), SHUT_WR);
#endif
    }
}

bool Socket::is_open() const {
    return fd_ != ~uintptr_t(0);
}

// ===================================================================
// Peer information
// ===================================================================

std::string Socket::remote_address() const {
    if (!is_open()) return {};
    std::string ip;
    uint16_t port;
    get_sock_name(fd_, /*peer=*/true, ip, port);
    return ip;
}

uint16_t Socket::remote_port() const {
    if (!is_open()) return 0;
    std::string ip;
    uint16_t port = 0;
    get_sock_name(fd_, /*peer=*/true, ip, port);
    return port;
}

std::string Socket::local_address() const {
    if (!is_open()) return {};
    std::string ip;
    uint16_t port;
    get_sock_name(fd_, /*peer=*/false, ip, port);
    return ip;
}

uint16_t Socket::local_port() const {
    if (!is_open()) return 0;
    std::string ip;
    uint16_t port = 0;
    get_sock_name(fd_, /*peer=*/false, ip, port);
    return port;
}

// ===================================================================
// Socket options
// ===================================================================

void Socket::set_nonblocking(bool enable) {
    if (is_open()) {
        set_nonblocking_impl(fd_, enable);
    }
}

void Socket::set_nodelay(bool enable) {
    if (!is_open()) return;
    set_int_sockopt(fd_, IPPROTO_TCP, TCP_NODELAY, enable ? 1 : 0);
}

void Socket::set_keepalive(bool enable) {
    if (!is_open()) return;
    set_int_sockopt(fd_, SOL_SOCKET, SO_KEEPALIVE, enable ? 1 : 0);
}

void Socket::set_send_buffer_size(int size) {
    if (!is_open() || size <= 0) return;
    set_int_sockopt(fd_, SOL_SOCKET, SO_SNDBUF, size);
}

void Socket::set_recv_buffer_size(int size) {
    if (!is_open() || size <= 0) return;
    set_int_sockopt(fd_, SOL_SOCKET, SO_RCVBUF, size);
}

void Socket::set_linger(bool enable, int timeout_sec) {
    if (!is_open()) return;

    struct linger ling{};
    ling.l_onoff  = enable ? 1 : 0;
    ling.l_linger = static_cast<unsigned short>(
        timeout_sec > 0 ? timeout_sec : 0);

    ::setsockopt(static_cast<SOCKET>(fd_), SOL_SOCKET, SO_LINGER,
                 reinterpret_cast<const char*>(&ling),
                 static_cast<int>(sizeof(ling)));
}

void Socket::set_send_timeout(int timeout_ms) {
    if (!is_open()) return;
    set_timeval_sockopt(fd_, SO_SNDTIMEO, timeout_ms);
}

void Socket::set_recv_timeout(int timeout_ms) {
    if (!is_open()) return;
    set_timeval_sockopt(fd_, SO_RCVTIMEO, timeout_ms);
}

} // namespace net
