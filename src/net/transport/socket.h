#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Socket -- cross-platform TCP socket wrapper (Windows Winsock2 backend).
//
// Provides RAII ownership of a single TCP socket file descriptor with
// move-only semantics.  All blocking I/O methods return core::Result
// so callers can propagate errors without exceptions.
// ---------------------------------------------------------------------------

#include "core/error.h"

#include <chrono>
#include <cstdint>
#include <span>
#include <string>

namespace net {

// Forward-declared SOCKET handle (avoids pulling <winsock2.h> into headers).
// On Windows SOCKET is defined as UINT_PTR which is uintptr_t.
// INVALID_SOCKET is ~(uintptr_t)0.

class Socket {
public:
    /// Default-constructs an invalid (closed) socket.
    Socket();
    ~Socket();

    // Move-only.
    Socket(Socket&& other) noexcept;
    Socket& operator=(Socket&& other) noexcept;
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    // -- Connection setup ---------------------------------------------------

    /// Connect to a remote host:port with a timeout in milliseconds.
    /// Uses non-blocking connect + select for the timeout.
    core::Result<void> connect(const std::string& host, uint16_t port,
                               int timeout_ms = 5000);

    /// Bind to the given local address and port, then listen with the
    /// specified backlog.
    core::Result<void> bind_listen(const std::string& host, uint16_t port,
                                   int backlog = 128);

    /// Accept an incoming connection. Blocks until a client connects.
    core::Result<Socket> accept();

    // -- Raw I/O ------------------------------------------------------------

    /// Send up to data.size() bytes. Returns the number actually sent.
    core::Result<size_t> send(std::span<const uint8_t> data);

    /// Receive up to buf.size() bytes. Returns the number actually read.
    /// Returns 0 on graceful close.
    core::Result<size_t> recv(std::span<uint8_t> buf);

    // -- Reliable I/O (loop until complete) ---------------------------------

    /// Send all bytes in data, looping until everything is written.
    core::Result<void> send_all(std::span<const uint8_t> data);

    /// Receive exactly buf.size() bytes, looping until the buffer is full
    /// or the timeout expires.  Returns the total number of bytes read
    /// (may be less than buf.size() on timeout or graceful close).
    core::Result<size_t> recv_all(std::span<uint8_t> buf,
                                  int timeout_ms = 30000);

    // -- Lifecycle ----------------------------------------------------------

    /// Close the underlying socket descriptor. Safe to call multiple times.
    void close();

    /// Initiate a graceful shutdown (sends FIN). The socket remains open
    /// for reading until the peer also closes.
    void shutdown_send();

    /// Returns true if the socket holds a valid descriptor.
    [[nodiscard]] bool is_open() const;

    // -- Peer information ---------------------------------------------------

    /// Returns the remote peer IP address as a string, or "" if unavailable.
    [[nodiscard]] std::string remote_address() const;

    /// Returns the remote peer port, or 0 if unavailable.
    [[nodiscard]] uint16_t remote_port() const;

    /// Returns the local bound IP address as a string, or "" if unavailable.
    [[nodiscard]] std::string local_address() const;

    /// Returns the local bound port, or 0 if unavailable.
    [[nodiscard]] uint16_t local_port() const;

    // -- Socket options -----------------------------------------------------

    /// Enable or disable non-blocking mode (ioctlsocket / FIONBIO).
    void set_nonblocking(bool enable);

    /// Enable or disable TCP_NODELAY (Nagle algorithm).
    void set_nodelay(bool enable);

    /// Enable or disable SO_KEEPALIVE.
    void set_keepalive(bool enable);

    /// Set the send buffer size (SO_SNDBUF).
    void set_send_buffer_size(int size);

    /// Set the receive buffer size (SO_RCVBUF).
    void set_recv_buffer_size(int size);

    /// Set the SO_LINGER option.  If enable is true, close() will block
    /// for up to timeout_sec seconds to flush pending data.
    void set_linger(bool enable, int timeout_sec);

    /// Set the send timeout (SO_SNDTIMEO).
    void set_send_timeout(int timeout_ms);

    /// Set the receive timeout (SO_RCVTIMEO).
    void set_recv_timeout(int timeout_ms);

    // -- Raw handle access (for integration with select/poll) ---------------

    /// Returns the raw OS socket handle. Callers must not close it directly.
    [[nodiscard]] uintptr_t native_handle() const { return fd_; }

private:
    /// Construct from a raw OS socket handle (used internally by accept()).
    explicit Socket(uintptr_t raw_fd);

    /// The underlying OS socket handle.  ~uintptr_t(0) == INVALID_SOCKET.
    uintptr_t fd_ = ~uintptr_t(0);
};

} // namespace net
