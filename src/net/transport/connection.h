#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Connection -- P2P connection state machine.
//
// Owns a Socket and provides framed message read/write with buffered
// partial-read assembly.  Tracks connection direction, state, and
// basic traffic statistics.
// ---------------------------------------------------------------------------

#include "net/transport/message.h"
#include "net/transport/socket.h"
#include "core/error.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace net {

// ===================================================================
// Connection state and direction enums
// ===================================================================

/// Lifecycle states for a peer connection.
enum class ConnState : uint8_t {
    CONNECTING,      // TCP handshake in progress
    CONNECTED,       // TCP established, version handshake not started
    VERSION_SENT,    // Our VERSION message has been sent
    HANDSHAKE_DONE,  // Version handshake complete (VERACK exchanged)
    DISCONNECTED,    // Connection closed or failed
};

/// Returns a human-readable name for a connection state.
[[nodiscard]] const char* conn_state_name(ConnState state) noexcept;

/// Direction of a connection relative to us.
enum class ConnDir : uint8_t {
    INBOUND,   // They connected to us
    OUTBOUND,  // We connected to them
};

// ===================================================================
// Connection
// ===================================================================

class Connection {
public:
    /// Construct a connection from an established socket.
    Connection(Socket socket, ConnDir direction, uint64_t id);
    ~Connection();

    // Non-copyable but movable.
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    Connection(Connection&& other) noexcept;
    Connection& operator=(Connection&&) = delete;

    // -- Framed I/O ---------------------------------------------------------

    /// Read one complete framed message from the socket.
    /// Blocks until a full message is available or an error occurs.
    core::Result<Message> read_message();

    /// Send a framed message over the socket.
    core::Result<void> send_message(const Message& msg);

    // -- State --------------------------------------------------------------

    [[nodiscard]] ConnState state() const;
    void set_state(ConnState s);

    [[nodiscard]] ConnDir direction() const;
    [[nodiscard]] uint64_t id() const;

    /// Direct access to the underlying socket (e.g. for select/poll).
    Socket& socket();
    const Socket& socket() const;

    // -- Statistics ---------------------------------------------------------

    /// Unix timestamp (seconds) when the connection was created.
    [[nodiscard]] int64_t connected_time() const;

    /// Cumulative bytes sent / received over this connection.
    [[nodiscard]] uint64_t bytes_sent() const;
    [[nodiscard]] uint64_t bytes_recv() const;

    /// Unix timestamp (seconds) of the most recent send / receive.
    [[nodiscard]] int64_t last_send() const;
    [[nodiscard]] int64_t last_recv() const;

    /// Remote address string (forwarded from Socket).
    [[nodiscard]] std::string remote_address() const;

    /// Remote port (forwarded from Socket).
    [[nodiscard]] uint16_t remote_port() const;

private:
    Socket socket_;
    ConnDir direction_;
    uint64_t id_;
    ConnState state_ = ConnState::CONNECTING;

    // Timestamps and counters.
    int64_t connected_time_;
    uint64_t bytes_sent_ = 0;
    uint64_t bytes_recv_ = 0;
    int64_t last_send_ = 0;
    int64_t last_recv_ = 0;

    // Receive buffer for partial message assembly.
    std::vector<uint8_t> recv_buf_;

    // Mutex protecting send path (recv is single-reader by design).
    mutable std::mutex send_mutex_;

    /// Attempt to parse a MessageHeader from the front of recv_buf_.
    /// Returns true if a complete header was parsed, false if more data
    /// is needed.  On protocol errors, returns an Error.
    core::Result<bool> read_header_from_buf(MessageHeader& header);

    /// Fill recv_buf_ until it has at least |needed| bytes.
    core::Result<void> ensure_recv_bytes(size_t needed);
};

} // namespace net
