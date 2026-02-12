// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Connection -- P2P connection state machine implementation.
//
// Provides framed message reading and writing over a TCP socket.  The
// receive side uses an internal buffer for partial-read assembly: TCP
// is a stream protocol, so a single recv() call may return less than
// one full message or the tail of one message concatenated with the
// head of the next.  The buffer handles both cases transparently.
//
// Thread safety:
//   - read_message() is designed for single-reader use (one thread
//     drives the read loop per connection).
//   - send_message() is protected by a mutex so multiple threads can
//     safely enqueue outgoing messages without interleaving wire bytes.
// ---------------------------------------------------------------------------

#include "net/transport/connection.h"
#include "core/logging.h"
#include "core/time.h"

#include <algorithm>
#include <cstring>

namespace net {

// ===================================================================
// ConnState name lookup
// ===================================================================

const char* conn_state_name(ConnState state) noexcept {
    switch (state) {
        case ConnState::CONNECTING:     return "CONNECTING";
        case ConnState::CONNECTED:      return "CONNECTED";
        case ConnState::VERSION_SENT:   return "VERSION_SENT";
        case ConnState::HANDSHAKE_DONE: return "HANDSHAKE_DONE";
        case ConnState::DISCONNECTED:   return "DISCONNECTED";
    }
    return "UNKNOWN";
}

// ===================================================================
// Internal constants
// ===================================================================

namespace {

/// Initial capacity for the receive buffer.  Chosen to hold at least
/// one full header plus a typical small payload (e.g. version, ping).
constexpr size_t INITIAL_RECV_BUF_CAPACITY = 4096;

/// Maximum receive buffer size before we force a compaction or error.
/// This prevents unbounded memory growth from a misbehaving peer that
/// sends very large payloads slowly.
constexpr size_t MAX_RECV_BUF_SIZE = 64 * 1024 * 1024; // 64 MB

/// Size of the stack-allocated chunk buffer used for each recv() call.
constexpr size_t RECV_CHUNK_SIZE = 16384;

/// Message read timeout in milliseconds.  If a partial message has
/// been received but no progress is made for this duration, the
/// read is abandoned and an error is returned.
constexpr int READ_PROGRESS_TIMEOUT_MS = 60000; // 60 seconds

} // anonymous namespace

// ===================================================================
// Construction / Destruction
// ===================================================================

Connection::Connection(Socket socket, ConnDir direction, uint64_t id)
    : socket_(std::move(socket))
    , direction_(direction)
    , id_(id)
    , connected_time_(core::get_time())
{
    // Pre-allocate the receive buffer to reduce early reallocations
    // during the handshake phase.
    recv_buf_.reserve(INITIAL_RECV_BUF_CAPACITY);

    // Configure the socket for P2P messaging:
    //   - TCP_NODELAY: disable Nagle for low-latency small messages
    //   - SO_KEEPALIVE: detect dead connections at the TCP level
    socket_.set_nodelay(true);
    socket_.set_keepalive(true);

    // Transition directly to CONNECTED since we receive an already-
    // established socket from the caller (either from connect() or
    // accept()).
    state_ = ConnState::CONNECTED;

    std::string dir_str = (direction_ == ConnDir::INBOUND)
                          ? "inbound" : "outbound";
    LOG_DEBUG(core::LogCategory::NET,
             "connection " + std::to_string(id_) + " established (" +
             dir_str + ") with " + socket_.remote_address() + ":" +
             std::to_string(socket_.remote_port()));
}

Connection::Connection(Connection&& other) noexcept
    : socket_(std::move(other.socket_))
    , direction_(other.direction_)
    , id_(other.id_)
    , state_(other.state_)
    , connected_time_(other.connected_time_)
    , bytes_sent_(other.bytes_sent_)
    , bytes_recv_(other.bytes_recv_)
    , last_send_(other.last_send_)
    , last_recv_(other.last_recv_)
    , recv_buf_(std::move(other.recv_buf_))
    // send_mutex_ is default-constructed (new mutex for moved-to object)
{
    other.state_ = ConnState::DISCONNECTED;
}

Connection::~Connection() {
    if (state_ != ConnState::DISCONNECTED) {
        LOG_DEBUG(core::LogCategory::NET,
                  "connection " + std::to_string(id_) +
                  " destructor (state=" +
                  std::string(conn_state_name(state_)) +
                  ", sent=" + std::to_string(bytes_sent_) +
                  ", recv=" + std::to_string(bytes_recv_) + ")");
        state_ = ConnState::DISCONNECTED;

        // Attempt a graceful shutdown before closing.
        socket_.shutdown_send();
        socket_.close();
    }
}

// ===================================================================
// Internal: ensure_recv_bytes
// ===================================================================

core::Result<void> Connection::ensure_recv_bytes(size_t needed) {
    // Guard against excessive buffer growth from misbehaving peers.
    if (needed > MAX_RECV_BUF_SIZE) {
        state_ = ConnState::DISCONNECTED;
        return core::Error(core::ErrorCode::PARSE_ERROR,
                           "recv buffer would exceed " +
                           std::to_string(MAX_RECV_BUF_SIZE / (1024 * 1024)) +
                           " MB limit on connection " +
                           std::to_string(id_));
    }

    uint8_t chunk[RECV_CHUNK_SIZE];

    while (recv_buf_.size() < needed) {
        // Compute how much to request.  We read at least one chunk
        // even if we only need a few bytes, to amortize syscall
        // overhead.
        size_t deficit = needed - recv_buf_.size();
        size_t want = std::max(deficit, RECV_CHUNK_SIZE);
        if (want > RECV_CHUNK_SIZE) {
            want = RECV_CHUNK_SIZE;
        }

        auto result = socket_.recv(
            std::span<uint8_t>(chunk, want));
        if (!result.ok()) {
            // Propagate the socket error (closed, reset, etc.)
            state_ = ConnState::DISCONNECTED;
            return result.error();
        }

        size_t n = result.value();
        if (n == 0) {
            // Peer closed the connection gracefully.
            state_ = ConnState::DISCONNECTED;
            return core::Error(core::ErrorCode::NETWORK_CLOSED,
                               "peer closed connection " +
                               std::to_string(id_) +
                               " (need " + std::to_string(needed) +
                               " bytes, have " +
                               std::to_string(recv_buf_.size()) + ")");
        }

        recv_buf_.insert(recv_buf_.end(), chunk, chunk + n);
        bytes_recv_ += n;
        last_recv_ = core::get_time();
    }

    return core::make_ok();
}

// ===================================================================
// Internal: read_header_from_buf
// ===================================================================

core::Result<bool> Connection::read_header_from_buf(MessageHeader& header) {
    if (recv_buf_.size() < MessageHeader::HEADER_SIZE) {
        return false; // Not enough data yet.
    }

    // Try to deserialize from the front of the buffer.
    auto result = MessageHeader::deserialize(
        std::span<const uint8_t>(recv_buf_.data(),
                                 MessageHeader::HEADER_SIZE));
    if (!result.ok()) {
        // Protocol error (bad magic, bad command, etc.)
        return result.error();
    }

    header = result.value();
    return true;
}

// ===================================================================
// read_message -- read one complete framed message
// ===================================================================

core::Result<Message> Connection::read_message() {
    if (state_ == ConnState::DISCONNECTED) {
        return core::Error(core::ErrorCode::NETWORK_CLOSED,
                           "read_message on disconnected connection " +
                           std::to_string(id_));
    }

    // ---------------------------------------------------------------
    // Phase 1: Accumulate the 24-byte header.
    // ---------------------------------------------------------------
    {
        auto rc = ensure_recv_bytes(MessageHeader::HEADER_SIZE);
        if (!rc.ok()) {
            return rc.error();
        }
    }

    MessageHeader header;
    {
        auto rc = read_header_from_buf(header);
        if (!rc.ok()) {
            // Protocol-level error (bad magic, invalid command, etc.).
            // Disconnect from this peer.
            state_ = ConnState::DISCONNECTED;
            LOG_WARN(core::LogCategory::NET,
                     "invalid header on connection " + std::to_string(id_) +
                     ": " + rc.error().message());
            return rc.error();
        }
        if (!rc.value()) {
            // Should not happen since we ensured enough bytes above.
            return core::Error(core::ErrorCode::INTERNAL_ERROR,
                               "unexpected header parse failure on "
                               "connection " + std::to_string(id_));
        }
    }

    // ---------------------------------------------------------------
    // Phase 2: Accumulate the payload.
    // ---------------------------------------------------------------
    size_t total_msg_size = MessageHeader::HEADER_SIZE +
                            header.payload_size;
    {
        auto rc = ensure_recv_bytes(total_msg_size);
        if (!rc.ok()) {
            return rc.error();
        }
    }

    // ---------------------------------------------------------------
    // Phase 3: Extract the message from the buffer.
    // ---------------------------------------------------------------
    Message msg;
    msg.header = header;

    if (header.payload_size > 0) {
        msg.payload.assign(
            recv_buf_.begin() +
                static_cast<ptrdiff_t>(MessageHeader::HEADER_SIZE),
            recv_buf_.begin() +
                static_cast<ptrdiff_t>(total_msg_size));
    }

    // Consume the processed bytes from the front of recv_buf_.
    // We use erase() which is O(N) but the alternative (maintaining
    // a read offset) adds complexity.  For typical message sizes
    // (<< 1 MB) this is fine.
    recv_buf_.erase(
        recv_buf_.begin(),
        recv_buf_.begin() + static_cast<ptrdiff_t>(total_msg_size));

    // Periodically shrink the buffer back to its initial capacity
    // to prevent it from staying large after a big message.
    if (recv_buf_.capacity() > INITIAL_RECV_BUF_CAPACITY * 4 &&
        recv_buf_.size() < INITIAL_RECV_BUF_CAPACITY) {
        recv_buf_.shrink_to_fit();
        recv_buf_.reserve(INITIAL_RECV_BUF_CAPACITY);
    }

    // ---------------------------------------------------------------
    // Phase 4: Validate the checksum.
    // ---------------------------------------------------------------
    if (!msg.verify_checksum()) {
        LOG_WARN(core::LogCategory::NET,
                 "checksum mismatch on '" + msg.header.get_command() +
                 "' (" + std::to_string(msg.payload.size()) +
                 " bytes) from connection " + std::to_string(id_));
        return core::Error(core::ErrorCode::PARSE_ERROR,
                           "message checksum mismatch for command '" +
                           msg.header.get_command() + "' on connection " +
                           std::to_string(id_));
    }

    LOG_TRACE(core::LogCategory::NET,
              "recv '" + msg.header.get_command() + "' (" +
              std::to_string(msg.payload.size()) + " bytes) from conn " +
              std::to_string(id_));

    return msg;
}

// ===================================================================
// send_message -- send one complete framed message
// ===================================================================

core::Result<void> Connection::send_message(const Message& msg) {
    if (state_ == ConnState::DISCONNECTED) {
        return core::Error(core::ErrorCode::NETWORK_CLOSED,
                           "send_message on disconnected connection " +
                           std::to_string(id_));
    }

    // Validate that the message is well-formed before sending.
    if (msg.header.magic != MessageHeader::MAGIC) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
                           "refusing to send message with wrong magic on "
                           "connection " + std::to_string(id_));
    }

    if (msg.header.payload_size != msg.payload.size()) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
                           "send_message: header payload_size (" +
                           std::to_string(msg.header.payload_size) +
                           ") does not match actual payload size (" +
                           std::to_string(msg.payload.size()) +
                           ") on connection " + std::to_string(id_));
    }

    // Serialize the full message (header + payload) into a single
    // contiguous buffer so we can send it atomically.
    std::vector<uint8_t> wire_data = msg.serialize();

    // Protect the send path with a mutex so concurrent callers do
    // not interleave wire bytes.  This allows the upper layer to
    // have multiple threads send messages to the same connection
    // without external synchronization.
    {
        std::unique_lock<std::mutex> lock(send_mutex_);

        auto rc = socket_.send_all(
            std::span<const uint8_t>(wire_data));
        if (!rc.ok()) {
            state_ = ConnState::DISCONNECTED;
            LOG_WARN(core::LogCategory::NET,
                     "send failed on connection " + std::to_string(id_) +
                     ": " + rc.error().message());
            return rc.error();
        }
    }

    bytes_sent_ += wire_data.size();
    last_send_ = core::get_time();

    LOG_TRACE(core::LogCategory::NET,
              "sent '" + msg.header.get_command() + "' (" +
              std::to_string(msg.payload.size()) + " bytes) to conn " +
              std::to_string(id_));

    return core::make_ok();
}

// ===================================================================
// Accessors
// ===================================================================

ConnState Connection::state() const {
    return state_;
}

void Connection::set_state(ConnState s) {
    if (state_ == s) return; // No-op if already in this state.

    LOG_DEBUG(core::LogCategory::NET,
              "connection " + std::to_string(id_) + " state " +
              conn_state_name(state_) + " -> " + conn_state_name(s));
    state_ = s;

    // If transitioning to DISCONNECTED, close the socket.
    if (s == ConnState::DISCONNECTED) {
        socket_.shutdown_send();
        socket_.close();
    }
}

ConnDir Connection::direction() const {
    return direction_;
}

uint64_t Connection::id() const {
    return id_;
}

Socket& Connection::socket() {
    return socket_;
}

const Socket& Connection::socket() const {
    return socket_;
}

int64_t Connection::connected_time() const {
    return connected_time_;
}

uint64_t Connection::bytes_sent() const {
    return bytes_sent_;
}

uint64_t Connection::bytes_recv() const {
    return bytes_recv_;
}

int64_t Connection::last_send() const {
    return last_send_;
}

int64_t Connection::last_recv() const {
    return last_recv_;
}

std::string Connection::remote_address() const {
    return socket_.remote_address();
}

uint16_t Connection::remote_port() const {
    return socket_.remote_port();
}

} // namespace net
