#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Stratum mining protocol server for FTC pool mining.
//
// Implements the Stratum v1 protocol, a JSON-line-based TCP protocol used
// by mining pools to distribute work to connected miners. Messages are
// newline-delimited JSON objects.
//
// Supported methods:
//   - mining.subscribe   -- Worker subscribes to job notifications.
//   - mining.authorize   -- Worker authenticates with username/password.
//   - mining.notify      -- Server pushes new work to connected workers.
//   - mining.submit      -- Worker submits a solution.
//   - mining.set_difficulty -- Server adjusts worker difficulty.
//
// The server runs in its own thread, accepting connections and dispatching
// messages. Each connected client is tracked in a StratumClient struct.
// ---------------------------------------------------------------------------

#include "core/channel.h"
#include "core/error.h"
#include "core/types.h"
#include "miner/block_template.h"
#include "miner/solver.h"
#include "net/transport/socket.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace miner {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default Stratum server port.
static constexpr uint16_t DEFAULT_STRATUM_PORT = 3333;

/// Maximum line length for a Stratum JSON message (16 KB).
static constexpr size_t MAX_STRATUM_LINE_LENGTH = 16384;

/// Maximum number of concurrent Stratum clients.
static constexpr size_t MAX_STRATUM_CLIENTS = 1024;

/// Stratum protocol version string.
static constexpr const char* STRATUM_VERSION = "FTC-Stratum/1.0";

/// Read timeout for client sockets (milliseconds).
static constexpr int STRATUM_READ_TIMEOUT_MS = 30000;

// ---------------------------------------------------------------------------
// StratumClient -- represents a connected mining worker
// ---------------------------------------------------------------------------

struct StratumClient {
    /// Unique client identifier (assigned by the server).
    uint64_t id = 0;

    /// The TCP socket for this client connection.
    net::Socket socket;

    /// Worker name (from mining.authorize).
    std::string worker_name;

    /// Worker password (from mining.authorize, rarely used meaningfully).
    std::string worker_pass;

    /// Whether this client has been authorized.
    bool authorized = false;

    /// Whether this client has subscribed.
    bool subscribed = false;

    /// Current difficulty for this worker.
    double difficulty = 1.0;

    /// Last job ID sent to this worker.
    std::string last_job_id;

    /// Number of valid shares submitted by this worker.
    uint64_t valid_shares = 0;

    /// Number of invalid shares submitted by this worker.
    uint64_t invalid_shares = 0;

    /// Receive buffer for accumulating partial messages.
    std::string recv_buffer;

    /// Client's remote address (for logging).
    std::string remote_addr;
};

// ---------------------------------------------------------------------------
// StratumShare -- a submitted share from a worker
// ---------------------------------------------------------------------------

/// Represents a share submission from a Stratum client.
struct StratumShare {
    /// The worker name that submitted this share.
    std::string worker_name;

    /// The job ID this share is for.
    std::string job_id;

    /// The nonce used by the worker.
    uint32_t nonce = 0;

    /// The Equihash solution bytes.
    std::vector<uint8_t> solution;

    /// The extra nonce assigned to this client.
    uint32_t extra_nonce = 0;

    /// The timestamp used by the worker.
    uint32_t time = 0;
};

// ---------------------------------------------------------------------------
// ShareCallback -- notification when a valid block-level share is found
// ---------------------------------------------------------------------------

/// Callback invoked when a submitted share also qualifies as a valid block.
using ShareCallback = std::function<void(
    const primitives::BlockHeader& header,
    const std::vector<uint8_t>& solution)>;

// ---------------------------------------------------------------------------
// StratumServer
// ---------------------------------------------------------------------------

/// TCP server implementing the Stratum v1 mining protocol.
///
/// Usage:
///   StratumServer server;
///   server.set_share_callback([&](auto& header, auto& sol) { ... });
///   server.start(3333);
///   // ... update work ...
///   server.notify_new_job(template);
///   // ... later ...
///   server.stop();
class StratumServer {
public:
    StratumServer();
    ~StratumServer();

    // Non-copyable, non-movable.
    StratumServer(const StratumServer&) = delete;
    StratumServer& operator=(const StratumServer&) = delete;
    StratumServer(StratumServer&&) = delete;
    StratumServer& operator=(StratumServer&&) = delete;

    // -- Lifecycle ----------------------------------------------------------

    /// Start the Stratum server on the given port.
    ///
    /// Opens a listening socket and spawns:
    ///   - An accept thread to handle incoming connections.
    ///   - A processing thread to read and dispatch messages.
    ///
    /// @param port  TCP port to listen on.
    /// @returns     core::make_ok() on success, or an error.
    [[nodiscard]] core::Result<void> start(uint16_t port = DEFAULT_STRATUM_PORT);

    /// Stop the Stratum server.
    ///
    /// Closes all client connections, shuts down the listener, and
    /// joins all threads.
    void stop();

    /// Check if the server is running.
    [[nodiscard]] bool is_running() const {
        return running_.load(std::memory_order_relaxed);
    }

    // -- Work distribution -------------------------------------------------

    /// Push a new mining job to all connected and authorized workers.
    ///
    /// Constructs a mining.notify message from the block template and
    /// sends it to each client. Previous jobs are invalidated (clean job).
    ///
    /// @param tmpl  The new block template.
    void notify_new_job(const BlockTemplate& tmpl);

    /// Set the difficulty for all connected workers.
    ///
    /// Sends a mining.set_difficulty message to each client.
    ///
    /// @param difficulty  The new difficulty target.
    void set_difficulty(double difficulty);

    // -- Callbacks ---------------------------------------------------------

    /// Set the callback for valid block-level shares.
    void set_share_callback(ShareCallback callback);

    // -- Statistics --------------------------------------------------------

    /// Get the number of currently connected clients.
    [[nodiscard]] size_t client_count() const;

    /// Get the total number of valid shares received.
    [[nodiscard]] uint64_t total_valid_shares() const;

    /// Get the total number of invalid shares received.
    [[nodiscard]] uint64_t total_invalid_shares() const;

private:
    // -- Accept thread ------------------------------------------------------

    /// Accept loop: listens for incoming connections and creates clients.
    void accept_loop();

    // -- Client I/O ---------------------------------------------------------

    /// Read and process messages from a single client.
    /// Runs in a per-client thread.
    void client_handler(uint64_t client_id);

    /// Process a single JSON-line message from a client.
    void process_message(uint64_t client_id, const std::string& line);

    // -- Protocol handlers --------------------------------------------------

    void handle_subscribe(uint64_t client_id, uint64_t msg_id);

    void handle_authorize(
        uint64_t client_id, uint64_t msg_id,
        const std::string& worker_name,
        const std::string& worker_pass);

    void handle_submit(
        uint64_t client_id, uint64_t msg_id,
        const StratumShare& share);

    // -- Message sending ----------------------------------------------------

    /// Send a JSON-line message to a specific client.
    /// @returns true if the message was sent successfully.
    bool send_to_client(uint64_t client_id, const std::string& json_line);

    /// Send a JSON-line message to all authorized clients.
    void broadcast(const std::string& json_line);

    /// Build a mining.notify JSON message from a block template.
    [[nodiscard]] std::string build_notify_message(
        const BlockTemplate& tmpl) const;

    /// Build a mining.set_difficulty JSON message.
    [[nodiscard]] std::string build_set_difficulty_message(
        double difficulty) const;

    // -- Client management --------------------------------------------------

    /// Remove a disconnected client.
    void remove_client(uint64_t client_id);

    /// Generate a unique extra nonce for a new client.
    [[nodiscard]] uint32_t generate_extra_nonce();

    // -- Data members -------------------------------------------------------

    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};

    /// Listening socket.
    net::Socket listen_socket_;

    /// Accept thread.
    std::thread accept_thread_;

    /// Per-client handler threads.
    std::vector<std::thread> client_threads_;

    /// Connected clients, keyed by client ID.
    mutable std::mutex clients_mutex_;
    std::unordered_map<uint64_t, std::unique_ptr<StratumClient>> clients_;

    /// Next client ID counter.
    std::atomic<uint64_t> next_client_id_{1};

    /// Next extra nonce counter.
    std::atomic<uint32_t> next_extra_nonce_{1};

    /// Current job ID (incremented with each new job).
    std::atomic<uint64_t> current_job_id_{0};

    /// Current block template (protected by template_mutex_).
    mutable std::mutex template_mutex_;
    std::unique_ptr<BlockTemplate> current_template_;

    /// Default difficulty for new workers.
    std::atomic<double> default_difficulty_{1.0};

    /// Share callback.
    ShareCallback share_callback_;

    /// Statistics.
    std::atomic<uint64_t> total_valid_shares_{0};
    std::atomic<uint64_t> total_invalid_shares_{0};

    /// Equihash solver for share verification.
    EquihashSolver verifier_;
};

} // namespace miner
