#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FTC_RPC_SERVER_H
#define FTC_RPC_SERVER_H

#include "core/channel.h"
#include "core/config.h"
#include "core/error.h"
#include "rpc/request.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace rpc {

// ---------------------------------------------------------------------------
// RpcHandler -- function signature for RPC command handlers
// ---------------------------------------------------------------------------
using RpcHandler = std::function<RpcResponse(const RpcRequest&)>;

// ---------------------------------------------------------------------------
// RpcCommand -- a registered command with its handler and metadata
// ---------------------------------------------------------------------------
struct RpcCommand {
    std::string name;
    RpcHandler  handler;
    std::string help;
    std::string category;
};

// ---------------------------------------------------------------------------
// RpcServer -- JSON-RPC HTTP server
// ---------------------------------------------------------------------------
// Listens on a configurable TCP port, accepts HTTP POST requests containing
// JSON-RPC 2.0 payloads, routes them to registered command handlers, and
// returns the JSON-RPC response.
//
// Features:
//   - HTTP Basic authentication (rpcuser/rpcpassword from config)
//   - Thread pool for concurrent request handling
//   - Bounded request queue via core::Channel
//   - Winsock2-based TCP on Windows
// ---------------------------------------------------------------------------

class RpcServer {
public:
    struct Config {
        std::string bind_address = "127.0.0.1";
        uint16_t    port         = 8332;
        std::string rpc_user;
        std::string rpc_password;
        int         num_threads  = 4;
        size_t      max_request_size = 16 * 1024 * 1024; // 16 MB
    };

    explicit RpcServer(Config config);
    ~RpcServer();

    // Non-copyable, non-movable.
    RpcServer(const RpcServer&)            = delete;
    RpcServer& operator=(const RpcServer&) = delete;
    RpcServer(RpcServer&&)                 = delete;
    RpcServer& operator=(RpcServer&&)      = delete;

    // -- Lifecycle -----------------------------------------------------------

    /// Initialize Winsock, bind, listen, start threads.
    core::Result<void> start();

    /// Stop the server: close the listen socket, join all threads.
    void stop();

    /// Returns true if the server is running.
    [[nodiscard]] bool is_running() const;

    // -- Command registration ------------------------------------------------

    /// Register an RPC command handler.
    void register_command(RpcCommand cmd);

    /// Register multiple commands at once.
    void register_commands(std::vector<RpcCommand> cmds);

    // -- Configuration from core::Config ------------------------------------

    /// Build an RpcServer::Config from the node's Config.
    static Config from_node_config(const core::Config& cfg);

private:
    Config config_;

    // Listen socket (platform handle)
    uintptr_t listen_socket_ = static_cast<uintptr_t>(~0);

    // Command registry
    std::map<std::string, RpcCommand> commands_;
    mutable std::mutex commands_mutex_;

    // Thread pool
    std::vector<std::jthread> worker_threads_;
    std::jthread accept_thread_;

    // Request queue
    struct PendingRequest {
        uintptr_t client_socket;
        std::string body;
        int64_t     received_at;
    };
    core::MpmcChannel<PendingRequest> request_queue_;

    std::atomic<bool> running_{false};
    std::atomic<bool> winsock_initialized_{false};

    // -- Internal methods ---------------------------------------------------

    /// Initialize Winsock (Windows) or no-op (POSIX).
    core::Result<void> init_network();

    /// Cleanup Winsock.
    void cleanup_network();

    /// The accept loop: accepts connections and enqueues requests.
    void accept_loop(std::stop_token stoken);

    /// Worker thread: dequeues and processes requests.
    void worker_loop(std::stop_token stoken);

    /// Read an HTTP request from a socket. Returns the POST body.
    /// Validates Content-Type and Authorization headers.
    struct HttpRequest {
        std::string method;  // "POST", "GET", etc.
        std::string path;
        std::string body;
        std::string auth_header;
        std::string content_type;
        bool        keep_alive = false;
    };
    HttpRequest read_http_request(uintptr_t sock);

    /// Send an HTTP response on the socket.
    void send_http_response(uintptr_t sock, int status_code,
                            const std::string& status_text,
                            const std::string& body,
                            const std::string& content_type = "application/json");

    /// Process a JSON-RPC request and return the response.
    RpcResponse process_request(const std::string& body);

    /// Close a socket handle.
    void close_socket(uintptr_t sock);
};

} // namespace rpc

#endif // FTC_RPC_SERVER_H
