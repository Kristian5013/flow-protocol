// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/server.h"
#include "rpc/util.h"
#include "core/hex.h"
#include "core/logging.h"
#include "core/random.h"
#include "core/time.h"
#include "net/address/netaddress.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

// Platform-specific socket includes
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "Ws2_32.lib")
    using socket_t = SOCKET;
    static constexpr socket_t INVALID_SOCK = INVALID_SOCKET;
    #define CLOSE_SOCKET closesocket
    #define SOCK_ERR WSAGetLastError()
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <unistd.h>
    using socket_t = int;
    static constexpr socket_t INVALID_SOCK = -1;
    #define CLOSE_SOCKET ::close
    #define SOCK_ERR errno
#endif

namespace rpc {

// ===========================================================================
// Construction / destruction
// ===========================================================================

RpcServer::RpcServer(Config config)
    : config_(std::move(config))
    , request_queue_(256) // bounded queue of 256 pending requests
{
}

RpcServer::~RpcServer() {
    stop();
}

// ===========================================================================
// Lifecycle
// ===========================================================================

core::Result<void> RpcServer::start() {
    if (running_.load()) {
        return core::Error(core::ErrorCode::RPC_ERROR, "RPC server already running");
    }

    // Generate cookie auth if no rpcuser/rpcpassword configured.
    generate_cookie();

    auto net_result = init_network();
    if (!net_result.ok()) return net_result;

    // Create listen socket
    socket_t sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCK) {
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "Failed to create listen socket");
    }

    // Allow address reuse
    int opt = 1;
#ifdef _WIN32
    ::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    ::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    // Bind
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.port);

    if (config_.bind_address == "0.0.0.0" || config_.bind_address.empty()) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, config_.bind_address.c_str(), &addr.sin_addr) != 1) {
            CLOSE_SOCKET(sock);
            return core::Error(core::ErrorCode::NETWORK_ERROR,
                               "Invalid bind address: " + config_.bind_address);
        }
    }

    if (::bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        CLOSE_SOCKET(sock);
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "Failed to bind RPC on port " + std::to_string(config_.port));
    }

    if (::listen(sock, SOMAXCONN) != 0) {
        CLOSE_SOCKET(sock);
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "Failed to listen on RPC port");
    }

    listen_socket_ = static_cast<uintptr_t>(sock);
    running_.store(true);

    LOG_INFO(core::LogCategory::RPC,
             "RPC server listening on " + config_.bind_address + ":" +
             std::to_string(config_.port));

    // Start worker threads
    for (int i = 0; i < config_.num_threads; ++i) {
        worker_threads_.emplace_back(
            [this](std::stop_token st) { worker_loop(st); });
    }

    // Start accept thread
    accept_thread_ = std::jthread(
        [this](std::stop_token st) { accept_loop(st); });

    return core::Result<void>{};
}

void RpcServer::stop() {
    if (!running_.exchange(false)) return;

    LOG_INFO(core::LogCategory::RPC, "RPC server shutting down");

    // Close listen socket to unblock accept()
    if (listen_socket_ != static_cast<uintptr_t>(~0)) {
        close_socket(listen_socket_);
        listen_socket_ = static_cast<uintptr_t>(~0);
    }

    // Close the request queue so workers exit
    request_queue_.close();

    // Request stop on all jthreads (they check stop_token)
    if (accept_thread_.joinable()) {
        accept_thread_.request_stop();
        accept_thread_.join();
    }

    for (auto& t : worker_threads_) {
        if (t.joinable()) {
            t.request_stop();
            t.join();
        }
    }
    worker_threads_.clear();

    delete_cookie();
    cleanup_network();
}

bool RpcServer::is_running() const {
    return running_.load(std::memory_order_relaxed);
}

// ===========================================================================
// Command registration
// ===========================================================================

void RpcServer::register_command(RpcCommand cmd) {
    std::lock_guard lock(commands_mutex_);
    register_help(cmd.name, cmd.help);
    commands_[cmd.name] = std::move(cmd);
}

void RpcServer::register_commands(std::vector<RpcCommand> cmds) {
    std::lock_guard lock(commands_mutex_);
    for (auto& cmd : cmds) {
        register_help(cmd.name, cmd.help);
        commands_[cmd.name] = std::move(cmd);
    }
}

RpcServer::Config RpcServer::from_node_config(const core::Config& cfg) {
    Config c;
    c.bind_address = cfg.get_or("rpcbind", "127.0.0.1");
    c.port = static_cast<uint16_t>(cfg.get_int("rpcport", 8332));
    c.rpc_user = cfg.get_or(core::CONF_RPCUSER, "");
    c.rpc_password = cfg.get_or(core::CONF_RPCPASSWORD, "");
    c.num_threads = static_cast<int>(cfg.get_int("rpcthreads", 4));
    return c;
}

// ===========================================================================
// Network initialization
// ===========================================================================

core::Result<void> RpcServer::init_network() {
#ifdef _WIN32
    WSADATA wsa_data;
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0) {
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "WSAStartup failed: " + std::to_string(result));
    }
    winsock_initialized_.store(true);
#endif
    return core::Result<void>{};
}

void RpcServer::cleanup_network() {
#ifdef _WIN32
    if (winsock_initialized_.exchange(false)) {
        WSACleanup();
    }
#endif
}

// ===========================================================================
// Accept loop
// ===========================================================================

void RpcServer::accept_loop(std::stop_token stoken) {
    while (!stoken.stop_requested() && running_.load()) {
        struct sockaddr_in client_addr{};
        int addr_len = sizeof(client_addr);

#ifdef _WIN32
        socket_t client = ::accept(
            static_cast<socket_t>(listen_socket_),
            reinterpret_cast<struct sockaddr*>(&client_addr), &addr_len);
#else
        socklen_t addr_len_s = static_cast<socklen_t>(addr_len);
        socket_t client = ::accept(
            static_cast<socket_t>(listen_socket_),
            reinterpret_cast<struct sockaddr*>(&client_addr), &addr_len_s);
#endif

        if (client == INVALID_SOCK) {
            if (!running_.load()) break;
            LOG_WARN(core::LogCategory::RPC, "RPC accept() failed");
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        // If shutdown was requested while we were in accept(), bail out.
        if (!running_.load()) {
            CLOSE_SOCKET(client);
            break;
        }

        // IP allowlist check
        {
            uint32_t ip = ntohl(client_addr.sin_addr.s_addr);
            if (!is_client_allowed(ip)) {
                CLOSE_SOCKET(client);
                continue;
            }
        }

        // Set receive timeout (5 seconds — short enough for clean shutdown)
#ifdef _WIN32
        DWORD timeout = 5000;
        ::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        ::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
                     &tv, sizeof(tv));
#endif

        try {
            HttpRequest http_req = read_http_request(static_cast<uintptr_t>(client));

            // Handle CORS preflight (before auth — browsers don't send
            // credentials on preflight requests).
            if (http_req.method == "OPTIONS") {
                send_http_response(static_cast<uintptr_t>(client),
                                   204, "No Content", "");
                close_socket(static_cast<uintptr_t>(client));
                continue;
            }

            // Check authentication (rpcuser:rpcpassword or cookie)
            if (!check_auth(http_req.auth_header)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                send_http_response(static_cast<uintptr_t>(client),
                                   401, "Unauthorized",
                                   R"({"error":"Unauthorized"})",
                                   "application/json");
                close_socket(static_cast<uintptr_t>(client));
                continue;
            }

            // Only accept POST
            if (http_req.method != "POST") {
                send_http_response(static_cast<uintptr_t>(client),
                                   405, "Method Not Allowed",
                                   R"({"error":"Only POST method accepted"})");
                close_socket(static_cast<uintptr_t>(client));
                continue;
            }

            // Enqueue for processing
            PendingRequest pending;
            pending.client_socket = static_cast<uintptr_t>(client);
            pending.body = std::move(http_req.body);
            pending.received_at = core::get_time_millis();

            if (!request_queue_.try_send(std::move(pending))) {
                send_http_response(static_cast<uintptr_t>(client),
                                   503, "Service Unavailable",
                                   R"({"error":"Server overloaded"})");
                close_socket(static_cast<uintptr_t>(client));
            }
        } catch (const std::exception& e) {
            // Silently drop — connection closed by client (common with rate-limited or scanning IPs)
            close_socket(static_cast<uintptr_t>(client));
        }
    }
}

// ===========================================================================
// Worker loop
// ===========================================================================

void RpcServer::worker_loop(std::stop_token stoken) {
    while (!stoken.stop_requested()) {
        auto pending_opt = request_queue_.try_receive_for(
            std::chrono::milliseconds(500));

        if (!pending_opt) {
            if (request_queue_.is_closed()) break;
            continue;
        }

        PendingRequest& pending = *pending_opt;
        uintptr_t client = pending.client_socket;

        try {
            RpcResponse resp = process_request(pending.body);
            std::string json_resp = resp.serialize();
            send_http_response(client, 200, "OK", json_resp);
        } catch (const std::exception& e) {
            LOG_ERROR(core::LogCategory::RPC,
                      std::string("RPC processing error: ") + e.what());
            RpcResponse err = make_error(RpcError::INTERNAL_ERROR,
                                         std::string("Internal error: ") + e.what());
            send_http_response(client, 500, "Internal Server Error",
                               err.serialize());
        }

        close_socket(client);
    }
}

// ===========================================================================
// HTTP request reading
// ===========================================================================

RpcServer::HttpRequest RpcServer::read_http_request(uintptr_t sock) {
    // Read data from socket until we have the full headers + body
    std::string buffer;
    buffer.reserve(4096);

    char recv_buf[4096];
    size_t header_end = std::string::npos;
    int64_t content_length = -1;

    while (true) {
        int n = ::recv(static_cast<socket_t>(sock), recv_buf, sizeof(recv_buf), 0);
        if (n <= 0) {
            throw std::runtime_error("Connection closed during HTTP read");
        }
        buffer.append(recv_buf, static_cast<size_t>(n));

        // Look for end of headers
        if (header_end == std::string::npos) {
            header_end = buffer.find("\r\n\r\n");
            if (header_end == std::string::npos) {
                if (buffer.size() > 64 * 1024) {
                    throw std::runtime_error("HTTP headers too large");
                }
                continue;
            }
            header_end += 4; // skip the \r\n\r\n
        }

        // Parse Content-Length from headers
        if (content_length < 0) {
            std::string headers_str = buffer.substr(0, header_end);
            // Case-insensitive search for Content-Length
            std::string headers_lower = headers_str;
            std::transform(headers_lower.begin(), headers_lower.end(),
                           headers_lower.begin(), ::tolower);
            size_t cl_pos = headers_lower.find("content-length:");
            if (cl_pos != std::string::npos) {
                size_t val_start = cl_pos + 15; // len("content-length:")
                size_t val_end = headers_lower.find("\r\n", val_start);
                std::string cl_str = headers_str.substr(val_start,
                    val_end != std::string::npos ? val_end - val_start : std::string::npos);
                // Trim whitespace
                size_t first = cl_str.find_first_not_of(" \t");
                if (first != std::string::npos) {
                    cl_str = cl_str.substr(first);
                }
                try {
                    content_length = std::stoll(cl_str);
                } catch (...) {
                    content_length = 0;
                }
            } else {
                content_length = 0;
            }

            if (static_cast<size_t>(content_length) > config_.max_request_size) {
                throw std::runtime_error("Request body too large");
            }
        }

        // Check if we have the full body
        size_t body_received = buffer.size() - header_end;
        if (static_cast<int64_t>(body_received) >= content_length) {
            break;
        }
    }

    // Parse the request line and headers
    HttpRequest req;

    // Request line: "POST / HTTP/1.1\r\n"
    size_t line_end = buffer.find("\r\n");
    if (line_end == std::string::npos) {
        throw std::runtime_error("Malformed HTTP request");
    }
    std::string request_line = buffer.substr(0, line_end);

    // Parse method
    size_t space1 = request_line.find(' ');
    if (space1 == std::string::npos) {
        throw std::runtime_error("Malformed HTTP request line");
    }
    req.method = request_line.substr(0, space1);

    // Parse path
    size_t space2 = request_line.find(' ', space1 + 1);
    if (space2 != std::string::npos) {
        req.path = request_line.substr(space1 + 1, space2 - space1 - 1);
    }

    // Parse headers
    std::string headers_section = buffer.substr(line_end + 2, header_end - line_end - 4);
    std::istringstream header_stream(headers_section);
    std::string header_line;
    while (std::getline(header_stream, header_line)) {
        if (!header_line.empty() && header_line.back() == '\r') {
            header_line.pop_back();
        }
        if (header_line.empty()) continue;

        size_t colon = header_line.find(':');
        if (colon == std::string::npos) continue;

        std::string name = header_line.substr(0, colon);
        std::string value = header_line.substr(colon + 1);

        // Trim whitespace from value
        size_t val_start = value.find_first_not_of(" \t");
        if (val_start != std::string::npos) {
            value = value.substr(val_start);
        }

        // Case-insensitive header comparison
        std::string name_lower = name;
        std::transform(name_lower.begin(), name_lower.end(),
                       name_lower.begin(), ::tolower);

        if (name_lower == "authorization") {
            req.auth_header = value;
        } else if (name_lower == "content-type") {
            req.content_type = value;
        } else if (name_lower == "connection") {
            std::string val_lower = value;
            std::transform(val_lower.begin(), val_lower.end(),
                           val_lower.begin(), ::tolower);
            req.keep_alive = (val_lower == "keep-alive");
        }
    }

    // Extract body
    req.body = buffer.substr(header_end,
                              static_cast<size_t>(content_length));

    return req;
}

// ===========================================================================
// HTTP response sending
// ===========================================================================

void RpcServer::send_http_response(uintptr_t sock, int status_code,
                                    const std::string& status_text,
                                    const std::string& body,
                                    const std::string& content_type) {
    std::string response;
    response.reserve(body.size() + 256);
    response += "HTTP/1.1 ";
    response += std::to_string(status_code);
    response += " ";
    response += status_text;
    response += "\r\n";
    response += "Content-Type: ";
    response += content_type;
    response += "\r\n";
    response += "Content-Length: ";
    response += std::to_string(body.size());
    response += "\r\n";
    response += "Connection: close\r\n";
    response += "Server: FTC-RPC/1.0\r\n";
    response += "Access-Control-Allow-Origin: *\r\n";
    response += "Access-Control-Allow-Methods: POST, OPTIONS\r\n";
    response += "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";
    response += "\r\n";
    response += body;

    const char* data = response.c_str();
    size_t total = response.size();
    size_t sent = 0;

    while (sent < total) {
        int n = ::send(static_cast<socket_t>(sock),
                       data + sent,
                       static_cast<int>(std::min(total - sent, size_t(65536))),
                       0);
        if (n <= 0) break;
        sent += static_cast<size_t>(n);
    }
}

// ===========================================================================
// Request processing
// ===========================================================================

RpcResponse RpcServer::process_request(const std::string& body) {
    // Parse JSON
    JsonValue json_val;
    try {
        json_val = parse_json(body);
    } catch (const std::exception& e) {
        return make_error(RpcError::PARSE_ERROR,
                          std::string("JSON parse error: ") + e.what());
    }

    // Handle batch requests (JSON array)
    if (json_val.is_array()) {
        const auto& arr = json_val.get_array();
        if (arr.empty()) {
            return make_error(RpcError::INVALID_REQUEST, "Empty batch request");
        }
        // Process first request only for now (batch support could be extended)
        // For simplicity, process each and return array -- but we return single
        // response wrapping all results
        JsonValue::Array results;
        for (const auto& item : arr) {
            try {
                RpcRequest rpc_req = RpcRequest::from_json(item);
                std::lock_guard lock(commands_mutex_);
                auto it = commands_.find(rpc_req.method);
                if (it == commands_.end()) {
                    results.push_back(
                        make_error(RpcError::METHOD_NOT_FOUND,
                                   "Method not found: " + rpc_req.method,
                                   rpc_req.id).to_json());
                } else {
                    try {
                        auto resp = it->second.handler(rpc_req);
                        results.push_back(resp.to_json());
                    } catch (const std::exception& ex) {
                        results.push_back(
                            make_error(RpcError::INTERNAL_ERROR, ex.what(),
                                       rpc_req.id).to_json());
                    }
                }
            } catch (const std::exception& ex) {
                results.push_back(
                    make_error(RpcError::INVALID_REQUEST, ex.what()).to_json());
            }
        }
        // Return a "batch response" -- wrap in special format
        RpcResponse batch_resp;
        batch_resp.result = JsonValue(std::move(results));
        batch_resp.error  = JsonValue(nullptr);
        batch_resp.id     = 0;
        return batch_resp;
    }

    // Single request
    RpcRequest rpc_req;
    try {
        rpc_req = RpcRequest::from_json(json_val);
    } catch (const std::exception& e) {
        return make_error(RpcError::INVALID_REQUEST,
                          std::string("Invalid request: ") + e.what());
    }

    LOG_DEBUG(core::LogCategory::RPC,
              "RPC call: " + rpc_req.method);

    // Look up handler
    RpcHandler handler;
    {
        std::lock_guard lock(commands_mutex_);
        auto it = commands_.find(rpc_req.method);
        if (it == commands_.end()) {
            return make_error(RpcError::METHOD_NOT_FOUND,
                              "Method not found: " + rpc_req.method,
                              rpc_req.id);
        }
        handler = it->second.handler;
    }

    // Execute handler
    try {
        return handler(rpc_req);
    } catch (const std::runtime_error& e) {
        return make_error(RpcError::MISC_ERROR, e.what(), rpc_req.id);
    } catch (const std::exception& e) {
        return make_error(RpcError::INTERNAL_ERROR,
                          std::string("Internal error: ") + e.what(),
                          rpc_req.id);
    }
}

// ===========================================================================
// Socket helpers
// ===========================================================================

void RpcServer::close_socket(uintptr_t sock) {
    if (sock != static_cast<uintptr_t>(~0)) {
        CLOSE_SOCKET(static_cast<socket_t>(sock));
    }
}

// ===========================================================================
// IP allowlist
// ===========================================================================

bool RpcServer::is_client_allowed(uint32_t ipv4_host_order) const {
    // Loopback (127.x.x.x) is always allowed.
    if ((ipv4_host_order >> 24) == 127) return true;

    // If allowlist is configured, check against it.
    if (!config_.allowed_subnets.empty()) {
        auto addr = net::NetAddress::from_ipv4(ipv4_host_order);
        for (const auto& subnet : config_.allowed_subnets) {
            if (subnet.contains(addr)) return true;
        }
        return false;
    }

    // No allowlist: only allow if we're bound to localhost.
    if (config_.bind_address == "127.0.0.1" || config_.bind_address == "::1") {
        return true;
    }

    // Bound to 0.0.0.0 with no allowlist — reject non-loopback.
    return false;
}

// ===========================================================================
// Authentication
// ===========================================================================

bool RpcServer::check_auth(std::string_view auth_header) const {
    // If no auth is configured at all (no user/pass, no cookie), allow.
    bool has_creds = !config_.rpc_user.empty() || !config_.rpc_password.empty();
    bool has_cookie = !cookie_credentials_.empty();
    if (!has_creds && !has_cookie) return true;

    if (auth_header.empty()) return false;

    // Try rpcuser:rpcpassword first
    if (has_creds) {
        if (verify_auth(auth_header, config_.rpc_user, config_.rpc_password)) {
            return true;
        }
    }

    // Try cookie auth: "__cookie__:HEXVALUE"
    if (has_cookie) {
        if (verify_auth(auth_header, "__cookie__", cookie_credentials_)) {
            return true;
        }
    }

    return false;
}

void RpcServer::generate_cookie() {
    if (!config_.rpc_user.empty() || !config_.rpc_password.empty()) {
        // Explicit credentials configured — skip cookie generation.
        return;
    }
    if (config_.data_dir.empty()) {
        LOG_WARN(core::LogCategory::RPC,
                 "No data directory set, skipping cookie auth generation");
        return;
    }

    // Generate 32 random bytes → 64 hex chars.
    auto random_bytes = core::get_random_bytes_vec(32);
    std::string hex_cookie = core::to_hex(random_bytes);

    cookie_credentials_ = hex_cookie;
    cookie_file_path_ = (std::filesystem::path(config_.data_dir) / ".cookie").string();

    // Write cookie file: "__cookie__:HEXVALUE"
    std::ofstream ofs(cookie_file_path_, std::ios::trunc);
    if (ofs.is_open()) {
        ofs << "__cookie__:" << hex_cookie;
        ofs.close();
        LOG_INFO(core::LogCategory::RPC,
                 "RPC cookie authentication file written to " + cookie_file_path_);
    } else {
        LOG_WARN(core::LogCategory::RPC,
                 "Failed to write cookie file: " + cookie_file_path_);
    }
}

void RpcServer::delete_cookie() {
    if (!cookie_file_path_.empty()) {
        std::error_code ec;
        std::filesystem::remove(cookie_file_path_, ec);
        cookie_file_path_.clear();
        cookie_credentials_.clear();
    }
}

} // namespace rpc
