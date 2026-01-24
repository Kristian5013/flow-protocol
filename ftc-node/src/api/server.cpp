#include "api/server.h"
#include "api/handlers.h"
#include "api/routes/routes.h"
#include "util/logging.h"
#include "chain/chain.h"
#include "chain/block.h"
#include "chain/transaction.h"
#include "chain/mempool.h"
#include "chain/utxo_set.h"
#include "p2p/peer_manager.h"
#include "p2pool/p2pool_net.h"
#include "crypto/keccak256.h"
#include "crypto/secp256k1.h"
#include "crypto/bech32.h"
#include "chain/genesis.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <optional>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#endif

namespace ftc {
namespace api {

// Helper functions for Hash256 operations
static std::string hashToHex(const crypto::Hash256& hash) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (const auto& byte : hash) {
        result += hex_chars[(byte >> 4) & 0x0F];
        result += hex_chars[byte & 0x0F];
    }
    return result;
}

static bool hexToHash(const std::string& hex, crypto::Hash256& hash) {
    if (hex.size() != 64) {
        return false;
    }
    auto hexCharToNibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < 32; ++i) {
        int hi = hexCharToNibble(hex[i * 2]);
        int lo = hexCharToNibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        hash[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

static std::string bytesToHex(const std::vector<uint8_t>& data) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (uint8_t byte : data) {
        result += hex_chars[(byte >> 4) & 0x0F];
        result += hex_chars[byte & 0x0F];
    }
    return result;
}

//-----------------------------------------------------------------------------
// HttpRequest implementation
//-----------------------------------------------------------------------------

std::string HttpRequest::getHeader(const std::string& name) const {
    // Case-insensitive header lookup
    std::string lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

    for (const auto& pair : headers) {
        std::string lower_key = pair.first;
        std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), ::tolower);
        if (lower_key == lower_name) {
            return pair.second;
        }
    }
    return "";
}

std::string HttpRequest::getQueryParam(const std::string& name, const std::string& default_val) const {
    auto it = query_params.find(name);
    return (it != query_params.end()) ? it->second : default_val;
}

std::string HttpRequest::getPathParam(const std::string& name) const {
    auto it = path_params.find(name);
    return (it != path_params.end()) ? it->second : "";
}

bool HttpRequest::isJson() const {
    std::string ct = getHeader("Content-Type");
    return ct.find("application/json") != std::string::npos;
}

//-----------------------------------------------------------------------------
// HttpResponse implementation
//-----------------------------------------------------------------------------

void HttpResponse::json(const std::string& json_str) {
    status = HttpStatus::OK;
    headers["Content-Type"] = "application/json; charset=utf-8";
    body = json_str;
}

void HttpResponse::error(HttpStatus code, const std::string& message) {
    status = code;
    headers["Content-Type"] = "application/json; charset=utf-8";

    JsonBuilder json;
    json.beginObject()
        .key("error").value(true)
        .key("code").value(static_cast<int64_t>(code))
        .key("message").value(message)
        .endObject();
    body = json.build();
}

void HttpResponse::success(const std::string& json_str) {
    status = HttpStatus::OK;
    headers["Content-Type"] = "application/json; charset=utf-8";
    body = json_str;
}

std::string HttpResponse::build() const {
    std::ostringstream oss;

    // Status line
    oss << "HTTP/1.1 " << static_cast<int>(status) << " ";
    switch (status) {
        case HttpStatus::OK: oss << "OK"; break;
        case HttpStatus::CREATED: oss << "Created"; break;
        case HttpStatus::ACCEPTED: oss << "Accepted"; break;
        case HttpStatus::NO_CONTENT: oss << "No Content"; break;
        case HttpStatus::BAD_REQUEST: oss << "Bad Request"; break;
        case HttpStatus::UNAUTHORIZED: oss << "Unauthorized"; break;
        case HttpStatus::FORBIDDEN: oss << "Forbidden"; break;
        case HttpStatus::NOT_FOUND: oss << "Not Found"; break;
        case HttpStatus::METHOD_NOT_ALLOWED: oss << "Method Not Allowed"; break;
        case HttpStatus::INTERNAL_ERROR: oss << "Internal Server Error"; break;
        case HttpStatus::NOT_IMPLEMENTED: oss << "Not Implemented"; break;
        case HttpStatus::SERVICE_UNAVAILABLE: oss << "Service Unavailable"; break;
        default: oss << "Unknown"; break;
    }
    oss << "\r\n";

    // Headers
    for (const auto& h : headers) {
        oss << h.first << ": " << h.second << "\r\n";
    }

    // Content-Length (if body present)
    if (!body.empty()) {
        oss << "Content-Length: " << body.size() << "\r\n";
    }

    // Server header
    oss << "Server: FTC/1.0\r\n";
    oss << "Connection: close\r\n";

    // End headers
    oss << "\r\n";

    // Body
    oss << body;

    return oss.str();
}

//-----------------------------------------------------------------------------
// Route implementation
//-----------------------------------------------------------------------------

bool Route::match(const std::string& path, std::map<std::string, std::string>& params) const {
    params.clear();

    // Split pattern and path into segments
    std::vector<std::string> pattern_parts, path_parts;

    auto split = [](const std::string& s, char delim) {
        std::vector<std::string> parts;
        std::string part;
        for (char c : s) {
            if (c == delim) {
                if (!part.empty()) {
                    parts.push_back(part);
                    part.clear();
                }
            } else {
                part += c;
            }
        }
        if (!part.empty()) {
            parts.push_back(part);
        }
        return parts;
    };

    pattern_parts = split(pattern, '/');
    path_parts = split(path, '/');

    // Must have same number of segments
    if (pattern_parts.size() != path_parts.size()) {
        return false;
    }

    // Match each segment
    for (size_t i = 0; i < pattern_parts.size(); ++i) {
        const std::string& p = pattern_parts[i];
        const std::string& v = path_parts[i];

        if (!p.empty() && p[0] == ':') {
            // Parameter segment - extract name and value
            std::string param_name = p.substr(1);
            params[param_name] = v;
        } else if (p != v) {
            // Literal segment must match exactly
            return false;
        }
    }

    return true;
}

//-----------------------------------------------------------------------------
// HttpConnection implementation
//-----------------------------------------------------------------------------

bool HttpConnection::parseRequest() {
    // Look for end of headers
    size_t header_end = read_buffer.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        return false;  // Need more data
    }

    // Parse request line
    size_t first_line_end = read_buffer.find("\r\n");
    std::string request_line = read_buffer.substr(0, first_line_end);

    // Split request line: METHOD PATH HTTP/VERSION
    std::istringstream iss(request_line);
    std::string method_str, path_and_query, version;
    iss >> method_str >> path_and_query >> version;

    pending_request.method = Server::parseMethod(method_str);

    // Split path and query string
    size_t query_pos = path_and_query.find('?');
    if (query_pos != std::string::npos) {
        pending_request.path = path_and_query.substr(0, query_pos);
        pending_request.query_string = path_and_query.substr(query_pos + 1);
        pending_request.query_params = Server::parseQueryString(pending_request.query_string);
    } else {
        pending_request.path = path_and_query;
    }

    // URL decode path
    pending_request.path = Server::urlDecode(pending_request.path);

    // Parse headers
    std::string headers_section = read_buffer.substr(first_line_end + 2, header_end - first_line_end - 2);
    std::istringstream header_stream(headers_section);
    std::string line;
    while (std::getline(header_stream, line)) {
        // Remove trailing \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) continue;

        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = line.substr(0, colon);
            std::string value = line.substr(colon + 1);
            // Trim leading whitespace from value
            while (!value.empty() && (value[0] == ' ' || value[0] == '\t')) {
                value = value.substr(1);
            }
            pending_request.headers[name] = value;
        }
    }

    // Check for body
    std::string content_length_str = pending_request.getHeader("Content-Length");
    size_t content_length = 0;
    if (!content_length_str.empty()) {
        content_length = std::stoull(content_length_str);
    }

    size_t body_start = header_end + 4;
    size_t available_body = read_buffer.size() - body_start;

    if (available_body < content_length) {
        return false;  // Need more data
    }

    // Extract body
    if (content_length > 0) {
        pending_request.body = read_buffer.substr(body_start, content_length);
    }

    // Remove processed data from buffer
    read_buffer = read_buffer.substr(body_start + content_length);

    pending_request.remote_addr = remote_addr;
    request_complete = true;
    return true;
}

void HttpConnection::close() {
    if (socket != INVALID_SOCKET) {
#ifdef _WIN32
        ::closesocket(socket);
#else
        ::close(socket);
#endif
        socket = INVALID_SOCKET;
    }
}

//-----------------------------------------------------------------------------
// Server implementation
//-----------------------------------------------------------------------------

Server::Server() : Server(Config{}) {}

Server::Server(const Config& config) : config_(config) {
#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif
}

Server::~Server() {
    stop();
#ifdef _WIN32
    WSACleanup();
#endif
}

bool Server::start() {
    if (running_) {
        return true;
    }

    // Create IPv6 socket (IPv6 only)
    listen_socket_ = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket_ == INVALID_SOCKET) {
        return false;
    }

    // Allow address reuse
    int opt = 1;
#ifdef _WIN32
    setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    // IPv6 only (no IPv4-mapped addresses)
    int ipv6only = 1;
#ifdef _WIN32
    setsockopt(listen_socket_, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&ipv6only, sizeof(ipv6only));
#else
    setsockopt(listen_socket_, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));
#endif

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(config_.port);

    // Parse IPv6 bind address from config
    if (inet_pton(AF_INET6, config_.host.c_str(), &addr.sin6_addr) != 1) {
        addr.sin6_addr = in6addr_loopback;  // Default to ::1 (localhost)
    }

    if (bind(listen_socket_, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
#ifdef _WIN32
        LOG_ERROR("API bind failed on [{}]:{} - error {}", config_.host, config_.port, WSAGetLastError());
#else
        LOG_ERROR("API bind failed on [{}]:{}", config_.host, config_.port);
#endif
        closesocket(listen_socket_);
        listen_socket_ = INVALID_SOCKET;
        return false;
    }

    if (listen(listen_socket_, SOMAXCONN) == SOCKET_ERROR) {
        LOG_ERROR("API listen failed");
        closesocket(listen_socket_);
        listen_socket_ = INVALID_SOCKET;
        return false;
    }

    // Set non-blocking
#ifdef _WIN32
    unsigned long mode = 1;
    ioctlsocket(listen_socket_, FIONBIO, &mode);
#else
    int flags = fcntl(listen_socket_, F_GETFL, 0);
    fcntl(listen_socket_, F_SETFL, flags | O_NONBLOCK);
#endif

    // Setup default API routes
    setupRoutes();

    running_ = true;
    stopping_ = false;

    // Start server thread
    server_thread_ = std::thread(&Server::serverThread, this);

    return true;
}

void Server::stop() {
    if (!running_) {
        return;
    }

    stopping_ = true;
    running_ = false;

    // Close listen socket
    if (listen_socket_ != INVALID_SOCKET) {
        closesocket(listen_socket_);
        listen_socket_ = INVALID_SOCKET;
    }

    // Wait for server thread
    if (server_thread_.joinable()) {
        server_thread_.join();
    }

    // Close all connections
    std::lock_guard<std::mutex> lock(conn_mutex_);
    for (auto& pair : connections_) {
        pair.second.close();
    }
    connections_.clear();
}

void Server::get(const std::string& pattern, RouteHandler handler) {
    addRoute(HttpMethod::GET, pattern, handler);
}

void Server::post(const std::string& pattern, RouteHandler handler) {
    addRoute(HttpMethod::POST, pattern, handler);
}

void Server::put(const std::string& pattern, RouteHandler handler) {
    addRoute(HttpMethod::PUT, pattern, handler);
}

void Server::del(const std::string& pattern, RouteHandler handler) {
    addRoute(HttpMethod::DELETE, pattern, handler);
}

void Server::addRoute(HttpMethod method, const std::string& pattern, RouteHandler handler) {
    Route route;
    route.method = method;
    route.pattern = pattern;
    route.handler = handler;

    // Extract parameter names from pattern
    std::string part;
    for (char c : pattern) {
        if (c == '/') {
            if (!part.empty() && part[0] == ':') {
                route.param_names.push_back(part.substr(1));
            }
            part.clear();
        } else {
            part += c;
        }
    }
    if (!part.empty() && part[0] == ':') {
        route.param_names.push_back(part.substr(1));
    }

    std::lock_guard<std::mutex> lock(routes_mutex_);
    routes_.push_back(std::move(route));
}

Route* Server::findRoute(HttpMethod method, const std::string& path,
                         std::map<std::string, std::string>& params) {
    std::lock_guard<std::mutex> lock(routes_mutex_);

    for (auto& route : routes_) {
        if (route.method == method && route.match(path, params)) {
            return &route;
        }
    }
    return nullptr;
}

void Server::serverThread() {
    while (running_ && !stopping_) {
        // Accept new connections
        acceptConnections();

        // Process existing connections
        processConnections();

        // Cleanup timed-out connections
        cleanupConnections();

        // Small sleep to prevent busy-waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void Server::acceptConnections() {
    if (listen_socket_ == INVALID_SOCKET) {
        return;
    }

    // IPv6 socket
    sockaddr_in6 client_addr{};
    socklen_t addr_len = sizeof(client_addr);

    socket_t client_socket = accept(listen_socket_, (sockaddr*)&client_addr, &addr_len);
    if (client_socket == INVALID_SOCKET) {
        return;  // No pending connection or error
    }

    // Check connection limit
    {
        std::lock_guard<std::mutex> lock(conn_mutex_);
        if (connections_.size() >= config_.max_connections) {
            closesocket(client_socket);
            return;
        }
    }

    // Set non-blocking
#ifdef _WIN32
    unsigned long mode = 1;
    ioctlsocket(client_socket, FIONBIO, &mode);
#else
    int flags = fcntl(client_socket, F_GETFL, 0);
    fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);
#endif

    // Create connection
    HttpConnection conn;
    conn.socket = client_socket;
    conn.last_activity = std::chrono::steady_clock::now();

    // Get remote IPv6 address
    char addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &client_addr.sin6_addr, addr_str, sizeof(addr_str));
    conn.remote_addr = addr_str;

    std::lock_guard<std::mutex> lock(conn_mutex_);
    connections_[client_socket] = std::move(conn);
}

void Server::processConnections() {
    std::lock_guard<std::mutex> lock(conn_mutex_);

    for (auto& pair : connections_) {
        HttpConnection& conn = pair.second;

        if (conn.socket == INVALID_SOCKET) {
            continue;
        }

        // Read available data
        char buffer[4096];
        int bytes = recv(conn.socket, buffer, sizeof(buffer), 0);

        if (bytes > 0) {
            conn.read_buffer.append(buffer, bytes);
            conn.last_activity = std::chrono::steady_clock::now();

            // Check request size limit
            if (conn.read_buffer.size() > config_.max_request_size) {
                HttpResponse response;
                response.error(HttpStatus::BAD_REQUEST, "Request too large");
                sendResponse(conn, response);
                conn.close();
                continue;
            }

            // Try to parse request
            if (conn.parseRequest()) {
                handleRequest(conn);
            }
        } else if (bytes == 0) {
            // Connection closed by client
            conn.close();
        }
#ifdef _WIN32
        else if (WSAGetLastError() != WSAEWOULDBLOCK) {
            conn.close();
        }
#else
        else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            conn.close();
        }
#endif

        // Send any pending write data
        if (!conn.write_buffer.empty() && conn.socket != INVALID_SOCKET) {
            int sent = send(conn.socket, conn.write_buffer.c_str(),
                           static_cast<int>(conn.write_buffer.size()), 0);
            if (sent > 0) {
                conn.write_buffer = conn.write_buffer.substr(sent);
            }
        }
    }
}

void Server::handleRequest(HttpConnection& conn) {
    request_count_++;

    HttpResponse response;

    // Handle CORS preflight if enabled
    if (config_.enable_cors && conn.pending_request.method == HttpMethod::OPTIONS) {
        response.status = HttpStatus::OK;
        response.headers["Access-Control-Allow-Origin"] = "*";
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
        response.headers["Access-Control-Max-Age"] = "86400";
        sendResponse(conn, response);
        return;
    }

    // Find matching route
    std::map<std::string, std::string> params;
    Route* route = findRoute(conn.pending_request.method, conn.pending_request.path, params);

    if (route) {
        conn.pending_request.path_params = params;

        try {
            route->handler(conn.pending_request, response);
        } catch (const std::exception& e) {
            error_count_++;
            response.error(HttpStatus::INTERNAL_ERROR, std::string("Internal error: ") + e.what());
        }
    } else {
        response.error(HttpStatus::NOT_FOUND, "Endpoint not found: " + conn.pending_request.path);
    }

    // Add CORS headers if enabled
    if (config_.enable_cors) {
        response.headers["Access-Control-Allow-Origin"] = "*";
    }

    sendResponse(conn, response);
}

void Server::sendResponse(HttpConnection& conn, const HttpResponse& response) {
    std::string raw = response.build();
    conn.write_buffer += raw;

    // Try to send immediately
    if (conn.socket != INVALID_SOCKET && !conn.write_buffer.empty()) {
        int sent = send(conn.socket, conn.write_buffer.c_str(),
                       static_cast<int>(conn.write_buffer.size()), 0);
        if (sent > 0) {
            conn.write_buffer = conn.write_buffer.substr(sent);
        }
    }

    // Close connection after response (HTTP/1.0 style for simplicity)
    // Keep-alive would require more complex state management
    if (conn.write_buffer.empty()) {
        conn.close();
    }

    // Reset for next request
    conn.request_complete = false;
    conn.pending_request = HttpRequest{};
}

void Server::cleanupConnections() {
    auto now = std::chrono::steady_clock::now();

    std::lock_guard<std::mutex> lock(conn_mutex_);

    for (auto it = connections_.begin(); it != connections_.end();) {
        HttpConnection& conn = it->second;

        // Check for closed sockets
        if (conn.socket == INVALID_SOCKET) {
            it = connections_.erase(it);
            continue;
        }

        // Check for timeout
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - conn.last_activity);

        if (elapsed > config_.timeout) {
            conn.close();
            it = connections_.erase(it);
            continue;
        }

        ++it;
    }
}

HttpMethod Server::parseMethod(const std::string& method) {
    if (method == "GET") return HttpMethod::GET;
    if (method == "POST") return HttpMethod::POST;
    if (method == "PUT") return HttpMethod::PUT;
    if (method == "DELETE") return HttpMethod::DELETE;
    if (method == "OPTIONS") return HttpMethod::OPTIONS;
    return HttpMethod::UNKNOWN;
}

std::string Server::methodToString(HttpMethod method) {
    switch (method) {
        case HttpMethod::GET: return "GET";
        case HttpMethod::POST: return "POST";
        case HttpMethod::PUT: return "PUT";
        case HttpMethod::DELETE: return "DELETE";
        case HttpMethod::OPTIONS: return "OPTIONS";
        default: return "UNKNOWN";
    }
}

std::string Server::statusToString(HttpStatus status) {
    switch (status) {
        case HttpStatus::OK: return "OK";
        case HttpStatus::CREATED: return "Created";
        case HttpStatus::ACCEPTED: return "Accepted";
        case HttpStatus::NO_CONTENT: return "No Content";
        case HttpStatus::BAD_REQUEST: return "Bad Request";
        case HttpStatus::UNAUTHORIZED: return "Unauthorized";
        case HttpStatus::FORBIDDEN: return "Forbidden";
        case HttpStatus::NOT_FOUND: return "Not Found";
        case HttpStatus::METHOD_NOT_ALLOWED: return "Method Not Allowed";
        case HttpStatus::INTERNAL_ERROR: return "Internal Server Error";
        case HttpStatus::NOT_IMPLEMENTED: return "Not Implemented";
        case HttpStatus::SERVICE_UNAVAILABLE: return "Service Unavailable";
        default: return "Unknown";
    }
}

std::map<std::string, std::string> Server::parseQueryString(const std::string& qs) {
    std::map<std::string, std::string> params;

    size_t pos = 0;
    while (pos < qs.size()) {
        size_t amp = qs.find('&', pos);
        if (amp == std::string::npos) amp = qs.size();

        std::string pair = qs.substr(pos, amp - pos);
        size_t eq = pair.find('=');

        if (eq != std::string::npos) {
            std::string key = urlDecode(pair.substr(0, eq));
            std::string value = urlDecode(pair.substr(eq + 1));
            params[key] = value;
        } else {
            params[urlDecode(pair)] = "";
        }

        pos = amp + 1;
    }

    return params;
}

std::string Server::urlDecode(const std::string& str) {
    std::string result;
    result.reserve(str.size());

    for (size_t i = 0; i < str.size(); ++i) {
        if (str[i] == '%' && i + 2 < str.size()) {
            int value;
            std::istringstream iss(str.substr(i + 1, 2));
            if (iss >> std::hex >> value) {
                result += static_cast<char>(value);
                i += 2;
            } else {
                result += str[i];
            }
        } else if (str[i] == '+') {
            result += ' ';
        } else {
            result += str[i];
        }
    }

    return result;
}

//-----------------------------------------------------------------------------
// JsonBuilder implementation
//-----------------------------------------------------------------------------

JsonBuilder& JsonBuilder::beginObject() {
    maybeComma();
    buffer_ += '{';
    need_comma_ = false;
    depth_++;
    return *this;
}

JsonBuilder& JsonBuilder::endObject() {
    buffer_ += '}';
    need_comma_ = true;
    depth_--;
    return *this;
}

JsonBuilder& JsonBuilder::beginArray() {
    maybeComma();
    buffer_ += '[';
    need_comma_ = false;
    depth_++;
    return *this;
}

JsonBuilder& JsonBuilder::endArray() {
    buffer_ += ']';
    need_comma_ = true;
    depth_--;
    return *this;
}

JsonBuilder& JsonBuilder::key(const std::string& k) {
    maybeComma();
    buffer_ += '"';
    buffer_ += escapeString(k);
    buffer_ += "\":";
    need_comma_ = false;
    return *this;
}

JsonBuilder& JsonBuilder::value(const std::string& v) {
    maybeComma();
    buffer_ += '"';
    buffer_ += escapeString(v);
    buffer_ += '"';
    need_comma_ = true;
    return *this;
}

JsonBuilder& JsonBuilder::value(const char* v) {
    maybeComma();
    buffer_ += '"';
    buffer_ += escapeString(v ? v : "");
    buffer_ += '"';
    need_comma_ = true;
    return *this;
}

JsonBuilder& JsonBuilder::value(int64_t v) {
    maybeComma();
    buffer_ += std::to_string(v);
    need_comma_ = true;
    return *this;
}

JsonBuilder& JsonBuilder::value(uint64_t v) {
    maybeComma();
    buffer_ += std::to_string(v);
    need_comma_ = true;
    return *this;
}

JsonBuilder& JsonBuilder::value(double v) {
    maybeComma();
    std::ostringstream oss;
    oss << std::setprecision(15) << v;
    buffer_ += oss.str();
    need_comma_ = true;
    return *this;
}

JsonBuilder& JsonBuilder::value(bool v) {
    maybeComma();
    buffer_ += v ? "true" : "false";
    need_comma_ = true;
    return *this;
}

JsonBuilder& JsonBuilder::nullValue() {
    maybeComma();
    buffer_ += "null";
    need_comma_ = true;
    return *this;
}

JsonBuilder& JsonBuilder::rawValue(const std::string& raw) {
    maybeComma();
    buffer_ += raw;
    need_comma_ = true;
    return *this;
}

void JsonBuilder::maybeComma() {
    if (need_comma_) {
        buffer_ += ',';
    }
}

std::string JsonBuilder::escapeString(const std::string& s) const {
    std::string result;
    result.reserve(s.size());

    for (char c : s) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    std::ostringstream oss;
                    oss << "\\u" << std::hex << std::setfill('0')
                        << std::setw(4) << static_cast<int>(c);
                    result += oss.str();
                } else {
                    result += c;
                }
                break;
        }
    }

    return result;
}

//-----------------------------------------------------------------------------
// JsonParser implementation
//-----------------------------------------------------------------------------

JsonParser::JsonParser(const std::string& json) : json_(json) {}

bool JsonParser::parse() {
    pos_ = 0;
    values_.clear();
    valid_ = false;

    skipWhitespace();
    if (pos_ >= json_.size()) {
        return false;
    }

    valid_ = parseValue();
    return valid_;
}

void JsonParser::skipWhitespace() {
    while (pos_ < json_.size() &&
           (json_[pos_] == ' ' || json_[pos_] == '\t' ||
            json_[pos_] == '\n' || json_[pos_] == '\r')) {
        pos_++;
    }
}

bool JsonParser::parseValue() {
    skipWhitespace();
    if (pos_ >= json_.size()) return false;

    char c = json_[pos_];
    if (c == '{') {
        root_type_ = "object";
        return parseObject();
    } else if (c == '[') {
        root_type_ = "array";
        return parseArray();
    } else if (c == '"') {
        root_type_ = "string";
        std::string s;
        return parseString(s);
    } else if (c == '-' || (c >= '0' && c <= '9')) {
        root_type_ = "number";
        return parseNumber();
    } else {
        root_type_ = "literal";
        return parseLiteral();
    }
}

bool JsonParser::parseObject() {
    if (pos_ >= json_.size() || json_[pos_] != '{') return false;
    pos_++;

    skipWhitespace();
    if (pos_ < json_.size() && json_[pos_] == '}') {
        pos_++;
        return true;
    }

    while (true) {
        skipWhitespace();
        if (pos_ >= json_.size() || json_[pos_] != '"') return false;

        std::string key;
        if (!parseString(key)) return false;

        skipWhitespace();
        if (pos_ >= json_.size() || json_[pos_] != ':') return false;
        pos_++;

        skipWhitespace();

        // Store start position of value
        size_t value_start = pos_;

        // Parse the value
        if (json_[pos_] == '"') {
            std::string val;
            if (!parseString(val)) return false;
            values_[key] = val;
        } else if (json_[pos_] == '{' || json_[pos_] == '[') {
            // Skip nested objects/arrays (don't store)
            int depth = 1;
            pos_++;
            while (pos_ < json_.size() && depth > 0) {
                char c = json_[pos_];
                if (c == '{' || c == '[') depth++;
                else if (c == '}' || c == ']') depth--;
                else if (c == '"') {
                    pos_++;
                    while (pos_ < json_.size() && json_[pos_] != '"') {
                        if (json_[pos_] == '\\') pos_++;
                        pos_++;
                    }
                }
                pos_++;
            }
        } else if (json_[pos_] == '-' || (json_[pos_] >= '0' && json_[pos_] <= '9')) {
            size_t start = pos_;
            if (!parseNumber()) return false;
            values_[key] = json_.substr(start, pos_ - start);
        } else {
            size_t start = pos_;
            if (!parseLiteral()) return false;
            values_[key] = json_.substr(start, pos_ - start);
        }

        skipWhitespace();
        if (pos_ >= json_.size()) return false;

        if (json_[pos_] == '}') {
            pos_++;
            return true;
        }

        if (json_[pos_] != ',') return false;
        pos_++;
    }
}

bool JsonParser::parseArray() {
    if (pos_ >= json_.size() || json_[pos_] != '[') return false;
    pos_++;

    skipWhitespace();
    if (pos_ < json_.size() && json_[pos_] == ']') {
        pos_++;
        return true;
    }

    int index = 0;
    while (true) {
        skipWhitespace();

        // Parse value
        if (json_[pos_] == '"') {
            std::string val;
            if (!parseString(val)) return false;
            values_[std::to_string(index)] = val;
        } else {
            size_t start = pos_;
            if (!parseValue()) return false;
            // Store simple values
            if (json_[start] != '{' && json_[start] != '[') {
                values_[std::to_string(index)] = json_.substr(start, pos_ - start);
            }
        }

        index++;
        skipWhitespace();
        if (pos_ >= json_.size()) return false;

        if (json_[pos_] == ']') {
            pos_++;
            return true;
        }

        if (json_[pos_] != ',') return false;
        pos_++;
    }
}

bool JsonParser::parseString(std::string& out) {
    if (pos_ >= json_.size() || json_[pos_] != '"') return false;
    pos_++;

    out.clear();
    while (pos_ < json_.size() && json_[pos_] != '"') {
        if (json_[pos_] == '\\') {
            pos_++;
            if (pos_ >= json_.size()) return false;
            switch (json_[pos_]) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u':
                    // Unicode escape (simplified)
                    if (pos_ + 4 >= json_.size()) return false;
                    pos_ += 4;
                    out += '?';  // Simplified: just output ?
                    break;
                default: return false;
            }
        } else {
            out += json_[pos_];
        }
        pos_++;
    }

    if (pos_ >= json_.size()) return false;
    pos_++;  // Skip closing quote
    return true;
}

bool JsonParser::parseNumber() {
    size_t start = pos_;

    if (pos_ < json_.size() && json_[pos_] == '-') pos_++;

    if (pos_ >= json_.size()) return false;

    if (json_[pos_] == '0') {
        pos_++;
    } else if (json_[pos_] >= '1' && json_[pos_] <= '9') {
        while (pos_ < json_.size() && json_[pos_] >= '0' && json_[pos_] <= '9') {
            pos_++;
        }
    } else {
        return false;
    }

    // Decimal part
    if (pos_ < json_.size() && json_[pos_] == '.') {
        pos_++;
        while (pos_ < json_.size() && json_[pos_] >= '0' && json_[pos_] <= '9') {
            pos_++;
        }
    }

    // Exponent part
    if (pos_ < json_.size() && (json_[pos_] == 'e' || json_[pos_] == 'E')) {
        pos_++;
        if (pos_ < json_.size() && (json_[pos_] == '+' || json_[pos_] == '-')) {
            pos_++;
        }
        while (pos_ < json_.size() && json_[pos_] >= '0' && json_[pos_] <= '9') {
            pos_++;
        }
    }

    return pos_ > start;
}

bool JsonParser::parseLiteral() {
    if (json_.substr(pos_, 4) == "true") {
        pos_ += 4;
        return true;
    } else if (json_.substr(pos_, 5) == "false") {
        pos_ += 5;
        return true;
    } else if (json_.substr(pos_, 4) == "null") {
        pos_ += 4;
        return true;
    }
    return false;
}

bool JsonParser::isObject() const { return root_type_ == "object"; }
bool JsonParser::isArray() const { return root_type_ == "array"; }
bool JsonParser::isString() const { return root_type_ == "string"; }
bool JsonParser::isNumber() const { return root_type_ == "number"; }
bool JsonParser::isBool() const {
    return root_type_ == "literal" && (json_ == "true" || json_ == "false");
}
bool JsonParser::isNull() const {
    return root_type_ == "literal" && json_ == "null";
}

bool JsonParser::hasKey(const std::string& key) const {
    return values_.find(key) != values_.end();
}

std::string JsonParser::getString(const std::string& key, const std::string& default_val) const {
    auto it = values_.find(key);
    return (it != values_.end()) ? it->second : default_val;
}

int64_t JsonParser::getInt(const std::string& key, int64_t default_val) const {
    auto it = values_.find(key);
    if (it != values_.end()) {
        try {
            return std::stoll(it->second);
        } catch (...) {}
    }
    return default_val;
}

uint64_t JsonParser::getUint(const std::string& key, uint64_t default_val) const {
    auto it = values_.find(key);
    if (it != values_.end()) {
        try {
            return std::stoull(it->second);
        } catch (...) {}
    }
    return default_val;
}

double JsonParser::getDouble(const std::string& key, double default_val) const {
    auto it = values_.find(key);
    if (it != values_.end()) {
        try {
            return std::stod(it->second);
        } catch (...) {}
    }
    return default_val;
}

bool JsonParser::getBool(const std::string& key, bool default_val) const {
    auto it = values_.find(key);
    if (it != values_.end()) {
        return it->second == "true";
    }
    return default_val;
}

std::vector<std::string> JsonParser::getStringArray(const std::string& key) const {
    // Simplified: doesn't support nested arrays
    std::vector<std::string> result;
    for (int i = 0; ; i++) {
        auto it = values_.find(std::to_string(i));
        if (it == values_.end()) break;
        result.push_back(it->second);
    }
    return result;
}

//-----------------------------------------------------------------------------
// setupRoutes - Register all API routes via modular route handlers
// Kristian Pilatovich 20091227 - First Real P2P
//-----------------------------------------------------------------------------

void Server::setupRoutes() {
    // Create route context with all dependencies
    routes::RouteContext ctx;
    ctx.server = this;
    ctx.chain = chain_;
    ctx.mempool = mempool_;
    ctx.utxo_set = utxo_set_;
    ctx.peer_manager = peer_manager_;
    ctx.message_handler = message_handler_;
    ctx.p2pool = p2pool_;

    // Register all route modules
    routes::setupStatusRoutes(ctx);   // /, /status, /health, /genesis, /sync
    routes::setupChainRoutes(ctx);    // /block, /tx, /mempool
    routes::setupAddressRoutes(ctx);  // /balance, /utxo, /address/history, /peers
    routes::setupWalletRoutes(ctx);   // /wallet/new, /wallet/send
    routes::setupMiningRoutes(ctx);   // /mining/*
    routes::setupP2PoolRoutes(ctx);   // /p2pool/*
}

} // namespace api
} // namespace ftc
