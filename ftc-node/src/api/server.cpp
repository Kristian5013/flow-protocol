#include "api/server.h"
#include "api/handlers.h"
#include "chain/chain.h"
#include "chain/block.h"
#include "chain/transaction.h"
#include "chain/mempool.h"
#include "chain/utxo_set.h"
#include "p2p/peer_manager.h"
#include "p2pool/p2pool_net.h"
#include "crypto/keccak256.h"
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

    // Create IPv6 socket (dual-stack: supports both IPv4 and IPv6)
    listen_socket_ = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket_ == INVALID_SOCKET) {
        // Fallback to IPv4 only
        listen_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listen_socket_ == INVALID_SOCKET) {
            return false;
        }

        // IPv4 only path
        int opt = 1;
#ifdef _WIN32
        setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
        setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(listen_socket_, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            closesocket(listen_socket_);
            listen_socket_ = INVALID_SOCKET;
            return false;
        }
    } else {
        // IPv6 dual-stack path
        int opt = 1;
#ifdef _WIN32
        setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
        setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

        // Disable IPV6_ONLY to enable dual-stack (accept both IPv4 and IPv6)
        int ipv6only = 0;
#ifdef _WIN32
        setsockopt(listen_socket_, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&ipv6only, sizeof(ipv6only));
#else
        setsockopt(listen_socket_, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));
#endif

        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(config_.port);
        addr.sin6_addr = in6addr_any;  // :: (all interfaces, IPv4 + IPv6)

        if (bind(listen_socket_, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            closesocket(listen_socket_);
            listen_socket_ = INVALID_SOCKET;
            return false;
        }
    }

    if (listen(listen_socket_, SOMAXCONN) == SOCKET_ERROR) {
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

    // Use sockaddr_storage to handle both IPv4 and IPv6
    sockaddr_storage client_addr{};
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

    // Get remote address (supports both IPv4 and IPv6)
    char addr_str[INET6_ADDRSTRLEN];
    if (client_addr.ss_family == AF_INET6) {
        sockaddr_in6* addr6 = (sockaddr_in6*)&client_addr;
        inet_ntop(AF_INET6, &addr6->sin6_addr, addr_str, sizeof(addr_str));
    } else {
        sockaddr_in* addr4 = (sockaddr_in*)&client_addr;
        inet_ntop(AF_INET, &addr4->sin_addr, addr_str, sizeof(addr_str));
    }
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
// setupRoutes - Default API endpoints
//-----------------------------------------------------------------------------

void Server::setupRoutes() {
    // Root endpoint
    get("/", [](const HttpRequest& req, HttpResponse& res) {
        JsonBuilder json;
        json.beginObject()
            .key("name").value("FTC Node API")
            .key("version").value("1.0.0")
            .key("endpoints").beginArray()
                .value("/status")
                .value("/block/:id")
                .value("/tx/:txid")
                .value("/mempool")
                .value("/balance/:address")
                .value("/utxo/:address")
                .value("/peers")
                .value("/mining/template")
            .endArray()
        .endObject();
        res.success(json.build());
    });

    // Status endpoint
    get("/status", [this](const HttpRequest& req, HttpResponse& res) {
        JsonBuilder json;
        json.beginObject()
            .key("node").value("FTC Node")
            .key("version").value("1.0.0")
            .key("network").value("mainnet")
            .key("running").value(true);

        if (chain_) {
            json.key("chain").beginObject()
                .key("height").value(static_cast<int64_t>(chain_->getHeight()))
                .key("best_hash").value(hashToHex(chain_->getBestHash()))
                .endObject();
        }

        if (mempool_) {
            auto stats = mempool_->getStats();
            json.key("mempool").beginObject()
                .key("size").value(static_cast<uint64_t>(stats.tx_count))
                .key("bytes").value(stats.total_size)
                .key("fees").value(stats.total_fee)
                .endObject();
        }

        if (peer_manager_) {
            json.key("peers").beginObject()
                .key("connected").value(static_cast<uint64_t>(peer_manager_->getPeerCount()))
                .key("inbound").value(static_cast<uint64_t>(peer_manager_->getInboundCount()))
                .key("outbound").value(static_cast<uint64_t>(peer_manager_->getOutboundCount()))
                .endObject();
        }

        json.endObject();
        res.success(json.build());
    });

    // Simple health check endpoint for monitoring/load balancers
    get("/health", [this](const HttpRequest& req, HttpResponse& res) {
        bool healthy = true;
        std::string status = "healthy";

        // Check chain is available
        if (!chain_) {
            healthy = false;
            status = "chain unavailable";
        }

        // Check peer connectivity (warn if no peers, but still healthy for first node)
        int peer_count = peer_manager_ ? peer_manager_->getPeerCount() : 0;

        JsonBuilder json;
        json.beginObject()
            .key("status").value(status)
            .key("healthy").value(healthy)
            .key("peers").value(static_cast<int64_t>(peer_count))
            .key("height").value(chain_ ? static_cast<int64_t>(chain_->getHeight()) : 0)
            .endObject();

        if (healthy) {
            res.success(json.build());
        } else {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, json.build());
        }
    });

    // Genesis block info endpoint - allows verification of genesis message
    get("/genesis", [this](const HttpRequest& req, HttpResponse& res) {
        // Get genesis block hash
        crypto::Hash256 genesis_hash{};
        if (chain_) {
            auto genesis_block = chain_->getBlock(0);
            if (genesis_block) {
                genesis_hash = genesis_block->getHash();
            }
        }

        JsonBuilder json;
        json.beginObject()
            .key("message").value(chain::genesis::GENESIS_MESSAGE)
            .key("timestamp").value(static_cast<int64_t>(chain::genesis::GENESIS_TIME))
            .key("timestamp_utc").value("2026-01-20 00:00:00 UTC")
            .key("hash").value(hashToHex(genesis_hash))
            .key("version").value(static_cast<int64_t>(chain::genesis::GENESIS_VERSION))
            .key("bits").value(static_cast<int64_t>(chain::genesis::GENESIS_BITS))
            .key("nonce").value(static_cast<int64_t>(chain::genesis::GENESIS_NONCE))
            .endObject();

        res.success(json.build());
    });

    // Get block by hash or height
    get("/block/:id", [this](const HttpRequest& req, HttpResponse& res) {
        if (!chain_) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Chain not available");
            return;
        }

        std::string id = req.getPathParam("id");

        std::optional<chain::Block> block;

        // Try as height first
        try {
            int32_t height = std::stoi(id);
            block = chain_->getBlock(height);
        } catch (...) {
            // Try as hash
            crypto::Hash256 hash;
            if (hexToHash(id, hash)) {
                block = chain_->getBlock(hash);
            }
        }

        if (!block) {
            res.error(HttpStatus::NOT_FOUND, "Block not found");
            return;
        }

        JsonBuilder json;
        json.beginObject()
            .key("hash").value(hashToHex(block->getHash()))
            .key("version").value(static_cast<int64_t>(block->header.version))
            .key("prev_hash").value(hashToHex(block->header.prev_hash))
            .key("merkle_root").value(hashToHex(block->header.merkle_root))
            .key("timestamp").value(static_cast<uint64_t>(block->header.timestamp))
            .key("bits").value(static_cast<uint64_t>(block->header.bits))
            .key("nonce").value(static_cast<uint64_t>(block->header.nonce))
            .key("tx_count").value(static_cast<uint64_t>(block->transactions.size()))
            .key("transactions").beginArray();

        for (const auto& tx : block->transactions) {
            json.value(hashToHex(tx.getTxId()));
        }

        json.endArray().endObject();
        res.success(json.build());
    });

    // Get transaction by txid
    get("/tx/:txid", [this](const HttpRequest& req, HttpResponse& res) {
        std::string txid_str = req.getPathParam("txid");

        crypto::Hash256 txid;
        if (!hexToHash(txid_str, txid)) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid txid format");
            return;
        }

        // Check mempool first
        if (mempool_) {
            auto tx = mempool_->getTransaction(txid);
            if (tx) {
                JsonBuilder json;
                json.beginObject()
                    .key("txid").value(hashToHex(tx->getTxId()))
                    .key("version").value(static_cast<int64_t>(tx->version))
                    .key("locktime").value(static_cast<uint64_t>(tx->locktime))
                    .key("confirmations").value(static_cast<int64_t>(0))
                    .key("in_mempool").value(true)
                    .key("input_count").value(static_cast<uint64_t>(tx->inputs.size()))
                    .key("output_count").value(static_cast<uint64_t>(tx->outputs.size()))
                    .endObject();
                res.success(json.build());
                return;
            }
        }

        // Search in confirmed transactions using transaction index
        if (chain_) {
            auto tx = chain_->getTx(txid);
            if (tx) {
                auto tip = chain_->getTip();
                int64_t confirmations = 0;

                // Find the block containing this transaction
                if (chain_->hasTx(txid)) {
                    // Get block height for confirmations calculation
                    // For now, just indicate it's confirmed
                    confirmations = 1;  // At least 1 confirmation if in chain
                    if (tip) {
                        // We'd need to store block height in tx index for accurate count
                        // For now, assume it's in the tip or recent blocks
                        confirmations = 1;
                    }
                }

                JsonBuilder json;
                json.beginObject()
                    .key("txid").value(hashToHex(tx->getTxId()))
                    .key("version").value(static_cast<int64_t>(tx->version))
                    .key("locktime").value(static_cast<uint64_t>(tx->locktime))
                    .key("confirmations").value(confirmations)
                    .key("in_mempool").value(false)
                    .key("input_count").value(static_cast<uint64_t>(tx->inputs.size()))
                    .key("output_count").value(static_cast<uint64_t>(tx->outputs.size()))
                    .endObject();
                res.success(json.build());
                return;
            }
        }

        res.error(HttpStatus::NOT_FOUND, "Transaction not found");
    });

    // Broadcast transaction
    post("/tx", [this](const HttpRequest& req, HttpResponse& res) {
        if (!mempool_) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Mempool not available");
            return;
        }

        JsonParser parser(req.body);
        if (!parser.parse() || !parser.isObject()) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid JSON body");
            return;
        }

        std::string hex = parser.getString("hex");
        if (hex.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "Missing 'hex' field (raw transaction)");
            return;
        }

        // Decode hex to transaction
        std::vector<uint8_t> raw_tx;
        raw_tx.reserve(hex.size() / 2);
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            int byte;
            std::istringstream iss(hex.substr(i, 2));
            if (!(iss >> std::hex >> byte)) {
                res.error(HttpStatus::BAD_REQUEST, "Invalid hex encoding");
                return;
            }
            raw_tx.push_back(static_cast<uint8_t>(byte));
        }

        // Deserialize transaction
        auto tx_opt = chain::Transaction::deserialize(raw_tx);
        if (!tx_opt) {
            res.error(HttpStatus::BAD_REQUEST, "Failed to decode transaction");
            return;
        }
        chain::Transaction& tx = *tx_opt;

        // Add to mempool
        int32_t current_height = chain_ ? chain_->getHeight() : 0;
        auto result = mempool_->addTransaction(tx, current_height);

        if (result == chain::MempoolReject::VALID) {
            JsonBuilder json;
            json.beginObject()
                .key("txid").value(hashToHex(tx.getTxId()))
                .key("accepted").value(true)
                .endObject();
            res.success(json.build());
        } else {
            std::string reason;
            switch (result) {
                case chain::MempoolReject::SCRIPT_ERROR: reason = "Invalid transaction (script error)"; break;
                case chain::MempoolReject::DOUBLE_SPEND: reason = "Double spend detected"; break;
                case chain::MempoolReject::INSUFFICIENT_FEE: reason = "Insufficient fee"; break;
                case chain::MempoolReject::MEMPOOL_FULL: reason = "Mempool full"; break;
                case chain::MempoolReject::ALREADY_IN_MEMPOOL: reason = "Already in mempool"; break;
                case chain::MempoolReject::MISSING_INPUTS: reason = "Missing inputs"; break;
                case chain::MempoolReject::IMMATURE_COINBASE: reason = "Immature coinbase (requires 100 confirmations)"; break;
                case chain::MempoolReject::NEGATIVE_FEE: reason = "Negative fee (outputs exceed inputs)"; break;
                case chain::MempoolReject::TOO_LARGE: reason = "Transaction too large"; break;
                case chain::MempoolReject::ALREADY_IN_CHAIN: reason = "Already in blockchain"; break;
                case chain::MempoolReject::ANCESTOR_LIMIT: reason = "Ancestor limit exceeded"; break;
                case chain::MempoolReject::DESCENDANT_LIMIT: reason = "Descendant limit exceeded"; break;
                default: reason = "Unknown error"; break;
            }
            res.error(HttpStatus::BAD_REQUEST, reason);
        }
    });

    // Mempool info
    get("/mempool", [this](const HttpRequest& req, HttpResponse& res) {
        if (!mempool_) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Mempool not available");
            return;
        }

        auto stats = mempool_->getStats();

        JsonBuilder json;
        json.beginObject()
            .key("size").value(static_cast<uint64_t>(stats.tx_count))
            .key("bytes").value(stats.total_size)
            .key("total_fees").value(stats.total_fee)
            .key("min_fee_rate").value(stats.min_fee_rate)
            .endObject();
        res.success(json.build());
    });

    // Mempool transaction IDs
    get("/mempool/txids", [this](const HttpRequest& req, HttpResponse& res) {
        if (!mempool_) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Mempool not available");
            return;
        }

        auto txids = mempool_->getAllTxids();

        JsonBuilder json;
        json.beginObject()
            .key("count").value(static_cast<uint64_t>(txids.size()))
            .key("txids").beginArray();

        for (const auto& txid : txids) {
            json.value(hashToHex(txid));
        }

        json.endArray().endObject();
        res.success(json.build());
    });

    // Get balance for address
    get("/balance/:address", [this](const HttpRequest& req, HttpResponse& res) {
        if (!utxo_set_) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "UTXO set not available");
            return;
        }

        std::string address = req.getPathParam("address");

        // Convert address to script pubkey using decodeAddress (supports bech32)
        std::vector<uint8_t> script_pubkey = decodeAddress(address);
        if (script_pubkey.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid address format");
            return;
        }

        auto balance = utxo_set_->getBalance(script_pubkey);

        JsonBuilder json;
        json.beginObject()
            .key("address").value(address)
            .key("confirmed").value(balance.confirmed)
            .key("unconfirmed").value(balance.unconfirmed)
            .key("total").value(balance.confirmed + balance.unconfirmed)
            .key("utxo_count").value(static_cast<uint64_t>(balance.utxos.size()))
            .endObject();
        res.success(json.build());
    });

    // Get UTXOs for address
    get("/utxo/:address", [this](const HttpRequest& req, HttpResponse& res) {
        if (!utxo_set_) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "UTXO set not available");
            return;
        }

        std::string address = req.getPathParam("address");

        // Convert address to script pubkey using decodeAddress (supports bech32)
        std::vector<uint8_t> script_pubkey = decodeAddress(address);
        if (script_pubkey.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid address format");
            return;
        }

        auto utxos = utxo_set_->getUTXOs(script_pubkey);

        JsonBuilder json;
        json.beginObject()
            .key("address").value(address)
            .key("count").value(static_cast<uint64_t>(utxos.size()))
            .key("utxos").beginArray();

        for (const auto& utxo : utxos) {
            json.beginObject()
                .key("txid").value(hashToHex(utxo.outpoint.txid))
                .key("vout").value(static_cast<uint64_t>(utxo.outpoint.index))
                .key("amount").value(utxo.value)
                .key("height").value(static_cast<int64_t>(utxo.height))
                .key("coinbase").value(utxo.coinbase)
                .endObject();
        }

        json.endArray().endObject();
        res.success(json.build());
    });

    // Get peers
    get("/peers", [this](const HttpRequest& req, HttpResponse& res) {
        if (!peer_manager_) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Peer manager not available");
            return;
        }

        auto peers = peer_manager_->getPeerInfo();

        JsonBuilder json;
        json.beginObject()
            .key("count").value(static_cast<uint64_t>(peers.size()))
            .key("peers").beginArray();

        for (const auto& peer : peers) {
            json.beginObject()
                .key("id").value(static_cast<uint64_t>(peer.id))
                .key("address").value(peer.addr.toString())
                .key("version").value(static_cast<int64_t>(peer.version))
                .key("user_agent").value(peer.user_agent)
                .key("height").value(static_cast<int64_t>(peer.best_height))
                .key("inbound").value(peer.direction == p2p::ConnectionDir::INBOUND)
                .key("ping_ms").value(peer.ping_usec / 1000)
                .key("bytes_sent").value(peer.bytes_sent)
                .key("bytes_recv").value(peer.bytes_recv)
                .endObject();
        }

        json.endArray().endObject();
        res.success(json.build());
    });

    // Banned peers
    get("/peers/banned", [this](const HttpRequest& req, HttpResponse& res) {
        if (!peer_manager_) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Peer manager not available");
            return;
        }

        auto bans = peer_manager_->getBanList();

        JsonBuilder json;
        json.beginObject()
            .key("count").value(static_cast<uint64_t>(bans.size()))
            .key("banned").beginArray();

        for (const auto& ban : bans) {
            json.beginObject()
                .key("address").value(ban.addr.toString())
                .key("reason").value(ban.reason)
                .key("ban_time").value(static_cast<int64_t>(ban.ban_time))
                .key("unban_time").value(static_cast<int64_t>(ban.unban_time))
                .endObject();
        }

        json.endArray().endObject();
        res.success(json.build());
    });

    // Mining template
    get("/mining/template", [this](const HttpRequest& req, HttpResponse& res) {
        if (!chain_ || !mempool_) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Chain or mempool not available");
            return;
        }

        // Get payout address from query parameter
        std::string payout_address = req.getQueryParam("address");

        // Get block template from mempool
        auto tmpl = mempool_->getBlockTemplate(
            chain_->getParams().max_block_size,
            chain_->getParams().max_block_sigops
        );

        // Get current tip
        auto tip = chain_->getTip();
        if (!tip) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "No chain tip");
            return;
        }

        int32_t height = tip->height + 1;
        uint64_t reward = chain_->getBlockReward(height);
        uint32_t bits = chain_->getNextWorkRequired(tip);
        uint32_t timestamp = static_cast<uint32_t>(std::time(nullptr));

        // Build coinbase transaction
        chain::Transaction coinbase;
        coinbase.version = 1;
        coinbase.locktime = 0;

        // Coinbase input
        chain::TxInput cb_input;
        cb_input.prevout.txid = crypto::Hash256{};  // Zero
        cb_input.prevout.index = 0xFFFFFFFF;
        cb_input.sequence = 0xFFFFFFFF;

        // Script with height (BIP34)
        std::vector<uint8_t> height_script;
        if (height < 17) {
            height_script.push_back(0x50 + height);  // OP_1 to OP_16
        } else if (height < 128) {
            height_script.push_back(0x01);
            height_script.push_back(static_cast<uint8_t>(height));
        } else if (height < 32768) {
            height_script.push_back(0x02);
            height_script.push_back(height & 0xFF);
            height_script.push_back((height >> 8) & 0xFF);
        } else {
            height_script.push_back(0x03);
            height_script.push_back(height & 0xFF);
            height_script.push_back((height >> 8) & 0xFF);
            height_script.push_back((height >> 16) & 0xFF);
        }

        // Add extra nonce space (8 bytes)
        height_script.push_back(0x08);  // Push 8 bytes
        for (int i = 0; i < 8; i++) {
            height_script.push_back(0x00);  // Extra nonce placeholder
        }

        cb_input.script_sig = height_script;
        coinbase.inputs.push_back(cb_input);

        // Coinbase output (reward + fees)
        uint64_t total_reward = reward + tmpl.total_fee;

        // Check if P2Pool is enabled - use PPLNS payouts
        bool use_p2pool_payouts = false;
        std::map<std::vector<uint8_t>, uint64_t> payouts;

        if (p2pool_ && p2pool_->isRunning() && !payout_address.empty()) {
            try {
                // Register this miner's share with P2Pool
                auto miner_script = chain::script::createP2PKHFromAddress(payout_address);
                if (!miner_script.empty()) {
                    p2pool_->registerMinerShare(miner_script);
                }

                // Get PPLNS payouts
                payouts = p2pool_->getPayouts();
                if (!payouts.empty()) {
                    use_p2pool_payouts = true;
                }
            } catch (const std::exception& e) {
                // Fall back to solo mining on error
                use_p2pool_payouts = false;
                payouts.clear();
            }
        }

        if (use_p2pool_payouts) {
            // Create multiple outputs for P2Pool PPLNS participants
            for (const auto& [script, amount] : payouts) {
                if (amount > 0) {
                    chain::TxOutput cb_output;
                    cb_output.value = amount;
                    cb_output.script_pubkey = script;
                    coinbase.outputs.push_back(cb_output);
                }
            }
        } else {
            // Solo mining - single output to miner
            chain::TxOutput cb_output;
            cb_output.value = total_reward;

            if (!payout_address.empty()) {
                cb_output.script_pubkey = chain::script::createP2PKHFromAddress(payout_address);
            } else {
                // OP_RETURN with message (unspendable, for testing)
                cb_output.script_pubkey = {0x6a, 0x07, 'F', 'T', 'C', 'P', 'O', 'O', 'L'};
            }
            coinbase.outputs.push_back(cb_output);
        }

        // Serialize coinbase
        std::vector<uint8_t> coinbase_data = coinbase.serialize();

        // Build complete transaction list for merkle root
        std::vector<crypto::Hash256> tx_hashes;
        tx_hashes.push_back(coinbase.getTxId());
        for (const auto& tx : tmpl.transactions) {
            tx_hashes.push_back(tx.getTxId());
        }

        // Calculate merkle root
        crypto::Hash256 merkle_root;
        if (tx_hashes.size() == 1) {
            merkle_root = tx_hashes[0];
        } else {
            while (tx_hashes.size() > 1) {
                std::vector<crypto::Hash256> new_level;
                for (size_t i = 0; i < tx_hashes.size(); i += 2) {
                    crypto::Hash256 left = tx_hashes[i];
                    crypto::Hash256 right = (i + 1 < tx_hashes.size()) ? tx_hashes[i + 1] : left;

                    // Concatenate and hash
                    std::vector<uint8_t> combined(64);
                    std::memcpy(combined.data(), left.data(), 32);
                    std::memcpy(combined.data() + 32, right.data(), 32);
                    new_level.push_back(crypto::keccak256(combined));
                }
                tx_hashes = std::move(new_level);
            }
            merkle_root = tx_hashes[0];
        }

        JsonBuilder json;
        json.beginObject()
            .key("version").value(static_cast<int64_t>(1))
            .key("height").value(static_cast<int64_t>(height))
            .key("prev_hash").value(hashToHex(tip->hash))
            .key("merkle_root").value(hashToHex(merkle_root))
            .key("timestamp").value(static_cast<int64_t>(timestamp))
            .key("bits").value(static_cast<uint64_t>(bits))
            .key("coinbase").value(bytesToHex(coinbase_data))
            .key("coinbase_value").value(reward + tmpl.total_fee)
            .key("block_reward").value(reward)
            .key("total_fees").value(tmpl.total_fee)
            .key("tx_count").value(static_cast<uint64_t>(tmpl.transactions.size()));

        // Transaction data (for building complete block)
        json.key("transactions").beginArray();
        for (const auto& tx : tmpl.transactions) {
            json.value(bytesToHex(tx.serialize()));
        }
        json.endArray();

        json.endObject();
        res.success(json.build());
    });

    // Submit mined block
    post("/mining/submit", [this](const HttpRequest& req, HttpResponse& res) {
        if (!chain_) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Chain not available");
            return;
        }

        JsonParser parser(req.body);
        if (!parser.parse() || !parser.isObject()) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid JSON body");
            return;
        }

        std::string hex = parser.getString("hex");
        if (hex.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "Missing 'hex' field (raw block)");
            return;
        }

        // Decode hex to block
        std::vector<uint8_t> raw_block;
        raw_block.reserve(hex.size() / 2);
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            int byte;
            std::istringstream iss(hex.substr(i, 2));
            if (!(iss >> std::hex >> byte)) {
                res.error(HttpStatus::BAD_REQUEST, "Invalid hex encoding");
                return;
            }
            raw_block.push_back(static_cast<uint8_t>(byte));
        }

        // Deserialize block
        auto block_opt = chain::Block::deserialize(raw_block);
        if (!block_opt) {
            res.error(HttpStatus::BAD_REQUEST, "Failed to decode block");
            return;
        }
        chain::Block& block = *block_opt;

        // Process block
        auto result = chain_->processBlock(block);

        if (result == chain::ValidationResult::VALID) {
            // Remove included transactions from mempool
            if (mempool_) {
                mempool_->removeForBlock(block.transactions);
            }

            JsonBuilder json;
            json.beginObject()
                .key("hash").value(hashToHex(block.getHash()))
                .key("accepted").value(true)
                .endObject();
            res.success(json.build());
        } else {
            std::string reason;
            switch (result) {
                case chain::ValidationResult::INVALID_BLOCK_HEADER: reason = "Invalid header"; break;
                case chain::ValidationResult::INVALID_POW: reason = "Invalid proof of work"; break;
                case chain::ValidationResult::INVALID_TIMESTAMP: reason = "Invalid timestamp"; break;
                case chain::ValidationResult::INVALID_MERKLE_ROOT: reason = "Invalid merkle root"; break;
                case chain::ValidationResult::INVALID_TX: reason = "Invalid transaction"; break;
                case chain::ValidationResult::INVALID_COINBASE: reason = "Invalid coinbase"; break;
                case chain::ValidationResult::DUPLICATE_TX: reason = "Duplicate block"; break;
                case chain::ValidationResult::BLOCK_MISSING_PREV: reason = "Orphan block"; break;
                default: reason = "Unknown error"; break;
            }
            res.error(HttpStatus::BAD_REQUEST, reason);
        }
    });

    // Mining info
    get("/mining/info", [this](const HttpRequest& req, HttpResponse& res) {
        if (!chain_) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Chain not available");
            return;
        }

        auto tip = chain_->getTip();
        int32_t height = tip ? tip->height : -1;
        uint32_t bits = tip ? chain_->getNextWorkRequired(tip) : 0;

        JsonBuilder json;
        json.beginObject()
            .key("height").value(static_cast<int64_t>(height + 1))
            .key("difficulty_bits").value(static_cast<uint64_t>(bits))
            .key("block_reward").value(chain_->getBlockReward(height + 1))
            .key("block_time_target").value(static_cast<uint64_t>(chain_->getParams().block_time))
            .key("difficulty_adjustment_interval").value(
                static_cast<uint64_t>(chain_->getParams().difficulty_adjustment_interval))
            .endObject();
        res.success(json.build());
    });

    // Generate blocks (CPU mining for testing)
    get("/mining/generate", [this](const HttpRequest& req, HttpResponse& res) {
        if (!chain_ || !mempool_) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Chain or mempool not available");
            return;
        }

        int num_blocks = 1;
        std::string blocks_str = req.getQueryParam("blocks");
        if (!blocks_str.empty()) {
            num_blocks = std::stoi(blocks_str);
            if (num_blocks < 1 || num_blocks > 100) {
                res.error(HttpStatus::BAD_REQUEST, "blocks must be 1-100");
                return;
            }
        }

        std::string payout_address = req.getQueryParam("address");
        std::vector<uint8_t> payout_script;
        if (!payout_address.empty()) {
            payout_script = decodeAddress(payout_address);
            if (payout_script.empty()) {
                res.error(HttpStatus::BAD_REQUEST, "Invalid payout address");
                return;
            }
        } else {
            // Default: OP_RETURN (burn)
            payout_script = {0x6a};  // OP_RETURN
        }

        std::vector<std::string> block_hashes;

        for (int i = 0; i < num_blocks; i++) {
            auto tip = chain_->getTip();
            if (!tip) {
                res.error(HttpStatus::SERVICE_UNAVAILABLE, "No chain tip");
                return;
            }

            int32_t height = tip->height + 1;
            uint64_t reward = chain_->getBlockReward(height);
            uint32_t bits = chain_->getNextWorkRequired(tip);
            // Ensure timestamp is greater than previous block + 1 second
            uint32_t min_timestamp = tip->timestamp + 1;
            uint32_t now = static_cast<uint32_t>(std::time(nullptr));
            uint32_t timestamp = std::max(min_timestamp, now);

            // Build coinbase transaction
            chain::Transaction coinbase;
            coinbase.version = 1;
            coinbase.locktime = 0;

            chain::TxInput cb_input;
            cb_input.prevout.txid = crypto::Hash256{};
            cb_input.prevout.index = 0xFFFFFFFF;
            cb_input.sequence = 0xFFFFFFFF;
            std::vector<uint8_t> height_script;
            height_script.push_back(0x01);
            height_script.push_back(static_cast<uint8_t>(height & 0xFF));
            cb_input.script_sig = height_script;
            coinbase.inputs.push_back(cb_input);

            chain::TxOutput cb_output;
            cb_output.value = reward;
            cb_output.script_pubkey = payout_script;
            coinbase.outputs.push_back(cb_output);

            // Build block
            chain::Block block;
            block.header.version = 1;
            block.header.prev_hash = tip->hash;
            block.header.timestamp = timestamp;
            block.header.bits = bits;
            block.header.nonce = 0;
            block.transactions.push_back(coinbase);

            // Compute merkle root
            block.header.merkle_root = block.calculateMerkleRoot();

            // Get target
            crypto::Hash256 target = chain::BlockHeader::bitsToTarget(bits);

            // Mine the block (simple CPU mining)
            bool found = false;
            for (uint32_t nonce = 0; nonce < 0xFFFFFFFF && !found; nonce++) {
                block.header.nonce = nonce;
                crypto::Hash256 hash = block.getHash();
                if (crypto::Keccak256::compare(hash, target) <= 0) {
                    found = true;
                }
                if (nonce % 1000000 == 0 && nonce > 0) {
                    // Update timestamp to avoid stale blocks
                    block.header.timestamp = static_cast<uint32_t>(std::time(nullptr));
                }
            }

            if (!found) {
                res.error(HttpStatus::INTERNAL_ERROR, "Failed to mine block");
                return;
            }

            // Submit the block
            auto result = chain_->processBlock(block);
            if (result != chain::ValidationResult::VALID) {
                res.error(HttpStatus::INTERNAL_ERROR, "Block validation failed");
                return;
            }

            // Broadcast via P2P
            crypto::Hash256 block_hash = block.getHash();
            if (peer_manager_) {
                peer_manager_->broadcastBlock(block_hash, block);
            }

            block_hashes.push_back(crypto::Keccak256::toHex(block.getHash()));
        }

        JsonBuilder json;
        json.beginObject();
        json.key("blocks_mined").value(static_cast<int64_t>(num_blocks));
        json.key("hashes").beginArray();
        for (const auto& hash : block_hashes) {
            json.value(hash);
        }
        json.endArray();
        json.endObject();
        res.success(json.build());
    });

    // =========================================================================
    // P2Pool Routes - Decentralized Mining Pool
    // =========================================================================

    // P2Pool status
    get("/p2pool/status", [this](const HttpRequest& req, HttpResponse& res) {
        if (!p2pool_) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "P2Pool not available");
            return;
        }

        auto stats = p2pool_->getStats();

        JsonBuilder json;
        json.beginObject()
            .key("enabled").value(true)
            .key("running").value(p2pool_->isRunning())
            .key("sharechain_height").value(static_cast<int64_t>(stats.sharechain_height))
            .key("sharechain_tip").value(hashToHex(stats.sharechain_tip))
            .key("pool_hashrate").value(stats.pool_hashrate)
            .key("active_miners").value(static_cast<int64_t>(stats.active_miners))
            .key("total_shares").value(stats.total_shares)
            .key("total_blocks").value(stats.total_blocks)
            .key("shares_per_minute").value(stats.shares_per_minute)
            .key("peer_count").value(static_cast<int64_t>(stats.peer_count))
            .endObject();
        res.success(json.build());
    });

    // Get P2Pool share template for mining
    get("/p2pool/template", [this](const HttpRequest& req, HttpResponse& res) {
        if (!p2pool_ || !chain_) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "P2Pool or chain not available");
            return;
        }

        // Get payout address from query parameter
        std::string payout_address = req.getQueryParam("address");
        if (payout_address.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "Missing 'address' query parameter");
            return;
        }

        // Decode address to script pubkey
        std::vector<uint8_t> payout_script = decodeAddress(payout_address);
        if (payout_script.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid payout address");
            return;
        }

        // Get share template from P2Pool
        auto share = p2pool_->getWorkTemplate(payout_script);

        // Get main chain info
        auto tip = chain_->getTip();
        if (!tip) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "No chain tip");
            return;
        }

        JsonBuilder json;
        json.beginObject()
            .key("share_version").value(static_cast<int64_t>(share.header.version))
            .key("share_target_bits").value(static_cast<uint64_t>(share.header.bits))
            .key("prev_share").value(hashToHex(share.header.prev_share))
            .key("block_prev_hash").value(hashToHex(share.header.block_prev_hash))
            .key("block_height").value(static_cast<int64_t>(share.header.block_height))
            .key("block_bits").value(static_cast<uint64_t>(share.header.block_bits))
            .key("timestamp").value(static_cast<int64_t>(share.header.timestamp))
            .key("merkle_root").value(hashToHex(share.header.merkle_root))
            .key("generation_tx").value(bytesToHex(share.generation_tx.serialize()))
            .key("main_chain_height").value(static_cast<int64_t>(tip->height))
            .key("main_chain_tip").value(hashToHex(tip->hash))
            .endObject();
        res.success(json.build());
    });

    // Submit share to P2Pool
    post("/p2pool/submit", [this](const HttpRequest& req, HttpResponse& res) {
        if (!p2pool_) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "P2Pool not available");
            return;
        }

        JsonParser parser(req.body);
        if (!parser.parse() || !parser.isObject()) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid JSON body");
            return;
        }

        // Get nonce and extra_nonce from request
        uint32_t nonce = static_cast<uint32_t>(parser.getInt("nonce"));
        std::string extra_nonce_hex = parser.getString("extra_nonce");

        std::vector<uint8_t> extra_nonce;
        if (!extra_nonce_hex.empty()) {
            for (size_t i = 0; i + 1 < extra_nonce_hex.size(); i += 2) {
                int byte;
                std::istringstream iss(extra_nonce_hex.substr(i, 2));
                if (iss >> std::hex >> byte) {
                    extra_nonce.push_back(static_cast<uint8_t>(byte));
                }
            }
        }

        // Submit to P2Pool
        if (p2pool_->submitWork(nonce, extra_nonce)) {
            JsonBuilder json;
            json.beginObject()
                .key("accepted").value(true)
                .key("message").value("Share submitted to P2Pool")
                .endObject();
            res.success(json.build());
        } else {
            res.error(HttpStatus::BAD_REQUEST, "Share rejected");
        }
    });

    // Get P2Pool payouts estimate
    get("/p2pool/payouts", [this](const HttpRequest& req, HttpResponse& res) {
        if (!p2pool_) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "P2Pool not available");
            return;
        }

        auto payouts = p2pool_->getEstimatedPayouts();

        JsonBuilder json;
        json.beginObject();
        json.key("payouts").beginArray();

        for (const auto& [script, amount] : payouts) {
            json.beginObject()
                .key("script").value(bytesToHex(script))
                .key("amount").value(amount)
                .endObject();
        }

        json.endArray();
        json.endObject();
        res.success(json.build());
    });
}

} // namespace api
} // namespace ftc
