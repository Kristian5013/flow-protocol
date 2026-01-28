#ifndef FTC_API_SERVER_H
#define FTC_API_SERVER_H

#include <string>
#include <cstdint>
#include <map>
#include <vector>
#include <functional>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket close
#endif

namespace ftc {

// Forward declarations
namespace chain {
class Chain;
class Mempool;
class UTXOSet;
}
namespace p2p {
class PeerManager;
class MessageHandler;
}
namespace p2pool {
class P2Pool;
}

namespace api {

// HTTP method
// Note: Must undefine DELETE on Windows to avoid macro conflict
#ifdef DELETE
#undef DELETE
#endif
enum class HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    OPTIONS,
    UNKNOWN
};

// HTTP status codes
enum class HttpStatus {
    OK = 200,
    CREATED = 201,
    ACCEPTED = 202,
    NO_CONTENT = 204,
    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    FORBIDDEN = 403,
    NOT_FOUND = 404,
    METHOD_NOT_ALLOWED = 405,
    INTERNAL_ERROR = 500,
    NOT_IMPLEMENTED = 501,
    SERVICE_UNAVAILABLE = 503
};

// HTTP request
struct HttpRequest {
    HttpMethod method = HttpMethod::UNKNOWN;
    std::string path;
    std::string query_string;
    std::map<std::string, std::string> headers;
    std::map<std::string, std::string> query_params;
    std::map<std::string, std::string> path_params;
    std::string body;
    std::string remote_addr;

    // Get header (case-insensitive)
    std::string getHeader(const std::string& name) const;

    // Get query parameter
    std::string getQueryParam(const std::string& name, const std::string& default_val = "") const;

    // Get path parameter
    std::string getPathParam(const std::string& name) const;

    // Check content type
    bool isJson() const;
};

// HTTP response
struct HttpResponse {
    HttpStatus status = HttpStatus::OK;
    std::map<std::string, std::string> headers;
    std::string body;

    // Set JSON body
    void json(const std::string& json_str);

    // Set error response
    void error(HttpStatus code, const std::string& message);

    // Set success response with JSON
    void success(const std::string& json_str);

    // Build raw HTTP response
    std::string build() const;
};

// Route handler type
using RouteHandler = std::function<void(const HttpRequest&, HttpResponse&)>;

// Route definition
struct Route {
    HttpMethod method;
    std::string pattern;        // e.g., "/block/:hash" or "/tx/:txid"
    RouteHandler handler;
    std::vector<std::string> param_names;  // Parameter names from pattern

    // Match path and extract parameters
    bool match(const std::string& path, std::map<std::string, std::string>& params) const;
};

// Client connection for HTTP
struct HttpConnection {
    socket_t socket = INVALID_SOCKET;
    std::string remote_addr;
    std::string read_buffer;
    std::string write_buffer;
    bool keep_alive = false;
    std::chrono::steady_clock::time_point last_activity;
    bool request_complete = false;
    HttpRequest pending_request;

    bool parseRequest();
    void close();
};

/**
 * HTTP Server - localhost-only JSON API
 *
 * Security: Only binds to ::1 (IPv6 localhost)
 * No authentication required for local access
 *
 * API endpoints:
 * - GET  /status              - Node status
 * - GET  /block/:id           - Get block by hash or height
 * - GET  /block/:id/header    - Get block header only
 * - GET  /tx/:txid            - Get transaction
 * - POST /tx                  - Broadcast transaction
 * - POST /tx/decode           - Decode raw transaction
 * - GET  /mempool             - Mempool info
 * - GET  /mempool/txids       - List mempool transaction IDs
 * - GET  /balance/:address    - Get address balance
 * - GET  /utxo/:address       - Get UTXOs for address
 * - GET  /address/:addr/history - Transaction history for address
 * - GET  /peers               - List connected peers
 * - GET  /peers/banned        - List banned peers
 * - GET  /wallet/new          - Generate new wallet (keypair)
 * - POST /wallet/send         - Send transaction (build, sign, broadcast)
 * - GET  /mining/info         - Mining info
 * - GET  /mining/template     - Get block template for mining
 * - POST /mining/submit       - Submit mined block
 */
class Server {
public:
    struct Config {
        std::string host = "::";   // All IPv6 interfaces (use ::1 for localhost only)
        uint16_t port = 17319;
        size_t max_connections = 100;
        size_t max_request_size = 1024 * 1024;  // 1 MB
        std::chrono::seconds timeout{30};
        bool enable_cors = true;  // Enable CORS for remote miners

        // Dashboard settings
        std::string web_root;      // Path to web dashboard files

        Config() = default;
    };

    Server();
    explicit Server(const Config& config);
    ~Server();

    // Non-copyable
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Set dependencies
    void setChain(chain::Chain* chain) { chain_ = chain; }
    void setMempool(chain::Mempool* mempool) { mempool_ = mempool; }
    void setUTXOSet(chain::UTXOSet* utxo_set) { utxo_set_ = utxo_set; }
    void setPeerManager(p2p::PeerManager* peer_mgr) { peer_manager_ = peer_mgr; }
    void setMessageHandler(p2p::MessageHandler* mh) { message_handler_ = mh; }
    void setP2Pool(p2pool::P2Pool* p2pool) { p2pool_ = p2pool; }
    p2pool::P2Pool* getP2Pool() const { return p2pool_; }

    // Lifecycle
    bool start();
    void stop();
    bool isRunning() const { return running_; }

    // Route registration
    void get(const std::string& pattern, RouteHandler handler);
    void post(const std::string& pattern, RouteHandler handler);
    void put(const std::string& pattern, RouteHandler handler);
    void del(const std::string& pattern, RouteHandler handler);

    // Statistics
    uint64_t getRequestCount() const { return request_count_; }
    uint64_t getConnectionCount() const { return connections_.size(); }

    // Config access
    const Config& getConfig() const { return config_; }

    // Static file serving
    static std::string getMimeType(const std::string& path);
    bool serveStaticFile(const std::string& path, HttpResponse& response);

private:
    // Setup default routes
    void setupRoutes();

    // Server thread
    void serverThread();

    // Connection handling
    void acceptConnections();
    void processConnections();
    void handleRequest(HttpConnection& conn);
    void sendResponse(HttpConnection& conn, const HttpResponse& response);
    void cleanupConnections();

    // Route matching
    Route* findRoute(HttpMethod method, const std::string& path,
                     std::map<std::string, std::string>& params);
    void addRoute(HttpMethod method, const std::string& pattern, RouteHandler handler);

public:
    // Parse helpers (public static for use by HttpConnection)
    static HttpMethod parseMethod(const std::string& method);
    static std::string methodToString(HttpMethod method);
    static std::string statusToString(HttpStatus status);
    static std::map<std::string, std::string> parseQueryString(const std::string& qs);
    static std::string urlDecode(const std::string& str);

private:

    // Configuration
    Config config_;

    // State
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    socket_t listen_socket_ipv4_ = INVALID_SOCKET;
    socket_t listen_socket_ipv6_ = INVALID_SOCKET;

    // Routes
    std::vector<Route> routes_;
    std::mutex routes_mutex_;

    // Connections
    std::map<socket_t, HttpConnection> connections_;
    std::mutex conn_mutex_;

    // Server thread
    std::thread server_thread_;

    // Dependencies
    chain::Chain* chain_ = nullptr;
    chain::Mempool* mempool_ = nullptr;
    chain::UTXOSet* utxo_set_ = nullptr;
    p2p::PeerManager* peer_manager_ = nullptr;
    p2p::MessageHandler* message_handler_ = nullptr;
    p2pool::P2Pool* p2pool_ = nullptr;

    // Statistics
    std::atomic<uint64_t> request_count_{0};
    std::atomic<uint64_t> error_count_{0};
};

// JSON helpers (simple manual JSON building for responses)
class JsonBuilder {
public:
    JsonBuilder& beginObject();
    JsonBuilder& endObject();
    JsonBuilder& beginArray();
    JsonBuilder& endArray();
    JsonBuilder& key(const std::string& k);
    JsonBuilder& value(const std::string& v);
    JsonBuilder& value(const char* v);  // Prevent const char* -> bool conversion
    JsonBuilder& value(int64_t v);
    JsonBuilder& value(uint64_t v);
    JsonBuilder& value(double v);
    JsonBuilder& value(bool v);
    JsonBuilder& nullValue();
    JsonBuilder& rawValue(const std::string& raw);

    std::string build() const { return buffer_; }
    void clear() { buffer_.clear(); need_comma_ = false; depth_ = 0; }

private:
    void maybeComma();
    std::string escapeString(const std::string& s) const;

    std::string buffer_;
    bool need_comma_ = false;
    int depth_ = 0;
};

// Simple JSON parser (for request bodies)
class JsonParser {
public:
    explicit JsonParser(const std::string& json);

    bool isObject() const;
    bool isArray() const;
    bool isString() const;
    bool isNumber() const;
    bool isBool() const;
    bool isNull() const;

    std::string getString(const std::string& key, const std::string& default_val = "") const;
    int64_t getInt(const std::string& key, int64_t default_val = 0) const;
    uint64_t getUint(const std::string& key, uint64_t default_val = 0) const;
    double getDouble(const std::string& key, double default_val = 0.0) const;
    bool getBool(const std::string& key, bool default_val = false) const;
    std::vector<std::string> getStringArray(const std::string& key) const;
    bool hasKey(const std::string& key) const;

    bool parse();
    bool isValid() const { return valid_; }

private:
    void skipWhitespace();
    bool parseValue();
    bool parseObject();
    bool parseArray();
    bool parseString(std::string& out);
    bool parseNumber();
    bool parseLiteral();

    std::string json_;
    size_t pos_ = 0;
    bool valid_ = false;

    // Parsed values (flat key-value for simple objects)
    std::map<std::string, std::string> values_;
    std::string root_type_;
};

} // namespace api
} // namespace ftc

#endif // FTC_API_SERVER_H
