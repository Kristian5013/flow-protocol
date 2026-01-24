#include "seed_client.h"
#include <sstream>
#include <cstring>
#include <chrono>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#define CLOSE_SOCKET closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
typedef int socket_t;
#define CLOSE_SOCKET close
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#endif

namespace seed {

// Default seed API
static const char* DEFAULT_API_HOST = "api.flowprotocol.net";
static const uint16_t DEFAULT_API_PORT = 443;

#ifdef _WIN32
static bool g_wsa_init = false;
static void initWinsock() {
    if (!g_wsa_init) {
        WSADATA data;
        WSAStartup(MAKEWORD(2, 2), &data);
        g_wsa_init = true;
    }
}
#endif

SeedClient::SeedClient(const std::string& network)
    : network_(network)
    , api_host_(DEFAULT_API_HOST)
    , api_port_(DEFAULT_API_PORT)
    , use_https_(true)
    , registered_(false)
    , discovered_count_(0)
    , heartbeat_running_(false)
    , heartbeat_port_(0)
    , height_ptr_(nullptr)
{
#ifdef _WIN32
    initWinsock();
#endif
}

SeedClient::~SeedClient() {
    stopHeartbeat();
}

void SeedClient::setEndpoint(const std::string& host, uint16_t port, bool use_https) {
    api_host_ = host;
    api_port_ = port;
    use_https_ = use_https;
}

// Simple HTTP GET (no SSL for now - use HTTP or reverse proxy)
std::string SeedClient::httpGet(const std::string& path) {
    // For HTTPS, we need OpenSSL or similar. For simplicity, fall back to HTTP
    // In production, use port 80 endpoint or add SSL support

    struct addrinfo hints{}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(use_https_ ? 443 : api_port_);

    if (getaddrinfo(api_host_.c_str(), port_str.c_str(), &hints, &res) != 0) {
        return "";
    }

    socket_t sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(res);
        return "";
    }

    // Set timeout
#ifdef _WIN32
    DWORD timeout = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    if (connect(sock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        CLOSE_SOCKET(sock);
        freeaddrinfo(res);
        return "";
    }
    freeaddrinfo(res);

    // Build HTTP request
    std::ostringstream req;
    req << "GET " << path << " HTTP/1.1\r\n";
    req << "Host: " << api_host_ << "\r\n";
    req << "User-Agent: ftc-node/1.0\r\n";
    req << "Accept: application/json\r\n";
    req << "Connection: close\r\n";
    req << "\r\n";

    std::string request = req.str();
    send(sock, request.c_str(), (int)request.size(), 0);

    // Read response
    std::string response;
    char buf[4096];
    int n;
    while ((n = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = 0;
        response += buf;
    }

    CLOSE_SOCKET(sock);

    // Extract body (after \r\n\r\n)
    size_t body_start = response.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        return response.substr(body_start + 4);
    }
    return "";
}

std::string SeedClient::httpPost(const std::string& path, const std::string& body) {
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(use_https_ ? 443 : api_port_);

    if (getaddrinfo(api_host_.c_str(), port_str.c_str(), &hints, &res) != 0) {
        return "";
    }

    socket_t sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(res);
        return "";
    }

#ifdef _WIN32
    DWORD timeout = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    if (connect(sock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        CLOSE_SOCKET(sock);
        freeaddrinfo(res);
        return "";
    }
    freeaddrinfo(res);

    // Build HTTP request
    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n";
    req << "Host: " << api_host_ << "\r\n";
    req << "User-Agent: ftc-node/1.0\r\n";
    req << "Content-Type: application/json\r\n";
    req << "Content-Length: " << body.size() << "\r\n";
    req << "Connection: close\r\n";
    req << "\r\n";
    req << body;

    std::string request = req.str();
    send(sock, request.c_str(), (int)request.size(), 0);

    // Read response
    std::string response;
    char buf[4096];
    int n;
    while ((n = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = 0;
        response += buf;
    }

    CLOSE_SOCKET(sock);

    // Extract body
    size_t body_start = response.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        return response.substr(body_start + 4);
    }
    return "";
}

// Simple JSON parsing for nodes response
std::vector<PeerInfo> SeedClient::parseNodesResponse(const std::string& json) {
    std::vector<PeerInfo> peers;

    // Find "nodes" array
    size_t nodes_pos = json.find("\"nodes\"");
    if (nodes_pos == std::string::npos) return peers;

    size_t arr_start = json.find('[', nodes_pos);
    if (arr_start == std::string::npos) return peers;

    // Parse each node object
    size_t pos = arr_start;
    while (true) {
        size_t obj_start = json.find('{', pos);
        if (obj_start == std::string::npos) break;

        size_t obj_end = json.find('}', obj_start);
        if (obj_end == std::string::npos) break;

        std::string obj = json.substr(obj_start, obj_end - obj_start + 1);

        PeerInfo peer;

        // Parse ip
        size_t ip_pos = obj.find("\"ip\":\"");
        if (ip_pos != std::string::npos) {
            size_t ip_start = ip_pos + 6;
            size_t ip_end = obj.find('"', ip_start);
            if (ip_end != std::string::npos) {
                peer.ip = obj.substr(ip_start, ip_end - ip_start);
            }
        }

        // Parse port
        size_t port_pos = obj.find("\"port\":");
        if (port_pos != std::string::npos) {
            peer.port = static_cast<uint16_t>(std::stoul(obj.substr(port_pos + 7)));
        }

        // Parse version
        size_t ver_pos = obj.find("\"version\":\"");
        if (ver_pos != std::string::npos) {
            size_t ver_start = ver_pos + 11;
            size_t ver_end = obj.find('"', ver_start);
            if (ver_end != std::string::npos) {
                peer.version = obj.substr(ver_start, ver_end - ver_start);
            }
        }

        // Parse height
        size_t height_pos = obj.find("\"height\":");
        if (height_pos != std::string::npos) {
            peer.height = static_cast<uint32_t>(std::stoul(obj.substr(height_pos + 9)));
        }

        // Parse country
        size_t country_pos = obj.find("\"country\":\"");
        if (country_pos != std::string::npos) {
            size_t c_start = country_pos + 11;
            size_t c_end = obj.find('"', c_start);
            if (c_end != std::string::npos) {
                peer.country = obj.substr(c_start, c_end - c_start);
            }
        }

        // Parse age
        size_t age_pos = obj.find("\"age\":");
        if (age_pos != std::string::npos) {
            peer.age_seconds = std::stoi(obj.substr(age_pos + 6));
        }

        if (!peer.ip.empty() && peer.port > 0) {
            peers.push_back(peer);
        }

        pos = obj_end + 1;
    }

    return peers;
}

std::vector<PeerInfo> SeedClient::discoverPeers(int max_peers) {
    std::string path = "/api/nodes?network=" + network_;
    std::string response = httpGet(path);

    if (response.empty()) {
        return {};
    }

    auto peers = parseNodesResponse(response);
    discovered_count_ = peers.size();

    // Limit results
    if (peers.size() > static_cast<size_t>(max_peers)) {
        peers.resize(max_peers);
    }

    if (on_peers_discovered_ && !peers.empty()) {
        on_peers_discovered_(peers);
    }

    return peers;
}

bool SeedClient::registerNode(uint16_t p2p_port, const std::string& version, uint32_t height) {
    std::ostringstream body;
    body << "{\"port\":" << p2p_port
         << ",\"version\":\"" << version << "\""
         << ",\"height\":" << height
         << ",\"network\":\"" << network_ << "\"}";

    std::string response = httpPost("/api/register", body.str());

    if (response.find("\"success\":true") != std::string::npos) {
        registered_ = true;
        version_ = version;
        return true;
    }

    return false;
}

void SeedClient::startHeartbeat(uint16_t p2p_port, uint32_t& height_ref) {
    if (heartbeat_running_) return;

    heartbeat_port_ = p2p_port;
    height_ptr_ = &height_ref;
    heartbeat_running_ = true;

    heartbeat_thread_ = std::thread([this]() {
        while (heartbeat_running_) {
            // Heartbeat every 5 minutes
            for (int i = 0; i < 300 && heartbeat_running_; ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            if (!heartbeat_running_) break;

            // Send heartbeat
            std::ostringstream body;
            body << "{\"port\":" << heartbeat_port_
                 << ",\"version\":\"" << version_ << "\""
                 << ",\"height\":" << (height_ptr_ ? *height_ptr_ : 0)
                 << ",\"network\":\"" << network_ << "\"}";

            httpPost("/api/heartbeat", body.str());
        }
    });
}

void SeedClient::stopHeartbeat() {
    heartbeat_running_ = false;
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
}

} // namespace seed
