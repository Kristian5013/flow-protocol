#include "seed_client.h"
#include <sstream>
#include <cstring>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#else
#include <cstdlib>
#include <cstdio>
#endif

namespace seed {

// Default seed API
static const char* DEFAULT_API_HOST = "api.flowprotocol.net";
static const uint16_t DEFAULT_API_PORT = 443;

#ifdef _WIN32

// WinHTTP-based HTTPS implementation for Windows

static bool parseUrl(const std::string& host, const std::string& path, uint16_t port, bool https,
                     std::wstring& w_host, std::wstring& w_path, INTERNET_PORT& w_port) {
    w_host = std::wstring(host.begin(), host.end());
    w_path = std::wstring(path.begin(), path.end());
    w_port = port;
    return !w_host.empty();
}

std::string SeedClient::httpGet(const std::string& path) {
    std::wstring w_host(api_host_.begin(), api_host_.end());
    std::wstring w_path(path.begin(), path.end());
    INTERNET_PORT port = use_https_ ? 443 : api_port_;

    // Open WinHTTP session
    HINTERNET session = WinHttpOpen(
        L"FTC-Node/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!session) {
        return "";
    }

    // Connect to server
    HINTERNET connect = WinHttpConnect(session, w_host.c_str(), port, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        return "";
    }

    // Open request
    DWORD flags = use_https_ ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(
        connect,
        L"GET",
        w_path.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags
    );

    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return "";
    }

    // Set timeouts (5 seconds)
    WinHttpSetTimeouts(request, 5000, 5000, 5000, 5000);

    // Send request
    BOOL result = WinHttpSendRequest(
        request,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0
    );

    if (!result) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return "";
    }

    // Receive response
    result = WinHttpReceiveResponse(request, NULL);
    if (!result) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return "";
    }

    // Check status code
    DWORD status_code = 0;
    DWORD size = sizeof(status_code);
    WinHttpQueryHeaders(
        request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &status_code,
        &size,
        WINHTTP_NO_HEADER_INDEX
    );

    if (status_code != 200) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return "";
    }

    // Read body
    std::string body;
    DWORD bytes_available = 0;
    do {
        bytes_available = 0;
        WinHttpQueryDataAvailable(request, &bytes_available);

        if (bytes_available > 0) {
            char* buffer = new char[bytes_available + 1];
            DWORD bytes_read = 0;

            if (WinHttpReadData(request, buffer, bytes_available, &bytes_read)) {
                buffer[bytes_read] = '\0';
                body.append(buffer, bytes_read);
            }

            delete[] buffer;
        }
    } while (bytes_available > 0);

    // Cleanup
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    return body;
}

std::string SeedClient::httpPost(const std::string& path, const std::string& body) {
    std::wstring w_host(api_host_.begin(), api_host_.end());
    std::wstring w_path(path.begin(), path.end());
    INTERNET_PORT port = use_https_ ? 443 : api_port_;

    HINTERNET session = WinHttpOpen(
        L"FTC-Node/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!session) {
        return "";
    }

    HINTERNET connect = WinHttpConnect(session, w_host.c_str(), port, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        return "";
    }

    DWORD flags = use_https_ ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(
        connect,
        L"POST",
        w_path.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags
    );

    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return "";
    }

    WinHttpSetTimeouts(request, 5000, 5000, 5000, 5000);

    // Set Content-Type header
    std::wstring headers = L"Content-Type: application/json";

    BOOL result = WinHttpSendRequest(
        request,
        headers.c_str(),
        static_cast<DWORD>(headers.length()),
        (LPVOID)body.c_str(),
        static_cast<DWORD>(body.length()),
        static_cast<DWORD>(body.length()),
        0
    );

    if (!result) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return "";
    }

    result = WinHttpReceiveResponse(request, NULL);
    if (!result) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return "";
    }

    // Read response body
    std::string response_body;
    DWORD bytes_available = 0;
    do {
        bytes_available = 0;
        WinHttpQueryDataAvailable(request, &bytes_available);

        if (bytes_available > 0) {
            char* buffer = new char[bytes_available + 1];
            DWORD bytes_read = 0;

            if (WinHttpReadData(request, buffer, bytes_available, &bytes_read)) {
                buffer[bytes_read] = '\0';
                response_body.append(buffer, bytes_read);
            }

            delete[] buffer;
        }
    } while (bytes_available > 0);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    return response_body;
}

#else

// Linux implementation using curl command

std::string SeedClient::httpGet(const std::string& path) {
    std::string protocol = use_https_ ? "https" : "http";
    std::string url = protocol + "://" + api_host_ + ":" + std::to_string(use_https_ ? 443 : api_port_) + path;

    std::string cmd = "curl -s -m 5 \"" + url + "\" 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");

    if (!pipe) {
        return "";
    }

    std::string result;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        result += buffer;
    }

    int status = pclose(pipe);
    if (status != 0) {
        return "";
    }

    return result;
}

std::string SeedClient::httpPost(const std::string& path, const std::string& body) {
    std::string protocol = use_https_ ? "https" : "http";
    std::string url = protocol + "://" + api_host_ + ":" + std::to_string(use_https_ ? 443 : api_port_) + path;

    // Escape single quotes in body
    std::string escaped_body;
    for (char c : body) {
        if (c == '\'') {
            escaped_body += "'\\''";
        } else {
            escaped_body += c;
        }
    }

    std::string cmd = "curl -s -m 5 -X POST -H \"Content-Type: application/json\" -d '" +
                      escaped_body + "' \"" + url + "\" 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");

    if (!pipe) {
        return "";
    }

    std::string result;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        result += buffer;
    }

    pclose(pipe);
    return result;
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
}

SeedClient::~SeedClient() {
    stopHeartbeat();
}

void SeedClient::setEndpoint(const std::string& host, uint16_t port, bool use_https) {
    api_host_ = host;
    api_port_ = port;
    use_https_ = use_https;
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
