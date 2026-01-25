#include "api_client.h"
#include <sstream>
#include <cstring>
#include <iostream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <cerrno>
#define closesocket close
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#endif

namespace net {

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

// Helper: connect to host:port with timeout (IPv4 and IPv6)
static SOCKET connectToHost(const std::string& host, uint16_t port, std::string& error) {
    struct addrinfo hints{}, *res, *p;
    hints.ai_family = AF_UNSPEC;  // IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(port);

    // Remove brackets from IPv6 address if present (e.g., [::1] -> ::1)
    std::string clean_host = host;
    if (!clean_host.empty() && clean_host.front() == '[') {
        size_t bracket_end = clean_host.find(']');
        if (bracket_end != std::string::npos) {
            clean_host = clean_host.substr(1, bracket_end - 1);
        }
    }

    int status = getaddrinfo(clean_host.c_str(), port_str.c_str(), &hints, &res);
    if (status != 0) {
        error = "DNS resolution failed";
        return INVALID_SOCKET;
    }

    SOCKET sock = INVALID_SOCKET;
    for (p = res; p != nullptr; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == INVALID_SOCKET) continue;

        // Set non-blocking mode for connect timeout
#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
#else
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

        // Start non-blocking connect
        int connect_result = ::connect(sock, p->ai_addr, static_cast<int>(p->ai_addrlen));

        if (connect_result == 0) {
            // Connected immediately (rare but possible)
        } else {
#ifdef _WIN32
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                closesocket(sock);
                sock = INVALID_SOCKET;
                continue;
            }
#else
            if (errno != EINPROGRESS) {
                closesocket(sock);
                sock = INVALID_SOCKET;
                continue;
            }
#endif
            // Wait for connection with timeout (2 seconds)
            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(sock, &writefds);

            struct timeval tv;
            tv.tv_sec = 2;
            tv.tv_usec = 0;

            int select_result = select(static_cast<int>(sock) + 1, nullptr, &writefds, nullptr, &tv);

            if (select_result <= 0) {
                // Timeout or error
                closesocket(sock);
                sock = INVALID_SOCKET;
                continue;
            }

            // Check if connection succeeded
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);

            if (so_error != 0) {
                closesocket(sock);
                sock = INVALID_SOCKET;
                continue;
            }
        }

        // Set back to blocking mode and set recv/send timeout
#ifdef _WIN32
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
        DWORD timeout = 2000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
        fcntl(sock, F_SETFL, flags);
        struct timeval recv_tv;
        recv_tv.tv_sec = 2;
        recv_tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_tv, sizeof(recv_tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &recv_tv, sizeof(recv_tv));
#endif
        break;  // Success
    }

    freeaddrinfo(res);

    if (sock == INVALID_SOCKET) {
        error = "Connection failed";
    }
    return sock;
}

APIClient::APIClient(const std::string& host, uint16_t port)
    : host_(host), port_(port), connected_(false)
{
#ifdef _WIN32
    initWinsock();
#endif
}

APIClient::~APIClient() {
    disconnect();
}

bool APIClient::connect() {
    std::string response = httpGet("/status");
    connected_ = !response.empty();
    return connected_;
}

void APIClient::disconnect() {
    connected_ = false;
}

std::string APIClient::httpGet(const std::string& path) {
    SOCKET sock = connectToHost(host_, port_, last_error_);
    if (sock == INVALID_SOCKET) {
        return "";
    }

    std::string request = "GET " + path + " HTTP/1.1\r\n";
    request += "Host: " + host_ + "\r\n";
    request += "Connection: close\r\n\r\n";

    send(sock, request.c_str(), static_cast<int>(request.size()), 0);

    std::string response;
    char buffer[4096];
    int received;
    while ((received = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[received] = '\0';
        response += buffer;
    }

    closesocket(sock);

    size_t body_start = response.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        return response.substr(body_start + 4);
    }

    return response;
}

std::string APIClient::httpPost(const std::string& path, const std::string& body) {
    std::string error;
    SOCKET sock = connectToHost(host_, port_, error);
    if (sock == INVALID_SOCKET) return "";

    std::ostringstream ss;
    ss << "POST " << path << " HTTP/1.1\r\n";
    ss << "Host: " << host_ << "\r\n";
    ss << "Content-Type: application/json\r\n";
    ss << "Content-Length: " << body.size() << "\r\n";
    ss << "Connection: close\r\n\r\n";
    ss << body;

    std::string request = ss.str();
    send(sock, request.c_str(), static_cast<int>(request.size()), 0);

    std::string response;
    char buffer[4096];
    int received;
    while ((received = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[received] = '\0';
        response += buffer;
    }

    closesocket(sock);

    size_t body_start = response.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        return response.substr(body_start + 4);
    }

    return response;
}

// Helper to convert hex to bytes
static std::vector<uint8_t> hexStringToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int byte = 0;
        for (int j = 0; j < 2; ++j) {
            char c = hex[i + j];
            byte <<= 4;
            if (c >= '0' && c <= '9') byte |= (c - '0');
            else if (c >= 'a' && c <= 'f') byte |= (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') byte |= (c - 'A' + 10);
        }
        bytes.push_back(static_cast<uint8_t>(byte));
    }
    return bytes;
}

// Helper to convert bytes to hex
static std::string bytesToHexString(const std::vector<uint8_t>& bytes) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes) {
        result += hex_chars[(byte >> 4) & 0x0F];
        result += hex_chars[byte & 0x0F];
    }
    return result;
}

std::optional<mining::Work> APIClient::getMiningTemplate(const std::string& address) {
    std::string response = httpGet("/mining/template?address=" + address);

    if (response.empty()) {
        return std::nullopt;
    }

    mining::Work work;

    // Extract height
    size_t pos = response.find("\"height\":");
    if (pos != std::string::npos) {
        work.height = std::stoul(response.substr(pos + 9));
    }

    // Extract bits
    pos = response.find("\"bits\":");
    if (pos != std::string::npos) {
        work.bits = std::stoul(response.substr(pos + 7));
        work.target = mining::Keccak256::bitsToTarget(work.bits);
    }

    // Extract prev_hash
    pos = response.find("\"prev_hash\":\"");
    if (pos != std::string::npos) {
        std::string hash_hex = response.substr(pos + 13, 64);
        work.prev_hash = mining::Keccak256::fromHex(hash_hex);
    }

    // Extract merkle_root
    pos = response.find("\"merkle_root\":\"");
    if (pos != std::string::npos) {
        std::string hash_hex = response.substr(pos + 15, 64);
        work.merkle_root = mining::Keccak256::fromHex(hash_hex);
    }

    // Extract timestamp
    pos = response.find("\"timestamp\":");
    if (pos != std::string::npos) {
        work.timestamp = std::stoul(response.substr(pos + 12));
    } else {
        work.timestamp = static_cast<uint32_t>(std::time(nullptr));
    }

    // Extract coinbase (hex)
    pos = response.find("\"coinbase\":\"");
    if (pos != std::string::npos) {
        size_t start = pos + 12;
        size_t end = response.find('"', start);
        if (end != std::string::npos) {
            std::string coinbase_hex = response.substr(start, end - start);
            work.coinbase = hexStringToBytes(coinbase_hex);
        }
    }

    // Extract transactions array (simplified parsing)
    pos = response.find("\"transactions\":[");
    if (pos != std::string::npos) {
        size_t start = pos + 16;
        size_t end = response.find(']', start);
        if (end != std::string::npos) {
            std::string txs = response.substr(start, end - start);
            size_t tx_pos = 0;
            while ((tx_pos = txs.find('"', tx_pos)) != std::string::npos) {
                tx_pos++;
                size_t tx_end = txs.find('"', tx_pos);
                if (tx_end != std::string::npos) {
                    work.transactions_hex.push_back(txs.substr(tx_pos, tx_end - tx_pos));
                    tx_pos = tx_end + 1;
                } else {
                    break;
                }
            }
        }
    }

    work.version = 1;
    work.job_id = std::to_string(work.height);

    return work;
}

bool APIClient::submitBlock(const mining::Solution& solution, const mining::Work& work) {
    std::vector<uint8_t> block_data = work.buildBlock(solution.nonce);
    std::string block_hex = bytesToHexString(block_data);

    std::ostringstream ss;
    ss << "{\"hex\":\"" << block_hex << "\"}";
    std::string response = httpPost("/mining/submit", ss.str());

    return response.find("\"accepted\":true") != std::string::npos;
}

int64_t APIClient::getBlockHeight() {
    std::string response = httpGet("/status");
    size_t pos = response.find("\"height\":");
    if (pos != std::string::npos) {
        return std::stoll(response.substr(pos + 9));
    }
    return -1;
}

uint32_t APIClient::getDifficulty() {
    std::string response = httpGet("/mining/info");
    size_t pos = response.find("\"difficulty_bits\":");
    if (pos != std::string::npos) {
        return std::stoul(response.substr(pos + 18));
    }
    return 0;
}

APIClient::NetworkStats APIClient::getNetworkStats() {
    NetworkStats stats;

    // Get peer count and height from /status endpoint
    std::string status_response = httpGet("/status");
    if (!status_response.empty()) {
        // Look for "chain_height":N
        size_t height_pos = status_response.find("\"chain_height\":");
        if (height_pos != std::string::npos) {
            stats.height = std::stoi(status_response.substr(height_pos + 15));
        }

        // Look for "peer_count":N
        size_t peers_pos = status_response.find("\"peer_count\":");
        if (peers_pos != std::string::npos) {
            stats.peer_count = std::stoul(status_response.substr(peers_pos + 13));
        }
    }

    // Get active miners from /p2pool/status endpoint
    std::string p2pool_response = httpGet("/p2pool/status");
    if (!p2pool_response.empty()) {
        // Look for "active_miners":N
        size_t miners_pos = p2pool_response.find("\"active_miners\":");
        if (miners_pos != std::string::npos) {
            stats.active_miners = std::stoul(p2pool_response.substr(miners_pos + 16));
            stats.p2pool_running = true;
        }

        // Also check "running":true
        if (p2pool_response.find("\"running\":true") != std::string::npos) {
            stats.p2pool_running = true;
        }
    }

    return stats;
}

} // namespace net
