#include "peer_manager.h"
#include "config/config.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <algorithm>

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
#define closesocket close
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#endif

namespace net {

#ifdef _WIN32
static bool g_wsa_peer_init = false;
static void initWinsockPeer() {
    if (!g_wsa_peer_init) {
        WSADATA data;
        WSAStartup(MAKEWORD(2, 2), &data);
        g_wsa_peer_init = true;
    }
}
#endif

PeerManager::PeerManager() : monitoring_(false) {
#ifdef _WIN32
    initWinsockPeer();
#endif
}

PeerManager::~PeerManager() {
    stopMonitoring();
}

bool PeerManager::loadPeersFile(const std::string& filename) {
    std::cout << "[Peers] Loading from: " << filename << "\n";

    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cout << "[Peers] File not found or cannot open\n";
        return false;
    }

    std::lock_guard<std::mutex> lock(peers_mutex_);
    peers_.clear();

    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;

        // Strip inline comments (everything after #)
        size_t comment_pos = line.find('#');
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }

        // Trim trailing whitespace
        while (!line.empty() && (line.back() == ' ' || line.back() == '\t' ||
                                  line.back() == '\r' || line.back() == '\n')) {
            line.pop_back();
        }

        if (line.empty()) continue;

        // Parse host:port
        auto [host, port] = StartupDialog::parseAddress(line);
        if (!host.empty()) {
            // Skip localhost/local addresses
            if (host == "::1" || host == "127.0.0.1" ||
                host == "localhost" || host.substr(0, 4) == "fe80") {
                continue;
            }
            PeerInfo peer;
            peer.host = host;
            peer.port = port;
            peers_.push_back(peer);
        }
    }

    std::cout << "[Peers] Loaded " << peers_.size() << " peer(s) from " << filename << "\n";
    return !peers_.empty();
}

bool PeerManager::savePeersFile(const std::string& filename) {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }

    file << "# FTC Miner Peers File (IPv6)\n";
    file << "# Format: [ipv6]:port or host:port (one per line)\n";
    file << "# Example: [2001:db8::1]:17319\n\n";

    // Sort by ping (best first)
    std::vector<PeerInfo> sorted = peers_;
    std::sort(sorted.begin(), sorted.end(), [](const PeerInfo& a, const PeerInfo& b) {
        if (a.ping_ms < 0) return false;
        if (b.ping_ms < 0) return true;
        return a.ping_ms < b.ping_ms;
    });

    for (const auto& peer : sorted) {
        // Skip localhost/local addresses - not useful for peers.dat
        if (peer.host == "::1" || peer.host == "127.0.0.1" ||
            peer.host == "localhost" || peer.host.substr(0, 4) == "fe80") {
            continue;
        }

        // Format IPv6 addresses with brackets: [ipv6]:port
        // Check if host contains ':' (IPv6) but doesn't already have brackets
        if (peer.host.find(':') != std::string::npos &&
            (peer.host.empty() || peer.host.front() != '[')) {
            file << "[" << peer.host << "]:" << peer.port;
        } else {
            file << peer.host << ":" << peer.port;
        }
        if (peer.ping_ms >= 0) {
            file << "  # ping=" << peer.ping_ms << "ms";
            if (peer.online) file << " online";
        }
        file << "\n";
    }

    return true;
}

void PeerManager::addPeer(const std::string& host, uint16_t port) {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    // Check if already exists
    for (const auto& p : peers_) {
        if (p.host == host && p.port == port) {
            return;
        }
    }

    PeerInfo peer;
    peer.host = host;
    peer.port = port;
    peers_.push_back(peer);
}

void PeerManager::addSeedNodes() {
    // Default seed nodes (public FTC nodes with IPv6)
    // Users should update peers.dat with their known nodes
    // Format: [ipv6]:port

    // No default seed nodes - user must configure peers.dat
    // or enter node address manually
}

PeerInfo* PeerManager::getBestPeer() {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    PeerInfo* best = nullptr;
    int64_t best_ping = INT64_MAX;

    for (auto& peer : peers_) {
        if (peer.online && peer.ping_ms >= 0 && peer.ping_ms < best_ping) {
            best_ping = peer.ping_ms;
            best = &peer;
        }
    }

    return best;
}

PeerInfo* PeerManager::getActivePeer() {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    if (active_peer_index_ >= 0 && active_peer_index_ < static_cast<int>(peers_.size())) {
        return &peers_[active_peer_index_];
    }
    return nullptr;
}

bool PeerManager::switchToNextPeer() {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    // Mark current as failed
    if (active_peer_index_ >= 0 && active_peer_index_ < static_cast<int>(peers_.size())) {
        peers_[active_peer_index_].fail_count++;
        peers_[active_peer_index_].online = false;
    }

    // Find next best online peer
    int64_t best_ping = INT64_MAX;
    int best_idx = -1;

    for (size_t i = 0; i < peers_.size(); ++i) {
        if (static_cast<int>(i) == active_peer_index_) continue;
        if (peers_[i].online && peers_[i].ping_ms >= 0 && peers_[i].ping_ms < best_ping) {
            best_ping = peers_[i].ping_ms;
            best_idx = static_cast<int>(i);
        }
    }

    if (best_idx >= 0) {
        active_peer_index_ = best_idx;
        std::cout << "[Peers] Switched to " << peers_[best_idx].host << ":"
                  << peers_[best_idx].port << " (ping: " << peers_[best_idx].ping_ms << "ms)\n";
        return true;
    }

    // No online peers, try to find any peer
    for (size_t i = 0; i < peers_.size(); ++i) {
        if (static_cast<int>(i) != active_peer_index_ && peers_[i].fail_count < 3) {
            active_peer_index_ = static_cast<int>(i);
            std::cout << "[Peers] Trying " << peers_[i].host << ":" << peers_[i].port << "\n";
            return true;
        }
    }

    return false;
}

int64_t PeerManager::measurePing(const std::string& host, uint16_t port) {
    auto start = std::chrono::steady_clock::now();

    // Use getaddrinfo for IPv6 support
    struct addrinfo hints{}, *res, *p;
    hints.ai_family = AF_INET6;       // IPv6 only
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(port);

    // Remove brackets from IPv6 address if present
    std::string clean_host = host;
    if (!clean_host.empty() && clean_host.front() == '[') {
        size_t bracket_end = clean_host.find(']');
        if (bracket_end != std::string::npos) {
            clean_host = clean_host.substr(1, bracket_end - 1);
        }
    }

    if (getaddrinfo(clean_host.c_str(), port_str.c_str(), &hints, &res) != 0) {
        return -1;
    }

    SOCKET sock = INVALID_SOCKET;
    for (p = res; p != nullptr; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == INVALID_SOCKET) continue;

        // Set timeout
#ifdef _WIN32
        DWORD timeout = 5000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

        if (::connect(sock, p->ai_addr, static_cast<int>(p->ai_addrlen)) != SOCKET_ERROR) {
            break;  // Success
        }
        closesocket(sock);
        sock = INVALID_SOCKET;
    }

    freeaddrinfo(res);

    if (sock == INVALID_SOCKET) return -1;

    // Measure TCP connect time only (more accurate ping)
    auto connect_time = std::chrono::steady_clock::now();
    int64_t ping_ms = std::chrono::duration_cast<std::chrono::microseconds>(connect_time - start).count() / 1000;

    // Still verify the API is working with a quick request
    std::string request = "GET /status HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
    send(sock, request.c_str(), static_cast<int>(request.size()), 0);

    char buffer[256];
    int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    closesocket(sock);

    if (received <= 0) return -1;

    // Return TCP connect time (not full HTTP round-trip)
    return ping_ms > 0 ? ping_ms : 1;  // Minimum 1ms
}

bool PeerManager::testPeer(PeerInfo& peer) {
    peer.last_check = std::chrono::steady_clock::now();
    int64_t ping = measurePing(peer.host, peer.port);

    if (ping >= 0) {
        peer.ping_ms = ping;
        peer.online = true;
        peer.fail_count = 0;
        return true;
    } else {
        peer.online = false;
        peer.fail_count++;
        return false;
    }
}

void PeerManager::testAllPeers() {
    // Test all peers silently
    for (auto& peer : peers_) {
        testPeer(peer);
    }

    // Set active peer to best one
    std::lock_guard<std::mutex> lock(peers_mutex_);
    int64_t best_ping = INT64_MAX;
    int best_idx = -1;

    for (size_t i = 0; i < peers_.size(); ++i) {
        if (peers_[i].online && peers_[i].ping_ms >= 0 && peers_[i].ping_ms < best_ping) {
            best_ping = peers_[i].ping_ms;
            best_idx = static_cast<int>(i);
        }
    }

    if (best_idx >= 0) {
        active_peer_index_ = best_idx;
    }
}

bool PeerManager::hasOnlinePeers() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (const auto& peer : peers_) {
        if (peer.online) return true;
    }
    return false;
}

size_t PeerManager::getOnlinePeerCount() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    size_t count = 0;
    for (const auto& peer : peers_) {
        if (peer.online) count++;
    }
    return count;
}

void PeerManager::startMonitoring(int interval_ms) {
    if (monitoring_) return;

    monitor_interval_ms_ = interval_ms;
    monitoring_ = true;
    monitor_thread_ = std::thread(&PeerManager::monitorThread, this);
}

void PeerManager::stopMonitoring() {
    monitoring_ = false;
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

void PeerManager::monitorThread() {
    while (monitoring_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(monitor_interval_ms_));
        if (!monitoring_) break;

        // Test all peers periodically
        for (auto& peer : peers_) {
            if (!monitoring_) break;
            testPeer(peer);
        }

        // Check if active peer is still best
        auto* best = getBestPeer();
        auto* active = getActivePeer();

        if (best && active && best != active) {
            // Switch if new peer is significantly better (>50ms difference)
            if (best->ping_ms + 50 < active->ping_ms) {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                for (size_t i = 0; i < peers_.size(); ++i) {
                    if (&peers_[i] == best) {
                        active_peer_index_ = static_cast<int>(i);
                        std::cout << "[Peers] Auto-switched to faster peer: "
                                  << best->host << " (" << best->ping_ms << "ms)\n";
                        break;
                    }
                }
            }
        }
    }
}

// StartupDialog implementation

std::string StartupDialog::showDialog(PeerManager& pm) {
    std::cout << "\n";
    std::cout << "+==========================================+\n";
    std::cout << "|     FTC Miner v2.0.0 - Keccak-256       |\n";
    std::cout << "|         GPU OpenCL Miner                 |\n";
    std::cout << "|  Kristian Pilatovich - First Real P2P   |\n";
    std::cout << "+==========================================+\n\n";

    // Use shared data directory (same as node)
    std::string data_dir = config::MinerConfig::getDataDir();
    std::string last_node_file = data_dir + "/last_node.txt";
    std::cout << "[Data] Using: " << data_dir << "\n\n";

    // Load last used node address
    std::string last_addr;
    std::ifstream lf(last_node_file);
    if (lf.is_open()) {
        std::getline(lf, last_addr);
        lf.close();
    }

    // Mode selection
    std::cout << "Select mode:\n";
    if (!last_addr.empty()) {
        std::cout << "  [1] Connect to " << last_addr << "\n";
        std::cout << "  [2] Enter different address\n";
        std::cout << "  [3] Benchmark mode\n";
        std::cout << "  [4] Exit\n";
        std::cout << "\nChoice [1]: ";

        std::string mode_choice;
        std::getline(std::cin, mode_choice);

        if (mode_choice == "4") return "";
        if (mode_choice == "3") return "BENCHMARK";

        if (mode_choice.empty() || mode_choice == "1") {
            // Use saved address
            auto [host, port] = parseAddress(last_addr);
            std::cout << "Connecting to " << host << ":" << port << "...\n";
            if (host.find(':') != std::string::npos) {
                return "STRATUM:[" + host + "]:" + std::to_string(port);
            }
            return "STRATUM:" + host + ":" + std::to_string(port);
        }
        // Fall through to manual entry for mode_choice == "2"
    } else {
        std::cout << "  [1] Connect to node (port 3333)\n";
        std::cout << "  [2] Benchmark mode\n";
        std::cout << "  [3] Exit\n";
        std::cout << "\nChoice [1]: ";

        std::string mode_choice;
        std::getline(std::cin, mode_choice);

        if (mode_choice == "3") return "";
        if (mode_choice == "2") return "BENCHMARK";
    }

    // Manual address entry
    std::cout << "\nEnter node address (IPv6: [ipv6]:port or host:port)\n";
    std::cout << "Default port: 3333\n";
    std::cout << "Example: [::1]:3333\n";
    std::cout << "\nNode address: ";

    std::string addr;
    std::getline(std::cin, addr);

    if (addr.empty()) {
        return "";
    }

    auto [host, port] = parseAddress(addr);
    if (host.empty()) {
        std::cout << "Invalid address format\n";
        return "";
    }

    // Default port 3333
    if (port == 17319) {
        port = 3333;
    }

    // Save for next time
    std::string save_addr;
    if (host.find(':') != std::string::npos) {
        save_addr = "[" + host + "]:" + std::to_string(port);
    } else {
        save_addr = host + ":" + std::to_string(port);
    }
    std::ofstream of(last_node_file);
    if (of.is_open()) {
        of << save_addr;
        of.close();
    }

    std::cout << "Connecting to " << host << ":" << port << "...\n";

    if (host.find(':') != std::string::npos) {
        return "STRATUM:[" + host + "]:" + std::to_string(port);
    }
    return "STRATUM:" + host + ":" + std::to_string(port);
}

std::pair<std::string, uint16_t> StartupDialog::parseAddress(const std::string& addr) {
    std::string trimmed = addr;

    // Trim whitespace
    while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t')) {
        trimmed.erase(0, 1);
    }
    while (!trimmed.empty() && (trimmed.back() == ' ' || trimmed.back() == '\t' ||
                                 trimmed.back() == '\r' || trimmed.back() == '\n')) {
        trimmed.pop_back();
    }

    if (trimmed.empty()) {
        return {"", 0};
    }

    // Remove protocol prefix if present
    if (trimmed.find("://") != std::string::npos) {
        trimmed = trimmed.substr(trimmed.find("://") + 3);
    }

    // Check for IPv6 address in brackets: [::1]:port or [2001:db8::1]:port
    if (!trimmed.empty() && trimmed.front() == '[') {
        size_t bracket_end = trimmed.find(']');
        if (bracket_end != std::string::npos) {
            std::string host = trimmed.substr(1, bracket_end - 1);  // Extract IPv6 without brackets

            // Check for port after bracket
            if (bracket_end + 1 < trimmed.size() && trimmed[bracket_end + 1] == ':') {
                std::string port_str = trimmed.substr(bracket_end + 2);

                // Remove any path after port
                size_t slash = port_str.find('/');
                if (slash != std::string::npos) {
                    port_str = port_str.substr(0, slash);
                }

                try {
                    uint16_t port = static_cast<uint16_t>(std::stoi(port_str));
                    return {host, port};
                } catch (...) {
                    return {host, 17319};
                }
            }
            return {host, 17319};
        }
    }

    // Count colons to detect bare IPv6 address (e.g., 2406:5900:2:d47::1234)
    size_t colon_count = std::count(trimmed.begin(), trimmed.end(), ':');

    // If more than one colon, it's a bare IPv6 address - use default port
    if (colon_count > 1) {
        return {trimmed, 17319};
    }

    // Parse host:port (IPv4 or hostname with port - exactly one colon)
    if (colon_count == 1) {
        size_t colon = trimmed.find(':');
        std::string host = trimmed.substr(0, colon);
        std::string port_str = trimmed.substr(colon + 1);

        // Remove any path after port
        size_t slash = port_str.find('/');
        if (slash != std::string::npos) {
            port_str = port_str.substr(0, slash);
        }

        try {
            uint16_t port = static_cast<uint16_t>(std::stoi(port_str));
            return {host, port};
        } catch (...) {
            return {trimmed, 17319};
        }
    }

    // No colons - just hostname, use default port
    return {trimmed, 17319};
}

} // namespace net
