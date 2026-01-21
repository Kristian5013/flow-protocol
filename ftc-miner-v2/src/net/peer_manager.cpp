#include "peer_manager.h"
#include <iostream>
#include <sstream>
#include <cstring>

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
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(peers_mutex_);
    peers_.clear();

    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;

        // Parse host:port
        auto [host, port] = StartupDialog::parseAddress(line);
        if (!host.empty()) {
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

    file << "# FTC Miner Peers File\n";
    file << "# Format: host:port (one per line)\n\n";

    // Sort by ping (best first)
    std::vector<PeerInfo> sorted = peers_;
    std::sort(sorted.begin(), sorted.end(), [](const PeerInfo& a, const PeerInfo& b) {
        if (a.ping_ms < 0) return false;
        if (b.ping_ms < 0) return true;
        return a.ping_ms < b.ping_ms;
    });

    for (const auto& peer : sorted) {
        file << peer.host << ":" << peer.port;
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

    // Use getaddrinfo for IPv4/IPv6 support
    struct addrinfo hints{}, *res, *p;
    hints.ai_family = AF_UNSPEC;  // IPv4 or IPv6
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

    // Send simple HTTP request to test
    std::string request = "GET /status HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
    send(sock, request.c_str(), static_cast<int>(request.size()), 0);

    char buffer[1024];
    int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    closesocket(sock);

    if (received <= 0) return -1;

    auto end = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
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
    std::cout << "[Peers] Testing " << peers_.size() << " peer(s)...\n";

    for (auto& peer : peers_) {
        bool ok = testPeer(peer);
        if (ok) {
            std::cout << "  " << peer.host << ":" << peer.port << " - " << peer.ping_ms << "ms OK\n";
        } else {
            std::cout << "  " << peer.host << ":" << peer.port << " - OFFLINE\n";
        }
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
        std::cout << "[Peers] Best peer: " << peers_[best_idx].host << ":"
                  << peers_[best_idx].port << " (" << peers_[best_idx].ping_ms << "ms)\n";
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
    std::cout << "+==========================================+\n\n";

    // Mode selection
    std::cout << "Select mode:\n";
    std::cout << "  [1] Connect to node (real mining)\n";
    std::cout << "  [2] Benchmark mode (test without node)\n";
    std::cout << "  [3] Exit\n";
    std::cout << "\nChoice [1]: ";

    std::string mode_choice;
    std::getline(std::cin, mode_choice);

    if (mode_choice == "3") {
        return "";
    }

    if (mode_choice == "2") {
        return "BENCHMARK";  // Special marker for benchmark mode
    }

    // Mode 1: Connect to node
    std::cout << "\n";

    // Try to load peers.dat
    bool has_peers = pm.loadPeersFile("peers.dat");

    if (has_peers && pm.getPeerCount() > 0) {
        std::cout << "Found peers.dat with " << pm.getPeerCount() << " peer(s)\n";
        std::cout << "Testing connectivity...\n\n";
        pm.testAllPeers();

        if (pm.hasOnlinePeers()) {
            std::cout << "\n";
            std::cout << "Node options:\n";
            std::cout << "  [1] Use best peer from peers.dat (recommended)\n";
            std::cout << "  [2] Enter node address manually\n";
            std::cout << "\nChoice [1]: ";

            std::string choice;
            std::getline(std::cin, choice);

            if (choice.empty() || choice == "1") {
                auto* best = pm.getBestPeer();
                if (best) {
                    return best->host + ":" + std::to_string(best->port);
                }
            }
            // choice == "2" falls through to manual entry
        } else {
            std::cout << "\nNo online peers found in peers.dat\n";
        }
    } else {
        std::cout << "No peers.dat file found.\n";
    }

    // Manual entry
    std::cout << "\nEnter node address (host:port or just host for default port 17319)\n";
    std::cout << "Examples: 192.168.1.100:17319, node.ftc.io, 10.0.0.5\n";
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

    // Add to peer manager and test
    pm.addPeer(host, port);

    std::cout << "Testing connection to " << host << ":" << port << "...\n";

    auto& peers = pm.getPeers();
    if (!peers.empty()) {
        if (pm.testPeer(peers.back())) {
            std::cout << "Connected! Ping: " << peers.back().ping_ms << "ms\n";
            pm.savePeersFile("peers.dat");
            return host + ":" + std::to_string(port);
        } else {
            std::cout << "Warning: Could not connect to " << host << ":" << port << "\n";
            std::cout << "Continuing anyway (node may come online later)...\n";
            return host + ":" + std::to_string(port);
        }
    }

    return "";
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
            std::string host = trimmed.substr(0, bracket_end + 1);  // Include brackets

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

    // Parse IPv4 host:port (use rfind to get last colon)
    size_t colon = trimmed.rfind(':');
    if (colon != std::string::npos) {
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

    return {trimmed, 17319};
}

} // namespace net
