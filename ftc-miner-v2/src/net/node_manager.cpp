#include "node_manager.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <pwd.h>
#include <unistd.h>
#endif

namespace net {

NodeManager::NodeManager() = default;
NodeManager::~NodeManager() = default;

void NodeManager::log(const std::string& msg, bool is_error) {
    if (log_callback_) {
        log_callback_(msg, is_error);
    }
}

bool NodeManager::parsePeerLine(const std::string& line, std::string& host, uint16_t& port) {
    std::string trimmed = line;

    // Skip comments and empty lines
    if (trimmed.empty() || trimmed[0] == '#') return false;

    // Trim whitespace
    size_t start = trimmed.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return false;
    size_t end = trimmed.find_last_not_of(" \t\r\n");
    trimmed = trimmed.substr(start, end - start + 1);

    if (trimmed.empty()) return false;

    // IPv6 format: [addr]:port
    if (trimmed[0] == '[') {
        size_t bracket_end = trimmed.find(']');
        if (bracket_end == std::string::npos) return false;

        host = trimmed.substr(1, bracket_end - 1);

        if (bracket_end + 1 < trimmed.size() && trimmed[bracket_end + 1] == ':') {
            try {
                port = static_cast<uint16_t>(std::stoi(trimmed.substr(bracket_end + 2)));
            } catch (...) {
                return false;
            }
        } else {
            port = 17319;  // Default API port
        }
        return true;
    }

    // IPv4 format: host:port
    size_t colon = trimmed.rfind(':');
    if (colon != std::string::npos) {
        host = trimmed.substr(0, colon);
        try {
            port = static_cast<uint16_t>(std::stoi(trimmed.substr(colon + 1)));
        } catch (...) {
            return false;
        }
    } else {
        host = trimmed;
        port = 17319;
    }

    return !host.empty();
}

bool NodeManager::loadPeers(const std::string& data_dir) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Use single peers.dat in FTC data directory
    std::string peers_path;
#ifdef _WIN32
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        peers_path = std::string(path) + "\\FTC\\peers.dat";
    }
#else
    const char* home = getenv("HOME");
    if (home) {
        peers_path = std::string(home) + "/.ftc/peers.dat";
    }
#endif

    if (peers_path.empty()) {
        return false;
    }

    std::ifstream file(peers_path);
    if (!file.is_open()) {
        return false;
    }

    int loaded = 0;
    std::string line;
    while (std::getline(file, line)) {
        std::string host;
        uint16_t port;

        if (parsePeerLine(line, host, port)) {
            // Convert P2P port to API port (17318 -> 17319)
            if (port == 17318) {
                port = 17319;
            }

            // Check if already exists
            bool exists = false;
            for (const auto& node : nodes_) {
                if (node.host == host && node.port == port) {
                    exists = true;
                    break;
                }
            }

            if (!exists) {
                NodeInfo info;
                info.host = host;
                info.port = port;
                info.last_check = std::chrono::steady_clock::now();
                nodes_.push_back(info);
                loaded++;
            }
        }
    }

    return loaded > 0;
}

void NodeManager::addNode(const std::string& host, uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if already exists
    for (const auto& node : nodes_) {
        if (node.host == host && node.port == port) {
            return;
        }
    }

    NodeInfo info;
    info.host = host;
    info.port = port;
    info.last_check = std::chrono::steady_clock::now();

    // Add at front (priority for manually specified nodes)
    nodes_.insert(nodes_.begin(), info);

    log("Added node: " + host + ":" + std::to_string(port));
}

bool NodeManager::checkNode(NodeInfo& node) {
    auto start = std::chrono::steady_clock::now();

    APIClient client(node.host, node.port);
    bool success = client.connect();

    auto end = std::chrono::steady_clock::now();
    double latency = std::chrono::duration<double, std::milli>(end - start).count();

    node.last_check = end;
    node.total_requests++;

    if (success) {
        node.available = true;
        node.consecutive_failures = 0;
        node.last_success = end;

        // Update average latency (exponential moving average)
        if (node.avg_latency_ms == 0) {
            node.avg_latency_ms = latency;
        } else {
            node.avg_latency_ms = node.avg_latency_ms * 0.7 + latency * 0.3;
        }
    } else {
        node.available = false;
        node.consecutive_failures++;
        node.total_failures++;
    }

    return success;
}

void NodeManager::selectBestNode() {
    if (nodes_.empty()) return;

    // Find node with best score
    int best_index = -1;
    double best_score = 999999.0;

    for (size_t i = 0; i < nodes_.size(); ++i) {
        double score = nodes_[i].score();
        if (score < best_score) {
            best_score = score;
            best_index = static_cast<int>(i);
        }
    }

    if (best_index >= 0 && best_index != current_index_) {
        current_index_ = best_index;
        const auto& node = nodes_[current_index_];

        current_client_ = std::make_unique<APIClient>(node.host, node.port);

        log("Selected node: " + node.host + ":" + std::to_string(node.port) +
            " (latency: " + std::to_string(static_cast<int>(node.avg_latency_ms)) + "ms)");

        if (on_node_changed_) {
            on_node_changed_(node.host, node.port);
        }
    }
}

void NodeManager::refreshNodes() {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& node : nodes_) {
        checkNode(node);
    }

    selectBestNode();
}

APIClient* NodeManager::getClient() {
    std::lock_guard<std::mutex> lock(mutex_);

    // If no client or current node is failing, try to find a working one
    if (!current_client_ || (current_index_ >= 0 &&
        nodes_[current_index_].consecutive_failures >= max_consecutive_failures_)) {

        // Check all nodes and select best
        for (auto& node : nodes_) {
            if (!node.available || node.consecutive_failures >= max_consecutive_failures_) {
                checkNode(node);
            }
        }
        selectBestNode();
    }

    return current_client_.get();
}

bool NodeManager::switchToNextNode() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (nodes_.size() <= 1) return false;

    // Mark current as unavailable
    if (current_index_ >= 0) {
        nodes_[current_index_].available = false;
        nodes_[current_index_].consecutive_failures = max_consecutive_failures_;
    }

    // Find next available node
    for (size_t i = 0; i < nodes_.size(); ++i) {
        int idx = (current_index_ + 1 + i) % nodes_.size();
        if (checkNode(nodes_[idx])) {
            current_index_ = idx;
            const auto& node = nodes_[current_index_];

            current_client_ = std::make_unique<APIClient>(node.host, node.port);

            log("Switched to node: " + node.host + ":" + std::to_string(node.port));

            if (on_node_changed_) {
                on_node_changed_(node.host, node.port);
            }
            return true;
        }
    }

    log("No available nodes found!", true);
    return false;
}

const NodeManager::NodeInfo* NodeManager::getCurrentNode() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (current_index_ >= 0 && current_index_ < static_cast<int>(nodes_.size())) {
        return &nodes_[current_index_];
    }
    return nullptr;
}

void NodeManager::recordSuccess(double latency_ms) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (current_index_ >= 0 && current_index_ < static_cast<int>(nodes_.size())) {
        auto& node = nodes_[current_index_];
        node.available = true;
        node.consecutive_failures = 0;
        node.total_requests++;
        node.last_success = std::chrono::steady_clock::now();

        // Update average latency
        if (node.avg_latency_ms == 0) {
            node.avg_latency_ms = latency_ms;
        } else {
            node.avg_latency_ms = node.avg_latency_ms * 0.8 + latency_ms * 0.2;
        }
    }
}

void NodeManager::recordFailure() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (current_index_ >= 0 && current_index_ < static_cast<int>(nodes_.size())) {
        auto& node = nodes_[current_index_];
        node.consecutive_failures++;
        node.total_failures++;
        node.total_requests++;

        if (node.consecutive_failures >= max_consecutive_failures_) {
            node.available = false;
            log("Node " + node.host + " marked unavailable after " +
                std::to_string(max_consecutive_failures_) + " failures", true);
        }
    }
}

size_t NodeManager::getAvailableCount() const {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t count = 0;
    for (const auto& node : nodes_) {
        if (node.available && node.consecutive_failures < max_consecutive_failures_) {
            count++;
        }
    }
    return count;
}

} // namespace net
