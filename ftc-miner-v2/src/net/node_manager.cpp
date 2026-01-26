#include "node_manager.h"
#include <algorithm>
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>

namespace net {

NodeManager::NodeManager() = default;

NodeManager::~NodeManager() {
    stopDHT();
}

bool NodeManager::startDHT() {
    if (dht_running_) return true;

    dht_ = std::make_unique<dht::DHT>(17322);  // Use different port than node (17321)

    // Set log callback (DHT already prefixes with [DHT])
    dht_->setLogCallback([this](const std::string& msg, bool is_error) {
        log(msg, is_error);
    });

    // Set peer found callback
    dht_->setOnPeerFound([this](const std::string& ip, uint16_t port) {
        onDHTPeerFound(ip, port);
    });

    if (!dht_->start()) {
        log("Failed to start DHT", true);
        return false;
    }

    dht_running_ = true;
    log("DHT started - discovering nodes...");
    return true;
}

void NodeManager::stopDHT() {
    if (dht_) {
        dht_->stop();
        dht_.reset();
    }
    dht_running_ = false;
}

void NodeManager::onDHTPeerFound(const std::string& ip, uint16_t port) {
    // DHT returns P2P port (17318), convert to API port (17319)
    uint16_t api_port = (port == 17318) ? 17319 : port;

    // Skip localhost
    if (ip == "::1" || ip == "127.0.0.1") return;

    // Skip known stale AWS prefixes (DHT caches old announcements)
    // AWS us-east-1 IPv6 prefix
    if (ip.find("2600:1f18:") == 0) {
        return;  // Skip AWS nodes that are likely stale
    }

    // Add node - verification happens later via checkNode/refreshNodes
    addNode(ip, api_port);
}

void NodeManager::log(const std::string& msg, bool is_error) {
    if (log_callback_) {
        log_callback_(msg, is_error);
    }
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
    // Don't log - DHT adds many nodes and we show count at startup
}

bool NodeManager::checkNode(NodeInfo& node) {
    auto start = std::chrono::steady_clock::now();

    if (debug_output_) {
        std::cerr << "[DEBUG] Checking node: " << node.host << ":" << node.port << std::endl;
    }

    APIClient client(node.host, node.port);

    // Get network stats which includes peer_count and height
    auto stats = client.getNetworkStats();

    auto end = std::chrono::steady_clock::now();
    double latency = std::chrono::duration<double, std::milli>(end - start).count();

    // Check if node responded and has sufficient peers (not isolated)
    // Require at least 2 peers - nodes with 1 peer might be in unstable state
    bool reachable = (stats.height > 0);
    bool has_peers = (stats.peer_count >= 2);
    bool success = reachable && has_peers;

    if (debug_output_) {
        std::cerr << "[DEBUG] Node " << node.host << ":" << node.port
                  << " reachable=" << (reachable ? "OK" : "FAILED")
                  << " peers=" << stats.peer_count
                  << " height=" << stats.height
                  << " latency=" << latency << "ms" << std::endl;
    }

    node.last_check = end;
    node.total_requests++;
    node.peer_count = stats.peer_count;
    node.height = stats.height;

    if (success) {
        node.available = true;
        node.consecutive_failures = 0;
        node.last_success = end;

        if (node.avg_latency_ms == 0) {
            node.avg_latency_ms = latency;
        } else {
            node.avg_latency_ms = node.avg_latency_ms * 0.7 + latency * 0.3;
        }
    } else {
        node.available = false;
        node.consecutive_failures++;
        node.total_failures++;

        if (reachable && !has_peers) {
            log("Node " + node.host + " has no peers (isolated)", true);
        }
    }

    return success;
}

void NodeManager::selectBestNode() {
    if (nodes_.empty()) return;

    // Find max height among all available PUBLIC nodes (exclude localhost)
    // Require at least 2 peers to be considered synced
    int32_t max_height = 0;
    for (const auto& node : nodes_) {
        // Skip localhost - only use public nodes
        if (node.host == "::1" || node.host == "127.0.0.1" || node.host == "localhost") {
            continue;
        }
        if (node.available && node.peer_count >= 2 && node.height > max_height) {
            max_height = node.height;
        }
    }

    if (max_height == 0) {
        log("No synchronized public nodes found!", true);
        return;
    }

    // Select best node that is synchronized (within 2 blocks of max height)
    int best_index = -1;
    double best_score = 999999.0;

    for (size_t i = 0; i < nodes_.size(); ++i) {
        const auto& node = nodes_[i];

        // Skip localhost - only use public nodes
        if (node.host == "::1" || node.host == "127.0.0.1" || node.host == "localhost") {
            continue;
        }

        // Skip unavailable or nodes without sufficient peers
        if (!node.available || node.peer_count < 2) continue;

        // Skip nodes that are behind (more than 2 blocks from max)
        if (node.height < max_height - 2) continue;

        // Score based on latency (lower is better)
        double score = node.avg_latency_ms + (node.consecutive_failures * 100.0);
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
            " (height: " + std::to_string(node.height) +
            ", peers: " + std::to_string(node.peer_count) +
            ", latency: " + std::to_string(static_cast<int>(node.avg_latency_ms)) + "ms)");

        if (on_node_changed_) {
            on_node_changed_(node.host, node.port);
        }
    }
}

void NodeManager::refreshNodes() {
    // Copy nodes for parallel checking
    std::vector<NodeInfo> nodes_copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        nodes_copy = nodes_;
    }

    if (nodes_copy.empty()) return;

    // Check ALL nodes in parallel (need all heights to find max)
    std::vector<std::thread> threads;
    threads.reserve(nodes_copy.size());

    for (size_t i = 0; i < nodes_copy.size(); ++i) {
        threads.emplace_back([this, i, &nodes_copy]() {
            checkNode(nodes_copy[i]);
        });
    }

    // Wait for all threads
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    // Update original nodes with results
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (size_t i = 0; i < nodes_copy.size() && i < nodes_.size(); ++i) {
            // Only update if this node was actually checked
            if (nodes_copy[i].total_requests > nodes_[i].total_requests) {
                nodes_[i].available = nodes_copy[i].available;
                nodes_[i].avg_latency_ms = nodes_copy[i].avg_latency_ms;
                nodes_[i].consecutive_failures = nodes_copy[i].consecutive_failures;
                nodes_[i].total_failures = nodes_copy[i].total_failures;
                nodes_[i].total_requests = nodes_copy[i].total_requests;
                nodes_[i].last_check = nodes_copy[i].last_check;
                nodes_[i].last_success = nodes_copy[i].last_success;
                nodes_[i].peer_count = nodes_copy[i].peer_count;
                nodes_[i].height = nodes_copy[i].height;
            }
        }
        selectBestNode();
    }
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
        // Skip localhost - only count public nodes
        if (node.host == "::1" || node.host == "127.0.0.1" || node.host == "localhost") {
            continue;
        }
        if (node.available && node.peer_count >= 2 &&
            node.consecutive_failures < max_consecutive_failures_) {
            count++;
        }
    }
    return count;
}

} // namespace net
