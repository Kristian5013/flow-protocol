#ifndef FTC_MINER_NET_NODE_MANAGER_H
#define FTC_MINER_NET_NODE_MANAGER_H

#include "api_client.h"
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>

namespace net {

/**
 * NodeManager - Multi-node management with automatic failover
 *
 * Features:
 * - Loads nodes from peers.dat (shared with ftc-node)
 * - Real-time health monitoring (latency, failures)
 * - Automatic failover when node becomes unavailable
 * - Selects best node based on response time
 *
 * Kristian Pilatovich 20091227 - First Real P2P
 */
class NodeManager {
public:
    struct NodeInfo {
        std::string host;
        uint16_t port;

        // Health metrics
        double avg_latency_ms = 0;      // Average response time
        int consecutive_failures = 0;   // Failures in a row
        int total_failures = 0;         // Total failures
        int total_requests = 0;         // Total requests made
        bool available = false;         // Currently reachable
        std::chrono::steady_clock::time_point last_check;
        std::chrono::steady_clock::time_point last_success;

        // Calculated score (lower is better)
        double score() const {
            if (!available || consecutive_failures >= 3) return 999999.0;
            return avg_latency_ms + (consecutive_failures * 100.0);
        }
    };

    using NodeChangedCallback = std::function<void(const std::string& host, uint16_t port)>;
    using LogCallback = std::function<void(const std::string& msg, bool is_error)>;

    NodeManager();
    ~NodeManager();

    // Load nodes from peers.dat (same format as ftc-node)
    // Searches: ./peers.dat, then data_dir/peers/peers.dat
    bool loadPeers(const std::string& data_dir = "");

    // Add node manually (e.g., from command line -o option)
    void addNode(const std::string& host, uint16_t port);

    // Get current best node's API client
    // Returns nullptr if no nodes available
    APIClient* getClient();

    // Force switch to next available node
    bool switchToNextNode();

    // Check all nodes and select best one
    void refreshNodes();

    // Get current node info
    const NodeInfo* getCurrentNode() const;

    // Get all nodes
    const std::vector<NodeInfo>& getNodes() const { return nodes_; }

    // Mark current request as success/failure
    void recordSuccess(double latency_ms);
    void recordFailure();

    // Callbacks
    void setOnNodeChanged(NodeChangedCallback cb) { on_node_changed_ = cb; }
    void setLogCallback(LogCallback cb) { log_callback_ = cb; }

    // Health check interval
    void setHealthCheckInterval(int ms) { health_check_interval_ms_ = ms; }

    // Get stats
    size_t getNodeCount() const { return nodes_.size(); }
    size_t getAvailableCount() const;

private:
    std::vector<NodeInfo> nodes_;
    std::unique_ptr<APIClient> current_client_;
    int current_index_ = -1;
    mutable std::mutex mutex_;

    NodeChangedCallback on_node_changed_;
    LogCallback log_callback_;

    int health_check_interval_ms_ = 5000;
    int max_consecutive_failures_ = 3;

    // Internal helpers
    bool checkNode(NodeInfo& node);
    void selectBestNode();
    void log(const std::string& msg, bool is_error = false);

    // Parse peers.dat line format: [IPv6]:port or IPv4:port
    bool parsePeerLine(const std::string& line, std::string& host, uint16_t& port);
};

} // namespace net

#endif // FTC_MINER_NET_NODE_MANAGER_H
