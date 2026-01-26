#ifndef FTC_MINER_NET_NODE_MANAGER_H
#define FTC_MINER_NET_NODE_MANAGER_H

#include "api_client.h"
#include "../dht/dht.h"
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <thread>

namespace net {

/**
 * NodeManager - Multi-node management with automatic failover
 *
 * Features:
 * - BitTorrent DHT peer discovery (automatic)
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

    // Start DHT peer discovery
    bool startDHT();

    // Stop DHT
    void stopDHT();

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

    // Control debug output (disable when TUI is active)
    void setDebugOutput(bool enabled) { debug_output_ = enabled; }

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

    // DHT for peer discovery
    std::unique_ptr<dht::DHT> dht_;
    std::atomic<bool> dht_running_{false};
    bool debug_output_ = true;  // Disabled when TUI is active

    // Internal helpers
    bool checkNode(NodeInfo& node);
    void selectBestNode();
    void log(const std::string& msg, bool is_error = false);
    void onDHTPeerFound(const std::string& ip, uint16_t port);
};

} // namespace net

#endif // FTC_MINER_NET_NODE_MANAGER_H
