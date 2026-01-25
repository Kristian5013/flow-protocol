#pragma once

#include "node_id.h"
#include <vector>
#include <mutex>
#include <functional>

namespace dht {

class RoutingTable {
public:
    static constexpr int K = 8;           // Max nodes per bucket
    static constexpr int NUM_BUCKETS = 160;

    explicit RoutingTable(const NodeId& local_id);

    // Add or update a node
    // Returns true if node was added/updated
    bool addNode(const NodeEntry& node);

    // Remove a node
    void removeNode(const NodeId& id);

    // Mark node as failed (increment fail count)
    void markFailed(const NodeId& id);

    // Get closest nodes to a target ID
    std::vector<NodeEntry> findClosest(const NodeId& target, int count = K) const;

    // Get all nodes
    std::vector<NodeEntry> getAllNodes() const;

    // Get total node count
    size_t size() const;

    // Get our node ID
    const NodeId& localId() const { return local_id_; }

    // Callback when we need to ping a node (for replacement)
    using PingCallback = std::function<void(const NodeEntry&)>;
    void setOnPingNeeded(PingCallback cb) { ping_callback_ = cb; }

private:
    NodeId local_id_;
    std::vector<NodeEntry> buckets_[NUM_BUCKETS];
    mutable std::mutex mutex_;
    PingCallback ping_callback_;

    int getBucketIndex(const NodeId& id) const;
};

} // namespace dht
