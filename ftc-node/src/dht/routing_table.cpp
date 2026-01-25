#include "routing_table.h"
#include <algorithm>
#include <ctime>

namespace dht {

RoutingTable::RoutingTable(const NodeId& local_id) : local_id_(local_id) {}

int RoutingTable::getBucketIndex(const NodeId& id) const {
    return local_id_.bucketIndex(id);
}

bool RoutingTable::addNode(const NodeEntry& node) {
    if (node.id == local_id_) {
        return false; // Don't add ourselves
    }

    std::lock_guard<std::mutex> lock(mutex_);

    int idx = getBucketIndex(node.id);
    auto& bucket = buckets_[idx];

    // Check if node already exists
    auto it = std::find_if(bucket.begin(), bucket.end(),
        [&node](const NodeEntry& e) { return e.id == node.id; });

    if (it != bucket.end()) {
        // Update existing node - move to end (most recently seen)
        it->last_seen = std::time(nullptr);
        it->fail_count = 0;
        it->ip = node.ip;
        it->port = node.port;

        // Move to end
        NodeEntry updated = *it;
        bucket.erase(it);
        bucket.push_back(updated);
        return true;
    }

    // New node
    if (bucket.size() < K) {
        // Bucket has space
        NodeEntry entry = node;
        entry.last_seen = std::time(nullptr);
        entry.fail_count = 0;
        bucket.push_back(entry);
        return true;
    }

    // Bucket is full - check if first node (least recently seen) is stale
    if (bucket.front().fail_count > 0) {
        // Replace stale node
        bucket.erase(bucket.begin());
        NodeEntry entry = node;
        entry.last_seen = std::time(nullptr);
        entry.fail_count = 0;
        bucket.push_back(entry);
        return true;
    }

    // Ping the least recently seen node to check if it's still alive
    if (ping_callback_) {
        ping_callback_(bucket.front());
    }

    return false; // Bucket full, node not added
}

void RoutingTable::removeNode(const NodeId& id) {
    std::lock_guard<std::mutex> lock(mutex_);

    int idx = getBucketIndex(id);
    auto& bucket = buckets_[idx];

    bucket.erase(
        std::remove_if(bucket.begin(), bucket.end(),
            [&id](const NodeEntry& e) { return e.id == id; }),
        bucket.end()
    );
}

void RoutingTable::markFailed(const NodeId& id) {
    std::lock_guard<std::mutex> lock(mutex_);

    int idx = getBucketIndex(id);
    auto& bucket = buckets_[idx];

    auto it = std::find_if(bucket.begin(), bucket.end(),
        [&id](const NodeEntry& e) { return e.id == id; });

    if (it != bucket.end()) {
        it->fail_count++;
        // Remove if too many failures
        if (it->fail_count >= 3) {
            bucket.erase(it);
        }
    }
}

std::vector<NodeEntry> RoutingTable::findClosest(const NodeId& target, int count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::pair<NodeId, NodeEntry>> candidates;

    // Collect all nodes with their distance to target
    for (int i = 0; i < NUM_BUCKETS; i++) {
        for (const auto& node : buckets_[i]) {
            NodeId dist = node.id ^ target;
            candidates.emplace_back(dist, node);
        }
    }

    // Sort by distance (XOR distance - smaller = closer)
    std::sort(candidates.begin(), candidates.end(),
        [](const auto& a, const auto& b) { return a.first < b.first; });

    // Return closest K nodes
    std::vector<NodeEntry> result;
    for (size_t i = 0; i < std::min(static_cast<size_t>(count), candidates.size()); i++) {
        result.push_back(candidates[i].second);
    }

    return result;
}

std::vector<NodeEntry> RoutingTable::getAllNodes() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<NodeEntry> result;
    for (int i = 0; i < NUM_BUCKETS; i++) {
        for (const auto& node : buckets_[i]) {
            result.push_back(node);
        }
    }
    return result;
}

size_t RoutingTable::size() const {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t count = 0;
    for (int i = 0; i < NUM_BUCKETS; i++) {
        count += buckets_[i].size();
    }
    return count;
}

} // namespace dht
