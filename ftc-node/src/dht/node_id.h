#pragma once

#include <array>
#include <string>
#include <cstdint>
#include <functional>

namespace dht {

// 160-bit Node ID (same as SHA1 hash size)
class NodeId {
public:
    static constexpr size_t SIZE = 20;

    NodeId();
    explicit NodeId(const std::array<uint8_t, SIZE>& data);
    explicit NodeId(const uint8_t* data);
    explicit NodeId(const std::string& data);

    // Generate random node ID
    static NodeId random();

    // Generate from data (SHA1 hash)
    static NodeId fromHash(const std::string& data);

    // XOR distance
    NodeId operator^(const NodeId& other) const;

    // Comparison (for sorting by distance)
    bool operator<(const NodeId& other) const;
    bool operator==(const NodeId& other) const;
    bool operator!=(const NodeId& other) const;

    // Get bucket index (0-159) for routing table
    // Returns the index of the first differing bit
    int bucketIndex(const NodeId& other) const;

    // Access raw data
    const uint8_t* data() const { return data_.data(); }
    const std::array<uint8_t, SIZE>& bytes() const { return data_; }

    // Convert to hex string
    std::string toHex() const;

    // Parse from hex string
    static NodeId fromHex(const std::string& hex);

    // For use in maps
    struct Hash {
        size_t operator()(const NodeId& id) const;
    };

private:
    std::array<uint8_t, SIZE> data_;
};

// DHT Node entry (ID + endpoint)
struct NodeEntry {
    NodeId id;
    std::string ip;      // IPv6 address string
    uint16_t port;       // UDP port

    // Last seen timestamp
    int64_t last_seen = 0;

    // Number of failed queries
    int fail_count = 0;

    bool operator==(const NodeEntry& other) const {
        return id == other.id;
    }
};

} // namespace dht
