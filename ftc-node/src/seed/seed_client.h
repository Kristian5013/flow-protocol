#ifndef FTC_NODE_SEED_CLIENT_H
#define FTC_NODE_SEED_CLIENT_H

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>
#include <cstdint>

namespace seed {

// Discovered peer info
struct PeerInfo {
    std::string ip;
    uint16_t port;
    std::string version;
    uint32_t height;
    std::string country;
    int age_seconds;  // Time since last heartbeat
};

// Seed discovery client
// Connects to api.flowprotocol.net for peer discovery
class SeedClient {
public:
    // network: "mainnet" or "testnet"
    explicit SeedClient(const std::string& network = "mainnet");
    ~SeedClient();

    // Set API endpoint (default: api.flowprotocol.net)
    void setEndpoint(const std::string& host, uint16_t port = 443, bool use_https = true);

    // Discover peers from seed API
    std::vector<PeerInfo> discoverPeers(int max_peers = 50);

    // Register this node with the seed network
    bool registerNode(uint16_t p2p_port, const std::string& version, uint32_t height);

    // Start background heartbeat (call registerNode first)
    void startHeartbeat(uint16_t p2p_port, uint32_t& height_ref);
    void stopHeartbeat();

    // Callback when new peers discovered
    using PeerCallback = std::function<void(const std::vector<PeerInfo>&)>;
    void setOnPeersDiscovered(PeerCallback cb) { on_peers_discovered_ = cb; }

    // Stats
    size_t getDiscoveredCount() const { return discovered_count_; }
    bool isRegistered() const { return registered_; }

private:
    std::string httpGet(const std::string& path);
    std::string httpPost(const std::string& path, const std::string& body);
    std::vector<PeerInfo> parseNodesResponse(const std::string& json);

    std::string network_;
    std::string api_host_;
    uint16_t api_port_;
    bool use_https_;

    std::atomic<bool> registered_;
    std::atomic<size_t> discovered_count_;

    // Heartbeat thread
    std::thread heartbeat_thread_;
    std::atomic<bool> heartbeat_running_;
    uint16_t heartbeat_port_;
    uint32_t* height_ptr_;
    std::string version_;

    PeerCallback on_peers_discovered_;
};

} // namespace seed

#endif // FTC_NODE_SEED_CLIENT_H
