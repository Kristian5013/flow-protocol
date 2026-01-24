#ifndef FTC_NODE_SEED_CLIENT_H
#define FTC_NODE_SEED_CLIENT_H

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace seed {

// Discovered peer info
struct PeerInfo {
    std::string ip;
    uint16_t port;
};

// DNS Seed client
// Resolves DNS seeds to get peer IP addresses
class SeedClient {
public:
    explicit SeedClient(uint16_t default_port = 17318);

    // Add a DNS seed hostname
    void addSeed(const std::string& hostname);

    // Discover peers by resolving all DNS seeds
    std::vector<PeerInfo> discoverPeers();

    // Callback when new peers discovered
    using PeerCallback = std::function<void(const std::vector<PeerInfo>&)>;
    void setOnPeersDiscovered(PeerCallback cb) { on_peers_discovered_ = cb; }

    // Stats
    size_t getDiscoveredCount() const { return discovered_count_; }

private:
    std::vector<std::string> resolveDNS(const std::string& hostname);

    std::vector<std::string> seeds_;
    uint16_t default_port_;
    size_t discovered_count_;
    PeerCallback on_peers_discovered_;
};

} // namespace seed

#endif // FTC_NODE_SEED_CLIENT_H
