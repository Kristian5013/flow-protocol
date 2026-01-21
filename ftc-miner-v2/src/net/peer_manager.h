#ifndef FTC_MINER_NET_PEER_MANAGER_H
#define FTC_MINER_NET_PEER_MANAGER_H

#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <fstream>
#include <algorithm>

namespace net {

struct PeerInfo {
    std::string host;
    uint16_t port = 17319;
    int64_t ping_ms = -1;      // -1 = not tested
    bool online = false;
    int fail_count = 0;
    std::chrono::steady_clock::time_point last_check;
};

class PeerManager {
public:
    PeerManager();
    ~PeerManager();

    // Load peers from file
    bool loadPeersFile(const std::string& filename = "peers.dat");

    // Save peers to file
    bool savePeersFile(const std::string& filename = "peers.dat");

    // Add peer manually
    void addPeer(const std::string& host, uint16_t port = 17319);

    // Get best peer (lowest ping, online)
    PeerInfo* getBestPeer();

    // Get current active peer
    PeerInfo* getActivePeer();

    // Mark current peer as failed and switch to next best
    bool switchToNextPeer();

    // Test connectivity and measure ping for all peers
    void testAllPeers();

    // Test single peer
    bool testPeer(PeerInfo& peer);

    // Start background ping monitoring
    void startMonitoring(int interval_ms = 30000);
    void stopMonitoring();

    // Get all peers
    std::vector<PeerInfo>& getPeers() { return peers_; }

    // Check if we have any online peers
    bool hasOnlinePeers() const;

    // Get peer count
    size_t getPeerCount() const { return peers_.size(); }
    size_t getOnlinePeerCount() const;

private:
    int64_t measurePing(const std::string& host, uint16_t port);
    void monitorThread();

    std::vector<PeerInfo> peers_;
    int active_peer_index_ = -1;
    mutable std::mutex peers_mutex_;

    std::atomic<bool> monitoring_;
    std::thread monitor_thread_;
    int monitor_interval_ms_ = 30000;
};

// Interactive startup helper
class StartupDialog {
public:
    // Show interactive dialog and return selected peer
    // Returns empty string if user wants to exit
    static std::string showDialog(PeerManager& pm);

    // Parse host:port string
    static std::pair<std::string, uint16_t> parseAddress(const std::string& addr);
};

} // namespace net

#endif // FTC_MINER_NET_PEER_MANAGER_H
