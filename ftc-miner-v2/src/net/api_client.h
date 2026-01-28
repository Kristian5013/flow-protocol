#ifndef FTC_MINER_NET_API_CLIENT_H
#define FTC_MINER_NET_API_CLIENT_H

#include "../mining/work.h"
#include <string>
#include <optional>

namespace net {

// Result of block/share submission
struct SubmitResult {
    bool accepted = false;   // Whether the share was accepted
    bool is_block = false;   // Whether it was also a valid block (met block difficulty)
};

class APIClient {
public:
    APIClient(const std::string& host, uint16_t port);
    ~APIClient();

    bool connect();
    void disconnect();
    bool isConnected() const { return connected_; }

    // Get mining work
    std::optional<mining::Work> getMiningTemplate(const std::string& address);

    // Submit found block/share (builds full block from work + solution)
    // solutions_found: total solutions found by miner (for accurate hashrate calculation)
    // share_only: if true, don't process as block even if it meets block difficulty (for stale blocks)
    SubmitResult submitBlock(const mining::Solution& solution, const mining::Work& work, uint64_t solutions_found = 0, bool share_only = false);

    // Get node status
    int64_t getBlockHeight();
    uint32_t getDifficulty();

    // Network stats (node count, active miners, height, hashrate)
    struct NetworkStats {
        uint32_t node_count = 0;         // FTC nodes connected (not DHT peers)
        uint32_t active_miners = 0;      // Miners in P2Pool
        int32_t height = 0;              // Blockchain height
        double network_hashrate = 0.0;   // Total network hashrate (H/s)

        // P2Pool stats
        bool p2pool_enabled = false;     // P2Pool available on node
        bool p2pool_running = false;     // P2Pool is active
        uint64_t sharechain_height = 0;  // P2Pool sharechain height
        uint64_t total_shares = 0;       // Total shares submitted
        uint64_t total_blocks = 0;       // Blocks found by P2Pool
        double shares_per_minute = 0.0;  // Share rate
        uint32_t p2pool_peers = 0;       // P2Pool network peers
    };
    NetworkStats getNetworkStats();

    std::string getLastError() const { return last_error_; }

private:
    std::string httpGet(const std::string& path);
    std::string httpPost(const std::string& path, const std::string& body);

    std::string host_;
    uint16_t port_;
    bool connected_;
    std::string last_error_;
};

} // namespace net

#endif // FTC_MINER_NET_API_CLIENT_H
