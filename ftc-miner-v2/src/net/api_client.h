#ifndef FTC_MINER_NET_API_CLIENT_H
#define FTC_MINER_NET_API_CLIENT_H

#include "../mining/work.h"
#include <string>
#include <optional>

namespace net {

class APIClient {
public:
    APIClient(const std::string& host, uint16_t port);
    ~APIClient();

    bool connect();
    void disconnect();
    bool isConnected() const { return connected_; }

    // Get mining work
    std::optional<mining::Work> getMiningTemplate(const std::string& address);

    // Submit found block (builds full block from work + solution)
    bool submitBlock(const mining::Solution& solution, const mining::Work& work);

    // Legacy submit (deprecated, returns false)
    bool submitBlock(const mining::Solution& solution) { return false; }

    // Get node status
    int64_t getBlockHeight();
    uint32_t getDifficulty();

    // Network stats (peer count, active miners, height, hashrate)
    struct NetworkStats {
        uint32_t peer_count = 0;
        uint32_t active_miners = 0;
        int32_t height = 0;
        bool p2pool_running = false;
        double network_hashrate = 0.0;  // Total network hashrate (H/s)
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
