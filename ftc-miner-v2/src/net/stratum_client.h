#ifndef FTC_MINER_NET_STRATUM_CLIENT_H
#define FTC_MINER_NET_STRATUM_CLIENT_H

#include "../mining/work.h"
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>

namespace net {

using WorkCallback = std::function<void(const mining::Work&)>;
using ConnectedCallback = std::function<void(bool)>;

class StratumClient {
public:
    StratumClient();
    ~StratumClient();

    bool connect(const std::string& url, const std::string& user, const std::string& pass);
    void disconnect();
    bool isConnected() const { return connected_; }

    void setWorkCallback(WorkCallback callback) { work_callback_ = callback; }
    void setConnectedCallback(ConnectedCallback callback) { connected_callback_ = callback; }

    bool submitShare(const mining::Solution& solution);

    std::string getLastError() const { return last_error_; }

private:
    void receiveLoop();
    void processMessage(const std::string& message);
    void sendMessage(const std::string& message);

    std::string host_;
    uint16_t port_;
    std::string user_;
    std::string password_;

    int socket_;
    std::atomic<bool> connected_;
    std::atomic<bool> running_;

    std::thread recv_thread_;
    std::mutex send_mutex_;

    WorkCallback work_callback_;
    ConnectedCallback connected_callback_;

    std::string extranonce1_;
    int extranonce2_size_;
    int message_id_;

    std::string last_error_;
};

} // namespace net

#endif // FTC_MINER_NET_STRATUM_CLIENT_H
