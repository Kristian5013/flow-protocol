#ifndef FTC_MINER_NET_STRATUM_CLIENT_H
#define FTC_MINER_NET_STRATUM_CLIENT_H

#include "../mining/work.h"
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>

namespace net {

using WorkCallback = std::function<void(const mining::Work&)>;
using ConnectedCallback = std::function<void(bool)>;
using ShareCallback = std::function<void(bool accepted)>;

class StratumClient {
public:
    StratumClient();
    ~StratumClient();

    bool connect(const std::string& url, const std::string& user, const std::string& pass);
    void disconnect();
    bool isConnected() const { return connected_; }
    bool isAuthorized() const { return authorized_; }

    void setWorkCallback(WorkCallback callback) { work_callback_ = callback; }
    void setConnectedCallback(ConnectedCallback callback) { connected_callback_ = callback; }
    void setShareCallback(ShareCallback callback) { share_callback_ = callback; }

    bool submitShare(const mining::Solution& solution);

    std::string getLastError() const { return last_error_; }
    double getDifficulty() const { return difficulty_; }
    uint32_t getSharesAccepted() const { return shares_accepted_; }
    uint32_t getSharesRejected() const { return shares_rejected_; }

private:
    void receiveLoop();
    void processMessage(const std::string& message);
    void sendMessage(const std::string& message);

    // Response handlers
    void handleSubscribeResponse(const std::string& message);
    void handleAuthorizeResponse(const std::string& message, int id);
    void handleSubmitResponse(const std::string& message, int id);
    void handleNotify(const std::string& message);
    void handleSetDifficulty(const std::string& message);

    // Helpers
    std::vector<uint8_t> hexToBytes(const std::string& hex);
    std::string bytesToHex(const std::vector<uint8_t>& bytes);

    std::string host_;
    uint16_t port_;
    std::string user_;
    std::string password_;

    int socket_;
    std::atomic<bool> connected_;
    std::atomic<bool> running_;
    std::atomic<bool> authorized_;

    std::thread recv_thread_;
    std::mutex send_mutex_;

    WorkCallback work_callback_;
    ConnectedCallback connected_callback_;
    ShareCallback share_callback_;

    std::string extranonce1_;
    int extranonce2_size_;
    int message_id_;
    uint32_t extranonce2_counter_;

    double difficulty_;
    std::atomic<uint32_t> shares_accepted_;
    std::atomic<uint32_t> shares_rejected_;

    // Current job data
    std::mutex job_mutex_;
    std::string current_job_id_;
    std::string current_prev_hash_;
    std::string current_coinbase1_;
    std::string current_coinbase2_;
    std::vector<std::string> current_merkle_branch_;
    std::string current_version_;
    std::string current_nbits_;
    std::string current_ntime_;
    uint32_t current_height_;

    std::string last_error_;
};

} // namespace net

#endif // FTC_MINER_NET_STRATUM_CLIENT_H
