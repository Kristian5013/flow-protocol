#ifndef FTC_STRATUM_SERVER_H
#define FTC_STRATUM_SERVER_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <cstdint>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

namespace stratum {

// Forward declarations
class Node;

// Mining job sent to miners
struct Job {
    std::string job_id;
    std::string prev_hash;          // 32 bytes hex (64 chars)
    std::string coinbase1;          // First part of coinbase
    std::string coinbase2;          // Second part of coinbase (after extranonce)
    std::vector<std::string> merkle_branch;
    std::string version;            // 4 bytes hex
    std::string nbits;              // 4 bytes hex
    std::string ntime;              // 4 bytes hex
    uint32_t height;
    bool clean_jobs;
};

// Connected miner session
struct MinerSession {
    socket_t socket;
    std::string address;
    std::string worker_name;
    std::string extranonce1;        // Unique per connection
    bool authorized;
    bool subscribed;
    uint64_t shares_accepted;
    uint64_t shares_rejected;
    std::chrono::steady_clock::time_point connected_at;
    std::string recv_buffer;

    MinerSession() : socket(INVALID_SOCKET), authorized(false),
                     subscribed(false), shares_accepted(0), shares_rejected(0) {}
};

// Callbacks for node integration
using BlockFoundCallback = std::function<bool(
    const std::vector<uint8_t>& header,
    uint32_t nonce,
    const std::vector<uint8_t>& coinbase
)>;

using GetWorkCallback = std::function<bool(
    const std::string& payout_address,
    Job& job
)>;

class StratumServer {
public:
    StratumServer(uint16_t port = 3333);
    ~StratumServer();

    // Start/stop the server
    bool start();
    void stop();
    bool isRunning() const { return running_; }

    // Set payout address for coinbase
    void setPayoutAddress(const std::string& address) { payout_address_ = address; }

    // Set callbacks
    void setBlockFoundCallback(BlockFoundCallback cb) { on_block_found_ = cb; }
    void setGetWorkCallback(GetWorkCallback cb) { get_work_ = cb; }

    // Notify all miners of new work
    void notifyNewBlock();

    // Get stats
    size_t getConnectedMiners() const;
    uint64_t getTotalSharesAccepted() const { return total_shares_accepted_; }
    uint64_t getTotalSharesRejected() const { return total_shares_rejected_; }

private:
    void acceptLoop();
    void minerThread(std::shared_ptr<MinerSession> session);
    void processMessage(std::shared_ptr<MinerSession> session, const std::string& message);

    // Stratum protocol handlers
    void handleSubscribe(std::shared_ptr<MinerSession> session, int id, const std::vector<std::string>& params);
    void handleAuthorize(std::shared_ptr<MinerSession> session, int id, const std::vector<std::string>& params);
    void handleSubmit(std::shared_ptr<MinerSession> session, int id, const std::vector<std::string>& params);

    // Send methods
    void sendResponse(std::shared_ptr<MinerSession> session, int id, const std::string& result, const std::string& error = "null");
    void sendNotify(std::shared_ptr<MinerSession> session, const Job& job);
    void sendDifficulty(std::shared_ptr<MinerSession> session, double difficulty);

    // Helper methods
    std::string generateExtranonce1();
    std::string buildCoinbase(const std::string& extranonce1, const std::string& extranonce2);
    bool validateShare(std::shared_ptr<MinerSession> session, const std::string& job_id,
                      const std::string& extranonce2, const std::string& ntime, const std::string& nonce);

    uint16_t port_;
    socket_t listen_socket_;
    std::atomic<bool> running_;
    std::string payout_address_;

    std::thread accept_thread_;
    std::vector<std::thread> miner_threads_;

    std::map<socket_t, std::shared_ptr<MinerSession>> sessions_;
    std::mutex sessions_mutex_;

    Job current_job_;
    std::mutex job_mutex_;
    uint32_t job_counter_;
    uint32_t extranonce_counter_;

    std::atomic<uint64_t> total_shares_accepted_;
    std::atomic<uint64_t> total_shares_rejected_;

    double share_difficulty_;  // Difficulty for share validation

    BlockFoundCallback on_block_found_;
    GetWorkCallback get_work_;

    static const int EXTRANONCE1_SIZE = 4;  // bytes
    static const int EXTRANONCE2_SIZE = 4;  // bytes
};

} // namespace stratum

#endif // FTC_STRATUM_SERVER_H
