#include "stratum_server.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <chrono>
#include <random>

namespace stratum {

#ifdef _WIN32
static bool g_wsa_initialized = false;
static void initWinsock() {
    if (!g_wsa_initialized) {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        g_wsa_initialized = true;
    }
}
#endif

// Helper: convert bytes to hex string
static std::string bytesToHex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

// Helper: convert hex string to bytes
static std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

// Simple JSON parser for stratum messages
static bool parseJsonRpc(const std::string& json, int& id, std::string& method, std::vector<std::string>& params) {
    // Very simple parser - finds "id":X, "method":"Y", "params":[...]

    // Find id
    size_t id_pos = json.find("\"id\"");
    if (id_pos != std::string::npos) {
        size_t colon = json.find(':', id_pos);
        if (colon != std::string::npos) {
            size_t start = colon + 1;
            while (start < json.size() && (json[start] == ' ' || json[start] == '\t')) start++;
            if (json[start] == 'n') {
                id = -1;  // null
            } else {
                id = std::stoi(json.substr(start));
            }
        }
    }

    // Find method
    size_t method_pos = json.find("\"method\"");
    if (method_pos != std::string::npos) {
        size_t quote1 = json.find('"', method_pos + 8);
        if (quote1 != std::string::npos) {
            size_t quote2 = json.find('"', quote1 + 1);
            if (quote2 != std::string::npos) {
                method = json.substr(quote1 + 1, quote2 - quote1 - 1);
            }
        }
    }

    // Find params array
    size_t params_pos = json.find("\"params\"");
    if (params_pos != std::string::npos) {
        size_t bracket = json.find('[', params_pos);
        if (bracket != std::string::npos) {
            size_t end_bracket = json.find(']', bracket);
            if (end_bracket != std::string::npos) {
                std::string params_str = json.substr(bracket + 1, end_bracket - bracket - 1);

                // Parse params - simple comma-separated values
                std::string current;
                bool in_string = false;
                for (char c : params_str) {
                    if (c == '"') {
                        in_string = !in_string;
                    } else if (c == ',' && !in_string) {
                        // Trim and add param
                        size_t start = current.find_first_not_of(" \t\"");
                        size_t end = current.find_last_not_of(" \t\"");
                        if (start != std::string::npos && end != std::string::npos) {
                            params.push_back(current.substr(start, end - start + 1));
                        } else if (current.find("true") != std::string::npos) {
                            params.push_back("true");
                        } else if (current.find("false") != std::string::npos) {
                            params.push_back("false");
                        }
                        current.clear();
                    } else {
                        current += c;
                    }
                }
                // Add last param
                if (!current.empty()) {
                    size_t start = current.find_first_not_of(" \t\"");
                    size_t end = current.find_last_not_of(" \t\"");
                    if (start != std::string::npos && end != std::string::npos) {
                        params.push_back(current.substr(start, end - start + 1));
                    }
                }
            }
        }
    }

    return !method.empty();
}

StratumServer::StratumServer(uint16_t port)
    : port_(port)
    , listen_socket_(INVALID_SOCKET)
    , running_(false)
    , job_counter_(0)
    , extranonce_counter_(0)
    , total_shares_accepted_(0)
    , total_shares_rejected_(0)
    , share_difficulty_(1.0)
{
#ifdef _WIN32
    initWinsock();
#endif
}

StratumServer::~StratumServer() {
    stop();
}

bool StratumServer::start() {
    if (running_) return true;

    // Create IPv6 listen socket
    listen_socket_ = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket_ == INVALID_SOCKET) {
        std::cerr << "[Stratum] Failed to create IPv6 socket\n";
        return false;
    }

    // Allow address reuse
    int opt = 1;
    setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    // Disable IPV6_V6ONLY to accept IPv4-mapped IPv6 connections
    int v6only = 0;
    setsockopt(listen_socket_, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&v6only, sizeof(v6only));

    // Bind to port (IPv6 any address)
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port_);

    if (bind(listen_socket_, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "[Stratum] Failed to bind to port " << port_ << "\n";
        closesocket(listen_socket_);
        return false;
    }

    // Listen
    if (listen(listen_socket_, 10) == SOCKET_ERROR) {
        std::cerr << "[Stratum] Failed to listen\n";
        closesocket(listen_socket_);
        return false;
    }

    running_ = true;

    // Start accept thread
    accept_thread_ = std::thread(&StratumServer::acceptLoop, this);
    return true;
}

void StratumServer::stop() {
    if (!running_) return;

    running_ = false;

    // Close listen socket to break accept()
    if (listen_socket_ != INVALID_SOCKET) {
        closesocket(listen_socket_);
        listen_socket_ = INVALID_SOCKET;
    }

    // Close all miner sessions
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (auto& pair : sessions_) {
            if (pair.second->socket != INVALID_SOCKET) {
                closesocket(pair.second->socket);
            }
        }
        sessions_.clear();
    }

    // Wait for threads
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }

    for (auto& t : miner_threads_) {
        if (t.joinable()) {
            t.join();
        }
    }
    miner_threads_.clear();

    std::cout << "[Stratum] Server stopped\n";
}

void StratumServer::acceptLoop() {
    while (running_) {
        struct sockaddr_in6 client_addr;
        socklen_t client_len = sizeof(client_addr);

        socket_t client_socket = accept(listen_socket_, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            if (running_) {
                std::cerr << "[Stratum] Accept failed\n";
            }
            continue;
        }

        // Create session
        auto session = std::make_shared<MinerSession>();
        session->socket = client_socket;

        // Convert IPv6 address to string
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &client_addr.sin6_addr, addr_str, sizeof(addr_str));
        session->address = addr_str;

        session->extranonce1 = generateExtranonce1();
        session->connected_at = std::chrono::steady_clock::now();

        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            sessions_[client_socket] = session;
        }

        std::cout << "[Stratum] Miner connected from " << session->address
                  << " (extranonce1: " << session->extranonce1 << ")\n";

        // Start miner thread
        miner_threads_.emplace_back(&StratumServer::minerThread, this, session);
    }
}

void StratumServer::minerThread(std::shared_ptr<MinerSession> session) {
    char buffer[4096];

    while (running_ && session->socket != INVALID_SOCKET) {
        int received = recv(session->socket, buffer, sizeof(buffer) - 1, 0);
        if (received <= 0) {
            break;  // Connection closed or error
        }

        buffer[received] = '\0';
        session->recv_buffer += buffer;

        // Process complete lines
        size_t newline;
        while ((newline = session->recv_buffer.find('\n')) != std::string::npos) {
            std::string message = session->recv_buffer.substr(0, newline);
            session->recv_buffer = session->recv_buffer.substr(newline + 1);

            // Remove \r if present
            if (!message.empty() && message.back() == '\r') {
                message.pop_back();
            }

            if (!message.empty()) {
                processMessage(session, message);
            }
        }
    }

    // Cleanup
    std::cout << "[Stratum] Miner disconnected: " << session->address << "\n";

    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_.erase(session->socket);
    }

    if (session->socket != INVALID_SOCKET) {
        closesocket(session->socket);
        session->socket = INVALID_SOCKET;
    }
}

void StratumServer::processMessage(std::shared_ptr<MinerSession> session, const std::string& message) {
    int id = 0;
    std::string method;
    std::vector<std::string> params;

    if (!parseJsonRpc(message, id, method, params)) {
        std::cerr << "[Stratum] Failed to parse: " << message << "\n";
        return;
    }

    if (method == "mining.subscribe") {
        handleSubscribe(session, id, params);
    } else if (method == "mining.authorize") {
        handleAuthorize(session, id, params);
    } else if (method == "mining.submit") {
        handleSubmit(session, id, params);
    } else if (method == "mining.extranonce.subscribe") {
        // Optional extension - just acknowledge
        sendResponse(session, id, "true");
    } else {
        std::cerr << "[Stratum] Unknown method: " << method << "\n";
        sendResponse(session, id, "null", "[20, \"Unknown method\", null]");
    }
}

void StratumServer::handleSubscribe(std::shared_ptr<MinerSession> session, int id,
                                     const std::vector<std::string>& params) {
    session->subscribed = true;

    // Response format: [[["mining.notify", "subscription_id"]], extranonce1, extranonce2_size]
    std::stringstream ss;
    ss << "[[[\"mining.set_difficulty\", \"" << session->extranonce1 << "\"],"
       << "[\"mining.notify\", \"" << session->extranonce1 << "\"]], "
       << "\"" << session->extranonce1 << "\", " << EXTRANONCE2_SIZE << "]";

    sendResponse(session, id, ss.str());

    // Send initial difficulty
    sendDifficulty(session, share_difficulty_);

    // Send current job if available
    {
        std::lock_guard<std::mutex> lock(job_mutex_);
        if (!current_job_.job_id.empty()) {
            sendNotify(session, current_job_);
        }
    }
}

void StratumServer::handleAuthorize(std::shared_ptr<MinerSession> session, int id,
                                     const std::vector<std::string>& params) {
    if (params.size() >= 1) {
        session->worker_name = params[0];
    }

    session->authorized = true;
    sendResponse(session, id, "true");

    std::cout << "[Stratum] Miner authorized: " << session->worker_name << "\n";
}

void StratumServer::handleSubmit(std::shared_ptr<MinerSession> session, int id,
                                  const std::vector<std::string>& params) {
    // params: [worker_name, job_id, extranonce2, ntime, nonce]
    if (params.size() < 5) {
        sendResponse(session, id, "null", "[21, \"Invalid parameters\", null]");
        session->shares_rejected++;
        total_shares_rejected_++;
        return;
    }

    const std::string& job_id = params[1];
    const std::string& extranonce2 = params[2];
    const std::string& ntime = params[3];
    const std::string& nonce = params[4];

    if (validateShare(session, job_id, extranonce2, ntime, nonce)) {
        session->shares_accepted++;
        total_shares_accepted_++;
        sendResponse(session, id, "true");
        std::cout << "[Stratum] Share accepted from " << session->worker_name << "\n";
    } else {
        session->shares_rejected++;
        total_shares_rejected_++;
        sendResponse(session, id, "null", "[23, \"Low difficulty share\", null]");
        std::cout << "[Stratum] Share rejected from " << session->worker_name << "\n";
    }
}

bool StratumServer::validateShare(std::shared_ptr<MinerSession> session,
                                   const std::string& job_id,
                                   const std::string& extranonce2,
                                   const std::string& ntime,
                                   const std::string& nonce) {
    std::lock_guard<std::mutex> lock(job_mutex_);

    // Check job_id matches
    if (job_id != current_job_.job_id) {
        std::cerr << "[Stratum] Stale job: " << job_id << " (current: " << current_job_.job_id << ")\n";
        return false;
    }

    // Build coinbase transaction
    std::string full_coinbase = current_job_.coinbase1 + session->extranonce1 + extranonce2 + current_job_.coinbase2;
    auto coinbase_bytes = hexToBytes(full_coinbase);

    // Build block header
    // version(4) + prev_hash(32) + merkle_root(32) + time(4) + bits(4) + nonce(4) = 80 bytes
    std::vector<uint8_t> header;
    header.reserve(80);

    // Version (little-endian)
    auto version_bytes = hexToBytes(current_job_.version);
    for (int i = 3; i >= 0; --i) header.push_back(version_bytes[i]);

    // Prev hash (already in internal byte order)
    auto prev_hash_bytes = hexToBytes(current_job_.prev_hash);
    header.insert(header.end(), prev_hash_bytes.begin(), prev_hash_bytes.end());

    // For merkle root, we need to compute it from coinbase + merkle branches
    // For now, just use a placeholder (this needs proper implementation)
    // TODO: Compute proper merkle root
    std::vector<uint8_t> merkle_root(32, 0);
    header.insert(header.end(), merkle_root.begin(), merkle_root.end());

    // ntime (little-endian)
    auto ntime_bytes = hexToBytes(ntime);
    for (int i = 3; i >= 0; --i) header.push_back(ntime_bytes[i]);

    // bits (little-endian)
    auto bits_bytes = hexToBytes(current_job_.nbits);
    for (int i = 3; i >= 0; --i) header.push_back(bits_bytes[i]);

    // nonce (little-endian)
    auto nonce_bytes = hexToBytes(nonce);
    for (int i = 3; i >= 0; --i) header.push_back(nonce_bytes[i]);

    // Try to submit as block
    if (on_block_found_) {
        uint32_t nonce_val = 0;
        for (int i = 0; i < 4; ++i) {
            nonce_val |= (static_cast<uint32_t>(nonce_bytes[3 - i]) << (i * 8));
        }

        if (on_block_found_(header, nonce_val, coinbase_bytes)) {
            std::cout << "[Stratum] *** BLOCK FOUND! ***\n";
            return true;
        }
    }

    // For share validation, just accept for now
    // TODO: Implement proper share difficulty check
    return true;
}

void StratumServer::sendResponse(std::shared_ptr<MinerSession> session, int id,
                                  const std::string& result, const std::string& error) {
    std::stringstream ss;
    ss << "{\"id\":" << id << ",\"result\":" << result << ",\"error\":" << error << "}\n";

    std::string response = ss.str();
    send(session->socket, response.c_str(), static_cast<int>(response.size()), 0);
}

void StratumServer::sendNotify(std::shared_ptr<MinerSession> session, const Job& job) {
    std::stringstream ss;
    ss << "{\"id\":null,\"method\":\"mining.notify\",\"params\":["
       << "\"" << job.job_id << "\","
       << "\"" << job.prev_hash << "\","
       << "\"" << job.coinbase1 << "\","
       << "\"" << job.coinbase2 << "\","
       << "[";  // merkle branches

    for (size_t i = 0; i < job.merkle_branch.size(); ++i) {
        if (i > 0) ss << ",";
        ss << "\"" << job.merkle_branch[i] << "\"";
    }

    ss << "],"
       << "\"" << job.version << "\","
       << "\"" << job.nbits << "\","
       << "\"" << job.ntime << "\","
       << (job.clean_jobs ? "true" : "false")
       << "]}\n";

    std::string notify = ss.str();
    send(session->socket, notify.c_str(), static_cast<int>(notify.size()), 0);
}

void StratumServer::sendDifficulty(std::shared_ptr<MinerSession> session, double difficulty) {
    std::stringstream ss;
    ss << "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[" << difficulty << "]}\n";

    std::string msg = ss.str();
    send(session->socket, msg.c_str(), static_cast<int>(msg.size()), 0);
}

std::string StratumServer::generateExtranonce1() {
    uint32_t en = ++extranonce_counter_;
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(EXTRANONCE1_SIZE * 2) << en;
    return ss.str();
}

void StratumServer::notifyNewBlock() {
    if (!get_work_) return;

    Job job;
    if (!get_work_(payout_address_, job)) {
        std::cerr << "[Stratum] Failed to get new work\n";
        return;
    }

    job.job_id = std::to_string(++job_counter_);
    job.clean_jobs = true;

    {
        std::lock_guard<std::mutex> lock(job_mutex_);
        current_job_ = job;
    }

    // Notify all connected miners
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    for (auto& pair : sessions_) {
        if (pair.second->subscribed) {
            sendNotify(pair.second, job);
        }
    }

    std::cout << "[Stratum] Notified " << sessions_.size() << " miners of new work (height: " << job.height << ")\n";
}

size_t StratumServer::getConnectedMiners() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(sessions_mutex_));
    return sessions_.size();
}

} // namespace stratum
