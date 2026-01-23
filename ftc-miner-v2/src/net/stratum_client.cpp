#include "stratum_client.h"
#include <sstream>
#include <iomanip>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#define closesocket close
#endif

namespace net {

StratumClient::StratumClient()
    : port_(3333)
    , socket_(-1)
    , connected_(false)
    , running_(false)
    , authorized_(false)
    , extranonce2_size_(4)
    , message_id_(1)
    , extranonce2_counter_(0)
    , difficulty_(1.0)
    , shares_accepted_(0)
    , shares_rejected_(0)
    , current_height_(0)
{}

StratumClient::~StratumClient() {
    disconnect();
}

std::vector<uint8_t> StratumClient::hexToBytes(const std::string& hex) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

std::string StratumClient::bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

bool StratumClient::connect(const std::string& url, const std::string& user, const std::string& pass) {
    // Parse URL: stratum+tcp://host:port or stratum+tcp://[ipv6]:port
    std::string parsed_url = url;
    if (parsed_url.find("stratum+tcp://") == 0) {
        parsed_url = parsed_url.substr(14);
    }

    // Handle IPv6 addresses with brackets: [::1]:3333
    if (!parsed_url.empty() && parsed_url.front() == '[') {
        size_t bracket_end = parsed_url.find(']');
        if (bracket_end == std::string::npos) {
            last_error_ = "Invalid IPv6 address format";
            return false;
        }
        host_ = parsed_url.substr(1, bracket_end - 1);

        size_t colon = parsed_url.find(':', bracket_end);
        if (colon != std::string::npos) {
            port_ = static_cast<uint16_t>(std::stoi(parsed_url.substr(colon + 1)));
        }
    } else {
        size_t colon = parsed_url.rfind(':');
        if (colon != std::string::npos) {
            host_ = parsed_url.substr(0, colon);
            port_ = static_cast<uint16_t>(std::stoi(parsed_url.substr(colon + 1)));
        } else {
            host_ = parsed_url;
        }
    }

    user_ = user;
    password_ = pass;

    // Create IPv6 socket
    socket_ = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ < 0) {
        last_error_ = "Failed to create socket";
        return false;
    }

    // IPv6-only mode
    int yes = 1;
    setsockopt(socket_, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&yes, sizeof(yes));

    // Resolve hostname (IPv6 only)
    struct addrinfo hints{}, *result;
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port_);
    int gai_err = getaddrinfo(host_.c_str(), port_str.c_str(), &hints, &result);

    if (gai_err != 0) {
        closesocket(socket_);
        last_error_ = "Failed to resolve hostname (IPv6 only)";
        return false;
    }

    // Try to connect
    int conn_result = -1;
    for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
        conn_result = ::connect(socket_, rp->ai_addr, (int)rp->ai_addrlen);
        if (conn_result == 0) break;
    }

    freeaddrinfo(result);

    if (conn_result < 0) {
        closesocket(socket_);
        last_error_ = "Connection failed";
        return false;
    }

    running_ = true;
    recv_thread_ = std::thread(&StratumClient::receiveLoop, this);

    // Send subscribe (id=1)
    sendMessage("{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"ftc-miner/2.0\"]}\n");

    // Send authorize (id=2)
    sendMessage("{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"" + user_ + "\",\"" + password_ + "\"]}\n");

    connected_ = true;
    if (connected_callback_) {
        connected_callback_(true);
    }

    return true;
}

void StratumClient::disconnect() {
    running_ = false;
    connected_ = false;
    authorized_ = false;

    if (socket_ >= 0) {
        closesocket(socket_);
        socket_ = -1;
    }

    if (recv_thread_.joinable()) {
        recv_thread_.join();
    }

    if (connected_callback_) {
        connected_callback_(false);
    }
}

void StratumClient::receiveLoop() {
    char buffer[4096];
    std::string recv_buffer;

    while (running_) {
        int received = recv(socket_, buffer, sizeof(buffer) - 1, 0);
        if (received <= 0) {
            if (running_) {
                connected_ = false;
                if (connected_callback_) {
                    connected_callback_(false);
                }
            }
            break;
        }

        buffer[received] = '\0';
        recv_buffer += buffer;

        // Process complete lines
        size_t newline;
        while ((newline = recv_buffer.find('\n')) != std::string::npos) {
            std::string message = recv_buffer.substr(0, newline);
            recv_buffer = recv_buffer.substr(newline + 1);

            if (!message.empty() && message.back() == '\r') {
                message.pop_back();
            }

            if (!message.empty()) {
                processMessage(message);
            }
        }
    }
}

void StratumClient::processMessage(const std::string& message) {
    // Check if it's a method call (notification)
    if (message.find("\"method\":\"mining.notify\"") != std::string::npos) {
        handleNotify(message);
    } else if (message.find("\"method\":\"mining.set_difficulty\"") != std::string::npos) {
        handleSetDifficulty(message);
    }
    // Check if it's a response to our requests
    else if (message.find("\"id\":1") != std::string::npos && message.find("\"result\":") != std::string::npos) {
        // Subscribe response
        handleSubscribeResponse(message);
    } else if (message.find("\"id\":2") != std::string::npos) {
        // Authorize response
        handleAuthorizeResponse(message, 2);
    } else if (message.find("\"id\":") != std::string::npos && message.find("\"result\":") != std::string::npos) {
        // Submit response (id > 2)
        size_t id_pos = message.find("\"id\":");
        if (id_pos != std::string::npos) {
            int id = std::stoi(message.substr(id_pos + 5));
            if (id > 2) {
                handleSubmitResponse(message, id);
            }
        }
    }
}

void StratumClient::handleSubscribeResponse(const std::string& message) {
    // Response: {"id":1,"result":[[...], "extranonce1", extranonce2_size],"error":null}
    // Extract extranonce1 - find the second-to-last quoted string before the number

    size_t result_pos = message.find("\"result\":");
    if (result_pos == std::string::npos) return;

    // Find extranonce1 (hex string after the nested arrays)
    // Look for pattern: ], "HEXSTRING", NUMBER]
    size_t bracket_pos = message.rfind(']');
    if (bracket_pos == std::string::npos) return;

    // Go back to find the extranonce2_size number
    size_t comma_before_size = message.rfind(',', bracket_pos);
    if (comma_before_size == std::string::npos) return;

    std::string size_str = message.substr(comma_before_size + 1, bracket_pos - comma_before_size - 1);
    // Remove whitespace
    size_t num_start = size_str.find_first_of("0123456789");
    if (num_start != std::string::npos) {
        extranonce2_size_ = std::stoi(size_str.substr(num_start));
    }

    // Find extranonce1 (quoted string before the size)
    size_t quote_end = message.rfind('"', comma_before_size);
    if (quote_end == std::string::npos) return;
    size_t quote_start = message.rfind('"', quote_end - 1);
    if (quote_start == std::string::npos) return;

    extranonce1_ = message.substr(quote_start + 1, quote_end - quote_start - 1);
}

void StratumClient::handleAuthorizeResponse(const std::string& message, int id) {
    // Response: {"id":2,"result":true,"error":null}
    if (message.find("\"result\":true") != std::string::npos) {
        authorized_ = true;
    } else {
        authorized_ = false;
        last_error_ = "Authorization failed";
    }
}

void StratumClient::handleSubmitResponse(const std::string& message, int id) {
    bool accepted = message.find("\"result\":true") != std::string::npos;

    if (accepted) {
        shares_accepted_++;
    } else {
        shares_rejected_++;
    }

    if (share_callback_) {
        share_callback_(accepted);
    }
}

void StratumClient::handleSetDifficulty(const std::string& message) {
    // {"id":null,"method":"mining.set_difficulty","params":[DIFF]}
    size_t params_pos = message.find("\"params\":[");
    if (params_pos == std::string::npos) return;

    size_t start = params_pos + 10;
    size_t end = message.find(']', start);
    if (end == std::string::npos) return;

    std::string diff_str = message.substr(start, end - start);
    difficulty_ = std::stod(diff_str);
}

void StratumClient::handleNotify(const std::string& message) {
    // {"id":null,"method":"mining.notify","params":["job_id","prev_hash","coinbase1","coinbase2",[merkle_branches],"version","nbits","ntime",clean_jobs]}

    size_t params_pos = message.find("\"params\":[");
    if (params_pos == std::string::npos) return;

    std::string params_str = message.substr(params_pos + 10);

    // Parse the params array manually
    std::vector<std::string> params;
    std::string current;
    bool in_string = false;
    bool in_array = false;
    int array_depth = 0;

    for (size_t i = 0; i < params_str.size(); ++i) {
        char c = params_str[i];

        if (c == '"' && (i == 0 || params_str[i-1] != '\\')) {
            in_string = !in_string;
            if (!in_array) continue;  // Skip quotes for top-level strings
        }

        if (!in_string) {
            if (c == '[') {
                if (array_depth == 0) {
                    in_array = true;
                }
                array_depth++;
                current += c;
                continue;
            }
            if (c == ']') {
                array_depth--;
                if (array_depth == 0) {
                    in_array = false;
                    params.push_back(current + c);
                    current.clear();
                    continue;
                } else if (array_depth < 0) {
                    break;  // End of params
                }
                current += c;
                continue;
            }
            if (c == ',' && !in_array) {
                if (!current.empty()) {
                    params.push_back(current);
                    current.clear();
                }
                continue;
            }
        }

        current += c;
    }
    if (!current.empty()) {
        params.push_back(current);
    }

    // Need at least 9 params: job_id, prev_hash, coinbase1, coinbase2, merkle_branches, version, nbits, ntime, clean_jobs
    if (params.size() < 9) return;

    {
        std::lock_guard<std::mutex> lock(job_mutex_);
        current_job_id_ = params[0];
        current_prev_hash_ = params[1];
        current_coinbase1_ = params[2];
        current_coinbase2_ = params[3];

        // Parse merkle branches array
        current_merkle_branch_.clear();
        std::string merkle_str = params[4];
        if (merkle_str.size() > 2) {  // More than just "[]"
            // Remove brackets
            merkle_str = merkle_str.substr(1, merkle_str.size() - 2);
            // Split by comma
            std::stringstream ss(merkle_str);
            std::string branch;
            while (std::getline(ss, branch, ',')) {
                // Remove quotes and whitespace
                size_t start = branch.find('"');
                size_t end = branch.rfind('"');
                if (start != std::string::npos && end != std::string::npos && end > start) {
                    current_merkle_branch_.push_back(branch.substr(start + 1, end - start - 1));
                }
            }
        }

        current_version_ = params[5];
        current_nbits_ = params[6];
        current_ntime_ = params[7];
    }

    // Build Work object for miner
    mining::Work work;
    work.job_id = current_job_id_;

    // Convert prev_hash from hex (already in correct byte order from server)
    auto prev_hash_bytes = hexToBytes(current_prev_hash_);
    if (prev_hash_bytes.size() == 32) {
        std::memcpy(work.prev_hash.data(), prev_hash_bytes.data(), 32);
    }

    // Parse version (hex, little-endian in stratum)
    auto version_bytes = hexToBytes(current_version_);
    if (version_bytes.size() >= 4) {
        work.version = version_bytes[0] | (version_bytes[1] << 8) |
                       (version_bytes[2] << 16) | (version_bytes[3] << 24);
    }

    // Parse bits (hex)
    auto bits_bytes = hexToBytes(current_nbits_);
    if (bits_bytes.size() >= 4) {
        work.bits = bits_bytes[0] | (bits_bytes[1] << 8) |
                    (bits_bytes[2] << 16) | (bits_bytes[3] << 24);
    }

    // Parse timestamp (hex)
    auto time_bytes = hexToBytes(current_ntime_);
    if (time_bytes.size() >= 4) {
        work.timestamp = time_bytes[0] | (time_bytes[1] << 8) |
                         (time_bytes[2] << 16) | (time_bytes[3] << 24);
    }

    // Build coinbase with our extranonce
    std::string full_coinbase = current_coinbase1_ + extranonce1_;
    // Add extranonce2 (zeros for now - will be varied during mining)
    for (int i = 0; i < extranonce2_size_; ++i) {
        full_coinbase += "00";
    }
    full_coinbase += current_coinbase2_;
    work.coinbase = hexToBytes(full_coinbase);

    // Store merkle branch
    for (const auto& branch : current_merkle_branch_) {
        auto branch_bytes = hexToBytes(branch);
        if (branch_bytes.size() == 32) {
            mining::Hash256 h;
            std::memcpy(h.data(), branch_bytes.data(), 32);
            work.merkle_branch.push_back(h);
        }
    }

    // Calculate target from bits
    // bits format: 0xAABBBBBB where AA is exponent, BBBBBB is mantissa
    uint32_t exp = (work.bits >> 24) & 0xFF;
    uint32_t mant = work.bits & 0x00FFFFFF;

    // Target = mantissa * 2^(8*(exponent-3))
    std::memset(work.target.data(), 0, 32);
    if (exp >= 3) {
        int shift = exp - 3;
        if (shift < 29) {
            work.target[31 - shift] = mant & 0xFF;
            work.target[30 - shift] = (mant >> 8) & 0xFF;
            work.target[29 - shift] = (mant >> 16) & 0xFF;
        }
    }

    // Estimate height from job parameters or track it
    work.height = current_height_;

    if (work_callback_) {
        work_callback_(work);
    }
}

void StratumClient::sendMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(send_mutex_);
    if (socket_ >= 0) {
        send(socket_, message.c_str(), static_cast<int>(message.size()), 0);
    }
}

bool StratumClient::submitShare(const mining::Solution& solution) {
    if (!connected_ || !authorized_) return false;

    std::lock_guard<std::mutex> lock(job_mutex_);

    // Generate extranonce2 (increment counter)
    extranonce2_counter_++;
    std::stringstream en2_ss;
    en2_ss << std::hex << std::setfill('0') << std::setw(extranonce2_size_ * 2) << extranonce2_counter_;
    std::string extranonce2 = en2_ss.str();

    // Format nonce as hex (little-endian)
    std::stringstream nonce_ss;
    nonce_ss << std::hex << std::setfill('0') << std::setw(8)
             << ((solution.nonce & 0xFF) << 24 |
                 ((solution.nonce >> 8) & 0xFF) << 16 |
                 ((solution.nonce >> 16) & 0xFF) << 8 |
                 ((solution.nonce >> 24) & 0xFF));
    std::string nonce_hex = nonce_ss.str();

    // Use current ntime
    std::string msg = "{\"id\":" + std::to_string(message_id_++) +
                      ",\"method\":\"mining.submit\",\"params\":[\"" +
                      user_ + "\",\"" +
                      current_job_id_ + "\",\"" +
                      extranonce2 + "\",\"" +
                      current_ntime_ + "\",\"" +
                      nonce_hex + "\"]}\n";

    sendMessage(msg);
    return true;
}

} // namespace net
