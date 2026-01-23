#include "stratum_client.h"

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
    , extranonce2_size_(4)
    , message_id_(1)
{}

StratumClient::~StratumClient() {
    disconnect();
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

    // Create IPv6 socket (dual-stack supports IPv4-mapped addresses)
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
    hints.ai_family = AF_INET6;  // IPv6 only
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port_);
    int gai_err = getaddrinfo(host_.c_str(), port_str.c_str(), &hints, &result);

    if (gai_err != 0) {
        closesocket(socket_);
        last_error_ = "Failed to resolve hostname (IPv6 only)";
        return false;
    }

    // Try to connect to resolved IPv6 addresses
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

    // Send subscribe
    sendMessage("{\"id\":" + std::to_string(message_id_++) +
                ",\"method\":\"mining.subscribe\",\"params\":[\"ftc-miner/2.0\"]}\n");

    // Send authorize
    sendMessage("{\"id\":" + std::to_string(message_id_++) +
                ",\"method\":\"mining.authorize\",\"params\":[\"" + user_ + "\",\"" + password_ + "\"]}\n");

    connected_ = true;
    if (connected_callback_) {
        connected_callback_(true);
    }

    return true;
}

void StratumClient::disconnect() {
    running_ = false;
    connected_ = false;

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
    // Simple JSON parsing for stratum messages

    if (message.find("\"method\":\"mining.notify\"") != std::string::npos) {
        // New work notification
        mining::Work work;
        // TODO: Parse work parameters
        work.height = 1;  // Placeholder

        if (work_callback_) {
            work_callback_(work);
        }
    } else if (message.find("\"method\":\"mining.set_difficulty\"") != std::string::npos) {
        // Difficulty update
        // TODO: Parse difficulty
    }
}

void StratumClient::sendMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(send_mutex_);
    if (socket_ >= 0) {
        send(socket_, message.c_str(), static_cast<int>(message.size()), 0);
    }
}

bool StratumClient::submitShare(const mining::Solution& solution) {
    if (!connected_) return false;

    std::string msg = "{\"id\":" + std::to_string(message_id_++) +
                      ",\"method\":\"mining.submit\",\"params\":[\"" + user_ + "\",\"" +
                      solution.job_id + "\",\"00000000\",\"00000000\",\"" +
                      std::to_string(solution.nonce) + "\"]}\n";

    sendMessage(msg);
    return true;
}

} // namespace net
