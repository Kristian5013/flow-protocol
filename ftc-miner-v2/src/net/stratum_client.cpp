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
    // Parse URL: stratum+tcp://host:port
    std::string parsed_url = url;
    if (parsed_url.find("stratum+tcp://") == 0) {
        parsed_url = parsed_url.substr(14);
    }

    size_t colon = parsed_url.rfind(':');
    if (colon != std::string::npos) {
        host_ = parsed_url.substr(0, colon);
        port_ = static_cast<uint16_t>(std::stoi(parsed_url.substr(colon + 1)));
    } else {
        host_ = parsed_url;
    }

    user_ = user;
    password_ = pass;

    // Create socket
    socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ < 0) {
        last_error_ = "Failed to create socket";
        return false;
    }

    // Resolve hostname
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port_);

    if (inet_pton(AF_INET, host_.c_str(), &server_addr.sin_addr) != 1) {
        // Try DNS resolution
        struct hostent* he = gethostbyname(host_.c_str());
        if (!he) {
            closesocket(socket_);
            last_error_ = "Failed to resolve hostname";
            return false;
        }
        memcpy(&server_addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    if (::connect(socket_, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
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
