#include "dht.h"
#include <cstring>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <chrono>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#else
#include <netdb.h>
#endif

namespace dht {

DHT::DHT(uint16_t port, bool mainnet)
    : port_(port), mainnet_(mainnet) {

    // Generate random node ID
    node_id_ = NodeId::random();

    // Generate info_hash for FTC network (v4 - classic 2016-block difficulty)
    std::string network_id = mainnet ? "FTC-mainnet-v4" : "FTC-testnet-v4";
    info_hash_ = NodeId::fromHash(network_id);

    // Initialize routing table
    routing_table_ = std::make_unique<RoutingTable>(node_id_);

    // Generate initial secret for tokens
    secret_.resize(16);
    std::random_device rd;
    for (auto& b : secret_) {
        b = static_cast<char>(rd() & 0xFF);
    }
    secret_time_ = std::time(nullptr);

    log("DHT initialized with node ID: " + node_id_.toHex().substr(0, 16) + "...");
    log("Info hash (FTC network): " + info_hash_.toHex().substr(0, 16) + "...");
}

DHT::~DHT() {
    stop();
}

bool DHT::start() {
    if (running_) return true;

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        log("WSAStartup failed", true);
        return false;
    }
#endif

    if (!initSocket()) {
        log("Failed to initialize UDP socket", true);
        return false;
    }

    running_ = true;

    // Start receive thread
    recv_thread_ = std::thread(&DHT::recvLoop, this);

    // Start maintenance thread
    maintenance_thread_ = std::thread(&DHT::maintenanceLoop, this);

    log("DHT started on port " + std::to_string(port_));
    log("Network: " + std::string(mainnet_ ? "FTC-mainnet-v4" : "FTC-testnet-v4"));
    log("Info hash: " + info_hash_.toHex().substr(0, 16) + "...");

    // Bootstrap and start searching for FTC peers
    bootstrap();

    // Wait a moment for bootstrap responses, then start searching
    std::thread([this]() {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        if (running_) {
            searchPeers();
        }
    }).detach();

    return true;
}

void DHT::stop() {
    if (!running_) return;

    running_ = false;

    closeSocket();

    if (recv_thread_.joinable()) {
        recv_thread_.join();
    }
    if (maintenance_thread_.joinable()) {
        maintenance_thread_.join();
    }

    log("DHT stopped");

#ifdef _WIN32
    WSACleanup();
#endif
}

bool DHT::initSocket() {
    int yes = 1;

    // Create IPv4 UDP socket
    socket_ipv4_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ipv4_ != INVALID_SOCKET) {
        setsockopt(socket_ipv4_, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
#ifdef _WIN32
        DWORD timeout = 1000;
        setsockopt(socket_ipv4_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
#else
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(socket_ipv4_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
        sockaddr_in addr4{};
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port_);
        addr4.sin_addr.s_addr = INADDR_ANY;

        if (bind(socket_ipv4_, (sockaddr*)&addr4, sizeof(addr4)) == SOCKET_ERROR) {
            log("Failed to bind IPv4 DHT socket to port " + std::to_string(port_), true);
            closesocket(socket_ipv4_);
            socket_ipv4_ = INVALID_SOCKET;
        } else {
            log("DHT IPv4 socket bound to port " + std::to_string(port_));
        }
    }

    // Create IPv6 UDP socket
    socket_ipv6_ = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ipv6_ != INVALID_SOCKET) {
        // IPv6 only - no dual-stack (we have separate IPv4 socket)
        int v6only = 1;
        setsockopt(socket_ipv6_, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&v6only, sizeof(v6only));
        setsockopt(socket_ipv6_, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
#ifdef _WIN32
        DWORD timeout = 1000;
        setsockopt(socket_ipv6_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
#else
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(socket_ipv6_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
        sockaddr_in6 addr6{};
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port_);
        addr6.sin6_addr = in6addr_any;

        if (bind(socket_ipv6_, (sockaddr*)&addr6, sizeof(addr6)) == SOCKET_ERROR) {
            log("Failed to bind IPv6 DHT socket to port " + std::to_string(port_), true);
            closesocket(socket_ipv6_);
            socket_ipv6_ = INVALID_SOCKET;
        } else {
            log("DHT IPv6 socket bound to port " + std::to_string(port_));
        }
    }

    // Need at least one socket
    if (socket_ipv4_ == INVALID_SOCKET && socket_ipv6_ == INVALID_SOCKET) {
        log("Failed to create any DHT socket", true);
        return false;
    }

    return true;
}

void DHT::closeSocket() {
    if (socket_ipv4_ != INVALID_SOCKET) {
        closesocket(socket_ipv4_);
        socket_ipv4_ = INVALID_SOCKET;
    }
    if (socket_ipv6_ != INVALID_SOCKET) {
        closesocket(socket_ipv6_);
        socket_ipv6_ = INVALID_SOCKET;
    }
}

void DHT::recvLoop() {
    uint8_t buffer[65536];

    while (running_) {
        fd_set readfds;
        FD_ZERO(&readfds);

        SOCKET max_fd = 0;
        if (socket_ipv4_ != INVALID_SOCKET) {
            FD_SET(socket_ipv4_, &readfds);
            if (socket_ipv4_ > max_fd) max_fd = socket_ipv4_;
        }
        if (socket_ipv6_ != INVALID_SOCKET) {
            FD_SET(socket_ipv6_, &readfds);
            if (socket_ipv6_ > max_fd) max_fd = socket_ipv6_;
        }

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ready = select(static_cast<int>(max_fd + 1), &readfds, nullptr, nullptr, &tv);
        if (ready <= 0) continue;

        // Check IPv4 socket
        if (socket_ipv4_ != INVALID_SOCKET && FD_ISSET(socket_ipv4_, &readfds)) {
            sockaddr_in from4{};
            socklen_t fromlen = sizeof(from4);
            int len = recvfrom(socket_ipv4_, (char*)buffer, sizeof(buffer), 0,
                              (sockaddr*)&from4, &fromlen);
            if (len > 0) {
                char ip_buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &from4.sin_addr, ip_buf, sizeof(ip_buf));
                handleMessage(buffer, len, std::string(ip_buf), ntohs(from4.sin_port));
            }
        }

        // Check IPv6 socket
        if (socket_ipv6_ != INVALID_SOCKET && FD_ISSET(socket_ipv6_, &readfds)) {
            sockaddr_in6 from6{};
            socklen_t fromlen = sizeof(from6);
            int len = recvfrom(socket_ipv6_, (char*)buffer, sizeof(buffer), 0,
                              (sockaddr*)&from6, &fromlen);
            if (len > 0) {
                char ip_buf[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &from6.sin6_addr, ip_buf, sizeof(ip_buf));
                handleMessage(buffer, len, std::string(ip_buf), ntohs(from6.sin6_port));
            }
        }
    }
}

void DHT::maintenanceLoop() {
    auto last_bootstrap = std::chrono::steady_clock::now();
    auto last_search = std::chrono::steady_clock::now();

    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        auto now = std::chrono::steady_clock::now();

        // Re-bootstrap every 5 minutes if routing table is small
        if (routing_table_->size() < 10 &&
            std::chrono::duration_cast<std::chrono::minutes>(now - last_bootstrap).count() >= 5) {
            bootstrap();
            last_bootstrap = now;
        }

        // Search for FTC peers every 60 seconds (clear dedup set to allow re-discovery)
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_search).count() >= 60) {
            // Clear old peers and queried nodes for fresh search
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                found_peers_.clear();
                queried_nodes_.clear();
            }
            searchPeers();
            last_search = now;
        }

        // Rotate token secret every 5 minutes
        if (std::time(nullptr) - secret_time_ > 300) {
            std::random_device rd;
            for (auto& b : secret_) {
                b = static_cast<char>(rd() & 0xFF);
            }
            secret_time_ = std::time(nullptr);
        }

        // Clean up old pending queries (timeout after 10 seconds)
        {
            std::lock_guard<std::mutex> lock(pending_mutex_);
            int64_t now_ts = std::time(nullptr);
            auto it = pending_queries_.begin();
            while (it != pending_queries_.end()) {
                if (now_ts - it->second.sent_time > 10) {
                    it = pending_queries_.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }
}

void DHT::handleMessage(const uint8_t* data, size_t len, const std::string& from_ip, uint16_t from_port) {
    BencodeValue msg;
    if (!Bencode::decode(data, len, msg) || !msg.isDict()) {
        return;
    }

    const auto& dict = msg.asDict();

    // Get transaction ID
    auto t_it = dict.find("t");
    if (t_it == dict.end() || !t_it->second.isString()) {
        return;
    }
    std::string txid = t_it->second.asString();

    // Get message type
    auto y_it = dict.find("y");
    if (y_it == dict.end() || !y_it->second.isString()) {
        return;
    }
    std::string type = y_it->second.asString();

    if (type == "q") {
        handleQuery(dict, txid, from_ip, from_port);
    } else if (type == "r") {
        handleResponse(dict, txid, from_ip, from_port);
    } else if (type == "e") {
        handleError(dict, txid);
    }
}

void DHT::handleQuery(const BencodeDict& msg, const std::string& txid, const std::string& sender_ip, uint16_t sender_port) {
    auto q_it = msg.find("q");
    if (q_it == msg.end() || !q_it->second.isString()) return;
    std::string query_type = q_it->second.asString();

    auto a_it = msg.find("a");
    if (a_it == msg.end() || !a_it->second.isDict()) return;
    const auto& args = a_it->second.asDict();

    // Get querying node's ID
    auto id_it = args.find("id");
    if (id_it == args.end() || !id_it->second.isString()) return;
    NodeId sender_id(id_it->second.asString());

    // Add sender to routing table
    NodeEntry sender;
    sender.id = sender_id;
    sender.ip = sender_ip;
    sender.port = sender_port;
    routing_table_->addNode(sender);

    if (query_type == "ping") {
        // Respond to ping
        BencodeDict response;
        response["t"] = txid;
        response["y"] = "r";
        BencodeDict r;
        r["id"] = std::string(reinterpret_cast<const char*>(node_id_.data()), NodeId::SIZE);
        response["r"] = r;
        sendMessage(response, sender_ip, sender_port);
    }
    else if (query_type == "find_node") {
        auto target_it = args.find("target");
        if (target_it == args.end() || !target_it->second.isString()) return;
        NodeId target(target_it->second.asString());

        // Find closest nodes
        auto closest = routing_table_->findClosest(target, 8);

        // Build compact node info for both IPv4 and IPv6
        std::string nodes4;  // 26 bytes per node: 20 ID + 4 IPv4 + 2 port
        std::string nodes6;  // 38 bytes per node: 20 ID + 16 IPv6 + 2 port
        for (const auto& node : closest) {
            if (isIPv4(node.ip)) {
                nodes4 += compactNodeInfo4(node.id, node.ip, node.port);
            } else {
                nodes6 += compactNodeInfo6(node.id, node.ip, node.port);
            }
        }

        BencodeDict response;
        response["t"] = txid;
        response["y"] = "r";
        BencodeDict r;
        r["id"] = std::string(reinterpret_cast<const char*>(node_id_.data()), NodeId::SIZE);
        if (!nodes4.empty()) {
            r["nodes"] = nodes4;
        }
        if (!nodes6.empty()) {
            r["nodes6"] = nodes6;
        }
        response["r"] = r;
        sendMessage(response, sender_ip, sender_port);
    }
    else if (query_type == "get_peers") {
        auto ih_it = args.find("info_hash");
        if (ih_it == args.end() || !ih_it->second.isString()) return;
        NodeId query_hash(ih_it->second.asString());

        // Generate token for this IP
        std::string token = generateToken(sender_ip);

        BencodeDict response;
        response["t"] = txid;
        response["y"] = "r";
        BencodeDict r;
        r["id"] = std::string(reinterpret_cast<const char*>(node_id_.data()), NodeId::SIZE);
        r["token"] = token;

        // Check if we have peers for this info_hash (only for FTC network)
        if (query_hash == info_hash_) {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            if (!found_peers_.empty()) {
                // Return peers as compact format (both IPv4 and IPv6)
                BencodeList peers_list;
                for (const auto& [id, peer] : found_peers_) {
                    const std::string& ip = peer.first;
                    uint16_t port = peer.second;
                    if (isIPv4(ip)) {
                        // IPv4: 6 bytes (4 IP + 2 port)
                        in_addr addr4{};
                        if (inet_pton(AF_INET, ip.c_str(), &addr4) == 1) {
                            std::string compact;
                            compact.append(reinterpret_cast<char*>(&addr4), 4);
                            uint16_t port_be = htons(port);
                            compact.append(reinterpret_cast<char*>(&port_be), 2);
                            peers_list.push_back(compact);
                        }
                    } else {
                        // IPv6: 18 bytes (16 IP + 2 port)
                        in6_addr addr6{};
                        if (inet_pton(AF_INET6, ip.c_str(), &addr6) == 1) {
                            std::string compact;
                            compact.append(reinterpret_cast<char*>(&addr6), 16);
                            uint16_t port_be = htons(port);
                            compact.append(reinterpret_cast<char*>(&port_be), 2);
                            peers_list.push_back(compact);
                        }
                    }
                }
                if (!peers_list.empty()) {
                    r["values"] = peers_list;
                }
            }
        }

        // Return closest nodes (both IPv4 and IPv6)
        auto closest = routing_table_->findClosest(query_hash, 8);
        std::string nodes4;
        std::string nodes6;
        for (const auto& node : closest) {
            if (isIPv4(node.ip)) {
                nodes4 += compactNodeInfo4(node.id, node.ip, node.port);
            } else {
                nodes6 += compactNodeInfo6(node.id, node.ip, node.port);
            }
        }
        if (!nodes4.empty()) {
            r["nodes"] = nodes4;
        }
        if (!nodes6.empty()) {
            r["nodes6"] = nodes6;
        }

        response["r"] = r;
        sendMessage(response, sender_ip, sender_port);
    }
    else if (query_type == "announce_peer") {
        auto ih_it = args.find("info_hash");
        auto port_it = args.find("port");
        auto token_it = args.find("token");

        if (ih_it == args.end() || port_it == args.end() || token_it == args.end()) return;
        if (!ih_it->second.isString() || !port_it->second.isInt() || !token_it->second.isString()) return;

        NodeId ann_hash(ih_it->second.asString());
        uint16_t ann_port = static_cast<uint16_t>(port_it->second.asInt());
        std::string ann_token = token_it->second.asString();

        // Verify token
        if (!verifyToken(sender_ip, ann_token)) {
            BencodeDict error;
            error["t"] = txid;
            error["y"] = "e";
            BencodeList e;
            e.push_back(int64_t(203));
            e.push_back("Bad token");
            error["e"] = e;
            sendMessage(error, sender_ip, sender_port);
            return;
        }

        // Only store peers for FTC network
        if (ann_hash == info_hash_) {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            std::string peer_key = sender_id.toHex();
            found_peers_[peer_key] = {sender_ip, ann_port};

            // Notify callback (only for FTC port)
            if (ann_port == 17318 && peer_callback_) {
                peer_callback_(sender_ip, ann_port);
            }
        }

        // Send response
        BencodeDict response;
        response["t"] = txid;
        response["y"] = "r";
        BencodeDict r;
        r["id"] = std::string(reinterpret_cast<const char*>(node_id_.data()), NodeId::SIZE);
        response["r"] = r;
        sendMessage(response, sender_ip, sender_port);
    }
}

void DHT::handleResponse(const BencodeDict& msg, const std::string& txid, const std::string& sender_ip, uint16_t sender_port) {
    auto r_it = msg.find("r");
    if (r_it == msg.end() || !r_it->second.isDict()) return;
    const auto& r = r_it->second.asDict();

    // Get responder's ID
    auto id_it = r.find("id");
    if (id_it == r.end() || !id_it->second.isString()) return;
    NodeId responder_id(id_it->second.asString());

    // Add responder to routing table
    NodeEntry responder;
    responder.id = responder_id;
    responder.ip = sender_ip;
    responder.port = sender_port;
    routing_table_->addNode(responder);

    // Check pending query
    std::string query_type;
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        auto it = pending_queries_.find(txid);
        if (it != pending_queries_.end()) {
            query_type = it->second.type;
            pending_queries_.erase(it);
        }
    }

    // Collect nodes for iterative lookup
    std::vector<std::pair<std::string, uint16_t>> closer_nodes;

    // Process nodes (IPv4 compact node info)
    auto nodes_it = r.find("nodes");
    if (nodes_it != r.end() && nodes_it->second.isString()) {
        const std::string& nodes = nodes_it->second.asString();
        // Each node is 26 bytes: 20 bytes ID + 4 bytes IPv4 + 2 bytes port
        for (size_t i = 0; i + 26 <= nodes.size(); i += 26) {
            NodeId id;
            std::string ip;
            uint16_t port;
            if (parseCompactNodeInfo4(nodes, i, id, ip, port)) {
                NodeEntry entry;
                entry.id = id;
                entry.ip = ip;
                entry.port = port;
                routing_table_->addNode(entry);
                closer_nodes.push_back({ip, port});
                if (routing_table_->size() < 50) {
                    sendPing(ip, port);
                }
            }
        }
    }

    // Process nodes6 (IPv6 compact node info)
    auto nodes6_it = r.find("nodes6");
    if (nodes6_it != r.end() && nodes6_it->second.isString()) {
        const std::string& nodes6 = nodes6_it->second.asString();
        // Each node is 38 bytes: 20 bytes ID + 16 bytes IPv6 + 2 bytes port
        for (size_t i = 0; i + 38 <= nodes6.size(); i += 38) {
            NodeId id;
            std::string ip;
            uint16_t port;
            if (parseCompactNodeInfo6(nodes6, i, id, ip, port)) {
                NodeEntry entry;
                entry.id = id;
                entry.ip = ip;
                entry.port = port;
                routing_table_->addNode(entry);
                closer_nodes.push_back({ip, port});
                if (routing_table_->size() < 50) {
                    sendPing(ip, port);
                }
            }
        }
    }

    // ITERATIVE LOOKUP: If this was a get_peers query and we got nodes (not values),
    // continue the search by querying those nodes (with deduplication to prevent spam)
    if (query_type == "get_peers" && !closer_nodes.empty()) {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (const auto& node : closer_nodes) {
            std::string key = node.first + ":" + std::to_string(node.second);
            if (queried_nodes_.count(key)) continue;
            queried_nodes_.insert(key);
            sendGetPeers(node.first, node.second);
        }
    }

    // Process peers (values) if present - both IPv4 (6 bytes) and IPv6 (18 bytes)
    auto values_it = r.find("values");
    if (values_it != r.end() && values_it->second.isList()) {
        for (const auto& v : values_it->second.asList()) {
            if (!v.isString()) continue;
            const std::string& peer = v.asString();

            std::string ip;
            uint16_t port;

            if (peer.size() == 6) {
                // IPv4: 4 bytes IP + 2 bytes port
                char ip_buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, peer.data(), ip_buf, sizeof(ip_buf));
                ip = ip_buf;
                port = ntohs(*reinterpret_cast<const uint16_t*>(peer.data() + 4));
            } else if (peer.size() == 18) {
                // IPv6: 16 bytes IP + 2 bytes port
                char ip_buf[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, peer.data(), ip_buf, sizeof(ip_buf));
                ip = ip_buf;
                port = ntohs(*reinterpret_cast<const uint16_t*>(peer.data() + 16));

                // Skip IPv4-mapped addresses and private ranges
                if (ip.find("::ffff:") == 0) continue;
                if (ip.find("fd") == 0 || ip.find("fe80:") == 0 || ip.find("fc") == 0) continue;
            } else {
                continue;
            }

            // Only accept FTC nodes (port 17318)
            if (port != 17318) continue;

            // Skip our own IP (self-discovery)
            if (local_ips_.count(ip)) continue;

            // Check if we already know this peer
            std::string peer_key = ip + ":" + std::to_string(port);
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                if (found_peers_.count(peer_key)) continue;
                found_peers_[peer_key] = {ip, port};
            }

            // Don't log individual peers - too spammy. Peer callback handles it.
            if (peer_callback_) {
                peer_callback_(ip, port);
            }
        }
    }

    // If we got a token, use it to announce (don't log every announce)
    auto token_it = r.find("token");
    if (token_it != r.end() && token_it->second.isString() && announced_port_ > 0) {
        sendAnnouncePeer(sender_ip, sender_port, token_it->second.asString());
    }
}

void DHT::handleError(const BencodeDict& msg, const std::string& txid) {
    // Just remove from pending
    std::lock_guard<std::mutex> lock(pending_mutex_);
    pending_queries_.erase(txid);
}

void DHT::sendPing(const std::string& ip, uint16_t port) {
    std::string txid = generateTxid();

    BencodeDict msg;
    msg["t"] = txid;
    msg["y"] = "q";
    msg["q"] = "ping";
    BencodeDict a;
    a["id"] = std::string(reinterpret_cast<const char*>(node_id_.data()), NodeId::SIZE);
    msg["a"] = a;

    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        pending_queries_[txid] = {"ping", NodeId(), std::time(nullptr)};
    }

    sendMessage(msg, ip, port);
}

void DHT::sendFindNode(const std::string& ip, uint16_t port, const NodeId& target) {
    std::string txid = generateTxid();

    BencodeDict msg;
    msg["t"] = txid;
    msg["y"] = "q";
    msg["q"] = "find_node";
    BencodeDict a;
    a["id"] = std::string(reinterpret_cast<const char*>(node_id_.data()), NodeId::SIZE);
    a["target"] = std::string(reinterpret_cast<const char*>(target.data()), NodeId::SIZE);
    a["want"] = BencodeList{std::string("n4"), std::string("n6")};  // Request both IPv4 and IPv6 nodes
    msg["a"] = a;

    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        pending_queries_[txid] = {"find_node", target, std::time(nullptr)};
    }

    sendMessage(msg, ip, port);
}

void DHT::sendGetPeers(const std::string& ip, uint16_t port) {
    std::string txid = generateTxid();

    BencodeDict msg;
    msg["t"] = txid;
    msg["y"] = "q";
    msg["q"] = "get_peers";
    BencodeDict a;
    a["id"] = std::string(reinterpret_cast<const char*>(node_id_.data()), NodeId::SIZE);
    a["info_hash"] = std::string(reinterpret_cast<const char*>(info_hash_.data()), NodeId::SIZE);
    a["want"] = BencodeList{std::string("n4"), std::string("n6")};
    msg["a"] = a;

    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        pending_queries_[txid] = {"get_peers", info_hash_, std::time(nullptr)};
    }

    sendMessage(msg, ip, port);
}

void DHT::sendAnnouncePeer(const std::string& ip, uint16_t port, const std::string& token) {
    std::string txid = generateTxid();

    BencodeDict msg;
    msg["t"] = txid;
    msg["y"] = "q";
    msg["q"] = "announce_peer";
    BencodeDict a;
    a["id"] = std::string(reinterpret_cast<const char*>(node_id_.data()), NodeId::SIZE);
    a["info_hash"] = std::string(reinterpret_cast<const char*>(info_hash_.data()), NodeId::SIZE);
    a["port"] = int64_t(announced_port_);
    a["token"] = token;
    a["implied_port"] = int64_t(0);  // Use our specified port
    msg["a"] = a;

    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        pending_queries_[txid] = {"announce_peer", info_hash_, std::time(nullptr)};
    }

    sendMessage(msg, ip, port);
}

void DHT::sendMessage(const BencodeDict& msg, const std::string& ip, uint16_t port) {
    std::string data = Bencode::encode(BencodeValue(msg));

    if (isIPv4(ip)) {
        // Send via IPv4 socket
        if (socket_ipv4_ == INVALID_SOCKET) return;
        sockaddr_in addr4{};
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port);
        if (inet_pton(AF_INET, ip.c_str(), &addr4.sin_addr) != 1) return;
        sendto(socket_ipv4_, data.data(), static_cast<int>(data.size()), 0,
               (const sockaddr*)&addr4, sizeof(addr4));
    } else {
        // Send via IPv6 socket
        if (socket_ipv6_ == INVALID_SOCKET) return;
        sockaddr_in6 addr6{};
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        if (inet_pton(AF_INET6, ip.c_str(), &addr6.sin6_addr) != 1) return;
        sendto(socket_ipv6_, data.data(), static_cast<int>(data.size()), 0,
               (const sockaddr*)&addr6, sizeof(addr6));
    }
}

std::string DHT::generateTxid() {
    uint16_t id = next_txid_++;
    char buf[2];
    buf[0] = (id >> 8) & 0xFF;
    buf[1] = id & 0xFF;
    return std::string(buf, 2);
}

std::string DHT::generateToken(const std::string& ip) {
    std::lock_guard<std::mutex> lock(token_mutex_);

    // Simple token: SHA1(secret + ip)
    std::string data = secret_ + ip;
    NodeId hash = NodeId::fromHash(data);
    std::string token(reinterpret_cast<const char*>(hash.data()), 8);

    tokens_[ip] = token;
    return token;
}

bool DHT::verifyToken(const std::string& ip, const std::string& token) {
    std::lock_guard<std::mutex> lock(token_mutex_);

    auto it = tokens_.find(ip);
    if (it != tokens_.end() && it->second == token) {
        return true;
    }

    // Also check current token
    std::string data = secret_ + ip;
    NodeId hash = NodeId::fromHash(data);
    std::string expected(reinterpret_cast<const char*>(hash.data()), 8);

    return token == expected;
}

void DHT::bootstrap() {
    log("Bootstrapping DHT (dual-stack)...");

    // Try to resolve and contact bootstrap nodes (both IPv4 and IPv6)
    for (const auto& [host, port] : bootstrap_nodes_) {
        // Try IPv4 first
        if (socket_ipv4_ != INVALID_SOCKET) {
            addrinfo hints{};
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;

            addrinfo* result = nullptr;
            if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result) == 0 && result) {
                for (addrinfo* p = result; p != nullptr; p = p->ai_next) {
                    if (p->ai_family == AF_INET) {
                        sockaddr_in* addr = (sockaddr_in*)p->ai_addr;
                        char ip_buf[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &addr->sin_addr, ip_buf, sizeof(ip_buf));
                        log("Bootstrap IPv4: " + host + " -> " + std::string(ip_buf));
                        sendFindNode(ip_buf, port, node_id_);
                        break;
                    }
                }
                freeaddrinfo(result);
            }
        }

        // Also try IPv6
        if (socket_ipv6_ != INVALID_SOCKET) {
            addrinfo hints{};
            hints.ai_family = AF_INET6;
            hints.ai_socktype = SOCK_DGRAM;

            addrinfo* result = nullptr;
            if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result) == 0 && result) {
                for (addrinfo* p = result; p != nullptr; p = p->ai_next) {
                    if (p->ai_family == AF_INET6) {
                        sockaddr_in6* addr = (sockaddr_in6*)p->ai_addr;
                        char ip_buf[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &addr->sin6_addr, ip_buf, sizeof(ip_buf));
                        log("Bootstrap IPv6: " + host + " -> " + std::string(ip_buf));
                        sendFindNode(ip_buf, port, node_id_);
                        break;
                    }
                }
                freeaddrinfo(result);
            }
        }
    }
}

void DHT::refreshBuckets() {
    // Find nodes close to random IDs in each bucket
    for (int i = 0; i < 160; i += 20) {
        NodeId target = NodeId::random();
        auto closest = routing_table_->findClosest(target, 3);
        for (const auto& node : closest) {
            sendFindNode(node.ip, node.port, target);
        }
    }
}

void DHT::searchPeers() {
    // Search for FTC peers by querying nodes close to info_hash
    auto closest = routing_table_->findClosest(info_hash_, 8);

    if (closest.empty()) {
        return;  // No nodes yet, will bootstrap
    }

    for (const auto& node : closest) {
        sendGetPeers(node.ip, node.port);
    }
}

void DHT::announce(uint16_t p2p_port) {
    announced_port_ = p2p_port;

    // Send get_peers to closest nodes (they will return tokens for announce)
    searchPeers();
}

size_t DHT::getRoutingTableSize() const {
    return routing_table_->size();
}

size_t DHT::getIPv4NodeCount() const {
    size_t count = 0;
    auto nodes = routing_table_->getAllNodes();
    for (const auto& node : nodes) {
        if (isIPv4(node.ip)) {
            ++count;
        }
    }
    return count;
}

size_t DHT::getIPv6NodeCount() const {
    size_t count = 0;
    auto nodes = routing_table_->getAllNodes();
    for (const auto& node : nodes) {
        if (!isIPv4(node.ip)) {
            ++count;
        }
    }
    return count;
}

void DHT::log(const std::string& msg, bool is_error) {
    if (log_callback_) {
        log_callback_("[DHT] " + msg, is_error);
    }
}

bool DHT::isIPv4(const std::string& ip) {
    // Simple check: if it contains a dot and no colon, it's IPv4
    return ip.find('.') != std::string::npos && ip.find(':') == std::string::npos;
}

std::string DHT::compactNodeInfo4(const NodeId& id, const std::string& ip, uint16_t port) {
    // IPv4 compact format: 26 bytes (20 ID + 4 IPv4 + 2 port)
    in_addr addr4{};
    if (inet_pton(AF_INET, ip.c_str(), &addr4) != 1) {
        return "";
    }

    std::string result;
    result.append(reinterpret_cast<const char*>(id.data()), NodeId::SIZE);
    result.append(reinterpret_cast<const char*>(&addr4), 4);
    uint16_t port_be = htons(port);
    result.append(reinterpret_cast<const char*>(&port_be), 2);

    return result;
}

std::string DHT::compactNodeInfo6(const NodeId& id, const std::string& ip, uint16_t port) {
    // IPv6 compact format: 38 bytes (20 ID + 16 IPv6 + 2 port)
    in6_addr addr6{};
    if (inet_pton(AF_INET6, ip.c_str(), &addr6) != 1) {
        return "";
    }

    std::string result;
    result.append(reinterpret_cast<const char*>(id.data()), NodeId::SIZE);
    result.append(reinterpret_cast<const char*>(&addr6), 16);
    uint16_t port_be = htons(port);
    result.append(reinterpret_cast<const char*>(&port_be), 2);

    return result;
}

bool DHT::parseCompactNodeInfo4(const std::string& data, size_t offset, NodeId& id, std::string& ip, uint16_t& port) {
    // IPv4 compact format: 26 bytes (20 ID + 4 IPv4 + 2 port)
    if (offset + 26 > data.size()) return false;

    id = NodeId(reinterpret_cast<const uint8_t*>(data.data() + offset));

    char ip_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, data.data() + offset + 20, ip_buf, sizeof(ip_buf));
    ip = ip_buf;

    port = ntohs(*reinterpret_cast<const uint16_t*>(data.data() + offset + 24));

    return true;
}

bool DHT::parseCompactNodeInfo6(const std::string& data, size_t offset, NodeId& id, std::string& ip, uint16_t& port) {
    // IPv6 compact format: 38 bytes (20 ID + 16 IPv6 + 2 port)
    if (offset + 38 > data.size()) return false;

    id = NodeId(reinterpret_cast<const uint8_t*>(data.data() + offset));

    char ip_buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, data.data() + offset + 20, ip_buf, sizeof(ip_buf));
    ip = ip_buf;

    port = ntohs(*reinterpret_cast<const uint16_t*>(data.data() + offset + 36));

    return true;
}

} // namespace dht
