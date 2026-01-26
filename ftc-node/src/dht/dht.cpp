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

    // Generate info_hash for FTC network
    std::string network_id = mainnet ? "FTC-mainnet-v2" : "FTC-testnet-v2";
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
    // Create IPv6 UDP socket
    socket_ = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ == INVALID_SOCKET) {
        log("Failed to create socket", true);
        return false;
    }

    // Allow IPv4-mapped addresses (dual-stack)
    int no = 0;
    setsockopt(socket_, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&no, sizeof(no));

    // Set non-blocking and reuse address
    int yes = 1;
    setsockopt(socket_, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));

    // Set receive timeout
#ifdef _WIN32
    DWORD timeout = 1000;
    setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    // Bind to port
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port_);
    addr.sin6_addr = in6addr_any;

    if (bind(socket_, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        log("Failed to bind to port " + std::to_string(port_), true);
        closeSocket();
        return false;
    }

    return true;
}

void DHT::closeSocket() {
    if (socket_ != INVALID_SOCKET) {
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    }
}

void DHT::recvLoop() {
    uint8_t buffer[65536];

    while (running_) {
        sockaddr_in6 from{};
        socklen_t fromlen = sizeof(from);

        int len = recvfrom(socket_, (char*)buffer, sizeof(buffer), 0,
                          (sockaddr*)&from, &fromlen);

        if (len > 0) {
            handleMessage(buffer, len, from);
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

void DHT::handleMessage(const uint8_t* data, size_t len, const sockaddr_in6& from) {
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
        handleQuery(dict, txid, from);
    } else if (type == "r") {
        handleResponse(dict, txid, from);
    } else if (type == "e") {
        handleError(dict, txid, from);
    }
}

void DHT::handleQuery(const BencodeDict& msg, const std::string& txid, const sockaddr_in6& from) {
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

    std::string sender_ip = addrToString(from);

    // Add sender to routing table
    NodeEntry sender;
    sender.id = sender_id;
    sender.ip = sender_ip;
    sender.port = ntohs(from.sin6_port);
    routing_table_->addNode(sender);

    if (query_type == "ping") {
        // Respond to ping
        BencodeDict response;
        response["t"] = txid;
        response["y"] = "r";
        BencodeDict r;
        r["id"] = std::string(reinterpret_cast<const char*>(node_id_.data()), NodeId::SIZE);
        response["r"] = r;
        sendMessage(response, from);
    }
    else if (query_type == "find_node") {
        auto target_it = args.find("target");
        if (target_it == args.end() || !target_it->second.isString()) return;
        NodeId target(target_it->second.asString());

        // Find closest nodes
        auto closest = routing_table_->findClosest(target, 8);

        // Build compact node info (20 bytes ID + 18 bytes IPv6 addr)
        std::string nodes6;
        for (const auto& node : closest) {
            nodes6 += compactNodeInfo(node.id, node.ip, node.port);
        }

        BencodeDict response;
        response["t"] = txid;
        response["y"] = "r";
        BencodeDict r;
        r["id"] = std::string(reinterpret_cast<const char*>(node_id_.data()), NodeId::SIZE);
        if (!nodes6.empty()) {
            r["nodes6"] = nodes6;
        }
        response["r"] = r;
        sendMessage(response, from);
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
                // Return peers as compact format
                std::string values;
                for (const auto& [id, peer] : found_peers_) {
                    sockaddr_in6 addr{};
                    if (stringToAddr(peer.first, peer.second, addr)) {
                        values += std::string(reinterpret_cast<char*>(&addr.sin6_addr), 16);
                        values += std::string(reinterpret_cast<char*>(&addr.sin6_port), 2);
                    }
                }
                if (!values.empty()) {
                    BencodeList peers_list;
                    // Each peer is 18 bytes
                    for (size_t i = 0; i + 18 <= values.size(); i += 18) {
                        peers_list.push_back(values.substr(i, 18));
                    }
                    r["values"] = peers_list;
                }
            }
        }

        // Return closest nodes
        auto closest = routing_table_->findClosest(query_hash, 8);
        std::string nodes6;
        for (const auto& node : closest) {
            nodes6 += compactNodeInfo(node.id, node.ip, node.port);
        }
        if (!nodes6.empty()) {
            r["nodes6"] = nodes6;
        }

        response["r"] = r;
        sendMessage(response, from);
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
            sendMessage(error, from);
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
        sendMessage(response, from);
    }
}

void DHT::handleResponse(const BencodeDict& msg, const std::string& txid, const sockaddr_in6& from) {
    auto r_it = msg.find("r");
    if (r_it == msg.end() || !r_it->second.isDict()) return;
    const auto& r = r_it->second.asDict();

    // Get responder's ID
    auto id_it = r.find("id");
    if (id_it == r.end() || !id_it->second.isString()) return;
    NodeId responder_id(id_it->second.asString());

    std::string responder_ip = addrToString(from);

    // Add responder to routing table
    NodeEntry responder;
    responder.id = responder_id;
    responder.ip = responder_ip;
    responder.port = ntohs(from.sin6_port);
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

    // Process nodes6 if present (IPv6 compact node info)
    auto nodes6_it = r.find("nodes6");
    if (nodes6_it != r.end() && nodes6_it->second.isString()) {
        const std::string& nodes6 = nodes6_it->second.asString();
        // Each node is 38 bytes: 20 bytes ID + 16 bytes IPv6 + 2 bytes port
        for (size_t i = 0; i + 38 <= nodes6.size(); i += 38) {
            NodeId id;
            std::string ip;
            uint16_t port;
            if (parseCompactNodeInfo(nodes6, i, id, ip, port)) {
                NodeEntry entry;
                entry.id = id;
                entry.ip = ip;
                entry.port = port;
                routing_table_->addNode(entry);

                // Collect for iterative lookup
                closer_nodes.push_back({ip, port});

                // If we don't have many nodes, ping them
                if (routing_table_->size() < 50) {
                    sendPing(ip, port);
                }
            }
        }
    }

    // Skip IPv4 nodes - we only want native IPv6

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

    // Process peers (values) if present - IPv6 only, port 17318 only
    auto values_it = r.find("values");
    if (values_it != r.end() && values_it->second.isList()) {
        for (const auto& v : values_it->second.asList()) {
            if (!v.isString()) continue;
            const std::string& peer = v.asString();

            // Only process IPv6 peers (18 bytes)
            if (peer.size() != 18) continue;

            sockaddr_in6 addr{};
            addr.sin6_family = AF_INET6;
            memcpy(&addr.sin6_addr, peer.data(), 16);
            memcpy(&addr.sin6_port, peer.data() + 16, 2);
            std::string ip = addrToString(addr);
            uint16_t port = ntohs(addr.sin6_port);

            // Skip IPv4-mapped addresses
            if (ip.find("::ffff:") == 0) continue;

            // Skip local/private IPv6 ranges (not globally routable)
            // fd00::/8 = Unique Local Address, fe80::/10 = Link-local
            if (ip.find("fd") == 0 || ip.find("fe80:") == 0 || ip.find("fc") == 0) continue;

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

            if (peer_callback_) {
                peer_callback_(ip, port);
            }
            // Don't log each peer - too spammy with many nodes
        }
    }

    // If we got a token, use it to announce (don't log every announce)
    auto token_it = r.find("token");
    if (token_it != r.end() && token_it->second.isString() && announced_port_ > 0) {
        sendAnnouncePeer(responder_ip, responder.port, token_it->second.asString());
    }
}

void DHT::handleError(const BencodeDict& msg, const std::string& txid, const sockaddr_in6& from) {
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
    a["want"] = BencodeList{std::string("n6")};  // Request IPv6 nodes
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
    a["want"] = BencodeList{std::string("n6")};
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
    sockaddr_in6 addr{};
    if (!stringToAddr(ip, port, addr)) {
        return;
    }
    sendMessage(msg, addr);
}

void DHT::sendMessage(const BencodeDict& msg, const sockaddr_in6& addr) {
    std::string data = Bencode::encode(BencodeValue(msg));
    sendto(socket_, data.data(), static_cast<int>(data.size()), 0,
           (const sockaddr*)&addr, sizeof(addr));
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
    log("Bootstrapping DHT...");

    // Try to resolve and contact bootstrap nodes
    for (const auto& [host, port] : bootstrap_nodes_) {
        // Resolve hostname
        addrinfo hints{};
        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = 0;  // Native IPv6 only (no IPv4-mapped)

        addrinfo* result = nullptr;
        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result) == 0 && result) {
            for (addrinfo* p = result; p != nullptr; p = p->ai_next) {
                if (p->ai_family == AF_INET6) {
                    sockaddr_in6* addr = (sockaddr_in6*)p->ai_addr;
                    std::string ip = addrToString(*addr);
                    log("Bootstrap: " + host + " -> " + ip);
                    sendFindNode(ip, port, node_id_);
                    break;
                }
            }
            freeaddrinfo(result);
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

void DHT::log(const std::string& msg, bool is_error) {
    if (log_callback_) {
        log_callback_("[DHT] " + msg, is_error);
    }
}

std::string DHT::addrToString(const sockaddr_in6& addr) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr.sin6_addr, buf, sizeof(buf));
    return std::string(buf);
}

bool DHT::stringToAddr(const std::string& ip, uint16_t port, sockaddr_in6& addr) {
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);

    if (inet_pton(AF_INET6, ip.c_str(), &addr.sin6_addr) == 1) {
        return true;
    }

    // Try as IPv4 and convert to IPv6-mapped
    in_addr addr4;
    if (inet_pton(AF_INET, ip.c_str(), &addr4) == 1) {
        // Create IPv4-mapped IPv6 address
        memset(&addr.sin6_addr, 0, sizeof(addr.sin6_addr));
        addr.sin6_addr.s6_addr[10] = 0xFF;
        addr.sin6_addr.s6_addr[11] = 0xFF;
        memcpy(&addr.sin6_addr.s6_addr[12], &addr4, 4);
        return true;
    }

    return false;
}

std::string DHT::compactNodeInfo(const NodeId& id, const std::string& ip, uint16_t port) {
    sockaddr_in6 addr{};
    if (!stringToAddr(ip, port, addr)) {
        return "";
    }

    std::string result;
    result.append(reinterpret_cast<const char*>(id.data()), NodeId::SIZE);
    result.append(reinterpret_cast<const char*>(&addr.sin6_addr), 16);
    uint16_t port_be = htons(port);
    result.append(reinterpret_cast<const char*>(&port_be), 2);

    return result;
}

bool DHT::parseCompactNodeInfo(const std::string& data, size_t offset, NodeId& id, std::string& ip, uint16_t& port) {
    if (offset + 38 > data.size()) return false;

    id = NodeId(reinterpret_cast<const uint8_t*>(data.data() + offset));

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    memcpy(&addr.sin6_addr, data.data() + offset + 20, 16);
    memcpy(&addr.sin6_port, data.data() + offset + 36, 2);

    ip = addrToString(addr);
    port = ntohs(addr.sin6_port);

    return true;
}

} // namespace dht
