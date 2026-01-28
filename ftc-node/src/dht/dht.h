#pragma once

#include "node_id.h"
#include "routing_table.h"
#include "bencode.h"
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <random>
#include <set>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#ifndef SOCKET
#define SOCKET int
#endif
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif
#ifndef closesocket
#define closesocket close
#endif
#endif

namespace dht {

class DHT {
public:
    // port - UDP port for DHT (default 17321)
    // mainnet - if true, uses mainnet info_hash
    explicit DHT(uint16_t port = 17321, bool mainnet = true);
    ~DHT();

    // Start DHT service
    bool start();

    // Stop DHT service
    void stop();

    // Check if running
    bool isRunning() const { return running_; }

    // Announce our FTC node on the DHT
    void announce(uint16_t p2p_port);

    // Get routing table size
    size_t getRoutingTableSize() const;

    // Get our node ID
    const NodeId& getNodeId() const { return node_id_; }

    // Get info hash (network identifier)
    const NodeId& getInfoHash() const { return info_hash_; }

    // Is mainnet?
    bool isMainnet() const { return mainnet_; }

    // Get port
    uint16_t getPort() const { return port_; }

    // Callback when FTC peer is found
    using PeerCallback = std::function<void(const std::string& ip, uint16_t port)>;
    void setOnPeerFound(PeerCallback cb) { peer_callback_ = cb; }

    // Add local IP to filter out self-discovery
    void addLocalIP(const std::string& ip) { local_ips_.insert(ip); }

    // Logging callback
    using LogCallback = std::function<void(const std::string& msg, bool is_error)>;
    void setLogCallback(LogCallback cb) { log_callback_ = cb; }

private:
    // Network
    uint16_t port_;
    SOCKET socket_ = INVALID_SOCKET;

    // DHT state
    NodeId node_id_;
    NodeId info_hash_;  // SHA1("FTC-mainnet-v4") or "FTC-testnet-v4"
    std::unique_ptr<RoutingTable> routing_table_;
    bool mainnet_;

    // Threading
    std::atomic<bool> running_{false};
    std::thread recv_thread_;
    std::thread maintenance_thread_;

    // Transaction ID management
    std::atomic<uint16_t> next_txid_{1};
    std::mutex pending_mutex_;
    struct PendingQuery {
        std::string type;  // "ping", "find_node", "get_peers", "announce_peer"
        NodeId target;
        int64_t sent_time;
    };
    std::map<std::string, PendingQuery> pending_queries_;

    // Token management for announce_peer
    std::mutex token_mutex_;
    std::map<std::string, std::string> tokens_;  // ip -> token
    std::string secret_;
    int64_t secret_time_ = 0;

    // Peer storage (found FTC peers)
    std::mutex peers_mutex_;
    std::map<std::string, std::pair<std::string, uint16_t>> found_peers_;  // key -> (ip, port)
    std::set<std::string> queried_nodes_;  // Nodes we've already sent get_peers to

    // Local IPs to filter out self-discovery
    std::set<std::string> local_ips_;

    // Our announced port
    uint16_t announced_port_ = 0;

    // Callbacks
    PeerCallback peer_callback_;
    LogCallback log_callback_;

    // Bootstrap nodes (BitTorrent DHT IPv6 network)
    const std::vector<std::pair<std::string, uint16_t>> bootstrap_nodes_ = {
        {"dht.transmissionbt.com", 6881},
        {"router.bittorrent.com", 6881},
        {"router.utorrent.com", 6881},
    };

    // Internal methods
    bool initSocket();
    void closeSocket();

    void recvLoop();
    void maintenanceLoop();

    void handleMessage(const uint8_t* data, size_t len, const sockaddr_in6& from);
    void handleQuery(const BencodeDict& msg, const std::string& txid, const sockaddr_in6& from);
    void handleResponse(const BencodeDict& msg, const std::string& txid, const sockaddr_in6& from);
    void handleError(const BencodeDict& msg, const std::string& txid, const sockaddr_in6& from);

    // RPC methods
    void sendPing(const std::string& ip, uint16_t port);
    void sendFindNode(const std::string& ip, uint16_t port, const NodeId& target);
    void sendGetPeers(const std::string& ip, uint16_t port);
    void sendAnnouncePeer(const std::string& ip, uint16_t port, const std::string& token);

    void sendMessage(const BencodeDict& msg, const std::string& ip, uint16_t port);
    void sendMessage(const BencodeDict& msg, const sockaddr_in6& addr);

    std::string generateTxid();
    std::string generateToken(const std::string& ip);
    bool verifyToken(const std::string& ip, const std::string& token);

    void bootstrap();
    void refreshBuckets();
    void searchPeers();

    void log(const std::string& msg, bool is_error = false);

    // Utility
    static std::string addrToString(const sockaddr_in6& addr);
    static bool stringToAddr(const std::string& ip, uint16_t port, sockaddr_in6& addr);
    static std::string compactNodeInfo(const NodeId& id, const std::string& ip, uint16_t port);
    static bool parseCompactNodeInfo(const std::string& data, size_t offset, NodeId& id, std::string& ip, uint16_t& port);
};

} // namespace dht
