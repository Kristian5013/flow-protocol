#ifndef FTC_P2P_PEER_MANAGER_H
#define FTC_P2P_PEER_MANAGER_H

#include "p2p/connection.h"
#include "p2p/protocol.h"
#include "crypto/keccak256.h"
#include <map>
#include <set>
#include <vector>
#include <deque>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <random>
#include <chrono>

namespace ftc {
namespace p2p {

// Use Hash256 from crypto namespace
using crypto::Hash256;

// Forward declarations
class MessageHandler;

} // namespace p2p
} // namespace ftc

// Forward declarations for chain types
namespace ftc {
namespace chain {
class Block;
class Transaction;
} // namespace chain
} // namespace ftc

namespace ftc {
namespace p2p {

// Bring chain types into scope
using chain::Block;
using chain::Transaction;

// Peer state
enum class PeerState {
    CONNECTING,         // TCP handshake in progress
    CONNECTED,          // TCP connected, VERSION not sent
    VERSION_SENT,       // VERSION sent, waiting for response
    VERSION_RECEIVED,   // VERSION received, VERACK not sent
    ESTABLISHED,        // Handshake complete
    DISCONNECTING       // Graceful shutdown
};

// Address information with metadata
struct AddrInfo {
    NetAddr addr;
    uint64_t services = 0;
    int64_t last_success = 0;       // Unix timestamp of last successful connection
    int64_t last_try = 0;           // Unix timestamp of last connection attempt
    int64_t last_seen = 0;          // Unix timestamp when we heard about this address
    int attempts = 0;               // Number of connection attempts
    int success_count = 0;          // Number of successful connections
    std::string source;             // How we learned about this address

    // Calculate address score for selection
    double getScore(int64_t now) const;
};

// Ban entry
struct BanEntry {
    NetAddr addr;
    int64_t ban_time;       // Unix timestamp when ban was created
    int64_t unban_time;     // Unix timestamp when ban expires
    std::string reason;
};

// Peer information
struct PeerInfo {
    Connection::Id id;
    NetAddr addr;
    PeerState state;
    ConnectionDir direction;

    // Version info
    int32_t version = 0;
    uint64_t services = 0;
    std::string user_agent;
    int32_t start_height = 0;
    bool relay = true;

    // Sync state
    int32_t best_height = 0;
    Hash256 best_hash;
    bool syncing = false;

    // Statistics
    std::chrono::steady_clock::time_point connect_time;
    int64_t ping_usec = -1;
    uint64_t bytes_sent = 0;
    uint64_t bytes_recv = 0;

    // Inventory
    std::set<Hash256> known_blocks;
    std::set<Hash256> known_txs;
};

// Callbacks
using NewPeerCallback = std::function<void(Connection::Id)>;
using PeerDisconnectCallback = std::function<void(Connection::Id, const std::string&)>;
using MessageReceivedCallback = std::function<void(Connection::Id, const Message&)>;

/**
 * PeerManager - manages peer connections and addresses
 *
 * Responsibilities:
 * - Maintain connections to peers (both inbound and outbound)
 * - Address management (known addresses, tried addresses)
 * - Ban management
 * - Peer selection for various tasks (sync, relay, etc.)
 * - Version handshake
 */
class PeerManager {
public:
    // Configuration
    struct Config {
        uint16_t listen_port = 17318;
        int max_inbound = 125;
        int max_outbound = 8;
        int max_outbound_full_relay = 8;
        int target_outbound = 8;
        std::chrono::seconds connect_timeout{60};
        std::chrono::seconds ping_interval{120};
        std::chrono::seconds inactivity_timeout{600};
        int ban_threshold = 100;
        std::chrono::seconds ban_duration{86400};   // 24 hours

        Config() = default;
    };

    PeerManager();
    explicit PeerManager(const Config& config);
    ~PeerManager();

    // Non-copyable
    PeerManager(const PeerManager&) = delete;
    PeerManager& operator=(const PeerManager&) = delete;

    // Lifecycle
    bool start();
    void stop();
    bool isRunning() const { return running_; }

    // Set callbacks
    void setNewPeerCallback(NewPeerCallback cb) { on_new_peer_ = cb; }
    void setPeerDisconnectCallback(PeerDisconnectCallback cb) { on_peer_disconnect_ = cb; }
    void setMessageCallback(MessageReceivedCallback cb) { on_message_ = cb; }

    // Callback setters (aliases for node.cpp compatibility)
    void setOnNewPeer(NewPeerCallback cb) { on_new_peer_ = cb; }
    void setOnPeerDisconnect(PeerDisconnectCallback cb) { on_peer_disconnect_ = cb; }
    void setOnMessage(MessageReceivedCallback cb) { on_message_ = cb; }

    // Version info setters
    void setOurVersion(int32_t version) { our_version_ = version; }
    void setOurServices(uint64_t services) { our_services_ = services; }
    void setOurUserAgent(const std::string& ua) { our_user_agent_ = ua; }
    void setOurHeight(int32_t height) { our_height_ = height; }

    // Manual connection
    bool connectTo(const NetAddr& addr);
    void disconnect(Connection::Id id, const std::string& reason = "");
    void disconnectAll(const std::string& reason = "");

    // Address management
    void addAddress(const NetAddr& addr, const std::string& source = "");
    void addAddresses(const std::vector<NetAddrTime>& addrs, const std::string& source = "");
    std::vector<NetAddrTime> getAddresses(size_t max_count = 1000) const;
    size_t getAddressCount() const;

    // Ban management
    void ban(const NetAddr& addr, const std::string& reason = "",
             std::chrono::seconds duration = std::chrono::seconds{86400});
    void unban(const NetAddr& addr);
    bool isBanned(const NetAddr& addr) const;
    std::vector<BanEntry> getBanList() const;
    void clearBans();

    // Peer access
    std::shared_ptr<Connection> getConnection(Connection::Id id);
    std::vector<PeerInfo> getPeerInfo() const;
    size_t getPeerCount() const;
    size_t getInboundCount() const;
    size_t getOutboundCount() const;

    // Send to peer(s)
    bool sendTo(Connection::Id id, const Message& msg);
    void broadcast(const Message& msg, Connection::Id exclude = 0);
    void broadcastBlock(const Hash256& hash, const Block& block);
    void broadcastTx(const Hash256& txid, const Transaction& tx);

    // Peer selection
    Connection::Id selectSyncPeer() const;
    std::vector<Connection::Id> selectRelayPeers(size_t count) const;

    // Inventory tracking
    void addKnownBlock(Connection::Id id, const Hash256& hash);
    void addKnownTx(Connection::Id id, const Hash256& txid);
    bool hasKnownBlock(Connection::Id id, const Hash256& hash) const;
    bool hasKnownTx(Connection::Id id, const Hash256& txid) const;

    // Update peer state
    void updatePeerHeight(Connection::Id id, int32_t height, const Hash256& hash);
    void markSyncing(Connection::Id id, bool syncing);

private:
    // Internal peer structure
    struct Peer {
        std::shared_ptr<Connection> conn;
        PeerState state = PeerState::CONNECTING;
        PeerInfo info;

        // Version handshake
        bool version_sent = false;
        bool version_received = false;
        bool verack_sent = false;
        bool verack_received = false;

        // Ping tracking
        uint64_t ping_nonce = 0;
        std::chrono::steady_clock::time_point ping_start;
        std::chrono::steady_clock::time_point last_ping_sent;

        // Inventory
        std::set<Hash256> known_blocks;
        std::set<Hash256> known_txs;
        std::deque<Hash256> pending_getdata;
    };

    // Thread functions
    void networkThread();
    void maintenanceThread();

    // Connection handling
    void onNewConnection(std::shared_ptr<Connection> conn);
    void onConnectionFailed(const NetAddr& addr);
    void onMessage(Connection::Id id, const Message& msg);
    void onDisconnect(Connection::Id id, const std::string& reason);

    // Message handlers
    void handleVersion(Peer& peer, const VersionMessage& msg);
    void handleVerack(Peer& peer);
    void handlePing(Peer& peer, const PingMessage& msg);
    void handlePong(Peer& peer, const PongMessage& msg);
    void handleGetAddr(Peer& peer);
    void handleAddr(Peer& peer, const AddrMessage& msg);
    void handleReject(Peer& peer, const RejectMessage& msg);

    // Handshake
    void sendVersion(Peer& peer);
    void sendVerack(Peer& peer);
    void completeHandshake(Peer& peer);

    // Address selection
    NetAddr selectAddressToConnect();
    void tryConnect();

    // Maintenance
    void checkTimeouts();
    void sendPings();
    void cleanupBans();
    void requestAddresses();

    // Configuration
    Config config_;

    // State
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};

    // Networking
    Listener listener_;
    SocketSet socket_set_;

    // Peers
    std::map<Connection::Id, Peer> peers_;
    mutable std::recursive_mutex peers_mutex_;

    // Address database
    std::map<NetAddr, AddrInfo> addresses_;
    std::set<NetAddr> tried_addresses_;
    mutable std::mutex addr_mutex_;

    // Ban database
    std::map<NetAddr, BanEntry> bans_;
    mutable std::mutex ban_mutex_;

    // Pending connections
    std::set<NetAddr> connecting_;
    std::mutex connecting_mutex_;

    // Threads
    std::thread network_thread_;
    std::thread maintenance_thread_;

    // Callbacks
    NewPeerCallback on_new_peer_;
    PeerDisconnectCallback on_peer_disconnect_;
    MessageReceivedCallback on_message_;

    // RNG
    mutable std::mt19937_64 rng_;
    mutable std::mutex rng_mutex_;

    // Node info for VERSION message
    int32_t our_version_ = 70015;
    uint64_t our_services_ = 1;  // NODE_NETWORK
    std::string our_user_agent_ = "/FTC:1.0.0/";
    std::atomic<int32_t> our_height_{0};

    // Statistics
    std::atomic<uint64_t> total_connections_{0};
    std::atomic<uint64_t> total_bytes_sent_{0};
    std::atomic<uint64_t> total_bytes_recv_{0};
};

} // namespace p2p
} // namespace ftc

#endif // FTC_P2P_PEER_MANAGER_H
