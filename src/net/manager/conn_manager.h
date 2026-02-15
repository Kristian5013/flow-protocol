#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// ConnManager -- connection lifecycle manager for the FTC P2P network.
//
// Owns all peer connections and provides:
//   - A listening thread that accepts inbound connections
//   - Methods to initiate outbound connections
//   - Peer lifecycle management (creation, lookup, disconnection)
//   - Message sending (unicast and broadcast)
//
// All connection events (new peer, message received, disconnect) are
// pushed into an event_channel_ that the NetManager's event loop consumes.
// This ensures that peer state mutations happen on a single thread (the
// actor model), avoiding nested mutex locks.
//
// Thread safety: public methods are safe to call from any thread.  The
// internal peers_ map is protected by peers_mutex_.  The listen thread
// and per-peer read threads run independently.
// ---------------------------------------------------------------------------

#include "core/channel.h"
#include "core/error.h"
#include "net/peer/peer_state.h"
#include "net/transport/connection.h"
#include "net/transport/message.h"
#include "net/transport/socket.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace net {

// ---------------------------------------------------------------------------
// PeerEvent -- events pushed to the NetManager event loop
// ---------------------------------------------------------------------------

enum class PeerEventType : uint8_t {
    CONNECTED,       // A new peer has connected (inbound or outbound)
    DISCONNECTED,    // A peer has disconnected
    MESSAGE,         // A framed message was received from a peer
    MISBEHAVIOR,     // Peer misbehavior detected (score increase)
};

struct PeerEvent {
    PeerEventType type = PeerEventType::CONNECTED;
    uint64_t      peer_id = 0;
    Message       msg;                       // Valid when type == MESSAGE
    DisconnectReason disconnect_reason = DisconnectReason::NONE;
    int32_t       misbehavior_score = 0;     // Increment when type == MISBEHAVIOR
    std::string   remote_addr;               // Remote IP:port string
    bool          inbound = false;           // True for inbound connections
};

// ---------------------------------------------------------------------------
// Peer -- represents one connected peer
// ---------------------------------------------------------------------------
// Wraps a Connection and adds higher-level state (handshake progress,
// announced services, best known height, etc.).
// ---------------------------------------------------------------------------

struct Peer {
    uint64_t    id = 0;
    Connection  conn;
    bool        inbound = false;

    // Handshake state
    PeerState   state = PeerState::CONNECTING;
    int32_t     version = 0;
    uint64_t    services = 0;
    std::string user_agent;
    int32_t     start_height = 0;
    bool        relay = true;
    uint64_t    nonce = 0;

    // Protocol feature negotiation
    bool        prefers_headers = false;   // SENDHEADERS received
    bool        send_compact = false;      // SENDCMPCT received
    int64_t     fee_filter = 0;            // FEEFILTER minimum fee rate (sat/kvB)

    // Stats
    PeerStats   stats;

    // Read loop thread (one per peer)
    std::jthread read_thread;

    Peer(uint64_t id, Connection conn, bool inbound);
    ~Peer();

    Peer(const Peer&) = delete;
    Peer& operator=(const Peer&) = delete;
    Peer(Peer&&) = delete;
    Peer& operator=(Peer&&) = delete;
};

// ---------------------------------------------------------------------------
// ConnManager
// ---------------------------------------------------------------------------

class ConnManager {
public:
    static constexpr int DEFAULT_MAX_OUTBOUND = 8;
    static constexpr int DEFAULT_MAX_INBOUND = 117;
    static constexpr int DEFAULT_MAX_TOTAL = 125;
    static constexpr uint16_t DEFAULT_PORT = 9333;

    struct Config {
        std::string bind_address = "0.0.0.0";
        uint16_t port = DEFAULT_PORT;
        int max_outbound = DEFAULT_MAX_OUTBOUND;
        int max_inbound = DEFAULT_MAX_INBOUND;
        bool listen = true;
    };

    explicit ConnManager(Config config,
                         core::Channel<PeerEvent>& event_channel);
    ~ConnManager();

    // Non-copyable, non-movable.
    ConnManager(const ConnManager&) = delete;
    ConnManager& operator=(const ConnManager&) = delete;
    ConnManager(ConnManager&&) = delete;
    ConnManager& operator=(ConnManager&&) = delete;

    // -- Lifecycle -----------------------------------------------------------

    /// Start the listener and connection manager threads.
    core::Result<void> start();

    /// Stop all threads and close all connections.
    void stop();

    /// Returns true if the connection manager is running.
    bool is_running() const { return running_.load(std::memory_order_relaxed); }

    // -- Connection management -----------------------------------------------

    /// Initiate an outbound connection to host:port.
    /// Returns the assigned peer ID on success.
    core::Result<uint64_t> connect_to(const std::string& host, uint16_t port);

    /// Disconnect a peer with the given reason.
    void disconnect(uint64_t peer_id, DisconnectReason reason);

    /// Remove a peer from the map (called from the event loop after the
    /// DISCONNECTED event is processed).  Joins the peer's read thread.
    void remove_peer(uint64_t peer_id);

    // -- Peer lookup ---------------------------------------------------------

    /// Get a peer by ID.  Returns nullptr if not found.
    Peer* get_peer(uint64_t peer_id);
    const Peer* get_peer(uint64_t peer_id) const;

    /// Return all current peer IDs.
    std::vector<uint64_t> get_peer_ids() const;

    /// Total number of connected peers.
    size_t peer_count() const;

    /// Number of outbound peers.
    size_t outbound_count() const;

    /// Number of inbound peers.
    size_t inbound_count() const;

    /// Return the set of currently connected remote IP addresses.
    std::unordered_set<std::string> get_connected_addresses() const;

    // -- Self-connection prevention ------------------------------------------

    /// Mark an address as our own (detected via nonce during VERSION exchange).
    void mark_self_address(const std::string& addr);

    /// Check if an address is known to be our own.
    bool is_self_address(const std::string& addr) const;

    // -- Message sending -----------------------------------------------------

    /// Send a message to a specific peer.
    void send_to(uint64_t peer_id, net::Message msg);

    /// Broadcast a message to all connected peers.
    void broadcast(const net::Message& msg);

    /// Broadcast a message to all peers matching a predicate.
    void broadcast_if(const net::Message& msg,
                      std::function<bool(const Peer&)> predicate);

private:
    Config config_;
    core::Channel<PeerEvent>& event_channel_;

    // Peer storage: peer_id -> unique_ptr<Peer>
    std::unordered_map<uint64_t, std::unique_ptr<Peer>> peers_;
    mutable std::mutex peers_mutex_;

    // Monotonically increasing peer ID allocator.
    std::atomic<uint64_t> next_peer_id_{1};

    // Addresses detected as our own via nonce self-connection check.
    std::unordered_set<std::string> self_addresses_;
    mutable std::mutex self_addr_mutex_;

    // Listen socket for accepting inbound connections.
    net::Socket listen_socket_;

    // Threads
    std::jthread listen_thread_;
    std::atomic<bool> running_{false};

    // -- Internal methods ----------------------------------------------------

    /// The listen loop: accepts inbound connections until stopped.
    void listen_loop(std::stop_token stoken);

    /// Handle a newly accepted inbound socket.
    void handle_accept(net::Socket socket);

    /// Per-peer read loop: reads messages and pushes events.
    void peer_read_loop(std::stop_token stoken, uint64_t peer_id);

    /// Allocate a unique peer ID (lock-free).
    uint64_t allocate_peer_id();

    /// Push a PeerEvent to the event channel.
    void push_event(PeerEvent event);
};

} // namespace net
