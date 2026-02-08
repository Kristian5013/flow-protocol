#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// NetManager -- top-level network manager for the FTC P2P subsystem.
//
// Ties together all networking components:
//   - ConnManager: connection lifecycle and socket I/O
//   - MsgProcessor: protocol message handling and sync logic
//   - AddrMan: peer address management and selection
//   - BanMan: ban list enforcement
//   - DNS seeds: initial peer discovery
//
// Architecture:
//   The NetManager owns a single event loop thread that reads PeerEvents
//   from a Channel and dispatches them to the MsgProcessor.  This is the
//   ACTOR MODEL: all chainstate-mutating work happens on this single thread,
//   eliminating the need for nested mutexes across subsystems.
//
//   Per-peer I/O threads (inside ConnManager) handle the blocking socket
//   reads and push events into the channel.
//
//   +----------+    +-----------+    PeerEvent     +------------+
//   | Listen   | -> | Per-peer  | -> Channel  ->   | Event loop |
//   | thread   |    | read      |                  | thread     |
//   +----------+    | threads   |                  |  (actor)   |
//                   +-----------+                  +------+-----+
//                                                         |
//                                                  MsgProcessor
//                                                  Chainstate
//                                                  Mempool
// ---------------------------------------------------------------------------

#include "core/channel.h"
#include "core/error.h"
#include "net/address/addrman.h"
#include "net/address/banman.h"
#include "net/manager/conn_manager.h"
#include "net/manager/msg_processor.h"
#include "primitives/block.h"
#include "primitives/transaction.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

// Forward declarations
namespace chain {
    class ChainstateManager;
} // namespace chain

namespace mempool {
    class Mempool;
} // namespace mempool

namespace net {

class NetManager {
public:
    struct Config {
        ConnManager::Config conn_config;
        std::vector<std::string> connect_nodes;   // -connect= explicit peers
        std::vector<std::string> add_nodes;        // -addnode= additional peers
        bool dns_seed = true;                      // Enable DNS seed lookup
    };

    /// Construct the network manager.
    ///
    /// @param config      Network configuration.
    /// @param chainstate  Reference to the chainstate manager.
    /// @param mempool     Reference to the transaction mempool.
    NetManager(Config config,
               chain::ChainstateManager& chainstate,
               mempool::Mempool& mempool);

    ~NetManager();

    // Non-copyable, non-movable.
    NetManager(const NetManager&) = delete;
    NetManager& operator=(const NetManager&) = delete;
    NetManager(NetManager&&) = delete;
    NetManager& operator=(NetManager&&) = delete;

    // -- Lifecycle -----------------------------------------------------------

    /// Start the network subsystem: bind the listener, start the event
    /// loop, and begin initial peer discovery.
    core::Result<void> start();

    /// Stop everything gracefully: close all connections, drain the event
    /// channel, and join all threads.
    void stop();

    /// Returns true if the network subsystem is running.
    bool is_running() const;

    // -- Manual peer operations ----------------------------------------------

    /// Manually connect to a peer (used by RPC addnode / connect).
    core::Result<uint64_t> connect_to(const std::string& host, uint16_t port);

    /// Manually disconnect a peer (used by RPC disconnectnode).
    void disconnect(uint64_t peer_id);

    // -- Broadcasting --------------------------------------------------------

    /// Broadcast a transaction to all connected peers.
    void broadcast_tx(const primitives::Transaction& tx);

    /// Broadcast a block to all connected peers.
    void broadcast_block(const primitives::Block& block);

    // -- Stats ---------------------------------------------------------------

    /// Total number of connected peers.
    size_t peer_count() const;

    /// Number of outbound peers.
    size_t outbound_count() const;

    // -- Access to internals (for RPC, testing, etc.) ------------------------

    ConnManager& conn_manager();
    const ConnManager& conn_manager() const;

    AddrMan& addr_manager();
    const AddrMan& addr_manager() const;

private:
    Config config_;

    // References to subsystems (not owned by NetManager).
    chain::ChainstateManager& chainstate_;
    mempool::Mempool& mempool_;

    // The event channel: per-peer read threads push PeerEvents here,
    // the event loop thread consumes them.
    core::Channel<PeerEvent> event_channel_;

    // Owned subsystem instances.
    AddrMan addrman_;
    BanMan banman_;

    std::unique_ptr<ConnManager> conn_manager_;
    std::unique_ptr<MsgProcessor> msg_processor_;

    // Event loop thread.
    std::jthread event_loop_thread_;
    std::atomic<bool> running_{false};

    // -- Event loop ----------------------------------------------------------

    /// The main event loop: reads PeerEvents from the channel and
    /// dispatches them to the MsgProcessor.  Also runs periodic tick
    /// logic (timeouts, pings, etc.).
    void event_loop(std::stop_token stoken);

    /// Dispatch a single PeerEvent to the appropriate handler.
    void dispatch_event(PeerEvent& event);

    // -- Connection bootstrapping --------------------------------------------

    /// Connect to the configured initial peers (-connect, -addnode).
    void seed_connections();

    /// Resolve DNS seeds and add results to the address manager.
    void dns_seed_lookup();

    /// Open outbound connections until we reach the configured maximum.
    void open_outbound_connections();

    /// Reconnect to -connect= peers that are no longer connected.
    void reconnect_configured_peers();

    // -- Tick constants ------------------------------------------------------
    static constexpr int64_t TICK_INTERVAL_MS = 1000;       // 1 second
    static constexpr int64_t DNS_SEED_DELAY = 11;           // seconds after start
    static constexpr int64_t OUTBOUND_RETRY_INTERVAL = 5;   // seconds
};

} // namespace net
