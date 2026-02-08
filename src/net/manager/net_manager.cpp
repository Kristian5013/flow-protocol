// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/manager/net_manager.h"

#include "chain/chainstate.h"
#include "core/logging.h"
#include "core/random.h"
#include "core/stream.h"
#include "core/time.h"
#include "net/dns_seeds.h"
#include "net/protocol/inventory.h"
#include "net/protocol/version.h"
#include "net/transport/message.h"
#include "primitives/block.h"
#include "primitives/transaction.h"

#include <algorithm>
#include <chrono>
#include <string>
#include <utility>

namespace net {

// ===========================================================================
// Construction / Destruction
// ===========================================================================

NetManager::NetManager(Config config,
                       chain::ChainstateManager& chainstate,
                       mempool::Mempool& mempool)
    : config_(std::move(config))
    , chainstate_(chainstate)
    , mempool_(mempool)
    , event_channel_(1024)  // Bounded channel: 1024 pending events max
{
}

NetManager::~NetManager() {
    stop();
}

// ===========================================================================
// Lifecycle
// ===========================================================================

core::Result<void> NetManager::start() {
    if (running_.load(std::memory_order_relaxed)) {
        return core::Error(core::ErrorCode::INTERNAL_ERROR,
                           "NetManager already running");
    }

    LOG_INFO(core::LogCategory::NET, "Starting network subsystem...");

    // Create the connection manager.
    conn_manager_ = std::make_unique<ConnManager>(
        config_.conn_config, event_channel_);

    // Create the message processor.
    msg_processor_ = std::make_unique<MsgProcessor>(
        chainstate_, *conn_manager_, addrman_);

    // Start the connection manager (binds listener, starts listen thread).
    auto start_result = conn_manager_->start();
    if (!start_result.ok()) {
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "Failed to start connection manager: " +
                           start_result.error().message());
    }

    running_.store(true, std::memory_order_release);

    // Start the event loop thread.
    event_loop_thread_ = std::jthread([this](std::stop_token stoken) {
        event_loop(stoken);
    });

    LOG_INFO(core::LogCategory::NET, "Network subsystem started successfully");

    return core::make_ok();
}

void NetManager::stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return;  // Already stopped.
    }

    LOG_INFO(core::LogCategory::NET, "Stopping network subsystem...");

    // Stop the connection manager first (closes all sockets, stops read
    // threads).  This will cause the read threads to push DISCONNECTED
    // events and then exit.
    if (conn_manager_) {
        conn_manager_->stop();
    }

    // Close the event channel.  This wakes up the event loop thread if
    // it is blocked on receive().
    event_channel_.close();

    // Join the event loop thread.
    if (event_loop_thread_.joinable()) {
        event_loop_thread_.request_stop();
        event_loop_thread_.join();
    }

    // Clean up.
    msg_processor_.reset();
    conn_manager_.reset();

    LOG_INFO(core::LogCategory::NET, "Network subsystem stopped");
}

bool NetManager::is_running() const {
    return running_.load(std::memory_order_relaxed);
}

// ===========================================================================
// Manual peer operations
// ===========================================================================

core::Result<uint64_t> NetManager::connect_to(const std::string& host,
                                               uint16_t port) {
    if (!conn_manager_) {
        return core::Error(core::ErrorCode::NETWORK_ERROR,
                           "Network not started");
    }
    return conn_manager_->connect_to(host, port);
}

void NetManager::disconnect(uint64_t peer_id) {
    if (conn_manager_) {
        conn_manager_->disconnect(peer_id,
                                  DisconnectReason::USER_REQUESTED);
    }
}

// ===========================================================================
// Broadcasting
// ===========================================================================

void NetManager::broadcast_tx(const primitives::Transaction& tx) {
    if (!conn_manager_) return;

    core::uint256 txid = tx.txid();

    // Build an INV message announcing the transaction.
    net::protocol::InvMessage inv;
    net::protocol::InvItem item;
    item.type = net::protocol::InvType::WITNESS_TX;
    item.hash = txid;
    inv.items.push_back(item);

    auto payload = inv.serialize();
    net::Message msg = net::Message::create(commands::INV,
                                            std::move(payload));
    conn_manager_->broadcast(msg);

    LOG_INFO(core::LogCategory::NET,
             "Broadcast tx " + txid.to_hex().substr(0, 16) + "...");
}

void NetManager::broadcast_block(const primitives::Block& block) {
    if (!conn_manager_) {
        LOG_WARN(core::LogCategory::NET, "broadcast_block: no conn_manager");
        return;
    }

    core::uint256 block_hash = block.hash();

    LOG_INFO(core::LogCategory::NET,
             "Broadcasting block " + block_hash.to_hex().substr(0, 16) +
             "... to " + std::to_string(conn_manager_->peer_count()) +
             " peers");

    // Build an INV message announcing the block.
    net::protocol::InvMessage inv;
    net::protocol::InvItem item;
    item.type = net::protocol::InvType::BLOCK;
    item.hash = block_hash;
    inv.items.push_back(item);

    auto payload = inv.serialize();
    net::Message msg = net::Message::create(commands::INV,
                                            std::move(payload));
    conn_manager_->broadcast(msg);
}

// ===========================================================================
// Stats
// ===========================================================================

size_t NetManager::peer_count() const {
    return conn_manager_ ? conn_manager_->peer_count() : 0;
}

size_t NetManager::outbound_count() const {
    return conn_manager_ ? conn_manager_->outbound_count() : 0;
}

// ===========================================================================
// Access to internals
// ===========================================================================

ConnManager& NetManager::conn_manager() {
    return *conn_manager_;
}

const ConnManager& NetManager::conn_manager() const {
    return *conn_manager_;
}

AddrMan& NetManager::addr_manager() {
    return addrman_;
}

const AddrMan& NetManager::addr_manager() const {
    return addrman_;
}

// ===========================================================================
// Event loop -- the heart of the actor model
// ===========================================================================

void NetManager::dispatch_event(PeerEvent& event) {
    switch (event.type) {
    case PeerEventType::CONNECTED:
        LOG_INFO(core::LogCategory::NET,
                 "Event: peer " + std::to_string(event.peer_id) +
                 " connected (" + event.remote_addr +
                 (event.inbound ? ", inbound)" : ", outbound)"));
        msg_processor_->on_peer_connected(
            event.peer_id, event.inbound);
        break;

    case PeerEventType::DISCONNECTED:
        LOG_INFO(core::LogCategory::NET,
                 "Event: peer " + std::to_string(event.peer_id) +
                 " disconnected (reason: " +
                 std::string(disconnect_reason_name(
                     event.disconnect_reason)) + ")");
        msg_processor_->on_peer_disconnected(event.peer_id);
        break;

    case PeerEventType::MESSAGE:
        msg_processor_->process_message(
            event.peer_id, event.msg);
        break;

    case PeerEventType::MISBEHAVIOR:
        msg_processor_->on_misbehavior(
            event.peer_id, event.misbehavior_score);
        break;
    }
}

void NetManager::event_loop(std::stop_token stoken) {
    LOG_INFO(core::LogCategory::NET, "Event loop thread started");

    // Track when we started for delayed DNS seeding.
    int64_t start_time = core::get_time();
    bool dns_seed_done = false;
    int64_t last_tick = core::get_time();
    int64_t last_outbound_attempt = 0;

    // Connect to explicitly configured peers first.
    seed_connections();

    while (!stoken.stop_requested() &&
           running_.load(std::memory_order_relaxed)) {

        // Try to receive an event with a short timeout so we can run
        // periodic tasks even when no events arrive.
        auto event_opt = event_channel_.try_receive_for(
            std::chrono::milliseconds(TICK_INTERVAL_MS));

        int64_t now = core::get_time();

        // Process the event if we got one, then drain any remaining
        // queued events.  This prevents handshake timeouts caused by
        // VERSION/VERACK messages stuck behind a burst of header or
        // block announcements.
        if (event_opt.has_value()) {
            dispatch_event(event_opt.value());

            // Drain up to MAX_BATCH_SIZE additional events without
            // blocking, to keep the queue from backing up.
            static constexpr int MAX_BATCH_SIZE = 128;
            for (int i = 0; i < MAX_BATCH_SIZE; ++i) {
                auto next = event_channel_.try_receive();
                if (!next.has_value()) break;
                dispatch_event(next.value());
            }
        }

        // Periodic tick: run approximately once per second.
        now = core::get_time();
        if ((now - last_tick) >= 1) {
            last_tick = now;

            // Run the message processor's periodic tasks (timeouts, pings).
            msg_processor_->on_tick(now);

            // DNS seed lookup after a short delay to allow explicit peers
            // to connect first.
            if (!dns_seed_done && config_.dns_seed &&
                (now - start_time) >= DNS_SEED_DELAY) {
                dns_seed_done = true;

                // Only do DNS seeding if we have very few peers.
                if (conn_manager_->peer_count() < 2) {
                    dns_seed_lookup();
                }
            }

            // Periodically try to open outbound connections.
            if ((now - last_outbound_attempt) >= OUTBOUND_RETRY_INTERVAL) {
                last_outbound_attempt = now;
                open_outbound_connections();
            }
        }
    }

    LOG_INFO(core::LogCategory::NET, "Event loop thread exiting");
}

// ===========================================================================
// Connection bootstrapping
// ===========================================================================

void NetManager::seed_connections() {
    // -connect= peers: connect ONLY to these peers (exclusive mode).
    if (!config_.connect_nodes.empty()) {
        LOG_INFO(core::LogCategory::NET,
                 "Connecting to " +
                 std::to_string(config_.connect_nodes.size()) +
                 " configured connect-only peers");

        for (const auto& node : config_.connect_nodes) {
            // Parse host:port.  If no port is specified, use the default.
            std::string host = node;
            uint16_t port = ConnManager::DEFAULT_PORT;

            // Handle IPv6 addresses in brackets: [::1]:9333
            size_t bracket_close = node.find(']');
            size_t colon_pos = std::string::npos;

            if (bracket_close != std::string::npos) {
                // IPv6 with brackets.
                host = node.substr(1, bracket_close - 1);
                if (bracket_close + 1 < node.size() &&
                    node[bracket_close + 1] == ':') {
                    port = static_cast<uint16_t>(
                        std::stoul(node.substr(bracket_close + 2)));
                }
            } else {
                colon_pos = node.rfind(':');
                if (colon_pos != std::string::npos) {
                    // Check if this is an IPv6 address without brackets
                    // (multiple colons).
                    size_t first_colon = node.find(':');
                    if (first_colon == colon_pos) {
                        // Only one colon -- this is host:port.
                        host = node.substr(0, colon_pos);
                        port = static_cast<uint16_t>(
                            std::stoul(node.substr(colon_pos + 1)));
                    }
                    // If multiple colons, treat the whole string as an
                    // IPv6 address and use the default port.
                }
            }

            auto result = conn_manager_->connect_to(host, port);
            if (result.ok()) {
                LOG_INFO(core::LogCategory::NET,
                         "Connected to configured peer " + node +
                         " (peer " + std::to_string(result.value()) + ")");
            } else {
                LOG_WARN(core::LogCategory::NET,
                         "Failed to connect to configured peer " +
                         node + ": " + result.error().message());
            }
        }

        // In -connect mode, do not add any other peers.
        return;
    }

    // -addnode= peers: connect to these in addition to normal discovery.
    for (const auto& node : config_.add_nodes) {
        std::string host = node;
        uint16_t port = ConnManager::DEFAULT_PORT;

        size_t bracket_close = node.find(']');
        size_t colon_pos = std::string::npos;

        if (bracket_close != std::string::npos) {
            host = node.substr(1, bracket_close - 1);
            if (bracket_close + 1 < node.size() &&
                node[bracket_close + 1] == ':') {
                port = static_cast<uint16_t>(
                    std::stoul(node.substr(bracket_close + 2)));
            }
        } else {
            colon_pos = node.rfind(':');
            if (colon_pos != std::string::npos) {
                size_t first_colon = node.find(':');
                if (first_colon == colon_pos) {
                    host = node.substr(0, colon_pos);
                    port = static_cast<uint16_t>(
                        std::stoul(node.substr(colon_pos + 1)));
                }
            }
        }

        auto result = conn_manager_->connect_to(host, port);
        if (result.ok()) {
            LOG_INFO(core::LogCategory::NET,
                     "Connected to addnode peer " + node +
                     " (peer " + std::to_string(result.value()) + ")");
        } else {
            LOG_WARN(core::LogCategory::NET,
                     "Failed to connect to addnode peer " +
                     node + ": " + result.error().message());
        }
    }
}

void NetManager::dns_seed_lookup() {
    LOG_INFO(core::LogCategory::NET, "Starting DNS seed lookup...");

    // Resolve all DNS seeds.
    auto addresses = net::resolve_all_dns_seeds();

    if (addresses.empty()) {
        LOG_WARN(core::LogCategory::NET,
                 "DNS seed resolution returned no addresses, "
                 "falling back to hardcoded seeds");

        // Fall back to hardcoded seed nodes.
        const auto& seeds = net::get_seed_nodes();
        for (const auto& seed : seeds) {
            // Parse the host:port from the seed entry.
            std::string host = seed;
            uint16_t port = ConnManager::DEFAULT_PORT;

            size_t bracket_close = seed.find(']');
            if (bracket_close != std::string::npos) {
                host = seed.substr(1, bracket_close - 1);
                if (bracket_close + 1 < seed.size() &&
                    seed[bracket_close + 1] == ':') {
                    port = static_cast<uint16_t>(
                        std::stoul(seed.substr(bracket_close + 2)));
                }
            } else {
                size_t colon_pos = seed.rfind(':');
                if (colon_pos != std::string::npos) {
                    size_t first_colon = seed.find(':');
                    if (first_colon == colon_pos) {
                        host = seed.substr(0, colon_pos);
                        port = static_cast<uint16_t>(
                            std::stoul(seed.substr(colon_pos + 1)));
                    }
                }
            }

            // Add to address manager as a seed.
            auto addr_result = net::NetAddress::from_string(host);
            if (addr_result.ok()) {
                AddressWithPort awp;
                awp.addr = addr_result.value();
                awp.port = port;
                awp.timestamp = core::get_time();
                awp.services = net::NODE_NETWORK | net::NODE_WITNESS;
                addrman_.add(awp, NetAddress());  // unknown source for seed
            }
        }
    } else {
        LOG_INFO(core::LogCategory::NET,
                 "DNS seeds returned " + std::to_string(addresses.size()) +
                 " addresses");

        for (const auto& addr_str : addresses) {
            auto addr_result = net::NetAddress::from_string(addr_str);
            if (addr_result.ok()) {
                AddressWithPort awp;
                awp.addr = addr_result.value();
                awp.port = ConnManager::DEFAULT_PORT;
                awp.timestamp = core::get_time();
                awp.services = net::NODE_NETWORK;
                addrman_.add(awp, NetAddress());
            }
        }
    }

    // After seeding the address manager, try to open outbound connections.
    open_outbound_connections();
}

void NetManager::open_outbound_connections() {
    if (!conn_manager_) return;

    // In -connect mode, reconnect to configured peers if disconnected.
    if (!config_.connect_nodes.empty()) {
        reconnect_configured_peers();
        return;
    }

    int max_outbound = config_.conn_config.max_outbound;
    int current_outbound = static_cast<int>(conn_manager_->outbound_count());

    if (current_outbound >= max_outbound) {
        return;  // Already at capacity.
    }

    int needed = max_outbound - current_outbound;

    LOG_DEBUG(core::LogCategory::NET,
              "Need " + std::to_string(needed) +
              " more outbound connections (have " +
              std::to_string(current_outbound) + "/" +
              std::to_string(max_outbound) + ")");

    // Try to connect to addresses from the address manager.
    int attempts = 0;
    int max_attempts = needed * 4;

    while (current_outbound < max_outbound && attempts < max_attempts) {
        ++attempts;

        // select(false) returns a random address from either table.
        auto candidate_opt = addrman_.select(false);
        if (!candidate_opt.has_value()) {
            LOG_DEBUG(core::LogCategory::NET,
                      "No candidate addresses available for outbound connections");
            break;
        }

        const auto& candidate = candidate_opt.value();
        std::string host = candidate.addr.to_string();
        uint16_t port = candidate.port;

        // Check the ban list.
        if (banman_.is_banned(candidate.addr)) {
            continue;
        }

        // Try to connect.
        auto result = conn_manager_->connect_to(host, port);
        if (result.ok()) {
            ++current_outbound;
            LOG_INFO(core::LogCategory::NET,
                     "Opened outbound connection to " +
                     host + ":" + std::to_string(port) +
                     " (peer " + std::to_string(result.value()) + ")");
        } else {
            LOG_DEBUG(core::LogCategory::NET,
                      "Failed to connect to " + host + ":" +
                      std::to_string(port) + ": " +
                      result.error().message());
            // Mark the address as failed in the address manager.
            addrman_.mark_attempt(candidate, core::get_time());
        }
    }
}

void NetManager::reconnect_configured_peers() {
    // Check each configured connect= peer and reconnect if not connected.
    for (const auto& node : config_.connect_nodes) {
        std::string host = node;
        uint16_t port = ConnManager::DEFAULT_PORT;

        size_t colon_pos = node.rfind(':');
        if (colon_pos != std::string::npos) {
            size_t first_colon = node.find(':');
            if (first_colon == colon_pos) {
                host = node.substr(0, colon_pos);
                port = static_cast<uint16_t>(
                    std::stoul(node.substr(colon_pos + 1)));
            }
        }

        // Check if we're already connected to this peer.
        bool already_connected = false;
        auto peer_ids = conn_manager_->get_peer_ids();
        for (uint64_t pid : peer_ids) {
            auto* peer = conn_manager_->get_peer(pid);
            if (peer && !peer->inbound &&
                peer->conn.remote_address() == host &&
                peer->conn.remote_port() == port &&
                peer->state != PeerState::DISCONNECTING &&
                peer->state != PeerState::DISCONNECTED) {
                already_connected = true;
                break;
            }
        }

        if (!already_connected) {
            auto result = conn_manager_->connect_to(host, port);
            if (result.ok()) {
                LOG_INFO(core::LogCategory::NET,
                         "Reconnected to configured peer " + node +
                         " (peer " + std::to_string(result.value()) + ")");
            }
        }
    }
}

} // namespace net
