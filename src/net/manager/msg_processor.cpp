// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/manager/msg_processor.h"

#include "chain/chainstate.h"
#include "core/logging.h"
#include "core/random.h"
#include "core/serialize.h"
#include "core/stream.h"
#include "core/time.h"
#include "core/types.h"
#include "net/address/addrman.h"
#include "net/address/netaddress.h"
#include "net/peer/peer_state.h"
#include "net/protocol/inventory.h"
#include "net/protocol/version.h"
#include "net/transport/message.h"
#include "primitives/block.h"
#include "primitives/block_header.h"
#include "primitives/transaction.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace net {

// ===========================================================================
// Construction
// ===========================================================================

MsgProcessor::MsgProcessor(chain::ChainstateManager& chainstate,
                           ConnManager& conn_manager,
                           AddrMan& addrman)
    : chainstate_(chainstate)
    , conn_manager_(conn_manager)
    , addrman_(addrman)
{
    local_nonce_ = core::get_random_uint64();
    last_tip_update_ = core::get_time();
    last_stale_check_ = core::get_time();
}

// ===========================================================================
// Event handlers
// ===========================================================================

void MsgProcessor::on_peer_connected(uint64_t peer_id, bool inbound) {
    LOG_INFO(core::LogCategory::NET,
             "Processing new connection: peer " + std::to_string(peer_id) +
             (inbound ? " (inbound)" : " (outbound)"));

    // For outbound connections, we initiate the handshake by sending VERSION.
    // For inbound connections, we wait for their VERSION first, then respond.
    if (!inbound) {
        send_version(peer_id, inbound);
    }
}

void MsgProcessor::on_peer_disconnected(uint64_t peer_id) {
    LOG_INFO(core::LogCategory::NET,
             "Peer " + std::to_string(peer_id) + " disconnected");

    // If the disconnected peer was our sync peer, try to find a new one.
    if (sync_peer_id_ == peer_id) {
        sync_peer_id_ = 0;
        LOG_INFO(core::LogCategory::NET,
                 "Sync peer disconnected, will try to find a new one");
    }

    // Clean up per-peer tracking state.
    peer_announced_blocks_.erase(peer_id);
    peer_announced_txs_.erase(peer_id);

    // Clean up any in-flight block requests from this peer.
    std::vector<core::uint256> to_remove;
    for (const auto& [hash, requesting_peer] : block_request_peer_) {
        if (requesting_peer == peer_id) {
            to_remove.push_back(hash);
        }
    }
    for (const auto& hash : to_remove) {
        blocks_in_flight_.erase(hash);
        block_request_peer_.erase(hash);
    }

    // Remove the peer from the connection manager.
    // (This is safe -- we are on the event loop thread.)
    conn_manager_.remove_peer(peer_id);
}

void MsgProcessor::on_misbehavior(uint64_t peer_id, int32_t score_increment) {
    Peer* peer = conn_manager_.get_peer(peer_id);
    if (!peer) return;

    peer->stats.misbehavior_score += score_increment;

    LOG_WARN(core::LogCategory::NET,
             "Peer " + std::to_string(peer_id) +
             " misbehavior score: " +
             std::to_string(peer->stats.misbehavior_score) +
             " (+" + std::to_string(score_increment) + ")");

    if (peer->stats.misbehavior_score >= PeerConfig::MISBEHAVIOR_THRESHOLD) {
        LOG_WARN(core::LogCategory::NET,
                 "Peer " + std::to_string(peer_id) +
                 " exceeded misbehavior threshold, disconnecting");
        conn_manager_.disconnect(peer_id, DisconnectReason::MISBEHAVIOR);
    }
}

// ===========================================================================
// Message dispatch
// ===========================================================================

void MsgProcessor::process_message(uint64_t peer_id,
                                   const net::Message& msg) {
    std::string command = msg.header.get_command();

    LOG_TRACE(core::LogCategory::NET,
              "Received " + command + " (" +
              std::to_string(msg.payload.size()) +
              " bytes) from peer " + std::to_string(peer_id));

    // Check that the peer exists.
    Peer* peer = conn_manager_.get_peer(peer_id);
    if (!peer) {
        LOG_WARN(core::LogCategory::NET,
                 "Received message from unknown peer " +
                 std::to_string(peer_id));
        return;
    }

    // Before the handshake is complete, only VERSION and VERACK are allowed.
    if (peer->state != PeerState::ACTIVE &&
        peer->state != PeerState::HANDSHAKE_DONE) {
        if (command != commands::VERSION && command != commands::VERACK) {
            LOG_WARN(core::LogCategory::NET,
                     "Received " + command + " from peer " +
                     std::to_string(peer_id) +
                     " before handshake complete");
            misbehaving(peer_id, 1,
                        "message before handshake: " + command);
            return;
        }
    }

    std::span<const uint8_t> payload(msg.payload);

    // Dispatch to the appropriate handler.
    if (command == commands::VERSION) {
        handle_version(peer_id, payload);
    } else if (command == commands::VERACK) {
        handle_verack(peer_id);
    } else if (command == commands::PING) {
        handle_ping(peer_id, payload);
    } else if (command == commands::PONG) {
        handle_pong(peer_id, payload);
    } else if (command == commands::ADDR) {
        handle_addr(peer_id, payload);
    } else if (command == commands::INV) {
        handle_inv(peer_id, payload);
    } else if (command == commands::GETDATA) {
        handle_getdata(peer_id, payload);
    } else if (command == commands::HEADERS) {
        handle_headers(peer_id, payload);
    } else if (command == commands::BLOCK) {
        handle_block(peer_id, payload);
    } else if (command == commands::TX) {
        handle_tx(peer_id, payload);
    } else if (command == commands::GETBLOCKS) {
        handle_getblocks(peer_id, payload);
    } else if (command == commands::GETHEADERS) {
        handle_getheaders(peer_id, payload);
    } else if (command == commands::GETADDR) {
        handle_getaddr(peer_id);
    } else if (command == commands::SENDHEADERS) {
        handle_sendheaders(peer_id);
    } else if (command == commands::SENDCMPCT) {
        handle_sendcmpct(peer_id, payload);
    } else if (command == commands::FEEFILTER) {
        handle_feefilter(peer_id, payload);
    } else if (command == commands::NOTFOUND) {
        handle_notfound(peer_id, payload);
    } else {
        // Unknown command -- log and ignore (do not penalize, as the peer
        // may be running a newer protocol version with extra messages).
        LOG_DEBUG(core::LogCategory::NET,
                  "Unknown message command '" + command +
                  "' from peer " + std::to_string(peer_id));
    }
}

// ===========================================================================
// Periodic tick
// ===========================================================================

void MsgProcessor::on_tick(int64_t now) {
    // ------------------------------------------------------------------
    // 1. Check for handshake timeouts.
    // ------------------------------------------------------------------
    auto peer_ids = conn_manager_.get_peer_ids();

    for (uint64_t peer_id : peer_ids) {
        Peer* peer = conn_manager_.get_peer(peer_id);
        if (!peer) continue;

        // Force-remove peers stuck in DISCONNECTING state for too long.
        // Normally the read loop detects socket closure and pushes a
        // DISCONNECTED event, but if that stalls, the peer lingers forever.
        if (peer->state == PeerState::DISCONNECTING ||
            peer->state == PeerState::DISCONNECTED) {
            int64_t elapsed = now - peer->stats.connected_time;
            if (elapsed > PeerConfig::HANDSHAKE_TIMEOUT) {
                LOG_WARN(core::LogCategory::NET,
                         "Force-removing stale peer " +
                         std::to_string(peer_id) +
                         " in state " +
                         std::string(peer_state_name(peer->state)));
                conn_manager_.remove_peer(peer_id);
            }
            continue;
        }

        // Handshake timeout: if we've been CONNECTED or VERSION_SENT for
        // too long without completing the handshake, disconnect.
        if (peer->state == PeerState::CONNECTED ||
            peer->state == PeerState::VERSION_SENT) {
            int64_t elapsed = now - peer->stats.connected_time;
            if (elapsed > PeerConfig::HANDSHAKE_TIMEOUT) {
                LOG_WARN(core::LogCategory::NET,
                         "Peer " + std::to_string(peer_id) +
                         " handshake timeout after " +
                         std::to_string(elapsed) + "s");
                conn_manager_.disconnect(peer_id, DisconnectReason::TIMEOUT);
                continue;
            }
        }

        // Only process operational peers below.
        if (!peer_state_is_operational(peer->state)) {
            continue;
        }

        // Inactivity timeout.
        int64_t last_activity = std::max(peer->stats.last_send,
                                         peer->stats.last_recv);
        if (last_activity > 0 &&
            (now - last_activity) > PeerConfig::TIMEOUT) {
            LOG_WARN(core::LogCategory::NET,
                     "Peer " + std::to_string(peer_id) +
                     " inactivity timeout");
            conn_manager_.disconnect(peer_id, DisconnectReason::TIMEOUT);
            continue;
        }

        // Periodic PING.
        if (peer->stats.pending_ping_nonce == 0) {
            // No pending ping -- check if it is time to send one.
            int64_t since_last_ping = now - peer->stats.ping_sent_time;
            if (since_last_ping >= PeerConfig::PING_INTERVAL) {
                send_ping(peer_id);
            }
        } else {
            // We have an outstanding ping -- check for ping timeout.
            int64_t ping_wait = now - peer->stats.ping_sent_time;
            if (ping_wait > PeerConfig::TIMEOUT) {
                LOG_WARN(core::LogCategory::NET,
                         "Peer " + std::to_string(peer_id) +
                         " ping timeout after " +
                         std::to_string(ping_wait) + "s");
                conn_manager_.disconnect(peer_id, DisconnectReason::TIMEOUT);
                continue;
            }
        }
    }

    // ------------------------------------------------------------------
    // 2. Stale tip detection.
    // ------------------------------------------------------------------
    if ((now - last_stale_check_) >= STALE_TIP_CHECK_INTERVAL) {
        last_stale_check_ = now;

        const auto& active_chain = chainstate_.active_chain();
        auto* tip = active_chain.tip();

        if (tip != nullptr) {
            int64_t tip_time = static_cast<int64_t>(tip->time);
            if ((now - tip_time) > STALE_TIP_THRESHOLD &&
                conn_manager_.outbound_count() > 0) {
                // Our tip is stale -- try to sync with a different peer.
                LOG_INFO(core::LogCategory::NET,
                         "Stale tip detected (tip time " +
                         core::format_iso8601(tip_time) +
                         "), attempting resync");
                maybe_start_sync();
            }
        }
    }

    // ------------------------------------------------------------------
    // 3. Block download timeout.
    // ------------------------------------------------------------------
    if (!blocks_in_flight_.empty()) {
        // Check if any block request has been outstanding too long.
        // In a production implementation we would track per-request timestamps.
        // Here we use a simplified approach: if we haven't received any block
        // in BLOCK_DOWNLOAD_TIMEOUT seconds, reset and retry.
        if (last_block_request_ > 0 &&
            (now - last_block_request_) > BLOCK_DOWNLOAD_TIMEOUT *
                static_cast<int64_t>(blocks_in_flight_.size())) {
            LOG_WARN(core::LogCategory::NET,
                     "Block download timeout: " +
                     std::to_string(blocks_in_flight_.size()) +
                     " blocks in flight");

            // Cancel all in-flight requests.
            blocks_in_flight_.clear();
            block_request_peer_.clear();

            // Try syncing from a different peer.
            if (sync_peer_id_ != 0) {
                misbehaving(sync_peer_id_, 10,
                            "block download timeout");
                sync_peer_id_ = 0;
            }
            maybe_start_sync();
        }
    }
}

// ===========================================================================
// VERSION handler
// ===========================================================================

void MsgProcessor::handle_version(uint64_t peer_id,
                                  std::span<const uint8_t> payload) {
    Peer* peer = conn_manager_.get_peer(peer_id);
    if (!peer) return;

    // Parse the version message.
    auto result = net::protocol::VersionMessage::deserialize(payload);
    if (!result.ok()) {
        LOG_WARN(core::LogCategory::NET,
                 "Failed to parse VERSION from peer " +
                 std::to_string(peer_id) + ": " +
                 result.error().message());
        conn_manager_.disconnect(peer_id, DisconnectReason::PROTOCOL_ERROR);
        return;
    }

    const auto& ver = result.value();

    LOG_INFO(core::LogCategory::NET,
             "Received VERSION from peer " + std::to_string(peer_id) +
             ": version=" + std::to_string(ver.version) +
             " services=" + std::to_string(ver.services) +
             " height=" + std::to_string(ver.start_height) +
             " agent=\"" + ver.user_agent + "\"");

    // Check minimum protocol version.
    if (ver.version < 70013) {
        LOG_WARN(core::LogCategory::NET,
                 "Peer " + std::to_string(peer_id) +
                 " has obsolete protocol version " +
                 std::to_string(ver.version));
        conn_manager_.disconnect(peer_id, DisconnectReason::PROTOCOL_ERROR);
        return;
    }

    // Check for self-connection: if the peer's nonce matches our own,
    // we are talking to ourselves.
    if (ver.nonce == local_nonce_ && local_nonce_ != 0) {
        std::string remote = peer->conn.remote_address();
        LOG_WARN(core::LogCategory::NET,
                 "Self-connection detected (nonce match) from peer " +
                 std::to_string(peer_id) + " (" + remote +
                 "), disconnecting");
        conn_manager_.mark_self_address(remote);
        conn_manager_.disconnect(peer_id, DisconnectReason::PROTOCOL_ERROR);
        return;
    }

    // Store the peer's version information.
    peer->version = ver.version;
    peer->services = ver.services;
    peer->user_agent = ver.user_agent;
    peer->start_height = ver.start_height;
    peer->relay = ver.relay;
    peer->nonce = ver.nonce;

    // Advance the handshake state.
    if (peer->inbound) {
        // Inbound: we received their VERSION. Now send ours and a VERACK.
        send_version(peer_id, true);
        send_verack(peer_id);
        peer->state = PeerState::HANDSHAKE_DONE;
    } else {
        // Outbound: we already sent our VERSION. Send VERACK.
        send_verack(peer_id);
        peer->state = PeerState::HANDSHAKE_DONE;
    }

    // Add a time offset sample from the peer's reported timestamp.
    int64_t peer_time = ver.timestamp;
    int64_t our_time = core::get_time();
    int64_t offset = peer_time - our_time;
    core::add_time_offset(offset);
}

// ===========================================================================
// VERACK handler
// ===========================================================================

void MsgProcessor::handle_verack(uint64_t peer_id) {
    Peer* peer = conn_manager_.get_peer(peer_id);
    if (!peer) return;

    LOG_INFO(core::LogCategory::NET,
             "Received VERACK from peer " + std::to_string(peer_id));

    // Transition to ACTIVE state.
    if (peer->state == PeerState::HANDSHAKE_DONE ||
        peer->state == PeerState::VERSION_SENT) {
        peer->state = PeerState::ACTIVE;

        LOG_INFO(core::LogCategory::NET,
                 "Peer " + std::to_string(peer_id) +
                 " handshake complete, now ACTIVE" +
                 " (version=" + std::to_string(peer->version) +
                 " height=" + std::to_string(peer->start_height) +
                 " agent=\"" + peer->user_agent + "\")");

        // Send feature negotiation messages.
        send_sendheaders(peer_id);

        // Request addresses from outbound peers.
        if (!peer->inbound) {
            send_getaddr(peer_id);
        }

        // Send a PING to establish baseline latency.
        send_ping(peer_id);

        // Consider this peer for header sync.
        maybe_start_sync();
    }
}

// ===========================================================================
// PING / PONG handlers
// ===========================================================================

void MsgProcessor::handle_ping(uint64_t peer_id,
                                std::span<const uint8_t> payload) {
    // PING carries an 8-byte nonce.
    if (payload.size() < 8) {
        misbehaving(peer_id, 1, "short PING payload");
        return;
    }

    core::SpanReader reader(payload);
    uint64_t nonce = core::ser_read_u64(reader);

    LOG_TRACE(core::LogCategory::NET,
              "Received PING from peer " + std::to_string(peer_id) +
              " nonce=" + std::to_string(nonce));

    // Respond with PONG carrying the same nonce.
    send_pong(peer_id, nonce);
}

void MsgProcessor::handle_pong(uint64_t peer_id,
                                std::span<const uint8_t> payload) {
    if (payload.size() < 8) {
        misbehaving(peer_id, 1, "short PONG payload");
        return;
    }

    core::SpanReader reader(payload);
    uint64_t nonce = core::ser_read_u64(reader);

    Peer* peer = conn_manager_.get_peer(peer_id);
    if (!peer) return;

    // Verify that the nonce matches our outstanding ping.
    if (nonce != peer->stats.pending_ping_nonce) {
        LOG_DEBUG(core::LogCategory::NET,
                  "PONG nonce mismatch from peer " +
                  std::to_string(peer_id));
        return;
    }

    // Compute round-trip time.
    int64_t now_ms = core::get_time_millis();
    int64_t rtt = now_ms - peer->stats.ping_sent_time;
    peer->stats.ping_time = rtt;
    peer->stats.pending_ping_nonce = 0;

    LOG_DEBUG(core::LogCategory::NET,
              "Peer " + std::to_string(peer_id) +
              " PONG rtt=" + std::to_string(rtt) + "ms");
}

// ===========================================================================
// ADDR handler
// ===========================================================================

void MsgProcessor::handle_addr(uint64_t peer_id,
                                std::span<const uint8_t> payload) {
    if (payload.empty()) return;

    core::SpanReader reader(payload);
    uint64_t count = 0;

    try {
        count = core::ser_read_compact_size(reader);
    } catch (const std::exception& e) {
        misbehaving(peer_id, 10, "malformed ADDR count");
        return;
    }

    // Limit address count per message.
    static constexpr uint64_t MAX_ADDR = 1000;
    if (count > MAX_ADDR) {
        misbehaving(peer_id, 20, "ADDR count exceeds limit: " +
                    std::to_string(count));
        return;
    }

    int64_t now = core::get_time();
    int addresses_added = 0;

    for (uint64_t i = 0; i < count; ++i) {
        try {
            auto addr = AddressWithPort::deserialize(reader);

            // Sanity check: discard addresses with timestamps too far in the
            // future or too old (>10 minutes ahead, or >3 hours old).
            if (addr.timestamp > now + 10 * 60) {
                addr.timestamp = now - 5 * 24 * 3600;
            }
            if (addr.timestamp < now - 3 * 3600) {
                // Still add but with a recent timestamp.
                addr.timestamp = now - 5 * 24 * 3600;
            }

            // Only add routable addresses.
            if (addr.addr.is_routable()) {
                // Source is the peer's address (approximated as the addr itself
                // since we don't have the peer's NetAddress handy here).
                addrman_.add(addr, addr.addr);
                ++addresses_added;
            }
        } catch (const std::exception& e) {
            misbehaving(peer_id, 1, "malformed address in ADDR");
            return;
        }
    }

    LOG_DEBUG(core::LogCategory::NET,
              "Received " + std::to_string(count) + " addresses from peer " +
              std::to_string(peer_id) + ", added " +
              std::to_string(addresses_added));
}

// ===========================================================================
// INV handler
// ===========================================================================

void MsgProcessor::handle_inv(uint64_t peer_id,
                               std::span<const uint8_t> payload) {
    auto result = net::protocol::InvMessage::deserialize(payload);
    if (!result.ok()) {
        misbehaving(peer_id, 10, "malformed INV");
        return;
    }

    const auto& inv = result.value();

    if (inv.items.size() > net::protocol::MAX_INV_ITEMS) {
        misbehaving(peer_id, 20, "INV too large: " +
                    std::to_string(inv.items.size()) + " items");
        return;
    }

    LOG_DEBUG(core::LogCategory::NET,
              "Received INV with " + std::to_string(inv.items.size()) +
              " items from peer " + std::to_string(peer_id));

    // Build a GETDATA request for items we don't have.
    std::vector<net::protocol::InvItem> to_request;

    for (const auto& item : inv.items) {
        switch (item.type) {
        case net::protocol::InvType::BLOCK:
        case net::protocol::InvType::WITNESS_BLOCK: {
            // Track that this peer has announced this block.
            peer_announced_blocks_[peer_id].insert(item.hash);

            // Check if we already have or are requesting this block.
            if (known_blocks_.count(item.hash) == 0 &&
                blocks_in_flight_.count(item.hash) == 0) {
                // Check if we have this block in our index.
                auto* block_index = chainstate_.lookup_block_index(item.hash);
                if (block_index == nullptr || !block_index->has_data()) {
                    to_request.push_back(item);
                } else {
                    known_blocks_.insert(item.hash);
                }
            }
            break;
        }
        case net::protocol::InvType::TX:
        case net::protocol::InvType::WITNESS_TX: {
            peer_announced_txs_[peer_id].insert(item.hash);

            if (known_txs_.count(item.hash) == 0) {
                to_request.push_back(item);
            }
            break;
        }
        default:
            break;
        }
    }

    if (!to_request.empty()) {
        net::protocol::InvMessage getdata;
        getdata.items = std::move(to_request);
        auto getdata_payload = getdata.serialize();

        net::Message getdata_msg = net::Message::create(
            commands::GETDATA, std::move(getdata_payload));
        send(peer_id, std::move(getdata_msg));

        // Track in-flight block requests.
        for (const auto& item : getdata.items) {
            if (item.type == net::protocol::InvType::BLOCK ||
                item.type == net::protocol::InvType::WITNESS_BLOCK) {
                blocks_in_flight_.insert(item.hash);
                block_request_peer_[item.hash] = peer_id;
            }
        }
        last_block_request_ = core::get_time();
    }
}

// ===========================================================================
// GETDATA handler
// ===========================================================================

void MsgProcessor::handle_getdata(uint64_t peer_id,
                                   std::span<const uint8_t> payload) {
    auto result = net::protocol::InvMessage::deserialize(payload);
    if (!result.ok()) {
        misbehaving(peer_id, 10, "malformed GETDATA");
        return;
    }

    const auto& request = result.value();

    if (request.items.size() > net::protocol::MAX_INV_ITEMS) {
        misbehaving(peer_id, 20, "GETDATA too large");
        return;
    }

    LOG_DEBUG(core::LogCategory::NET,
              "Received GETDATA with " + std::to_string(request.items.size()) +
              " items from peer " + std::to_string(peer_id));

    // Collect items we cannot provide for a NOTFOUND response.
    std::vector<net::protocol::InvItem> not_found;

    for (const auto& item : request.items) {
        switch (item.type) {
        case net::protocol::InvType::BLOCK:
        case net::protocol::InvType::WITNESS_BLOCK: {
            auto* block_index = chainstate_.lookup_block_index(item.hash);
            if (block_index != nullptr && block_index->has_data()) {
                auto block_result = chainstate_.read_block(block_index);
                if (block_result.ok()) {
                    auto block_bytes = block_result.value().serialize();
                    send(peer_id,
                         net::Message::create(commands::BLOCK,
                                              std::move(block_bytes)));
                    LOG_DEBUG(core::LogCategory::NET,
                              "Served block " + item.hash.to_hex().substr(0, 16) +
                              "... to peer " + std::to_string(peer_id));
                } else {
                    not_found.push_back(item);
                }
            } else {
                not_found.push_back(item);
            }
            break;
        }
        case net::protocol::InvType::TX:
        case net::protocol::InvType::WITNESS_TX: {
            // TODO: look up tx in mempool and serve it when mempool is
            // wired into the message processor.  For now, report NOTFOUND.
            not_found.push_back(item);
            break;
        }
        default:
            not_found.push_back(item);
            break;
        }
    }

    // Send NOTFOUND for any items we could not provide.
    if (!not_found.empty()) {
        net::protocol::InvMessage nf_msg;
        nf_msg.items = std::move(not_found);
        auto nf_payload = nf_msg.serialize();
        send(peer_id,
             net::Message::create(commands::NOTFOUND, std::move(nf_payload)));
    }
}

// ===========================================================================
// HEADERS handler
// ===========================================================================

void MsgProcessor::handle_headers(uint64_t peer_id,
                                   std::span<const uint8_t> payload) {
    if (payload.empty()) return;

    core::SpanReader reader(payload);
    uint64_t count = 0;

    try {
        count = core::ser_read_compact_size(reader);
    } catch (const std::exception& e) {
        misbehaving(peer_id, 10, "malformed HEADERS count");
        return;
    }

    static constexpr uint64_t MAX_HEADERS = 2000;
    if (count > MAX_HEADERS) {
        misbehaving(peer_id, 20, "HEADERS count exceeds limit: " +
                    std::to_string(count));
        return;
    }

    LOG_DEBUG(core::LogCategory::NET,
              "Received HEADERS with " + std::to_string(count) +
              " headers from peer " + std::to_string(peer_id));

    int accepted = 0;

    for (uint64_t i = 0; i < count; ++i) {
        try {
            // Each header is 80 bytes + a CompactSize tx count (which should
            // be 0 in a HEADERS message).
            auto header = primitives::BlockHeader::deserialize(reader);

            // Read and discard the tx count (always 0 in HEADERS).
            uint64_t tx_count = core::ser_read_compact_size(reader);
            (void)tx_count;

            // Accept the header into the block index.
            auto accept_result = chainstate_.accept_block_header(header);
            if (accept_result.ok()) {
                ++accepted;
                known_blocks_.insert(header.hash());
            } else {
                LOG_DEBUG(core::LogCategory::NET,
                          "Header rejected from peer " +
                          std::to_string(peer_id) + ": " +
                          accept_result.error().message());
                // Do NOT penalize for rejected headers.  During reorgs
                // and competing chain tips, a peer may legitimately
                // send headers whose parent we do not know yet.  This
                // is normal P2P behaviour, not misbehaviour.
            }
        } catch (const std::exception& e) {
            misbehaving(peer_id, 10, "malformed header in HEADERS");
            return;
        }
    }

    LOG_INFO(core::LogCategory::NET,
             "Accepted " + std::to_string(accepted) + "/" +
             std::to_string(count) + " headers from peer " +
             std::to_string(peer_id));

    last_tip_update_ = core::get_time();

    // If we received a full batch of headers, request more.
    if (count == MAX_HEADERS && peer_id == sync_peer_id_) {
        send_getheaders(peer_id);
    }

    // If we received fewer than a full batch, headers sync is up to date.
    // Try to activate the best chain and request block data.
    if (count < MAX_HEADERS) {
        auto activate_result = chainstate_.activate_best_chain();
        if (activate_result.ok() && activate_result.value()) {
            LOG_INFO(core::LogCategory::NET, "Chain tip updated");
        }

        // Request block data for any headers we accepted but don't have
        // full block data for.
        if (accepted > 0) {
            request_blocks(peer_id);
        }
    }
}

// ===========================================================================
// BLOCK handler
// ===========================================================================

void MsgProcessor::handle_block(uint64_t peer_id,
                                 std::span<const uint8_t> payload) {
    core::DataStream stream(std::vector<uint8_t>(payload.begin(),
                                                  payload.end()));
    auto result = primitives::Block::deserialize(stream);
    if (!result.ok()) {
        misbehaving(peer_id, 10, "malformed BLOCK: " +
                    result.error().message());
        return;
    }

    primitives::Block block = std::move(result).value();
    core::uint256 block_hash = block.hash();

    LOG_INFO(core::LogCategory::NET,
             "Received block " + block_hash.to_hex().substr(0, 16) +
             "... (" + std::to_string(block.tx_count()) +
             " txs) from peer " + std::to_string(peer_id));

    // Remove from in-flight tracking.
    blocks_in_flight_.erase(block_hash);
    block_request_peer_.erase(block_hash);
    known_blocks_.insert(block_hash);

    // Accept the block into chainstate.
    auto accept_result = chainstate_.accept_block(block);
    if (!accept_result.ok()) {
        const auto& msg = accept_result.error().message();

        // "previous block not found" is not misbehavior -- the block
        // arrived before we finished syncing (orphan block).  Just
        // ignore it; we will request it again later once we catch up.
        if (msg.find("previous block not found") != std::string::npos) {
            LOG_DEBUG(core::LogCategory::NET,
                      "Orphan block " + block_hash.to_hex().substr(0, 16) +
                      "... from peer " + std::to_string(peer_id) +
                      " (parent not yet synced)");
            return;
        }

        LOG_WARN(core::LogCategory::NET,
                 "Block " + block_hash.to_hex().substr(0, 16) +
                 "... rejected: " + msg);

        if (accept_result.error().code() ==
            core::ErrorCode::VALIDATION_ERROR) {
            misbehaving(peer_id, 100, "invalid block");
        }
        return;
    }

    // Try to activate the best chain with the new block.
    auto activate_result = chainstate_.activate_best_chain();
    if (activate_result.ok() && activate_result.value()) {
        auto* tip = chainstate_.active_chain().tip();
        if (tip) {
            LOG_INFO(core::LogCategory::NET,
                     "New chain tip: height=" +
                     std::to_string(tip->height) +
                     " hash=" + tip->block_hash.to_hex().substr(0, 16) + "...");

            // Periodically flush to disk (every 100 blocks during sync,
            // or every block if chain is nearly synced).
            if (tip->height % 100 == 0 ||
                blocks_in_flight_.empty()) {
                chainstate_.flush();
            }
        }
        last_tip_update_ = core::get_time();

        // Relay the new block to other peers.
        relay_block(block_hash);
    }

    // Request more blocks if we have pending headers.
    if (!blocks_in_flight_.empty() || sync_peer_id_ == peer_id) {
        request_blocks(peer_id);
    }
}

// ===========================================================================
// TX handler
// ===========================================================================

void MsgProcessor::handle_tx(uint64_t peer_id,
                              std::span<const uint8_t> payload) {
    core::DataStream stream(std::vector<uint8_t>(payload.begin(),
                                                  payload.end()));
    auto result = primitives::Transaction::deserialize(stream);
    if (!result.ok()) {
        misbehaving(peer_id, 1, "malformed TX: " +
                    result.error().message());
        return;
    }

    primitives::Transaction tx = std::move(result).value();
    core::uint256 txid = tx.txid();

    LOG_DEBUG(core::LogCategory::NET,
              "Received tx " + txid.to_hex().substr(0, 16) +
              "... from peer " + std::to_string(peer_id));

    // Check if we already know about this transaction.
    if (known_txs_.count(txid) > 0) {
        return;
    }
    known_txs_.insert(txid);

    // In a production implementation, we would validate the transaction
    // against the UTXO set and mempool policy, then add it to the mempool.
    // For the initial implementation we accept the tx optimistically and
    // relay it.

    // Relay to other peers.
    relay_tx(txid);
}

// ===========================================================================
// GETBLOCKS handler
// ===========================================================================

void MsgProcessor::handle_getblocks(uint64_t peer_id,
                                     std::span<const uint8_t> payload) {
    if (payload.size() < 4) {
        misbehaving(peer_id, 1, "short GETBLOCKS");
        return;
    }

    core::SpanReader reader(payload);

    try {
        // Read protocol version field (unused, but part of the wire format).
        int32_t version = core::ser_read_i32(reader);
        (void)version;

        // Read block locator hashes.
        uint64_t hash_count = core::ser_read_compact_size(reader);
        if (hash_count > 101) {
            misbehaving(peer_id, 10, "GETBLOCKS locator too large");
            return;
        }

        std::vector<core::uint256> locator;
        locator.reserve(static_cast<size_t>(hash_count));
        for (uint64_t i = 0; i < hash_count; ++i) {
            locator.push_back(core::ser_read_uint256(reader));
        }

        // Read the stop hash.
        core::uint256 stop_hash = core::ser_read_uint256(reader);

        // Find the fork point using the locator.
        const auto& active_chain = chainstate_.active_chain();
        chain::BlockIndex* fork_point = nullptr;

        for (const auto& hash : locator) {
            auto* index = chainstate_.lookup_block_index(hash);
            if (index != nullptr && active_chain.contains(index)) {
                fork_point = index;
                break;
            }
        }

        // If no locator hash matched, start from genesis.
        if (!fork_point) {
            fork_point = active_chain.genesis();
        }
        if (!fork_point) return;

        // Send up to 500 inventory items starting after the fork point.
        static constexpr int MAX_INV_SEND = 500;
        std::vector<net::protocol::InvItem> items;
        int height = fork_point->height + 1;
        int chain_height = active_chain.height();

        while (height <= chain_height &&
               static_cast<int>(items.size()) < MAX_INV_SEND) {
            auto* block = active_chain.at(height);
            if (!block) break;

            net::protocol::InvItem item;
            item.type = net::protocol::InvType::BLOCK;
            item.hash = block->block_hash;
            items.push_back(item);

            if (block->block_hash == stop_hash) break;
            ++height;
        }

        if (!items.empty()) {
            net::protocol::InvMessage inv;
            inv.items = std::move(items);
            auto inv_payload = inv.serialize();
            send(peer_id,
                 net::Message::create(commands::INV,
                                      std::move(inv_payload)));
        }
    } catch (const std::exception& e) {
        misbehaving(peer_id, 10, "malformed GETBLOCKS payload");
    }
}

// ===========================================================================
// GETHEADERS handler
// ===========================================================================

void MsgProcessor::handle_getheaders(uint64_t peer_id,
                                      std::span<const uint8_t> payload) {
    if (payload.size() < 4) {
        misbehaving(peer_id, 1, "short GETHEADERS");
        return;
    }

    core::SpanReader reader(payload);

    try {
        // Protocol version (unused).
        int32_t version = core::ser_read_i32(reader);
        (void)version;

        // Read block locator hashes.
        uint64_t hash_count = core::ser_read_compact_size(reader);
        if (hash_count > 101) {
            misbehaving(peer_id, 10, "GETHEADERS locator too large");
            return;
        }

        std::vector<core::uint256> locator;
        locator.reserve(static_cast<size_t>(hash_count));
        for (uint64_t i = 0; i < hash_count; ++i) {
            locator.push_back(core::ser_read_uint256(reader));
        }

        // Stop hash.
        core::uint256 stop_hash = core::ser_read_uint256(reader);

        // Find the fork point.
        const auto& active_chain = chainstate_.active_chain();
        chain::BlockIndex* fork_point = nullptr;

        for (const auto& hash : locator) {
            auto* index = chainstate_.lookup_block_index(hash);
            if (index != nullptr && active_chain.contains(index)) {
                fork_point = index;
                break;
            }
        }

        if (!fork_point) {
            fork_point = active_chain.genesis();
        }
        if (!fork_point) return;

        // Collect headers starting after the fork point.
        static constexpr int MAX_HEADERS_SEND = 2000;
        std::vector<primitives::BlockHeader> headers;
        int height = fork_point->height + 1;
        int chain_height = active_chain.height();

        while (height <= chain_height &&
               static_cast<int>(headers.size()) < MAX_HEADERS_SEND) {
            auto* block = active_chain.at(height);
            if (!block) break;

            headers.push_back(block->get_block_header());

            if (block->block_hash == stop_hash) break;
            ++height;
        }

        // Serialize the HEADERS response.
        // Format: compact_size(count) + for each: header(80) + compact_size(0)
        core::DataStream stream;
        core::ser_write_compact_size(stream, headers.size());
        for (const auto& header : headers) {
            header.serialize(stream);
            core::ser_write_compact_size(stream, 0); // tx count = 0
        }

        auto header_payload = stream.release();
        send(peer_id,
             net::Message::create(commands::HEADERS,
                                  std::move(header_payload)));

        LOG_DEBUG(core::LogCategory::NET,
                  "Sent " + std::to_string(headers.size()) +
                  " headers to peer " + std::to_string(peer_id));
    } catch (const std::exception& e) {
        misbehaving(peer_id, 10, "malformed GETHEADERS payload");
    }
}

// ===========================================================================
// GETADDR handler
// ===========================================================================

void MsgProcessor::handle_getaddr(uint64_t peer_id) {
    LOG_DEBUG(core::LogCategory::NET,
              "Received GETADDR from peer " + std::to_string(peer_id));

    // Get a selection of addresses from the address manager.
    auto addresses = addrman_.get_addr_all(1000);

    if (addresses.empty()) {
        return;
    }

    // Serialize the ADDR message.
    core::DataStream stream;
    core::ser_write_compact_size(stream, addresses.size());
    for (const auto& addr : addresses) {
        addr.serialize(stream);
    }

    auto addr_payload = stream.release();
    send(peer_id,
         net::Message::create(commands::ADDR, std::move(addr_payload)));

    LOG_DEBUG(core::LogCategory::NET,
              "Sent " + std::to_string(addresses.size()) +
              " addresses to peer " + std::to_string(peer_id));
}

// ===========================================================================
// SENDHEADERS handler
// ===========================================================================

void MsgProcessor::handle_sendheaders(uint64_t peer_id) {
    Peer* peer = conn_manager_.get_peer(peer_id);
    if (!peer) return;

    LOG_DEBUG(core::LogCategory::NET,
              "Peer " + std::to_string(peer_id) +
              " requested SENDHEADERS mode");

    peer->prefers_headers = true;
}

// ===========================================================================
// SENDCMPCT handler
// ===========================================================================

void MsgProcessor::handle_sendcmpct(uint64_t peer_id,
                                     std::span<const uint8_t> payload) {
    if (payload.size() < 9) {
        misbehaving(peer_id, 1, "short SENDCMPCT payload");
        return;
    }

    Peer* peer = conn_manager_.get_peer(peer_id);
    if (!peer) return;

    core::SpanReader reader(payload);
    bool announce = core::ser_read_bool(reader);
    uint64_t version = core::ser_read_u64(reader);

    LOG_DEBUG(core::LogCategory::NET,
              "Peer " + std::to_string(peer_id) +
              " sent SENDCMPCT: announce=" +
              (announce ? "true" : "false") +
              " version=" + std::to_string(version));

    // We accept SENDCMPCT to track the peer's preference but we do not
    // implement compact blocks in this initial version.
    if (version == 1 || version == 2) {
        peer->send_compact = announce;
    }
}

// ===========================================================================
// FEEFILTER handler
// ===========================================================================

void MsgProcessor::handle_feefilter(uint64_t peer_id,
                                     std::span<const uint8_t> payload) {
    if (payload.size() < 8) {
        misbehaving(peer_id, 1, "short FEEFILTER payload");
        return;
    }

    Peer* peer = conn_manager_.get_peer(peer_id);
    if (!peer) return;

    core::SpanReader reader(payload);
    int64_t fee_rate = core::ser_read_i64(reader);

    // Sanity check: the fee rate should be non-negative and reasonable.
    if (fee_rate < 0) {
        misbehaving(peer_id, 1, "negative FEEFILTER value");
        return;
    }

    // Cap at a reasonable maximum (100 BTC/kvB).
    static constexpr int64_t MAX_FEE_FILTER = 10000000000LL;
    if (fee_rate > MAX_FEE_FILTER) {
        fee_rate = MAX_FEE_FILTER;
    }

    peer->fee_filter = fee_rate;

    LOG_DEBUG(core::LogCategory::NET,
              "Peer " + std::to_string(peer_id) +
              " set fee filter to " + std::to_string(fee_rate) +
              " sat/kvB");
}

// ===========================================================================
// NOTFOUND handler
// ===========================================================================

void MsgProcessor::handle_notfound(uint64_t peer_id,
                                    std::span<const uint8_t> payload) {
    auto result = net::protocol::InvMessage::deserialize(payload);
    if (!result.ok()) {
        return;  // Not worth penalizing for a malformed NOTFOUND.
    }

    const auto& msg = result.value();

    LOG_DEBUG(core::LogCategory::NET,
              "Peer " + std::to_string(peer_id) +
              " NOTFOUND for " + std::to_string(msg.items.size()) +
              " items");

    // Remove any in-flight block requests that this peer can't serve.
    for (const auto& item : msg.items) {
        if (item.type == net::protocol::InvType::BLOCK ||
            item.type == net::protocol::InvType::WITNESS_BLOCK) {
            auto it = block_request_peer_.find(item.hash);
            if (it != block_request_peer_.end() &&
                it->second == peer_id) {
                blocks_in_flight_.erase(item.hash);
                block_request_peer_.erase(it);
            }
        }
    }
}

// ===========================================================================
// Sync helpers
// ===========================================================================

void MsgProcessor::maybe_start_sync() {
    // Don't start a new sync if we already have one in progress.
    if (sync_peer_id_ != 0) {
        // Verify the sync peer is still connected.
        if (conn_manager_.get_peer(sync_peer_id_) == nullptr) {
            sync_peer_id_ = 0;
        } else {
            return;
        }
    }

    // Select the best outbound peer for syncing.  Prefer the peer with the
    // highest reported start_height, but accept ANY operational outbound
    // peer as fallback -- the peer may have received blocks after the
    // VERSION exchange and we won't know until we send GETHEADERS.
    uint64_t best_peer = 0;
    int32_t best_height = 0;
    uint64_t any_peer = 0;

    auto peer_ids = conn_manager_.get_peer_ids();
    for (uint64_t pid : peer_ids) {
        Peer* peer = conn_manager_.get_peer(pid);
        if (!peer) continue;
        if (!peer_state_is_operational(peer->state)) continue;

        if (any_peer == 0) {
            any_peer = pid;
        }
        if (!peer->inbound && peer->start_height > best_height) {
            best_height = peer->start_height;
            best_peer = pid;
        }
    }

    int our_height = chainstate_.active_chain().height();

    // Prefer a peer that claims to have more blocks.
    if (best_peer != 0 && best_height > our_height) {
        // Use best_peer.
    } else if (any_peer != 0) {
        // No peer claims higher height, but send GETHEADERS anyway
        // to discover blocks mined after the VERSION handshake.
        best_peer = any_peer;
    } else {
        return;
    }

    sync_peer_id_ = best_peer;

    LOG_INFO(core::LogCategory::NET,
             "Starting headers sync with peer " +
             std::to_string(sync_peer_id_) +
             " (their height=" + std::to_string(best_height) +
             " our height=" + std::to_string(our_height) + ")");

    send_getheaders(sync_peer_id_);
}

void MsgProcessor::send_getheaders(uint64_t peer_id) {
    // Build a block locator from our active chain.
    auto locator = chainstate_.active_chain().get_locator();

    // If we have accepted headers beyond the active chain tip (common during
    // headers-first IBD where headers are fetched before block data), prepend
    // the best header hash.  This tells the peer "I know about headers up to
    // this hash, send me what comes after" and prevents re-sending headers
    // we already have.
    auto* best_hdr = chainstate_.best_header();
    if (best_hdr) {
        const core::uint256& best_hash = best_hdr->block_hash;
        bool already_present = false;
        for (const auto& h : locator) {
            if (h == best_hash) {
                already_present = true;
                break;
            }
        }
        if (!already_present) {
            locator.insert(locator.begin(), best_hash);
        }
    }

    // Build the GETHEADERS message payload:
    //   version (int32) + compact_size(locator.size()) + locator hashes +
    //   stop_hash (zero = no stop).
    core::DataStream stream;
    core::ser_write_i32(stream, net::protocol::PROTOCOL_VERSION);
    core::ser_write_compact_size(stream, locator.size());
    for (const auto& hash : locator) {
        core::ser_write_uint256(stream, hash);
    }
    // Stop hash: all zeros (get as many as possible).
    core::uint256 stop_hash;
    core::ser_write_uint256(stream, stop_hash);

    auto payload = stream.release();
    send(peer_id,
         net::Message::create(commands::GETHEADERS, std::move(payload)));

    LOG_DEBUG(core::LogCategory::NET,
              "Sent GETHEADERS to peer " + std::to_string(peer_id) +
              " (locator size=" + std::to_string(locator.size()) + ")");
}

void MsgProcessor::request_blocks(uint64_t peer_id) {
    // Find block indices that we have headers for but not full data.
    const auto& active_chain = chainstate_.active_chain();
    auto* best_header = chainstate_.best_header();

    if (!best_header) return;

    auto* tip = active_chain.tip();
    int start_height = tip ? (tip->height + 1) : 0;

    // Walk from start_height to best_header, requesting blocks we don't have.
    std::vector<net::protocol::InvItem> to_request;
    static constexpr int MAX_BLOCKS_REQUEST = 16;

    for (int h = start_height;
         h <= best_header->height &&
         static_cast<int>(to_request.size()) < MAX_BLOCKS_REQUEST;
         ++h) {
        // Walk the best header chain to find the block at height h.
        auto* index = best_header->get_ancestor(h);
        if (!index) break;

        if (!index->has_data() &&
            blocks_in_flight_.count(index->block_hash) == 0) {
            net::protocol::InvItem item;
            item.type = net::protocol::InvType::BLOCK;
            item.hash = index->block_hash;
            to_request.push_back(item);

            blocks_in_flight_.insert(index->block_hash);
            block_request_peer_[index->block_hash] = peer_id;
        }
    }

    if (!to_request.empty()) {
        net::protocol::InvMessage getdata;
        getdata.items = std::move(to_request);
        auto getdata_payload = getdata.serialize();

        send(peer_id,
             net::Message::create(commands::GETDATA,
                                  std::move(getdata_payload)));

        last_block_request_ = core::get_time();

        LOG_DEBUG(core::LogCategory::NET,
                  "Requested " +
                  std::to_string(getdata.items.size()) +
                  " blocks from peer " + std::to_string(peer_id));
    }
}

// ===========================================================================
// Relay helpers
// ===========================================================================

void MsgProcessor::relay_block(const core::uint256& hash) {
    auto peer_ids = conn_manager_.get_peer_ids();

    for (uint64_t pid : peer_ids) {
        Peer* peer = conn_manager_.get_peer(pid);
        if (!peer) continue;
        if (!peer_state_is_operational(peer->state)) continue;

        // Check if this peer prefers HEADERS announcements.
        if (peer->prefers_headers) {
            // Look up the block header and send it via HEADERS.
            auto* block_index = chainstate_.lookup_block_index(hash);
            if (block_index) {
                primitives::BlockHeader header =
                    block_index->get_block_header();

                core::DataStream stream;
                core::ser_write_compact_size(stream, 1);
                header.serialize(stream);
                core::ser_write_compact_size(stream, 0); // tx_count = 0

                auto payload = stream.release();
                send(pid, net::Message::create(commands::HEADERS,
                                               std::move(payload)));
            }
        } else {
            // Send an INV announcement.
            net::protocol::InvMessage inv;
            net::protocol::InvItem item;
            item.type = net::protocol::InvType::BLOCK;
            item.hash = hash;
            inv.items.push_back(item);

            auto payload = inv.serialize();
            send(pid,
                 net::Message::create(commands::INV, std::move(payload)));
        }
    }
}

void MsgProcessor::relay_tx(const core::uint256& txid) {
    net::protocol::InvMessage inv;
    net::protocol::InvItem item;
    item.type = net::protocol::InvType::TX;
    item.hash = txid;
    inv.items.push_back(item);

    auto payload = inv.serialize();
    net::Message msg = net::Message::create(commands::INV,
                                            std::move(payload));

    // Broadcast to all operational peers that haven't already announced
    // this transaction to us.
    conn_manager_.broadcast_if(msg, [&](const Peer& peer) {
        if (!peer_state_is_operational(peer.state)) {
            return false;
        }
        // Don't relay back to the peer that sent it.
        auto it = peer_announced_txs_.find(peer.id);
        if (it != peer_announced_txs_.end() &&
            it->second.count(txid) > 0) {
            return false;
        }
        // Respect the peer's fee filter.
        // In a production implementation, we would check the tx fee rate
        // against peer.fee_filter.
        return true;
    });
}

// ===========================================================================
// Utility message builders
// ===========================================================================

void MsgProcessor::send_version(uint64_t peer_id, bool inbound) {
    Peer* peer = conn_manager_.get_peer(peer_id);
    if (!peer) return;

    net::protocol::VersionMessage ver;
    ver.version = net::protocol::PROTOCOL_VERSION;
    ver.services = net::protocol::NODE_NETWORK | net::protocol::NODE_WITNESS;
    ver.timestamp = core::get_time();
    ver.nonce = local_nonce_;
    ver.user_agent = "/FTC:1.0.0/";

    // Set our current best height.
    auto* tip = chainstate_.active_chain().tip();
    ver.start_height = tip ? tip->height : 0;
    ver.relay = true;

    // Set address fields.
    // addr_recv is the remote peer's address.
    // addr_from is our address (usually 0.0.0.0 for privacy).
    ver.addr_recv_services = 0;
    ver.addr_recv_port = peer->conn.remote_port();
    ver.addr_from_services = ver.services;
    ver.addr_from_port = ConnManager::DEFAULT_PORT;

    auto payload = ver.serialize();
    send(peer_id,
         net::Message::create(commands::VERSION, std::move(payload)));

    if (!inbound) {
        peer->state = PeerState::VERSION_SENT;
    }

    LOG_DEBUG(core::LogCategory::NET,
              "Sent VERSION to peer " + std::to_string(peer_id) +
              " (height=" + std::to_string(ver.start_height) + ")");
}

void MsgProcessor::send_verack(uint64_t peer_id) {
    net::protocol::VerackMessage verack;
    auto payload = verack.serialize();
    send(peer_id,
         net::Message::create(commands::VERACK, std::move(payload)));

    LOG_DEBUG(core::LogCategory::NET,
              "Sent VERACK to peer " + std::to_string(peer_id));
}

void MsgProcessor::send_ping(uint64_t peer_id) {
    Peer* peer = conn_manager_.get_peer(peer_id);
    if (!peer) return;

    uint64_t nonce = core::get_random_uint64();
    peer->stats.pending_ping_nonce = nonce;
    peer->stats.ping_sent_time = core::get_time_millis();

    core::DataStream stream;
    core::ser_write_u64(stream, nonce);
    auto payload = stream.release();

    send(peer_id,
         net::Message::create(commands::PING, std::move(payload)));

    LOG_TRACE(core::LogCategory::NET,
              "Sent PING to peer " + std::to_string(peer_id) +
              " nonce=" + std::to_string(nonce));
}

void MsgProcessor::send_pong(uint64_t peer_id, uint64_t nonce) {
    core::DataStream stream;
    core::ser_write_u64(stream, nonce);
    auto payload = stream.release();

    send(peer_id,
         net::Message::create(commands::PONG, std::move(payload)));

    LOG_TRACE(core::LogCategory::NET,
              "Sent PONG to peer " + std::to_string(peer_id) +
              " nonce=" + std::to_string(nonce));
}

void MsgProcessor::send_getaddr(uint64_t peer_id) {
    send(peer_id,
         net::Message::create(commands::GETADDR, {}));

    LOG_DEBUG(core::LogCategory::NET,
              "Sent GETADDR to peer " + std::to_string(peer_id));
}

void MsgProcessor::send_sendheaders(uint64_t peer_id) {
    send(peer_id,
         net::Message::create(commands::SENDHEADERS, {}));

    LOG_DEBUG(core::LogCategory::NET,
              "Sent SENDHEADERS to peer " + std::to_string(peer_id));
}

void MsgProcessor::send(uint64_t peer_id, net::Message msg) {
    conn_manager_.send_to(peer_id, std::move(msg));
}

void MsgProcessor::misbehaving(uint64_t peer_id, int32_t howmuch,
                                const std::string& reason) {
    Peer* peer = conn_manager_.get_peer(peer_id);
    if (!peer) return;

    peer->stats.misbehavior_score += howmuch;

    LOG_WARN(core::LogCategory::NET,
             "Misbehaving peer " + std::to_string(peer_id) +
             " (+" + std::to_string(howmuch) +
             " -> " + std::to_string(peer->stats.misbehavior_score) +
             "): " + reason);

    if (peer->stats.misbehavior_score >= PeerConfig::MISBEHAVIOR_THRESHOLD) {
        LOG_WARN(core::LogCategory::NET,
                 "Banning peer " + std::to_string(peer_id) +
                 " for misbehavior");

        // Add to ban list.
        std::string addr = peer->conn.remote_address();
        // In a production implementation, we would add the address to the
        // ban manager: banman_.ban(addr, BanReason::MISBEHAVIOR);

        conn_manager_.disconnect(peer_id, DisconnectReason::MISBEHAVIOR);
    }
}

} // namespace net
