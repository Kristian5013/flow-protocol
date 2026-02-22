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
    LOG_DEBUG(core::LogCategory::NET,
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
        LOG_DEBUG(core::LogCategory::NET,
                 "Sync peer disconnected, will try to find a new one");
    }

    // Clean up per-peer tracking state.
    peer_announced_blocks_.erase(peer_id);
    peer_announced_txs_.erase(peer_id);
    last_header_from_peer_.erase(peer_id);
    peer_stalling_since_.erase(peer_id);

    // Clean up any in-flight block requests from this peer.
    std::vector<core::uint256> to_remove;
    for (const auto& [hash, req] : block_requests_) {
        if (req.peer_id == peer_id) {
            to_remove.push_back(hash);
        }
    }
    for (const auto& hash : to_remove) {
        cancel_block_request(hash);
    }

    // If blocks were freed, try to re-request from an outbound peer.
    if (!to_remove.empty()) {
        auto* best_hdr = chainstate_.best_header();
        auto* tip = chainstate_.active_chain().tip();
        if (best_hdr && tip && best_hdr != tip &&
            best_hdr->chain_work >= tip->chain_work) {
            for (uint64_t pid : get_outbound_peers()) {
                request_blocks(pid);
            }
        }
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

    // Check that the peer exists and is not already disconnecting.
    // After a peer is removed, queued messages may still arrive — drop silently.
    Peer* peer = conn_manager_.get_peer(peer_id);
    if (!peer) return;

    if (peer->state == PeerState::DISCONNECTING ||
        peer->state == PeerState::DISCONNECTED) {
        return;
    }

    // Before the handshake is complete, only VERSION and VERACK are allowed.
    // Instant disconnect (+100) to prevent queue flooding from misbehaving peers.
    if (peer->state != PeerState::ACTIVE &&
        peer->state != PeerState::HANDSHAKE_DONE) {
        if (command != commands::VERSION && command != commands::VERACK) {
            misbehaving(peer_id, 100,
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
            if ((now - tip_time) > STALE_TIP_THRESHOLD) {
                if (!stale_tip_logged_) {
                    LOG_INFO(core::LogCategory::NET,
                             "Stale tip detected (tip time " +
                             core::format_iso8601(tip_time) +
                             "), attempting resync");
                    stale_tip_logged_ = true;
                }
                maybe_start_sync();

                // If no outbound peers, probe ALL connected peers
                // for headers — inbound peers may have newer blocks.
                if (conn_manager_.outbound_count() == 0) {
                    auto all_peers = conn_manager_.get_peer_ids();
                    for (uint64_t pid : all_peers) {
                        Peer* p = conn_manager_.get_peer(pid);
                        if (p && peer_state_is_operational(p->state)) {
                            send_getheaders(pid);
                        }
                    }
                }
            } else {
                stale_tip_logged_ = false;
            }
        }
    }

    // ------------------------------------------------------------------
    // 2b. Periodic header probe — discover competing chains.
    // ------------------------------------------------------------------
    // Prefer outbound peers.  If none exist, fall back to probing
    // inbound peers so we can still discover new blocks.
    static constexpr int64_t FAST_HEADER_PROBE = 15;  // seconds
    if ((now - last_header_probe_) >= FAST_HEADER_PROBE) {
        last_header_probe_ = now;
        auto outbound = get_outbound_peers();
        if (!outbound.empty()) {
            for (uint64_t pid : outbound) {
                send_getheaders(pid);
            }
        } else {
            // No outbound — probe inbound so we don't get stuck.
            auto all_peers = conn_manager_.get_peer_ids();
            for (uint64_t pid : all_peers) {
                Peer* p = conn_manager_.get_peer(pid);
                if (p && peer_state_is_operational(p->state)) {
                    send_getheaders(pid);
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // 3. Pipeline stalling detection (Bitcoin Core style).
    //
    // A peer is "stalling" if it is holding the lowest in-flight block
    // and preventing other peers from advancing the download window.
    // peer_stalling_since_[pid] is set by request_blocks() when it
    // identifies a pipeline blocker.
    //
    // If a peer has been stalling for > block_stalling_timeout_:
    //   - Disconnect the peer (it will reconnect automatically).
    //   - Double the timeout (exponential backoff) to prevent cascade
    //     disconnects when our own bandwidth is the bottleneck.
    // The timeout decays by 0.85x whenever the chain tip advances.
    // ------------------------------------------------------------------
    {
        std::vector<uint64_t> to_disconnect;
        for (const auto& [pid, stall_time] : peer_stalling_since_) {
            if (stall_time == 0) continue;
            int64_t elapsed = now - stall_time;
            if (elapsed > block_stalling_timeout_) {
                to_disconnect.push_back(pid);
            }
        }
        for (uint64_t pid : to_disconnect) {
            LOG_WARN(core::LogCategory::NET,
                     "Peer " + std::to_string(pid) +
                     " stalling block download for " +
                     std::to_string(now - peer_stalling_since_[pid]) +
                     "s (timeout=" +
                     std::to_string(block_stalling_timeout_) +
                     "s), disconnecting");
            peer_stalling_since_.erase(pid);
            conn_manager_.disconnect(pid, DisconnectReason::TIMEOUT);

            // Exponential backoff: double the timeout to avoid cascading
            // disconnects when our bandwidth is the real bottleneck.
            int64_t new_timeout = std::min(
                block_stalling_timeout_ * 2, BLOCK_STALLING_TIMEOUT_MAX);
            if (new_timeout != block_stalling_timeout_) {
                LOG_INFO(core::LogCategory::NET,
                         "Block stalling timeout increased: " +
                         std::to_string(block_stalling_timeout_) +
                         "s -> " + std::to_string(new_timeout) + "s");
                block_stalling_timeout_ = new_timeout;
            }
        }
    }

    // ------------------------------------------------------------------
    // 3b. Slow block download timeout.
    //
    // Independent of the fast stalling detection above.  If any single
    // block request has been outstanding for > BLOCK_DOWNLOAD_TIMEOUT
    // (60s), cancel it and request from other peers.  This handles the
    // case where no alternate peer triggered stalling detection.
    // ------------------------------------------------------------------
    {
        std::vector<core::uint256> timed_out;
        for (const auto& [hash, req] : block_requests_) {
            if ((now - req.request_time) > BLOCK_DOWNLOAD_TIMEOUT) {
                timed_out.push_back(hash);
            }
        }
        if (!timed_out.empty()) {
            LOG_DEBUG(core::LogCategory::NET,
                     "Clearing " + std::to_string(timed_out.size()) +
                     " block requests (download timeout " +
                     std::to_string(BLOCK_DOWNLOAD_TIMEOUT) + "s)");
            for (const auto& hash : timed_out) {
                cancel_block_request(hash);
            }
            sync_peer_id_ = 0;

            // Re-request from any operational peer.
            for (uint64_t pid : get_outbound_peers()) {
                request_blocks(pid);
            }
            auto all_peers = conn_manager_.get_peer_ids();
            for (uint64_t pid : all_peers) {
                Peer* p = conn_manager_.get_peer(pid);
                if (p && p->inbound && peer_state_is_operational(p->state)) {
                    request_blocks(pid);
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // 4. Block download catch-up.
    // ------------------------------------------------------------------
    static constexpr int64_t BLOCK_CATCHUP_INTERVAL = 3;  // seconds

    if ((now - last_block_catchup_) >= BLOCK_CATCHUP_INTERVAL) {
        last_block_catchup_ = now;

        auto* best_hdr = chainstate_.best_header();
        auto* tip = chainstate_.active_chain().tip();

        if (best_hdr && tip && best_hdr != tip &&
            best_hdr->chain_work >= tip->chain_work) {
            LOG_DEBUG(core::LogCategory::NET,
                     "Block catch-up: header h=" +
                     std::to_string(best_hdr->height) +
                     " tip h=" + std::to_string(tip->height) +
                     " in_flight=" +
                     std::to_string(block_requests_.size()));

            for (uint64_t pid : get_outbound_peers()) {
                request_blocks(pid);
            }
        }

        // If synced, probe one outbound peer for new headers.
        if (best_hdr && tip && best_hdr == tip) {
            auto outbound = get_outbound_peers();
            if (!outbound.empty()) {
                send_getheaders(outbound.front());
            }
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

    LOG_DEBUG(core::LogCategory::NET,
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

    LOG_DEBUG(core::LogCategory::NET,
             "Received VERACK from peer " + std::to_string(peer_id));

    // Transition to ACTIVE state.
    if (peer->state == PeerState::HANDSHAKE_DONE ||
        peer->state == PeerState::VERSION_SENT) {
        peer->state = PeerState::ACTIVE;

        LOG_DEBUG(core::LogCategory::NET,
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

        // Mark outbound peer addresses as good in the address manager.
        // This promotes them to the "tried" table and records last_success,
        // preventing them from becoming "terrible" after future failures.
        if (!peer->inbound) {
            auto addr_result = NetAddress::from_string(
                peer->conn.remote_address());
            if (addr_result.ok()) {
                AddressWithPort awp;
                awp.addr = addr_result.value();
                awp.port = peer->conn.remote_port();
                awp.timestamp = core::get_time();
                addrman_.mark_good(awp, core::get_time());
            }
        }

        // If this inbound peer claims a higher chain than ours, request
        // headers from them so we can learn about blocks they have mined.
        // maybe_start_sync() only considers outbound peers, so inbound
        // miners would never propagate their blocks to seed nodes without
        // this explicit request.
        int our_height = chainstate_.active_chain().height();
        if (peer->inbound && peer->start_height > our_height) {
            LOG_DEBUG(core::LogCategory::NET,
                     "Inbound peer " + std::to_string(peer_id) +
                     " has higher chain (height=" +
                     std::to_string(peer->start_height) +
                     " vs our " + std::to_string(our_height) +
                     "), requesting headers");
            send_getheaders(peer_id);
        }

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

    // Get the peer's address as source for AddrMan bucketing.
    // Using the actual peer address (not the announced address) ensures
    // proper bucket distribution and prevents collisions.
    NetAddress source_addr;
    Peer* sender = conn_manager_.get_peer(peer_id);
    if (sender) {
        auto sa = NetAddress::from_string(sender->conn.remote_address());
        if (sa.ok()) source_addr = sa.value();
    }

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
                addrman_.add(addr, source_addr);
                ++addresses_added;
            }
        } catch (const std::exception& e) {
            misbehaving(peer_id, 1, "malformed address in ADDR");
            return;
        }
    }

    LOG_INFO(core::LogCategory::NET,
             "Received " + std::to_string(count) + " addresses from peer " +
             std::to_string(peer_id) + ", added " +
             std::to_string(addresses_added) + " to AddrMan");
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
                !is_block_in_flight(item.hash)) {
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
        int64_t req_time = core::get_time();
        for (const auto& item : getdata.items) {
            if (item.type == net::protocol::InvType::BLOCK ||
                item.type == net::protocol::InvType::WITNESS_BLOCK) {
                block_requests_[item.hash] = {peer_id, req_time};
            }
        }
        last_block_request_ = req_time;
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
    int new_headers = 0;
    core::uint256 last_accepted_hash;

    for (uint64_t i = 0; i < count; ++i) {
        try {
            // Each header is 80 bytes + a CompactSize tx count (which should
            // be 0 in a HEADERS message).
            auto header = primitives::BlockHeader::deserialize(reader);

            // Read and discard the tx count (always 0 in HEADERS).
            uint64_t tx_count = core::ser_read_compact_size(reader);
            (void)tx_count;

            core::uint256 hdr_hash = header.hash();

            // Accept the header into the block index.
            auto accept_result = chainstate_.accept_block_header(header);
            if (accept_result.ok()) {
                ++accepted;
                last_accepted_hash = hdr_hash;
                // Count genuinely new headers (not already known).
                if (!known_blocks_.count(hdr_hash)) {
                    ++new_headers;
                }
                known_blocks_.insert(hdr_hash);
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

    // Track the last accepted header from this peer so that GETHEADERS
    // locators can include fork-chain progress even before the fork
    // surpasses our active chain's total work.
    if (accepted > 0) {
        last_header_from_peer_[peer_id] = last_accepted_hash;
    }

    if (new_headers > 0) {
        LOG_DEBUG(core::LogCategory::NET,
                 "Accepted " + std::to_string(accepted) + "/" +
                 std::to_string(count) + " headers (" +
                 std::to_string(new_headers) + " new) from peer " +
                 std::to_string(peer_id));
    }

    // Only reset stale-tip timer when genuinely new data arrives.
    // Empty responses from syncing peers must not suppress stale detection.
    if (new_headers > 0) {
        last_tip_update_ = core::get_time();
    }

    // If we received a full batch of headers, request more.
    if (count == MAX_HEADERS && peer_id == sync_peer_id_) {
        send_getheaders(peer_id);
    }

    // If ALL headers were rejected (e.g. parent unknown because we are
    // behind), send GETHEADERS to sync up.  Without this, a node that
    // misses a few blocks will keep receiving tip announcements it cannot
    // connect and never catch up.
    if (accepted == 0 && count > 0) {
        LOG_DEBUG(core::LogCategory::NET,
                 "All " + std::to_string(count) +
                 " headers rejected from peer " +
                 std::to_string(peer_id) +
                 ", sending GETHEADERS to sync");
        send_getheaders(peer_id);
        // Don't return -- fall through to check if we need block downloads.
        // We may have headers from a previous sync that need block data.
    }

    // If we received fewer than a full batch, headers sync is complete.
    // Clear the sync peer so future maybe_start_sync() can pick a new one.
    if (count < MAX_HEADERS && peer_id == sync_peer_id_) {
        LOG_DEBUG(core::LogCategory::NET,
                 "Headers sync complete with peer " +
                 std::to_string(sync_peer_id_));
        sync_peer_id_ = 0;
    }

    // Try to activate the best chain and request block data.
    // This runs for EVERY headers response (not just partial batches)
    // so that block downloads are pipelined with header downloads.
    auto activate_result = chainstate_.activate_best_chain();
    if (activate_result.ok() && activate_result.value()) {
        LOG_DEBUG(core::LogCategory::NET, "Chain tip updated");
    }

    // Request block data if our best header is ahead of our active tip.
    // This covers:
    //   - Normal headers-first sync (accepted > 0)
    //   - Resumed sync after discovering headers are already known
    //   - Pipelined block download during multi-batch header sync
    auto* best_hdr = chainstate_.best_header();
    auto* tip = chainstate_.active_chain().tip();
    if (best_hdr && tip && best_hdr != tip &&
        best_hdr->chain_work >= tip->chain_work) {
        request_blocks(peer_id);
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

    LOG_DEBUG(core::LogCategory::NET,
             "Received block " + block_hash.to_hex().substr(0, 16) +
             "... (" + std::to_string(block.tx_count()) +
             " txs) from peer " + std::to_string(peer_id));

    // Remove from in-flight tracking.
    cancel_block_request(block_hash);
    // Peer delivered a block — clear stalling flag (Bitcoin Core style).
    peer_stalling_since_.erase(peer_id);
    known_blocks_.insert(block_hash);

    // Accept the block into chainstate.
    bool block_accepted = false;
    auto accept_result = chainstate_.accept_block(block);
    if (!accept_result.ok()) {
        // Orphan block (parent not yet synced) is not misbehavior.
        // Fall through to request more blocks so the pipeline continues.
        if (accept_result.error().code() == core::ErrorCode::VALIDATION_ORPHAN) {
            LOG_DEBUG(core::LogCategory::NET,
                      "Orphan block " + block_hash.to_hex().substr(0, 16) +
                      "... from peer " + std::to_string(peer_id) +
                      " (parent not yet synced)");
        } else {
            LOG_WARN(core::LogCategory::NET,
                     "Block " + block_hash.to_hex().substr(0, 16) +
                     "... rejected: " + accept_result.error().message());

            if (accept_result.error().code() ==
                core::ErrorCode::VALIDATION_ERROR) {
                misbehaving(peer_id, 100, "invalid block");
            }
            return;
        }
    } else {
        block_accepted = true;
    }

    if (block_accepted) {
        auto activate_result = chainstate_.activate_best_chain();
        if (activate_result.ok() && activate_result.value()) {
            auto* tip = chainstate_.active_chain().tip();
            if (tip) {
                LOG_INFO(core::LogCategory::NET,
                         "New chain tip: height=" +
                         std::to_string(tip->height) +
                         " hash=" + tip->block_hash.to_hex().substr(0, 16) +
                         "...");

                if (tip->height % 100 == 0 || block_requests_.empty()) {
                    chainstate_.flush();
                }
            }
            last_tip_update_ = core::get_time();
            relay_block(block_hash);

            // Decay the stalling timeout toward default (Bitcoin Core style).
            // Successful chain advancement means the network is healthy,
            // so gradually become less tolerant of stalling again.
            if (block_stalling_timeout_ > BLOCK_STALLING_TIMEOUT_DEFAULT) {
                int64_t decayed = static_cast<int64_t>(
                    block_stalling_timeout_ * 0.85);
                block_stalling_timeout_ = std::max(
                    decayed, BLOCK_STALLING_TIMEOUT_DEFAULT);
            }
        }
    }

    // Request more blocks — runs for both accepted and orphan blocks.
    {
        auto* best_hdr = chainstate_.best_header();
        auto* tip = chainstate_.active_chain().tip();
        bool more_to_download = best_hdr && tip && best_hdr != tip &&
            best_hdr->chain_work >= tip->chain_work;

        if (!block_requests_.empty() || sync_peer_id_ == peer_id ||
            more_to_download) {
            request_blocks(peer_id);
        }
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
    bool had_block_notfound = false;
    for (const auto& item : msg.items) {
        if (item.type == net::protocol::InvType::BLOCK ||
            item.type == net::protocol::InvType::WITNESS_BLOCK) {
            auto it = block_requests_.find(item.hash);
            if (it != block_requests_.end() &&
                it->second.peer_id == peer_id) {
                cancel_block_request(item.hash);
                had_block_notfound = true;
            }
        }
    }

    // Mark this peer as not having the blocks we need so it won't be
    // selected again by request_blocks().
    if (had_block_notfound) {
        Peer* nf_peer = conn_manager_.get_peer(peer_id);
        if (nf_peer) {
            int our_height = chainstate_.active_chain().height();
            if (nf_peer->start_height > our_height) {
                LOG_DEBUG(core::LogCategory::NET,
                         "Peer " + std::to_string(peer_id) +
                         " NOTFOUND blocks, lowering start_height from " +
                         std::to_string(nf_peer->start_height) +
                         " to " + std::to_string(our_height));
                nf_peer->start_height = our_height;
            }
        }

        // Retry with any peer that still claims higher height.
        auto* best_hdr = chainstate_.best_header();
        auto* tip = chainstate_.active_chain().tip();
        if (best_hdr && tip && best_hdr != tip &&
            best_hdr->chain_work >= tip->chain_work) {
            // Try outbound first, then any peer.
            auto all_peers = conn_manager_.get_peer_ids();
            for (uint64_t pid : all_peers) {
                if (pid == peer_id) continue;
                Peer* p = conn_manager_.get_peer(pid);
                if (!p || !peer_state_is_operational(p->state)) continue;
                if (p->start_height <= chainstate_.active_chain().height()) continue;
                LOG_DEBUG(core::LogCategory::NET,
                         "NOTFOUND retry: requesting blocks from peer " +
                         std::to_string(pid));
                request_blocks(pid);
                break;
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

    // Select the best peer for syncing.  Prefer outbound peers, but
    // fall back to inbound if no outbound connections exist (e.g. seed
    // nodes that lost their outbound connection).
    uint64_t best_peer = 0;
    int32_t best_height = 0;
    uint64_t any_outbound = 0;

    auto peer_ids = conn_manager_.get_peer_ids();
    for (uint64_t pid : peer_ids) {
        Peer* peer = conn_manager_.get_peer(pid);
        if (!peer) continue;
        if (peer->inbound) continue;
        if (!peer_state_is_operational(peer->state)) continue;

        if (any_outbound == 0) {
            any_outbound = pid;
        }
        if (peer->start_height > best_height) {
            best_height = peer->start_height;
            best_peer = pid;
        }
    }

    int our_height = chainstate_.active_chain().height();

    if (best_peer != 0 && best_height > our_height) {
        // Use best outbound peer that claims more blocks.
    } else if (any_outbound != 0) {
        // No outbound peer claims higher height, but send GETHEADERS
        // anyway to discover blocks mined after the VERSION handshake.
        best_peer = any_outbound;
    } else {
        // No outbound peers at all — fall back to the best inbound peer.
        for (uint64_t pid : peer_ids) {
            Peer* peer = conn_manager_.get_peer(pid);
            if (!peer || !peer_state_is_operational(peer->state)) continue;
            if (peer->start_height > best_height) {
                best_height = peer->start_height;
                best_peer = pid;
            }
        }
        if (best_peer == 0) return;
    }

    sync_peer_id_ = best_peer;

    LOG_DEBUG(core::LogCategory::NET,
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

    // Include the last header we received from this specific peer.
    // This is critical for fork-chain syncing: when a peer sends us headers
    // from a competing fork whose cumulative work hasn't yet surpassed our
    // active chain, best_header_ won't point to that fork.  Without this,
    // the locator only contains our active chain hashes, the peer always
    // resolves the same fork point, and we loop receiving the same headers.
    auto peer_it = last_header_from_peer_.find(peer_id);
    if (peer_it != last_header_from_peer_.end()) {
        const core::uint256& peer_hash = peer_it->second;
        bool already_present = false;
        for (const auto& h : locator) {
            if (h == peer_hash) {
                already_present = true;
                break;
            }
        }
        if (!already_present) {
            locator.insert(locator.begin(), peer_hash);
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

    // If best_header IS on the active chain and we already have all data,
    // there is nothing to download.
    if (active_chain.tip() == best_header) {
        LOG_DEBUG(core::LogCategory::NET,
                  "request_blocks: tip == best_header at h=" +
                  std::to_string(best_header->height) + ", nothing to do");
        return;
    }

    LOG_DEBUG(core::LogCategory::NET,
             "request_blocks: best_header h=" +
             std::to_string(best_header->height) +
             " tip h=" + std::to_string(active_chain.height()) +
             " caller=" + std::to_string(peer_id));

    // Find where best_header's chain diverges from our active chain.
    // For the common case (same chain) fork == tip, so start_height ==
    // tip + 1 as before.  For a competing fork, we start downloading
    // from the fork point so the full alternate chain can be obtained.
    auto* fork = best_header;
    while (fork && fork->height > 0 && !active_chain.contains(fork)) {
        fork = fork->prev;
    }
    int start_height = fork ? (fork->height + 1) : 0;

    LOG_DEBUG(core::LogCategory::NET,
              "request_blocks: best_header h=" +
              std::to_string(best_header->height) +
              " active_tip h=" +
              std::to_string(active_chain.height()) +
              " fork h=" + std::to_string(fork ? fork->height : -1) +
              " start_height=" + std::to_string(start_height) +
              " caller_peer=" + std::to_string(peer_id));

    // Pick the best peer to request blocks from.
    // When best_header is on a competing fork, prefer the peer who
    // sent us the fork headers (peer_id) since they are most likely to
    // have the block data.  Only override if another peer reports a
    // higher chain and the caller peer doesn't claim to have blocks.
    uint64_t best_peer = peer_id;

    // Check if we're downloading a fork chain (best_header differs
    // from active chain).  In that case, the caller peer IS the one
    // with the fork blocks — don't let start_height-based selection
    // override it.
    bool downloading_fork = (start_height <= active_chain.height());

    if (!downloading_fork) {
        // Select the best peer: highest start_height among outbound,
        // then inbound.  Simple selection — stalling is handled
        // separately via the nodeStaller pattern below.
        int best_height = 0;
        for (uint64_t pid : get_outbound_peers()) {
            Peer* p = conn_manager_.get_peer(pid);
            if (!p) continue;
            if (p->start_height > best_height) {
                best_height = p->start_height;
                best_peer = pid;
            }
        }
        if (best_height < start_height) {
            auto all_peers = conn_manager_.get_peer_ids();
            for (uint64_t pid : all_peers) {
                Peer* p = conn_manager_.get_peer(pid);
                if (!p || !peer_state_is_operational(p->state)) continue;
                if (p->start_height > best_height) {
                    best_height = p->start_height;
                    best_peer = pid;
                }
            }
        }
    }

    // Walk from start_height to best_header, requesting blocks we don't have.
    std::vector<net::protocol::InvItem> to_request;
    static constexpr int MAX_BLOCKS_REQUEST = 128;

    // Pre-count current in-flight for best_peer.
    int peer_in_flight = 0;
    for (const auto& [bh, req] : block_requests_) {
        if (req.peer_id == best_peer) ++peer_in_flight;
    }

    // Collect candidate block indices by walking backward from best_header
    // to start_height.  Reverse to get ascending order.
    int scan_end = best_header->height;
    int scan_begin = start_height;
    if (scan_end - scan_begin > MAX_BLOCKS_IN_TRANSIT_PER_PEER * 2) {
        scan_end = scan_begin + MAX_BLOCKS_IN_TRANSIT_PER_PEER * 2;
    }

    std::vector<chain::BlockIndex*> candidates;
    candidates.reserve(scan_end - scan_begin + 1);
    auto* walk = best_header->get_ancestor(scan_end);
    while (walk && walk->height >= scan_begin) {
        candidates.push_back(walk);
        walk = walk->prev;
    }
    std::reverse(candidates.begin(), candidates.end());

    // Bitcoin Core "nodeStaller" pattern: when we can't assign any blocks
    // to this peer because another peer already has them in-flight, record
    // that other peer as the potential pipeline blocker.
    uint64_t node_staller = 0;

    int64_t now = core::get_time();
    for (auto* index : candidates) {
        if (static_cast<int>(to_request.size()) >= MAX_BLOCKS_REQUEST) break;
        if (peer_in_flight >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) break;

        if (index->has_data()) continue;

        if (is_block_in_flight(index->block_hash)) {
            // Block already requested from someone.  Record the first
            // such peer as the potential staller (they are blocking us).
            if (node_staller == 0) {
                auto it = block_requests_.find(index->block_hash);
                if (it != block_requests_.end() &&
                    it->second.peer_id != best_peer) {
                    node_staller = it->second.peer_id;
                }
            }
            continue;
        }

        net::protocol::InvItem item;
        item.type = net::protocol::InvType::BLOCK;
        item.hash = index->block_hash;
        to_request.push_back(item);
        block_requests_[index->block_hash] = {best_peer, now};
        ++peer_in_flight;
    }

    // If we couldn't assign ANY new blocks because another peer has them
    // all in-flight, mark that peer as stalling (if not already marked).
    // The on_tick() handler will disconnect after block_stalling_timeout_.
    if (to_request.empty() && node_staller != 0) {
        auto [it, inserted] = peer_stalling_since_.try_emplace(
            node_staller, now);
        if (inserted) {
            LOG_DEBUG(core::LogCategory::NET,
                     "Peer " + std::to_string(node_staller) +
                     " blocking download pipeline, marked as stalling");
        }
    }

    if (!to_request.empty()) {
        // Send in batches of 16 to avoid overwhelming the serving peer's
        // event loop (handle_getdata reads+sends all items synchronously).
        static constexpr size_t GETDATA_BATCH = 16;
        for (size_t i = 0; i < to_request.size(); i += GETDATA_BATCH) {
            size_t end = std::min(i + GETDATA_BATCH, to_request.size());
            net::protocol::InvMessage getdata;
            getdata.items.assign(
                std::make_move_iterator(to_request.begin() + i),
                std::make_move_iterator(to_request.begin() + end));
            auto getdata_payload = getdata.serialize();
            send(best_peer,
                 net::Message::create(commands::GETDATA,
                                      std::move(getdata_payload)));
        }

        last_block_request_ = now;

        LOG_DEBUG(core::LogCategory::NET,
                 "Requested " +
                 std::to_string(to_request.size()) +
                 " blocks (in_flight=" +
                 std::to_string(block_requests_.size()) +
                 ") from peer " + std::to_string(best_peer) +
                 (downloading_fork ? " (fork download)" : ""));
    } else {
        LOG_DEBUG(core::LogCategory::NET,
                 "request_blocks: nothing to request"
                 " (in_flight=" +
                 std::to_string(block_requests_.size()) + ")");
    }
}

// ===========================================================================
// Block request helpers
// ===========================================================================

std::vector<uint64_t> MsgProcessor::get_outbound_peers() const {
    std::vector<uint64_t> result;
    auto peer_ids = conn_manager_.get_peer_ids();
    for (uint64_t pid : peer_ids) {
        const Peer* p = conn_manager_.get_peer(pid);
        if (!p || p->inbound || !peer_state_is_operational(p->state)) continue;
        result.push_back(pid);
    }
    return result;
}

uint64_t MsgProcessor::cancel_block_request(const core::uint256& hash) {
    auto it = block_requests_.find(hash);
    if (it == block_requests_.end()) return 0;
    uint64_t peer_id = it->second.peer_id;
    block_requests_.erase(it);
    return peer_id;
}

bool MsgProcessor::is_block_in_flight(const core::uint256& hash) const {
    return block_requests_.count(hash) != 0;
}

// ===========================================================================
// Relay helpers
// ===========================================================================

void MsgProcessor::relay_block(const core::uint256& hash) {
    // Bitcoin-style block relay: announce via HEADERS (preferred) or INV.
    // The peer decides whether to request the full block via GETDATA.
    // This avoids pushing full block data to peers that already have it.
    auto* block_index = chainstate_.lookup_block_index(hash);
    if (!block_index) return;

    // Prepare HEADERS payload (1 header + 0 tx count).
    primitives::BlockHeader header = block_index->get_block_header();
    core::DataStream hdr_stream;
    core::ser_write_compact_size(hdr_stream, 1);
    header.serialize(hdr_stream);
    core::ser_write_compact_size(hdr_stream, 0);
    auto hdr_payload = hdr_stream.release();

    // Prepare INV payload (for peers that don't prefer headers).
    net::protocol::InvMessage inv;
    net::protocol::InvItem inv_item;
    inv_item.type = net::protocol::InvType::BLOCK;
    inv_item.hash = hash;
    inv.items.push_back(inv_item);
    auto inv_payload = inv.serialize();

    auto peer_ids = conn_manager_.get_peer_ids();
    int sent_count = 0;

    for (uint64_t pid : peer_ids) {
        Peer* peer = conn_manager_.get_peer(pid);
        if (!peer) continue;
        if (!peer_state_is_operational(peer->state)) continue;

        // Don't announce back to peers who already told us about this block.
        if (peer_announced_blocks_.count(pid) &&
            peer_announced_blocks_[pid].count(hash)) {
            continue;
        }

        if (peer->prefers_headers) {
            // Send HEADERS — peer will accept the header, then GETDATA
            // the full block if it wants it.
            auto hdr_copy = hdr_payload;
            send(pid, net::Message::create(commands::HEADERS,
                                           std::move(hdr_copy)));
        } else {
            // Send INV — peer will GETDATA if interested.
            auto inv_copy = inv_payload;
            send(pid, net::Message::create(commands::INV,
                                           std::move(inv_copy)));
        }

        ++sent_count;
    }

    LOG_INFO(core::LogCategory::NET,
             "Announced block " + hash.to_hex().substr(0, 16) +
             "... to " + std::to_string(sent_count) + " peers");
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
