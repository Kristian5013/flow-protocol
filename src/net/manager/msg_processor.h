#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// MsgProcessor -- protocol message handler for the FTC P2P network.
//
// Receives parsed messages from the event loop and dispatches them to the
// appropriate handler method.  Each handler validates the message payload,
// updates peer state, interacts with the chainstate / mempool as needed,
// and may generate response messages.
//
// This class is NOT thread-safe on its own -- it is designed to be called
// exclusively from the NetManager event loop (single-threaded actor model).
// ---------------------------------------------------------------------------

#include "core/error.h"
#include "core/types.h"
#include "net/manager/conn_manager.h"
#include "net/transport/message.h"

#include <cstdint>
#include <span>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Forward declarations to avoid pulling in full headers.
namespace chain {
    class ChainstateManager;
} // namespace chain

namespace mempool {
    struct MempoolEntry;
} // namespace mempool

namespace net {
    class AddrMan;
} // namespace net

namespace net::sync {
    class HeadersSync;
} // namespace net::sync

namespace net {

// ---------------------------------------------------------------------------
// MsgProcessor
// ---------------------------------------------------------------------------

class MsgProcessor {
public:
    /// Construct the message processor with references to subsystem managers.
    ///
    /// All references must outlive this object.  The MsgProcessor does not
    /// own any of them.
    MsgProcessor(chain::ChainstateManager& chainstate,
                 ConnManager& conn_manager,
                 AddrMan& addrman);

    // Non-copyable, non-movable.
    MsgProcessor(const MsgProcessor&) = delete;
    MsgProcessor& operator=(const MsgProcessor&) = delete;
    MsgProcessor(MsgProcessor&&) = delete;
    MsgProcessor& operator=(MsgProcessor&&) = delete;

    ~MsgProcessor() = default;

    // -- Event handlers (called from the event loop) -------------------------

    /// Process a new peer connection (send VERSION message).
    void on_peer_connected(uint64_t peer_id, bool inbound);

    /// Process a peer disconnection.
    void on_peer_disconnected(uint64_t peer_id);

    /// Process a received message from a peer.
    void process_message(uint64_t peer_id, const net::Message& msg);

    /// Process misbehavior for a peer (increment score, ban if threshold).
    void on_misbehavior(uint64_t peer_id, int32_t score_increment);

    /// Periodic tick handler (called every ~1 second from the event loop).
    /// Handles timeouts, pings, stale tip detection, etc.
    void on_tick(int64_t now);

private:
    // -- References to subsystem managers ------------------------------------
    chain::ChainstateManager& chainstate_;
    ConnManager& conn_manager_;
    AddrMan& addrman_;

    // -- Self-connection detection -------------------------------------------
    // A random nonce generated once at startup and included in every VERSION
    // message we send.  If we receive a VERSION with this same nonce, the
    // remote peer is actually ourselves.
    uint64_t local_nonce_ = 0;

    // -- Sync state ----------------------------------------------------------
    // These are lightweight state trackers; the heavy sync logic lives in
    // the net::sync classes.
    uint64_t      sync_peer_id_ = 0;
    int64_t       last_tip_update_ = 0;
    int64_t       last_block_request_ = 0;

    // -- Inventory tracking --------------------------------------------------
    // Track which inventory items we have already seen or requested to
    // avoid duplicate requests and relays.
    std::unordered_set<core::uint256> known_blocks_;
    std::unordered_set<core::uint256> known_txs_;
    std::unordered_set<core::uint256> blocks_in_flight_;
    std::unordered_map<core::uint256, uint64_t> block_request_peer_;

    // Per-peer sets of inventory items they have announced to us.
    std::unordered_map<uint64_t, std::unordered_set<core::uint256>>
        peer_announced_blocks_;
    std::unordered_map<uint64_t, std::unordered_set<core::uint256>>
        peer_announced_txs_;

    // -- Block download parameters -------------------------------------------
    static constexpr int64_t STALE_TIP_CHECK_INTERVAL = 30;     // seconds
    static constexpr int64_t STALE_TIP_THRESHOLD = 30 * 60;     // 30 minutes
    static constexpr int64_t BLOCK_DOWNLOAD_TIMEOUT = 30;       // seconds
    static constexpr int     MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16;
    int64_t last_stale_check_ = 0;
    int64_t last_header_probe_ = 0;
    int64_t last_block_catchup_ = 0;

    // Per-block request timestamps (for stalling detection).
    std::unordered_map<core::uint256, int64_t> block_request_time_;

    // Last header hash received from each peer.  Used in GETHEADERS locators
    // so that a peer sending fork-chain headers can continue from where it
    // left off, even before the fork chain's cumulative work exceeds ours.
    std::unordered_map<uint64_t, core::uint256> last_header_from_peer_;

    // -- Message handlers ----------------------------------------------------
    // Each handler receives the peer ID and the raw payload bytes (after
    // the message header has been stripped).

    void handle_version(uint64_t peer_id, std::span<const uint8_t> payload);
    void handle_verack(uint64_t peer_id);
    void handle_ping(uint64_t peer_id, std::span<const uint8_t> payload);
    void handle_pong(uint64_t peer_id, std::span<const uint8_t> payload);
    void handle_addr(uint64_t peer_id, std::span<const uint8_t> payload);
    void handle_inv(uint64_t peer_id, std::span<const uint8_t> payload);
    void handle_getdata(uint64_t peer_id, std::span<const uint8_t> payload);
    void handle_headers(uint64_t peer_id, std::span<const uint8_t> payload);
    void handle_block(uint64_t peer_id, std::span<const uint8_t> payload);
    void handle_tx(uint64_t peer_id, std::span<const uint8_t> payload);
    void handle_getblocks(uint64_t peer_id, std::span<const uint8_t> payload);
    void handle_getheaders(uint64_t peer_id, std::span<const uint8_t> payload);
    void handle_getaddr(uint64_t peer_id);
    void handle_sendheaders(uint64_t peer_id);
    void handle_sendcmpct(uint64_t peer_id, std::span<const uint8_t> payload);
    void handle_feefilter(uint64_t peer_id, std::span<const uint8_t> payload);
    void handle_notfound(uint64_t peer_id, std::span<const uint8_t> payload);

    // -- Sync helpers --------------------------------------------------------

    /// Choose a sync peer (highest-work outbound peer with good state).
    void maybe_start_sync();

    /// Build and send a GETHEADERS message to the sync peer.
    void send_getheaders(uint64_t peer_id);

    /// Request block data for known headers that we have not yet downloaded.
    void request_blocks(uint64_t peer_id);

    // -- Relay helpers -------------------------------------------------------

    /// Announce a new block hash to all peers via INV (or HEADERS for those
    /// that requested SENDHEADERS).
    void relay_block(const core::uint256& hash);

    /// Announce a new transaction hash to all peers via INV.
    void relay_tx(const core::uint256& txid);

    // -- Utility -------------------------------------------------------------

    /// Build and send a VERSION message to a peer.
    void send_version(uint64_t peer_id, bool inbound);

    /// Send a VERACK message to a peer.
    void send_verack(uint64_t peer_id);

    /// Send a PING message with a random nonce.
    void send_ping(uint64_t peer_id);

    /// Send a PONG message with the given nonce.
    void send_pong(uint64_t peer_id, uint64_t nonce);

    /// Send a GETADDR message.
    void send_getaddr(uint64_t peer_id);

    /// Send a SENDHEADERS message.
    void send_sendheaders(uint64_t peer_id);

    /// Send a message to a peer (convenience wrapper).
    void send(uint64_t peer_id, net::Message msg);

    /// Increase the misbehavior score for a peer.
    void misbehaving(uint64_t peer_id, int32_t howmuch,
                     const std::string& reason);
};

} // namespace net
