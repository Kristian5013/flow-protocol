#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "core/types.h"
#include "primitives/block_header.h"
#include "primitives/transaction.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace net::protocol {

// ---------------------------------------------------------------------------
// BIP152 Compact Block Relay -- protocol constants
// ---------------------------------------------------------------------------
// BIP152 defines a method to relay blocks more efficiently by sending
// only short transaction IDs (6-byte truncated SipHash values) for
// transactions the receiver is likely to have in its mempool, plus the
// full serialization of any transactions the receiver is expected to lack
// (typically just the coinbase).

/// Maximum number of short IDs in a compact block message.
inline constexpr size_t MAX_COMPACT_SHORT_IDS = 100000;

/// Maximum number of prefilled transactions in a compact block message.
inline constexpr size_t MAX_COMPACT_PREFILLED_TXS = 10000;

/// Maximum number of transaction indices in a getblocktxn request.
inline constexpr size_t MAX_BLOCKTXN_INDICES = 50000;

/// Maximum number of transactions in a blocktxn response.
inline constexpr size_t MAX_BLOCKTXN_TXS = 50000;

/// Size of a BIP152 short transaction ID on the wire: 6 bytes (48 bits).
inline constexpr size_t SHORT_ID_SIZE = 6;

/// Current compact block protocol version.
inline constexpr uint64_t COMPACT_BLOCK_VERSION = 1;

// ---------------------------------------------------------------------------
// PrefilledTransaction -- a transaction with its index in the block
// ---------------------------------------------------------------------------
// Used within CmpctBlockMessage to send transactions that the sender
// expects the receiver to be missing (typically the coinbase transaction).
// The index is differentially encoded on the wire for compactness.
// ---------------------------------------------------------------------------
struct PrefilledTransaction {
    uint16_t index = 0;
    primitives::Transaction tx;
};

// ---------------------------------------------------------------------------
// SendCmpctMessage -- negotiate compact block relay (SENDCMPCT command)
// ---------------------------------------------------------------------------
// Sent at connection startup to negotiate BIP152 compact block relay.
//
// high_bandwidth = true requests that the peer send compact blocks directly
// without waiting for a getdata request (high-bandwidth mode).  In this
// mode the peer sends cmpctblock messages proactively.
//
// high_bandwidth = false requests low-bandwidth mode where the peer sends
// inv/headers first, and the receiver requests the compact block via getdata.
//
// Wire format:
//   high_bandwidth   bool     (1 byte: 0 or 1)
//   version          uint64   (8 bytes LE)
//
// Total: 9 bytes.
// ---------------------------------------------------------------------------
struct SendCmpctMessage {
    bool     high_bandwidth = false;
    uint64_t version        = COMPACT_BLOCK_VERSION;

    /// Serialize the sendcmpct message payload.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize a sendcmpct message from raw bytes.
    [[nodiscard]] static core::Result<SendCmpctMessage> deserialize(
        std::span<const uint8_t> data);

    /// Validate the message (version check).
    [[nodiscard]] core::Result<void> validate() const;
};

// ---------------------------------------------------------------------------
// CmpctBlockMessage -- compact block announcement (CMPCTBLOCK command)
// ---------------------------------------------------------------------------
// Contains a block header, a nonce for SipHash short-ID computation,
// short transaction IDs (6-byte truncated hashes), and a set of prefilled
// transactions (with differentially-encoded indices).
//
// Wire format:
//   header              BlockHeader    (80 bytes)
//   nonce               uint64         (8 bytes LE)
//   short_ids_count     compact_size
//   short_ids[]         [count]        (6 bytes each, LE)
//   prefilled_count     compact_size
//   prefilled[]         [count]        (compact_size diff_index + serialized tx)
//
// The receiver uses the nonce together with the block header hash to
// compute a SipHash key, then matches the short IDs against its mempool.
// ---------------------------------------------------------------------------
struct CmpctBlockMessage {
    primitives::BlockHeader              header;
    uint64_t                             nonce = 0;
    std::vector<uint64_t>                short_ids;        // 6-byte truncated txids
    std::vector<PrefilledTransaction>    prefilled_txs;

    /// Serialize the cmpctblock message payload.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize a cmpctblock message from raw bytes.
    [[nodiscard]] static core::Result<CmpctBlockMessage> deserialize(
        std::span<const uint8_t> data);

    /// Validate the message (limits, index ordering).
    [[nodiscard]] core::Result<void> validate() const;

    /// Return the block hash from the header.
    [[nodiscard]] core::uint256 block_hash() const;

    /// Return the total number of transactions in the block
    /// (short_ids + prefilled).
    [[nodiscard]] size_t total_tx_count() const noexcept;
};

// ---------------------------------------------------------------------------
// GetBlockTxnMessage -- request missing transactions (GETBLOCKTXN command)
// ---------------------------------------------------------------------------
// Sent after receiving a cmpctblock to request transactions that could not
// be reconstructed from the mempool.
//
// Wire format:
//   block_hash       uint256        (32 bytes)
//   index_count      compact_size
//   indices[]        [count]        (compact_size, differentially encoded)
//
// Differential encoding: the first index is stored as-is, subsequent
// indices store (current_index - previous_index - 1).
// ---------------------------------------------------------------------------
struct GetBlockTxnMessage {
    core::uint256          block_hash;
    std::vector<uint16_t>  indices;    // absolute transaction indices

    /// Serialize the getblocktxn message payload.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize a getblocktxn message from raw bytes.
    [[nodiscard]] static core::Result<GetBlockTxnMessage> deserialize(
        std::span<const uint8_t> data);

    /// Validate the message (index count, ordering).
    [[nodiscard]] core::Result<void> validate() const;
};

// ---------------------------------------------------------------------------
// BlockTxnMessage -- deliver requested transactions (BLOCKTXN command)
// ---------------------------------------------------------------------------
// Sent in response to a getblocktxn request, carrying the transactions
// that the requesting node was missing for block reconstruction.
//
// Wire format:
//   block_hash    uint256        (32 bytes)
//   tx_count      compact_size
//   txs[]         [count]        (each serialized in BIP144 format)
// ---------------------------------------------------------------------------
struct BlockTxnMessage {
    core::uint256                         block_hash;
    std::vector<primitives::Transaction>  txs;

    /// Serialize the blocktxn message payload.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize a blocktxn message from raw bytes.
    [[nodiscard]] static core::Result<BlockTxnMessage> deserialize(
        std::span<const uint8_t> data);

    /// Validate the message (tx count).
    [[nodiscard]] core::Result<void> validate() const;
};

} // namespace net::protocol
