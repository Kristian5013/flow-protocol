#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "core/types.h"
#include "primitives/transaction.h"

#include <cstdint>
#include <span>
#include <vector>

namespace net::protocol {

// ---------------------------------------------------------------------------
// Protocol constants for transaction messages
// ---------------------------------------------------------------------------

/// Maximum serialized size of a single transaction message (400 kB).
/// This is a network-layer DoS protection limit.  Actual consensus limits
/// on transaction size (weight) may be more nuanced.
inline constexpr size_t MAX_TX_MESSAGE_SIZE = 400 * 1024;

/// Minimum size of a valid transaction on the wire.
/// A minimal non-witness transaction is: version(4) + vin_count(1) +
/// prevout(32+4) + script_len(1) + sequence(4) + vout_count(1) +
/// value(8) + script_len(1) + locktime(4) = ~60 bytes.
inline constexpr size_t MIN_TX_MESSAGE_SIZE = 10;

// ---------------------------------------------------------------------------
// TxMessage -- wraps a primitives::Transaction for P2P serialization
// ---------------------------------------------------------------------------
// The tx message delivers a single transaction, typically in response to a
// getdata request or as an unsolicited relay from a peer.  The wire format
// is the BIP144 segwit-aware serialization: if witness data is present,
// the marker byte (0x00) and flag byte (0x01) are inserted after the version
// field, and witness stacks follow the outputs.
//
// Wire format (BIP144 segwit):
//   version      int32            (4 bytes)
//   marker       uint8 = 0x00    (1 byte, only if witness)
//   flag         uint8 = 0x01    (1 byte, only if witness)
//   vin_count    compact_size
//   vin[]        [serialized inputs]
//   vout_count   compact_size
//   vout[]       [serialized outputs]
//   witness[]    [witness stacks, only if witness]
//   locktime     uint32           (4 bytes)
// ---------------------------------------------------------------------------
struct TxMessage {
    primitives::Transaction tx;

    /// Serialize the tx message payload using BIP144 format.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize a tx message from raw bytes.
    [[nodiscard]] static core::Result<TxMessage> deserialize(
        std::span<const uint8_t> data);

    /// Return the transaction ID (non-witness hash).
    [[nodiscard]] const core::uint256& txid() const;

    /// Return the witness transaction ID.
    [[nodiscard]] const core::uint256& wtxid() const;

    /// Return the virtual size of the transaction in vbytes.
    [[nodiscard]] size_t vsize() const;

    /// Return true if the transaction contains witness data.
    [[nodiscard]] bool has_witness() const;
};

} // namespace net::protocol
