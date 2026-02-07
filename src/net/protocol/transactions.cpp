// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/protocol/transactions.h"

#include "core/error.h"
#include "core/serialize.h"
#include "core/stream.h"
#include "primitives/transaction.h"

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>

namespace net::protocol {

// ===========================================================================
// TxMessage serialization
// ===========================================================================

std::vector<uint8_t> TxMessage::serialize() const {
    // Delegate to the primitives::Transaction serialization which already
    // handles BIP144 segwit format (marker + flag + witness stacks).
    return tx.serialize();
}

// ===========================================================================
// TxMessage deserialization
// ===========================================================================

core::Result<TxMessage> TxMessage::deserialize(
    std::span<const uint8_t> data) {
    try {
        // Reject obviously oversized transaction messages
        if (data.size() > MAX_TX_MESSAGE_SIZE) {
            return core::Error(core::ErrorCode::PARSE_OVERFLOW,
                "TxMessage payload exceeds MAX_TX_MESSAGE_SIZE ("
                + std::to_string(MAX_TX_MESSAGE_SIZE) + " bytes), got "
                + std::to_string(data.size()));
        }

        // Minimum sanity check: a transaction needs at least a version field
        // and a locktime, plus some input/output structure.
        if (data.size() < MIN_TX_MESSAGE_SIZE) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "TxMessage payload too short: "
                + std::to_string(data.size()) + " bytes (min "
                + std::to_string(MIN_TX_MESSAGE_SIZE) + ")");
        }

        core::DataStream stream{data};

        auto tx_result = primitives::Transaction::deserialize(stream);
        if (!tx_result.ok()) {
            return core::Error(core::ErrorCode::PARSE_ERROR,
                "Failed to deserialize TxMessage: "
                + tx_result.error().message());
        }

        TxMessage msg;
        msg.tx = std::move(tx_result).value();
        return msg;
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to deserialize TxMessage: ") + e.what());
    }
}

// ===========================================================================
// TxMessage accessors
// ===========================================================================

const core::uint256& TxMessage::txid() const {
    return tx.txid();
}

const core::uint256& TxMessage::wtxid() const {
    return tx.wtxid();
}

size_t TxMessage::vsize() const {
    return tx.vsize();
}

bool TxMessage::has_witness() const {
    return tx.has_witness();
}

} // namespace net::protocol
