#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/coins.h"
#include "core/error.h"
#include "core/serialize.h"
#include "core/stream.h"

#include <cstdint>
#include <span>
#include <vector>

namespace chain { namespace storage {

// ---------------------------------------------------------------------------
// TxUndo -- undo data for a single transaction
// ---------------------------------------------------------------------------
// Stores the coins (UTXOs) that were consumed by a transaction's inputs,
// in input order.  Used to reverse the effects of connecting a block.
// ---------------------------------------------------------------------------
struct TxUndo {
    /// The coins spent by this transaction's inputs (one per input, in order).
    std::vector<chain::Coin> spent_coins;

    /// Serialize to a byte vector.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize from a DataStream.
    [[nodiscard]] static core::Result<TxUndo> deserialize(
        core::DataStream& stream);
};

// ---------------------------------------------------------------------------
// BlockUndo -- undo data for an entire block
// ---------------------------------------------------------------------------
// Contains one TxUndo per transaction in the block EXCEPT the coinbase
// (the coinbase creates new coins and has no inputs to undo).
// ---------------------------------------------------------------------------
struct BlockUndo {
    /// Undo data for each non-coinbase transaction, in block order.
    std::vector<TxUndo> tx_undo;

    /// Serialize the full block undo to a byte vector.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize from a raw byte span.
    [[nodiscard]] static core::Result<BlockUndo> deserialize(
        std::span<const uint8_t> data);
};

}} // namespace chain::storage
