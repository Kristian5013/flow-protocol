#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "core/types.h"
#include "primitives/amount.h"
#include "primitives/outpoint.h"
#include "primitives/txout.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

namespace chain {

// ---------------------------------------------------------------------------
// Coin -- a single unspent transaction output in the UTXO set
// ---------------------------------------------------------------------------
// Represents a TxOutput together with the metadata needed to validate
// spending: the block height at which it was confirmed, and whether it
// originated from a coinbase transaction (coinbase outputs require a
// maturity period before they can be spent).
//
// A "spent" coin is represented by the sentinel value Amount(-1) in the
// output.  This allows in-place marking without removing from the map,
// which simplifies undo logic.
// ---------------------------------------------------------------------------
struct Coin {
    /// The output itself (amount + scriptPubKey).
    primitives::TxOutput out;

    /// Height of the block that contains the transaction.
    int height = 0;

    /// True if the containing transaction is a coinbase transaction.
    bool is_coinbase = false;

    /// Default constructor: creates a zero-valued, non-coinbase coin.
    Coin() = default;

    /// Construct a coin from an output, block height, and coinbase flag.
    Coin(primitives::TxOutput out_in, int height_in, bool coinbase);

    /// Returns true if this coin has been marked as spent.
    /// A spent coin has its output amount set to the sentinel value -1.
    bool is_spent() const;

    /// Serialize the coin to a byte vector for persistent storage.
    /// Format: height (4 bytes LE) | coinbase flag (1 byte) |
    ///         amount (8 bytes LE) | script_pubkey length (compact size) |
    ///         script_pubkey bytes.
    std::vector<uint8_t> serialize() const;

    /// Deserialize a coin from a byte span.
    /// Returns an error if the data is malformed or too short.
    static core::Result<Coin> deserialize(std::span<const uint8_t> data);

    /// Estimate the dynamic memory usage of this coin (heap allocations).
    /// Useful for tracking UTXO set memory consumption.
    size_t dynamic_memory_usage() const;
};

// ---------------------------------------------------------------------------
// CoinEntry -- key type for the UTXO map
// ---------------------------------------------------------------------------
// Wraps a primitives::OutPoint (txid + output index) for use as a key
// in unordered containers.
// ---------------------------------------------------------------------------
struct CoinEntry {
    primitives::OutPoint outpoint;

    CoinEntry() = default;
    explicit CoinEntry(const primitives::OutPoint& op) : outpoint(op) {}
    CoinEntry(const core::uint256& txid, uint32_t n)
        : outpoint(txid, n) {}

    bool operator==(const CoinEntry& other) const = default;
};

} // namespace chain

// ---------------------------------------------------------------------------
// std::hash specialization for CoinEntry
// ---------------------------------------------------------------------------
template <>
struct std::hash<chain::CoinEntry> {
    std::size_t operator()(const chain::CoinEntry& entry) const noexcept {
        // FNV-1a hash combining the txid bytes and the output index.
        std::size_t h = 14695981039346656037ULL;
        const uint8_t* p = entry.outpoint.txid.data();
        for (std::size_t i = 0; i < entry.outpoint.txid.size(); ++i) {
            h ^= static_cast<std::size_t>(p[i]);
            h *= 1099511628211ULL;
        }
        h ^= static_cast<std::size_t>(entry.outpoint.n);
        h *= 1099511628211ULL;
        return h;
    }
};
