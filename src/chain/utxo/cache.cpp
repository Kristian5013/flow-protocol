// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/utxo/cache.h"

#include "chain/coins.h"
#include "core/error.h"
#include "core/types.h"
#include "primitives/block.h"
#include "primitives/outpoint.h"
#include "primitives/transaction.h"
#include "primitives/txin.h"
#include "primitives/txout.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <vector>

namespace chain::utxo {

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

UtxoCache::UtxoCache() = default;
UtxoCache::~UtxoCache() = default;

// ---------------------------------------------------------------------------
// OutPointHash
// ---------------------------------------------------------------------------

size_t UtxoCache::OutPointHash::operator()(
    const primitives::OutPoint& op) const
{
    // FNV-1a combination of the txid bytes and the output index.
    size_t h = 14695981039346656037ULL;
    const uint8_t* p = op.txid.data();
    for (size_t i = 0; i < op.txid.size(); ++i) {
        h ^= static_cast<size_t>(p[i]);
        h *= 1099511628211ULL;
    }
    h ^= static_cast<size_t>(op.n);
    h *= 1099511628211ULL;
    return h;
}

// ---------------------------------------------------------------------------
// UtxoView interface (shared lock)
// ---------------------------------------------------------------------------

const Coin* UtxoCache::get_coin(const primitives::OutPoint& outpoint) const {
    std::shared_lock lock(mutex_);
    auto it = coins_.find(outpoint);
    if (it == coins_.end()) {
        return nullptr;
    }
    return &it->second;
}

bool UtxoCache::has_coin(const primitives::OutPoint& outpoint) const {
    std::shared_lock lock(mutex_);
    auto it = coins_.find(outpoint);
    return it != coins_.end() && !it->second.is_spent();
}

core::uint256 UtxoCache::get_best_block() const {
    std::shared_lock lock(mutex_);
    return best_block_;
}

size_t UtxoCache::size() const {
    std::shared_lock lock(mutex_);
    return coins_.size();
}

size_t UtxoCache::dynamic_memory_usage() const {
    std::shared_lock lock(mutex_);

    // Estimate: each bucket pointer + each entry (OutPoint + Coin + overhead).
    // OutPoint: 32 (txid) + 4 (n) = 36 bytes
    // Coin: TxOutput (8 amount + vector ~24 header + script data) + 4 height + 1 coinbase
    // Hash map node overhead: ~64 bytes (next pointer, hash, etc.)
    constexpr size_t per_entry_overhead = 64;
    constexpr size_t outpoint_size = 36;
    constexpr size_t coin_base_size = 8 + 24 + 4 + 1; // amount + vector header + height + coinbase

    size_t total = coins_.bucket_count() * sizeof(void*);
    for (const auto& [op, coin] : coins_) {
        total += per_entry_overhead + outpoint_size + coin_base_size;
        total += coin.out.script_pubkey.capacity();
    }
    return total;
}

// ---------------------------------------------------------------------------
// Mutating operations (exclusive lock)
// ---------------------------------------------------------------------------

void UtxoCache::add_coin(const primitives::OutPoint& outpoint, Coin coin) {
    std::unique_lock lock(mutex_);
    coins_.insert_or_assign(outpoint, std::move(coin));
}

std::optional<Coin> UtxoCache::spend_coin(const primitives::OutPoint& outpoint) {
    std::unique_lock lock(mutex_);
    auto it = coins_.find(outpoint);
    if (it == coins_.end()) {
        return std::nullopt;
    }
    Coin spent = std::move(it->second);
    coins_.erase(it);
    return spent;
}

core::Result<std::vector<Coin>> UtxoCache::connect_block(
    const primitives::Block& block, int height)
{
    std::unique_lock lock(mutex_);

    const auto& txs = block.transactions();
    if (txs.empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "block has no transactions");
    }

    std::vector<Coin> spent_coins;

    // Phase 1: spend all inputs (skip coinbase at index 0).
    for (size_t tx_idx = 1; tx_idx < txs.size(); ++tx_idx) {
        const auto& tx = txs[tx_idx];
        for (const auto& input : tx.vin()) {
            auto it = coins_.find(input.prevout);
            if (it == coins_.end()) {
                return core::Error(core::ErrorCode::VALIDATION_ERROR,
                    "missing input coin: " + input.prevout.to_string());
            }
            if (it->second.is_spent()) {
                return core::Error(core::ErrorCode::VALIDATION_ERROR,
                    "attempt to spend already-spent coin: " +
                    input.prevout.to_string());
            }
            spent_coins.push_back(std::move(it->second));
            coins_.erase(it);
        }
    }

    // Phase 2: add all outputs (including coinbase).
    for (size_t tx_idx = 0; tx_idx < txs.size(); ++tx_idx) {
        const auto& tx = txs[tx_idx];
        const core::uint256& txid = tx.txid();
        bool is_cb = tx.is_coinbase();

        for (uint32_t out_idx = 0; out_idx < tx.vout().size(); ++out_idx) {
            const auto& output = tx.vout()[out_idx];
            primitives::OutPoint outpoint(txid, out_idx);
            Coin coin(output, static_cast<int32_t>(height), is_cb);
            coins_.insert_or_assign(outpoint, std::move(coin));
        }
    }

    return spent_coins;
}

core::Result<void> UtxoCache::disconnect_block(
    const primitives::Block& block,
    const std::vector<Coin>& spent_coins)
{
    std::unique_lock lock(mutex_);

    const auto& txs = block.transactions();
    if (txs.empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "block has no transactions");
    }

    // Phase 1: remove all outputs in reverse transaction order.
    for (auto tx_it = txs.rbegin(); tx_it != txs.rend(); ++tx_it) {
        const auto& tx = *tx_it;
        const core::uint256& txid = tx.txid();
        for (uint32_t out_idx = 0; out_idx < tx.vout().size(); ++out_idx) {
            primitives::OutPoint outpoint(txid, out_idx);
            coins_.erase(outpoint);
        }
    }

    // Phase 2: restore spent coins in reverse transaction order
    // (skipping the coinbase, which has no real inputs).
    //
    // The spent_coins vector was built in forward order: tx_1 inputs first,
    // then tx_2 inputs, etc.  We restore in reverse transaction order, so
    // we walk spent_coins from the end backwards.
    size_t spent_idx = spent_coins.size();
    for (auto tx_it = txs.rbegin(); tx_it != txs.rend(); ++tx_it) {
        const auto& tx = *tx_it;
        if (tx.is_coinbase()) {
            continue;
        }
        // This transaction has tx.vin().size() spent coins.
        size_t input_count = tx.vin().size();
        if (spent_idx < input_count) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "spent_coins underflow during disconnect");
        }
        spent_idx -= input_count;

        for (size_t i = 0; i < input_count; ++i) {
            const auto& input = tx.vin()[i];
            coins_.insert_or_assign(input.prevout,
                                    spent_coins[spent_idx + i]);
        }
    }

    if (spent_idx != 0) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "spent_coins count mismatch during disconnect");
    }

    return core::make_ok();
}

void UtxoCache::set_best_block(const core::uint256& hash) {
    std::unique_lock lock(mutex_);
    best_block_ = hash;
}

void UtxoCache::clear() {
    std::unique_lock lock(mutex_);
    coins_.clear();
    best_block_ = core::uint256();
}

std::vector<primitives::OutPoint> UtxoCache::get_all_outpoints() const {
    std::shared_lock lock(mutex_);
    std::vector<primitives::OutPoint> result;
    result.reserve(coins_.size());
    for (const auto& [op, coin] : coins_) {
        result.push_back(op);
    }
    return result;
}

Coin& UtxoCache::access_coin(const primitives::OutPoint& outpoint) {
    std::unique_lock lock(mutex_);
    // operator[] inserts a default-constructed Coin if not present.
    return coins_[outpoint];
}

} // namespace chain::utxo
