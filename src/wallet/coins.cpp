// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/coins.h"
#include "core/hex.h"
#include "core/logging.h"
#include "core/stream.h"
#include "primitives/script/script.h"

#include <algorithm>
#include <cstring>

namespace wallet {

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

core::Result<void> CoinTracker::init(const KeyManager& keys, WalletDB& db) {
    std::lock_guard lock(mutex_);
    keys_ = &keys;
    db_ = &db;

    auto result = load_coins();
    if (!result.ok()) return result;

    LOG_INFO(core::LogCategory::WALLET,
             "CoinTracker initialized with " +
             std::to_string(coins_.size()) + " coins");
    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// Block scanning
// ---------------------------------------------------------------------------

core::Result<size_t> CoinTracker::scan_block(
    const primitives::Block& block, int height) {
    std::lock_guard lock(mutex_);

    size_t relevant_count = 0;
    const auto& txs = block.transactions();

    for (size_t tx_idx = 0; tx_idx < txs.size(); ++tx_idx) {
        const auto& tx = txs[tx_idx];
        bool is_relevant = false;
        bool is_coinbase_tx = tx.is_coinbase();

        // Check outputs for coins belonging to this wallet.
        for (size_t vout_idx = 0; vout_idx < tx.vout().size(); ++vout_idx) {
            const auto& output = tx.vout()[vout_idx];

            if (check_ownership(output.script_pubkey)) {
                WalletCoin coin;
                coin.outpoint = primitives::OutPoint(
                    tx.txid(), static_cast<uint32_t>(vout_idx));
                coin.output = output;
                coin.height = height;
                coin.is_coinbase = is_coinbase_tx;
                coin.is_change = false;  // Will be updated by AddressBook.
                coin.is_spent = false;

                auto add_result = add_coin(coin);
                if (!add_result.ok()) {
                    LOG_WARN(core::LogCategory::WALLET,
                             "Failed to add coin: " +
                             add_result.error().message());
                }

                is_relevant = true;
            }
        }

        // Check inputs for coins being spent by this wallet.
        if (!is_coinbase_tx) {
            for (const auto& input : tx.vin()) {
                auto it = coins_.find(input.prevout);
                if (it != coins_.end() && !it->second.is_spent) {
                    it->second.is_spent = true;
                    it->second.spending_txid = tx.txid();

                    auto store_result = store_coin(it->second);
                    if (!store_result.ok()) {
                        LOG_WARN(core::LogCategory::WALLET,
                                 "Failed to update spent coin: " +
                                 store_result.error().message());
                    }

                    is_relevant = true;
                }
            }
        }

        if (is_relevant) {
            wallet_txids_.insert(tx.txid());
            ++relevant_count;
        }
    }

    if (relevant_count > 0) {
        LOG_INFO(core::LogCategory::WALLET,
                 "Block " + std::to_string(height) + ": found " +
                 std::to_string(relevant_count) + " wallet transactions");
    }

    return relevant_count;
}

core::Result<bool> CoinTracker::scan_transaction(
    const primitives::Transaction& tx, int height) {
    std::lock_guard lock(mutex_);

    bool is_relevant = false;

    // Check outputs.
    for (size_t vout_idx = 0; vout_idx < tx.vout().size(); ++vout_idx) {
        const auto& output = tx.vout()[vout_idx];

        if (check_ownership(output.script_pubkey)) {
            WalletCoin coin;
            coin.outpoint = primitives::OutPoint(
                tx.txid(), static_cast<uint32_t>(vout_idx));
            coin.output = output;
            coin.height = height;
            coin.is_coinbase = tx.is_coinbase();
            coin.is_change = false;
            coin.is_spent = false;

            auto add_result = add_coin(coin);
            if (!add_result.ok()) {
                LOG_WARN(core::LogCategory::WALLET,
                         "Failed to add coin: " +
                         add_result.error().message());
            }
            is_relevant = true;
        }
    }

    // Check inputs for spending.
    if (!tx.is_coinbase()) {
        for (const auto& input : tx.vin()) {
            auto it = coins_.find(input.prevout);
            if (it != coins_.end() && !it->second.is_spent) {
                it->second.is_spent = true;
                it->second.spending_txid = tx.txid();

                auto store_result = store_coin(it->second);
                if (!store_result.ok()) {
                    LOG_WARN(core::LogCategory::WALLET,
                             "Failed to update spent coin: " +
                             store_result.error().message());
                }
                is_relevant = true;
            }
        }
    }

    if (is_relevant) {
        wallet_txids_.insert(tx.txid());
    }

    return is_relevant;
}

// ---------------------------------------------------------------------------
// Ownership checks
// ---------------------------------------------------------------------------

bool CoinTracker::is_mine(
    const std::vector<uint8_t>& script_pubkey) const {
    std::lock_guard lock(mutex_);
    return check_ownership(script_pubkey);
}

void CoinTracker::set_ownership_check(OwnershipCheck check) {
    std::lock_guard lock(mutex_);
    custom_check_ = std::move(check);
}

bool CoinTracker::check_ownership(
    const std::vector<uint8_t>& script_pubkey) const {
    // First try the custom check if available.
    if (custom_check_ && custom_check_(script_pubkey)) {
        return true;
    }

    // Then try to extract the pubkey hash and check the key manager.
    if (!keys_) return false;

    auto pkh = extract_pubkey_hash(script_pubkey);
    if (pkh.has_value()) {
        return keys_->has_key_for_hash(pkh.value());
    }

    return false;
}

std::optional<core::uint160> CoinTracker::extract_pubkey_hash(
    const std::vector<uint8_t>& script_pubkey) {
    primitives::script::Script script{
        std::span<const uint8_t>{script_pubkey}};

    // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    auto p2pkh_hash = script.get_p2pkh_hash();
    if (p2pkh_hash.has_value()) return p2pkh_hash;

    // P2WPKH: OP_0 <20>
    auto p2wpkh_hash = script.get_p2wpkh_hash();
    if (p2wpkh_hash.has_value()) return p2wpkh_hash;

    // P2SH: We would need the redeem script to determine ownership.
    // For now, P2SH-P2WPKH is handled when the script is P2SH and
    // we recognize the inner script.
    // This is a simplification; a full implementation would track
    // known P2SH scripts.

    return std::nullopt;
}

// ---------------------------------------------------------------------------
// UTXO queries
// ---------------------------------------------------------------------------

std::vector<WalletCoin> CoinTracker::get_spendable_coins(
    int minconf, int chain_height) const {
    std::lock_guard lock(mutex_);

    std::vector<WalletCoin> result;
    for (const auto& [outpoint, coin] : coins_) {
        if (coin.is_spent) continue;

        int confirmations = (coin.height > 0)
            ? (chain_height - coin.height + 1)
            : 0;

        if (confirmations < minconf) continue;

        // Coinbase outputs require COINBASE_MATURITY confirmations.
        if (coin.is_coinbase && confirmations < 100) continue;

        result.push_back(coin);
    }

    // Sort by value (largest first) for better coin selection.
    std::sort(result.begin(), result.end(),
              [](const WalletCoin& a, const WalletCoin& b) {
                  return a.output.amount > b.output.amount;
              });

    return result;
}

std::vector<WalletCoin> CoinTracker::get_all_coins() const {
    std::lock_guard lock(mutex_);

    std::vector<WalletCoin> result;
    result.reserve(coins_.size());
    for (const auto& [outpoint, coin] : coins_) {
        result.push_back(coin);
    }
    return result;
}

primitives::Amount CoinTracker::get_balance(
    int minconf, int chain_height) const {

    auto spendable = get_spendable_coins(minconf, chain_height);
    int64_t total = 0;
    for (const auto& coin : spendable) {
        total += coin.output.amount.value();
    }
    return primitives::Amount(total);
}

core::Result<WalletCoin> CoinTracker::get_coin(
    const primitives::OutPoint& outpoint) const {
    std::lock_guard lock(mutex_);

    auto it = coins_.find(outpoint);
    if (it == coins_.end()) {
        return core::Error(core::ErrorCode::STORAGE_NOT_FOUND,
                           "Coin not found: " + outpoint.to_string());
    }
    return it->second;
}

// ---------------------------------------------------------------------------
// State updates
// ---------------------------------------------------------------------------

core::Result<void> CoinTracker::mark_spent(
    const primitives::OutPoint& outpoint,
    const core::uint256& spending_txid) {
    std::lock_guard lock(mutex_);

    auto it = coins_.find(outpoint);
    if (it == coins_.end()) {
        return core::Error(core::ErrorCode::STORAGE_NOT_FOUND,
                           "Coin not found: " + outpoint.to_string());
    }

    it->second.is_spent = true;
    it->second.spending_txid = spending_txid;
    return store_coin(it->second);
}

core::Result<void> CoinTracker::mark_confirmed(
    const core::uint256& txid, int height) {
    std::lock_guard lock(mutex_);

    bool found = false;
    for (auto& [outpoint, coin] : coins_) {
        if (outpoint.txid == txid && coin.height == 0) {
            coin.height = height;
            auto result = store_coin(coin);
            if (!result.ok()) return result;
            found = true;
        }
    }

    if (!found) {
        return core::Error(core::ErrorCode::STORAGE_NOT_FOUND,
                           "No unconfirmed coins for txid");
    }

    return core::Result<void>{};
}

void CoinTracker::clear_unconfirmed() {
    std::lock_guard lock(mutex_);

    for (auto it = coins_.begin(); it != coins_.end(); ) {
        if (it->second.height == 0) {
            it = coins_.erase(it);
        } else {
            ++it;
        }
    }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

size_t CoinTracker::utxo_count() const {
    std::lock_guard lock(mutex_);
    size_t count = 0;
    for (const auto& [_, coin] : coins_) {
        if (!coin.is_spent) ++count;
    }
    return count;
}

size_t CoinTracker::spent_count() const {
    std::lock_guard lock(mutex_);
    size_t count = 0;
    for (const auto& [_, coin] : coins_) {
        if (coin.is_spent) ++count;
    }
    return count;
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

core::Result<void> CoinTracker::add_coin(const WalletCoin& coin) {
    // Check for duplicate.
    auto it = coins_.find(coin.outpoint);
    if (it != coins_.end()) {
        // Update existing entry if the new one has more information.
        if (coin.height > 0 && it->second.height == 0) {
            it->second.height = coin.height;
            return store_coin(it->second);
        }
        return core::Result<void>{};
    }

    coins_[coin.outpoint] = coin;
    return store_coin(coin);
}

core::Result<void> CoinTracker::load_coins() {
    if (!db_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "CoinTracker not initialized");
    }

    coins_.clear();
    wallet_txids_.clear();

    auto records = db_->read_by_prefix("coin:");
    for (const auto& [db_key, data] : records) {
        // Minimum data size: 32(txid) + 4(n) + 8(amount) + 4(height) +
        //                    1(flags) = 49, plus variable script
        if (data.size() < 49) {
            LOG_WARN(core::LogCategory::WALLET,
                     "Skipping malformed coin record: " + db_key);
            continue;
        }

        WalletCoin coin;
        size_t pos = 0;

        // Read txid (32 bytes).
        std::array<uint8_t, 32> txid_bytes{};
        std::copy(data.begin() + pos, data.begin() + pos + 32,
                  txid_bytes.begin());
        coin.outpoint.txid = core::uint256::from_bytes(
            std::span<const uint8_t, 32>(txid_bytes));
        pos += 32;

        // Read output index (4 bytes LE).
        coin.outpoint.n = static_cast<uint32_t>(data[pos]) |
                          (static_cast<uint32_t>(data[pos+1]) << 8) |
                          (static_cast<uint32_t>(data[pos+2]) << 16) |
                          (static_cast<uint32_t>(data[pos+3]) << 24);
        pos += 4;

        // Read amount (8 bytes LE).
        int64_t amount_val = 0;
        for (int i = 0; i < 8; ++i) {
            amount_val |= static_cast<int64_t>(data[pos + i]) << (i * 8);
        }
        coin.output.amount = primitives::Amount(amount_val);
        pos += 8;

        // Read height (4 bytes LE).
        coin.height = static_cast<int>(
            static_cast<uint32_t>(data[pos]) |
            (static_cast<uint32_t>(data[pos+1]) << 8) |
            (static_cast<uint32_t>(data[pos+2]) << 16) |
            (static_cast<uint32_t>(data[pos+3]) << 24));
        pos += 4;

        // Read flags (1 byte).
        uint8_t flags = data[pos++];
        coin.is_change = (flags & 0x01) != 0;
        coin.is_coinbase = (flags & 0x02) != 0;
        coin.is_spent = (flags & 0x04) != 0;

        // Read script_pubkey (remaining bytes).
        if (pos < data.size()) {
            coin.output.script_pubkey.assign(
                data.begin() + pos, data.end());
        }

        coins_[coin.outpoint] = coin;
        wallet_txids_.insert(coin.outpoint.txid);
    }

    return core::Result<void>{};
}

core::Result<void> CoinTracker::store_coin(const WalletCoin& coin) {
    if (!db_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "CoinTracker not initialized");
    }

    std::vector<uint8_t> data;
    data.reserve(49 + coin.output.script_pubkey.size());

    // Txid (32 bytes).
    data.insert(data.end(),
                coin.outpoint.txid.data(),
                coin.outpoint.txid.data() + 32);

    // Output index (4 bytes LE).
    uint32_t n = coin.outpoint.n;
    data.push_back(static_cast<uint8_t>(n & 0xFF));
    data.push_back(static_cast<uint8_t>((n >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>((n >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((n >> 24) & 0xFF));

    // Amount (8 bytes LE).
    int64_t amount_val = coin.output.amount.value();
    for (int i = 0; i < 8; ++i) {
        data.push_back(static_cast<uint8_t>(
            (amount_val >> (i * 8)) & 0xFF));
    }

    // Height (4 bytes LE).
    auto h = static_cast<uint32_t>(coin.height);
    data.push_back(static_cast<uint8_t>(h & 0xFF));
    data.push_back(static_cast<uint8_t>((h >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>((h >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((h >> 24) & 0xFF));

    // Flags (1 byte).
    uint8_t flags = 0;
    if (coin.is_change) flags |= 0x01;
    if (coin.is_coinbase) flags |= 0x02;
    if (coin.is_spent) flags |= 0x04;
    data.push_back(flags);

    // Script pubkey.
    data.insert(data.end(),
                coin.output.script_pubkey.begin(),
                coin.output.script_pubkey.end());

    std::string db_key = "coin:" + coin.outpoint.to_string();
    return db_->write(db_key, std::span<const uint8_t>(data));
}

} // namespace wallet
