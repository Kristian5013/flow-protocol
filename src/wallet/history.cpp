// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/history.h"
#include "core/hex.h"
#include "core/logging.h"
#include "wallet/addresses.h"
#include "wallet/balance.h"
#include "wallet/keys.h"

#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace wallet {

// ---------------------------------------------------------------------------
// TxCategory string conversion
// ---------------------------------------------------------------------------

std::string tx_category_string(TxCategory category) {
    switch (category) {
        case TxCategory::SEND:     return "send";
        case TxCategory::RECEIVE:  return "receive";
        case TxCategory::GENERATE: return "generate";
        case TxCategory::IMMATURE: return "immature";
        case TxCategory::ORPHAN:   return "orphan";
        default:                    return "unknown";
    }
}

// ---------------------------------------------------------------------------
// Transaction categorization
// ---------------------------------------------------------------------------

TxCategory categorize_transaction(
    const WalletTx& wtx, int chain_height, int coinbase_maturity) {

    // Coinbase transactions.
    if (wtx.category == TxCategory::GENERATE ||
        wtx.category == TxCategory::IMMATURE) {
        int confirmations = 0;
        if (wtx.height > 0 && chain_height >= wtx.height) {
            confirmations = chain_height - wtx.height + 1;
        }

        if (confirmations < 1) {
            return TxCategory::ORPHAN;
        } else if (confirmations < coinbase_maturity) {
            return TxCategory::IMMATURE;
        } else {
            return TxCategory::GENERATE;
        }
    }

    if (wtx.is_send) return TxCategory::SEND;
    return TxCategory::RECEIVE;
}

// ---------------------------------------------------------------------------
// Build transaction history from coins
// ---------------------------------------------------------------------------

namespace {

/// Build wallet transactions from the coin set. Groups coins by txid
/// and determines net amounts and categories.
std::vector<WalletTx> build_tx_list(
    const CoinTracker& coins,
    const KeyManager& keys,
    const AddressBook& addresses,
    int chain_height) {

    auto all_coins = coins.get_all_coins();

    // Group coins by txid. Track both outputs (received) and spending txids.
    struct TxInfo {
        core::uint256 txid;
        int64_t received = 0;
        int64_t sent = 0;
        int height = 0;
        int64_t time = 0;
        bool is_coinbase = false;
        std::vector<std::string> out_addrs;
        size_t num_outputs = 0;
        size_t num_inputs = 0;
    };

    std::unordered_map<core::uint256, TxInfo> tx_map;

    for (const auto& coin : all_coins) {
        // Record this coin's txid as a receiving transaction.
        auto& info = tx_map[coin.outpoint.txid];
        info.txid = coin.outpoint.txid;
        info.received += coin.output.amount.value();
        if (coin.height > 0 && (info.height == 0 || coin.height < info.height)) {
            info.height = coin.height;
        }
        info.is_coinbase = info.is_coinbase || coin.is_coinbase;
        ++info.num_outputs;

        // Try to determine the address for this output.
        primitives::script::Script script(std::span<const uint8_t>(
            coin.output.script_pubkey));
        auto p2wpkh = script.get_p2wpkh_hash();
        auto p2pkh = script.get_p2pkh_hash();

        std::string addr_str;
        if (p2wpkh.has_value()) {
            auto addr = primitives::Address::from_witness_v0_keyhash(
                p2wpkh.value());
            addr_str = addr.to_string();
        } else if (p2pkh.has_value()) {
            auto addr = primitives::Address::from_pubkey_hash(p2pkh.value());
            addr_str = addr.to_string();
        }

        if (!addr_str.empty()) {
            info.out_addrs.push_back(addr_str);
        }

        // If this coin was spent, record the spending transaction.
        if (coin.is_spent && !coin.spending_txid.is_zero()) {
            auto& spend_info = tx_map[coin.spending_txid];
            spend_info.txid = coin.spending_txid;
            spend_info.sent += coin.output.amount.value();
            ++spend_info.num_inputs;
        }
    }

    // Build WalletTx entries.
    std::vector<WalletTx> result;
    result.reserve(tx_map.size());

    for (auto& [txid, info] : tx_map) {
        WalletTx wtx;
        wtx.txid = txid;
        wtx.height = info.height;

        int confirmations = 0;
        if (info.height > 0 && chain_height >= info.height) {
            confirmations = chain_height - info.height + 1;
        }
        wtx.confirmations = confirmations;

        // Estimate time from height (approximately 60 seconds per block
        // from genesis time). In production this would come from the
        // block header timestamp.
        // For now, use height as a proxy for ordering.
        wtx.time = static_cast<int64_t>(info.height);

        // Calculate net amount.
        int64_t net = info.received - info.sent;
        wtx.amount = primitives::Amount(net);
        wtx.is_send = (info.sent > 0 && info.received <= info.sent);

        if (wtx.is_send) {
            // For send transactions, the "amount" is the net outflow.
            wtx.fee = primitives::Amount(info.sent - info.received);
            wtx.amount = primitives::Amount(-info.sent + info.received);
        } else {
            wtx.fee = primitives::Amount(0);
        }

        // Determine category.
        if (info.is_coinbase) {
            if (confirmations < COINBASE_MATURITY) {
                wtx.category = TxCategory::IMMATURE;
            } else {
                wtx.category = TxCategory::GENERATE;
            }
        } else if (wtx.is_send) {
            wtx.category = TxCategory::SEND;
        } else {
            wtx.category = TxCategory::RECEIVE;
        }

        // Set address and label.
        wtx.output_addresses = std::move(info.out_addrs);
        if (!wtx.output_addresses.empty()) {
            wtx.address = wtx.output_addresses[0];
            wtx.label = addresses.get_label(wtx.address);
        }

        wtx.num_inputs = info.num_inputs;
        wtx.num_outputs = info.num_outputs;

        result.push_back(std::move(wtx));
    }

    return result;
}

/// Apply filter to a list of wallet transactions.
std::vector<WalletTx> apply_filter(
    std::vector<WalletTx>& txs, TxFilter filter) {
    if (filter == TxFilter::ALL) return txs;

    std::vector<WalletTx> filtered;
    for (auto& tx : txs) {
        bool include = false;
        switch (filter) {
            case TxFilter::SEND:
                include = (tx.category == TxCategory::SEND);
                break;
            case TxFilter::RECEIVE:
                include = (tx.category == TxCategory::RECEIVE);
                break;
            case TxFilter::COINBASE:
                include = (tx.category == TxCategory::GENERATE ||
                           tx.category == TxCategory::IMMATURE);
                break;
            default:
                include = true;
                break;
        }
        if (include) {
            filtered.push_back(std::move(tx));
        }
    }
    return filtered;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::vector<WalletTx> get_transactions(
    const WalletDB& db,
    const CoinTracker& coins,
    const KeyManager& keys,
    const AddressBook& addresses,
    int chain_height,
    size_t count,
    size_t skip,
    TxFilter filter) {

    // Build the full transaction list from coins.
    auto all_txs = build_tx_list(coins, keys, addresses, chain_height);

    // Also load any stored transaction records that might not be in the
    // coin set (e.g., historical send transactions).
    auto stored_keys = db.list_by_prefix("tx:");
    for (const auto& key : stored_keys) {
        // Extract txid hex from "tx:<hex>".
        if (key.size() <= 3) continue;
        std::string txid_hex = key.substr(3);

        auto txid = core::uint256::from_hex(txid_hex);

        // Check if we already have this transaction.
        bool found = false;
        for (const auto& tx : all_txs) {
            if (tx.txid == txid) {
                found = true;
                break;
            }
        }

        if (!found) {
            auto loaded = load_wallet_tx(db, txid);
            if (loaded.ok()) {
                // Update confirmations.
                auto& wtx = loaded.value();
                if (wtx.height > 0 && chain_height >= wtx.height) {
                    wtx.confirmations = chain_height - wtx.height + 1;
                }
                wtx.category = categorize_transaction(
                    wtx, chain_height);
                all_txs.push_back(std::move(wtx));
            }
        }
    }

    // Apply filter.
    auto filtered = apply_filter(all_txs, filter);

    // Sort by time/height, newest first.
    std::sort(filtered.begin(), filtered.end(),
              [](const WalletTx& a, const WalletTx& b) {
                  if (a.height != b.height) {
                      // Unconfirmed (height 0) comes first (newest).
                      if (a.height == 0) return true;
                      if (b.height == 0) return false;
                      return a.height > b.height;
                  }
                  return a.time > b.time;
              });

    // Apply pagination.
    if (skip >= filtered.size()) return {};

    auto begin = filtered.begin() + static_cast<ptrdiff_t>(skip);
    auto end = begin + static_cast<ptrdiff_t>(
        std::min(count, filtered.size() - skip));

    return std::vector<WalletTx>(begin, end);
}

core::Result<WalletTx> get_transaction_detail(
    const WalletDB& db,
    const CoinTracker& coins,
    const KeyManager& keys,
    const AddressBook& addresses,
    const core::uint256& txid,
    int chain_height) {

    // First try loading from the DB.
    auto db_result = load_wallet_tx(db, txid);
    if (db_result.ok()) {
        auto& wtx = db_result.value();
        if (wtx.height > 0 && chain_height >= wtx.height) {
            wtx.confirmations = chain_height - wtx.height + 1;
        }
        wtx.category = categorize_transaction(wtx, chain_height);
        return wtx;
    }

    // Fall back to building from coins.
    auto all_txs = build_tx_list(coins, keys, addresses, chain_height);
    for (auto& tx : all_txs) {
        if (tx.txid == txid) {
            return tx;
        }
    }

    return core::Error(core::ErrorCode::STORAGE_NOT_FOUND,
                       "Transaction not found: " + txid.to_hex());
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

core::Result<void> store_wallet_tx(WalletDB& db, const WalletTx& wtx) {
    // Serialize: amount(8) + fee(8) + height(4) + time(8) + flags(1) +
    //            address_len(2) + address + label_len(2) + label
    std::vector<uint8_t> data;
    data.reserve(64);

    // Amount (8 bytes LE).
    int64_t amount_val = wtx.amount.value();
    for (int i = 0; i < 8; ++i) {
        data.push_back(static_cast<uint8_t>((amount_val >> (i * 8)) & 0xFF));
    }

    // Fee (8 bytes LE).
    int64_t fee_val = wtx.fee.value();
    for (int i = 0; i < 8; ++i) {
        data.push_back(static_cast<uint8_t>((fee_val >> (i * 8)) & 0xFF));
    }

    // Height (4 bytes LE).
    auto h = static_cast<uint32_t>(wtx.height);
    data.push_back(static_cast<uint8_t>(h & 0xFF));
    data.push_back(static_cast<uint8_t>((h >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>((h >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((h >> 24) & 0xFF));

    // Time (8 bytes LE).
    for (int i = 0; i < 8; ++i) {
        data.push_back(static_cast<uint8_t>(
            (wtx.time >> (i * 8)) & 0xFF));
    }

    // Flags (1 byte).
    uint8_t flags = 0;
    if (wtx.is_send) flags |= 0x01;
    flags |= (static_cast<uint8_t>(wtx.category) << 1);
    data.push_back(flags);

    // Address (2B len + bytes).
    auto addr_len = static_cast<uint16_t>(
        std::min(wtx.address.size(), size_t(65535)));
    data.push_back(static_cast<uint8_t>(addr_len & 0xFF));
    data.push_back(static_cast<uint8_t>((addr_len >> 8) & 0xFF));
    if (addr_len > 0) {
        data.insert(data.end(), wtx.address.begin(),
                    wtx.address.begin() + addr_len);
    }

    // Label (2B len + bytes).
    auto label_len = static_cast<uint16_t>(
        std::min(wtx.label.size(), size_t(65535)));
    data.push_back(static_cast<uint8_t>(label_len & 0xFF));
    data.push_back(static_cast<uint8_t>((label_len >> 8) & 0xFF));
    if (label_len > 0) {
        data.insert(data.end(), wtx.label.begin(),
                    wtx.label.begin() + label_len);
    }

    std::string db_key = "tx:" + wtx.txid.to_hex();
    return db.write(db_key, std::span<const uint8_t>(data));
}

core::Result<WalletTx> load_wallet_tx(const WalletDB& db,
                                        const core::uint256& txid) {
    std::string db_key = "tx:" + txid.to_hex();
    auto data_result = db.read(db_key);
    if (!data_result.ok()) {
        return data_result.error();
    }

    const auto& data = data_result.value();
    // Minimum: 8 + 8 + 4 + 8 + 1 + 2 + 2 = 33 bytes.
    if (data.size() < 33) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Transaction record too short");
    }

    WalletTx wtx;
    wtx.txid = txid;
    size_t pos = 0;

    // Amount (8 bytes LE).
    int64_t amount_val = 0;
    for (int i = 0; i < 8; ++i) {
        amount_val |= static_cast<int64_t>(data[pos + i]) << (i * 8);
    }
    wtx.amount = primitives::Amount(amount_val);
    pos += 8;

    // Fee (8 bytes LE).
    int64_t fee_val = 0;
    for (int i = 0; i < 8; ++i) {
        fee_val |= static_cast<int64_t>(data[pos + i]) << (i * 8);
    }
    wtx.fee = primitives::Amount(fee_val);
    pos += 8;

    // Height (4 bytes LE).
    wtx.height = static_cast<int>(
        static_cast<uint32_t>(data[pos]) |
        (static_cast<uint32_t>(data[pos+1]) << 8) |
        (static_cast<uint32_t>(data[pos+2]) << 16) |
        (static_cast<uint32_t>(data[pos+3]) << 24));
    pos += 4;

    // Time (8 bytes LE).
    wtx.time = 0;
    for (int i = 0; i < 8; ++i) {
        wtx.time |= static_cast<int64_t>(data[pos + i]) << (i * 8);
    }
    pos += 8;

    // Flags (1 byte).
    uint8_t flags = data[pos++];
    wtx.is_send = (flags & 0x01) != 0;
    wtx.category = static_cast<TxCategory>((flags >> 1) & 0x07);

    // Address.
    if (pos + 2 <= data.size()) {
        uint16_t addr_len = static_cast<uint16_t>(data[pos]) |
                            (static_cast<uint16_t>(data[pos+1]) << 8);
        pos += 2;
        if (addr_len > 0 && pos + addr_len <= data.size()) {
            wtx.address.assign(
                reinterpret_cast<const char*>(data.data() + pos),
                addr_len);
            pos += addr_len;
        }
    }

    // Label.
    if (pos + 2 <= data.size()) {
        uint16_t label_len = static_cast<uint16_t>(data[pos]) |
                             (static_cast<uint16_t>(data[pos+1]) << 8);
        pos += 2;
        if (label_len > 0 && pos + label_len <= data.size()) {
            wtx.label.assign(
                reinterpret_cast<const char*>(data.data() + pos),
                label_len);
        }
    }

    return wtx;
}

} // namespace wallet
