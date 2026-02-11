// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/wallet_rpc.h"
#include "rpc/util.h"

#include "core/logging.h"
#include "primitives/address.h"
#include "primitives/script/script.h"
#include "primitives/script/standard.h"
#include "wallet/keys.h"
#include "wallet/wallet.h"

#include <cstdint>
#include <string>

namespace rpc {

namespace {

/// Check that the wallet is available, return error response if not.
bool check_wallet(wallet::Wallet* w, const RpcRequest& req, RpcResponse& err) {
    if (!w) {
        err = make_error(RpcError::WALLET_NOT_FOUND,
                         "No wallet loaded. Start with wallet=1 in config.",
                         req.id);
        return false;
    }
    if (!w->is_loaded()) {
        err = make_error(RpcError::WALLET_NOT_FOUND,
                         "Wallet is not loaded.", req.id);
        return false;
    }
    return true;
}

/// Derive an address string from a scriptPubKey.
std::string address_from_script(const std::vector<uint8_t>& script_pubkey) {
    namespace ps = primitives::script;
    ps::Script script{std::span<const uint8_t>{script_pubkey.data(), script_pubkey.size()}};
    auto solution = ps::solve(script);

    switch (solution.type) {
    case ps::TxoutType::WITNESS_V0_KEYHASH:
        if (!solution.solutions.empty() && solution.solutions[0].size() == 20) {
            core::uint160 hash;
            std::memcpy(hash.data(), solution.solutions[0].data(), 20);
            return primitives::Address::from_witness_v0_keyhash(hash).to_string();
        }
        break;
    case ps::TxoutType::PUBKEYHASH:
        if (!solution.solutions.empty() && solution.solutions[0].size() == 20) {
            core::uint160 hash;
            std::memcpy(hash.data(), solution.solutions[0].data(), 20);
            return primitives::Address::from_pubkey_hash(hash).to_string();
        }
        break;
    case ps::TxoutType::SCRIPTHASH:
        if (!solution.solutions.empty() && solution.solutions[0].size() == 20) {
            core::uint160 hash;
            std::memcpy(hash.data(), solution.solutions[0].data(), 20);
            return primitives::Address::from_script_hash(hash).to_string();
        }
        break;
    case ps::TxoutType::WITNESS_V1_TAPROOT:
        if (!solution.solutions.empty() && solution.solutions[0].size() == 32) {
            core::uint256 key;
            std::memcpy(key.data(), solution.solutions[0].data(), 32);
            return primitives::Address::from_witness_v1_taproot(key).to_string();
        }
        break;
    default:
        break;
    }
    return "(unknown)";
}

} // anonymous namespace

// ===========================================================================
// getbalance
// ===========================================================================

RpcResponse rpc_getbalance(const RpcRequest& req, wallet::Wallet* wallet) {
    RpcResponse err;
    if (!check_wallet(wallet, req, err)) return err;

    auto balance = wallet->get_balance();
    return make_result(JsonValue(format_amount(balance.confirmed.value())), req.id);
}

// ===========================================================================
// getnewaddress
// ===========================================================================

RpcResponse rpc_getnewaddress(const RpcRequest& req, wallet::Wallet* wallet) {
    RpcResponse err;
    if (!check_wallet(wallet, req, err)) return err;

    std::string label = param_string(req.params, 0, "");

    auto result = wallet->get_new_address(label);
    if (!result.ok()) {
        return make_error(RpcError::WALLET_ERROR,
                          result.error().message(), req.id);
    }

    std::string addr = result.value();

    // Also return the private key (WIF + hex) in the same response.
    JsonValue obj(JsonValue::Object{});
    obj["address"] = JsonValue(addr);

    auto key_result = wallet->key_manager().export_key(addr);
    if (key_result.ok()) {
        std::string wif = key_result.value();
        obj["wif"] = JsonValue(wif);
        auto secret = wallet::KeyManager::decode_wif(wif);
        if (secret.ok()) {
            obj["hex"] = JsonValue(hex_encode(secret.value().data(), 32));
        }
    }

    LOG_INFO(core::LogCategory::RPC, "getnewaddress: " + addr);

    return make_result(std::move(obj), req.id);
}

// ===========================================================================
// sendtoaddress
// ===========================================================================

RpcResponse rpc_sendtoaddress(const RpcRequest& req, wallet::Wallet* wallet) {
    RpcResponse err;
    if (!check_wallet(wallet, req, err)) return err;

    std::string addr = param_string(req.params, 0);
    int64_t amount = parse_amount(param_value(req.params, 1));

    if (wallet->is_locked()) {
        return make_error(RpcError::WALLET_UNLOCK_NEEDED,
                          "Wallet is locked, please unlock first", req.id);
    }

    if (amount <= 0) {
        return make_error(RpcError::INVALID_PARAMETER,
                          "Invalid amount", req.id);
    }

    auto result = wallet->send_to_address(addr, primitives::Amount(amount));
    if (!result.ok()) {
        return make_error(RpcError::WALLET_ERROR,
                          result.error().message(), req.id);
    }

    auto& tx = result.value();
    std::string txid_hex = tx.txid().to_hex();

    LOG_INFO(core::LogCategory::RPC,
             "sendtoaddress: " + txid_hex + " to " + addr +
             " amount=" + format_amount(amount));

    return make_result(JsonValue(txid_hex), req.id);
}

// ===========================================================================
// listtransactions
// ===========================================================================

RpcResponse rpc_listtransactions(const RpcRequest& req, wallet::Wallet* wallet) {
    RpcResponse err;
    if (!check_wallet(wallet, req, err)) return err;

    int64_t count = param_int(req.params, 0, 10);
    int64_t skip  = param_int(req.params, 1, 0);

    if (count < 0 || count > 10000) {
        return make_error(RpcError::INVALID_PARAMETER,
                          "Invalid count (0-10000)", req.id);
    }
    if (skip < 0) {
        return make_error(RpcError::INVALID_PARAMETER,
                          "Invalid skip (must be >= 0)", req.id);
    }

    auto txs = wallet->list_transactions(
        static_cast<size_t>(count), static_cast<size_t>(skip));

    JsonValue::Array tx_arr;
    for (const auto& wtx : txs) {
        JsonValue obj(JsonValue::Object{});
        obj["address"]       = JsonValue(wtx.address);
        obj["category"]      = JsonValue(wallet::tx_category_string(wtx.category));
        obj["amount"]        = JsonValue(format_amount(wtx.amount.value()));
        obj["fee"]           = JsonValue(format_amount(wtx.fee.value()));
        obj["confirmations"] = JsonValue(static_cast<int64_t>(wtx.confirmations));
        obj["txid"]          = JsonValue(wtx.txid.to_hex());
        obj["time"]          = JsonValue(wtx.time);
        obj["timereceived"]  = JsonValue(wtx.time);
        tx_arr.push_back(std::move(obj));
    }

    return make_result(JsonValue(std::move(tx_arr)), req.id);
}

// ===========================================================================
// listunspent
// ===========================================================================

RpcResponse rpc_listunspent(const RpcRequest& req, wallet::Wallet* wallet) {
    RpcResponse err;
    if (!check_wallet(wallet, req, err)) return err;

    int64_t minconf = param_int(req.params, 0, 1);
    int64_t maxconf = param_int(req.params, 1, 9999999);

    if (minconf < 0 || maxconf < 0 || minconf > maxconf) {
        return make_error(RpcError::INVALID_PARAMETER,
                          "Invalid confirmation range", req.id);
    }

    auto utxos = wallet->list_unspent(
        static_cast<int>(minconf), static_cast<int>(maxconf));

    JsonValue::Array utxo_arr;
    for (const auto& u : utxos) {
        JsonValue obj(JsonValue::Object{});
        obj["txid"]          = JsonValue(u.outpoint.txid.to_hex());
        obj["vout"]          = JsonValue(static_cast<int64_t>(u.outpoint.n));
        obj["address"]       = JsonValue(address_from_script(u.output.script_pubkey));
        obj["scriptPubKey"]  = JsonValue(hex_encode(u.output.script_pubkey));
        obj["amount"]        = JsonValue(format_amount(u.output.amount.value()));
        obj["spendable"]     = JsonValue(!u.is_spent);
        obj["safe"]          = JsonValue(true);
        utxo_arr.push_back(std::move(obj));
    }

    return make_result(JsonValue(std::move(utxo_arr)), req.id);
}

// ===========================================================================
// dumpprivkey
// ===========================================================================

RpcResponse rpc_dumpprivkey(const RpcRequest& req, wallet::Wallet* wallet) {
    RpcResponse err;
    if (!check_wallet(wallet, req, err)) return err;

    std::string addr = param_string(req.params, 0);

    if (wallet->is_locked()) {
        return make_error(RpcError::WALLET_UNLOCK_NEEDED,
                          "Wallet is locked", req.id);
    }

    auto result = wallet->key_manager().export_key(addr);
    if (!result.ok()) {
        return make_error(RpcError::WALLET_ERROR,
                          "Private key for address " + addr + " is not known",
                          req.id);
    }

    // Also provide the raw hex private key.
    std::string wif = result.value();
    auto secret = wallet::KeyManager::decode_wif(wif);

    JsonValue obj(JsonValue::Object{});
    obj["wif"] = JsonValue(wif);
    if (secret.ok()) {
        obj["hex"] = JsonValue(hex_encode(secret.value().data(), 32));
    }

    return make_result(std::move(obj), req.id);
}

// ===========================================================================
// importprivkey
// ===========================================================================

RpcResponse rpc_rescanwallet(const RpcRequest& req, wallet::Wallet* wallet) {
    RpcResponse err;
    if (!check_wallet(wallet, req, err)) return err;

    int from_height = static_cast<int>(param_int(req.params, 0, 0));

    auto result = wallet->rescan(from_height);
    if (!result.ok()) {
        return make_error(RpcError::WALLET_ERROR,
                          "Rescan failed: " + result.error().message(),
                          req.id);
    }

    JsonValue obj(JsonValue::Object{});
    obj["start_height"] = JsonValue(static_cast<int64_t>(from_height));
    obj["stop_height"] = JsonValue(static_cast<int64_t>(wallet->last_scanned_height()));
    return make_result(obj, req.id);
}

RpcResponse rpc_importprivkey(const RpcRequest& req, wallet::Wallet* wallet) {
    RpcResponse err;
    if (!check_wallet(wallet, req, err)) return err;

    std::string wif = param_string(req.params, 0);

    if (wallet->is_locked()) {
        return make_error(RpcError::WALLET_UNLOCK_NEEDED,
                          "Wallet is locked", req.id);
    }

    auto result = wallet->key_manager().import_key(wif);
    if (!result.ok()) {
        return make_error(RpcError::WALLET_ERROR,
                          "Failed to import private key: " +
                          result.error().message(), req.id);
    }

    LOG_INFO(core::LogCategory::RPC,
             "importprivkey: key imported, address=" + result.value());

    return make_result(JsonValue(nullptr), req.id);
}

// ===========================================================================
// Registration
// ===========================================================================

void register_wallet_rpcs(RpcServer& server, wallet::Wallet* wallet) {
    server.register_commands({
        {"getbalance",
         [wallet](const RpcRequest& r) { return rpc_getbalance(r, wallet); },
         "getbalance\n"
         "Returns the total available balance in FTC.",
         "wallet"},

        {"getnewaddress",
         [wallet](const RpcRequest& r) { return rpc_getnewaddress(r, wallet); },
         "getnewaddress ( \"label\" )\n"
         "Returns a new FTC address with private key (address, wif, hex).",
         "wallet"},

        {"sendtoaddress",
         [wallet](const RpcRequest& r) { return rpc_sendtoaddress(r, wallet); },
         "sendtoaddress \"address\" amount ( \"comment\" )\n"
         "Send an amount to a given address. Returns the transaction id.",
         "wallet"},

        {"listtransactions",
         [wallet](const RpcRequest& r) { return rpc_listtransactions(r, wallet); },
         "listtransactions ( count skip )\n"
         "Returns up to 'count' most recent transactions, skipping the first 'skip'.",
         "wallet"},

        {"listunspent",
         [wallet](const RpcRequest& r) { return rpc_listunspent(r, wallet); },
         "listunspent ( minconf maxconf )\n"
         "Returns array of unspent transaction outputs with between minconf and maxconf confirmations.",
         "wallet"},

        {"dumpprivkey",
         [wallet](const RpcRequest& r) { return rpc_dumpprivkey(r, wallet); },
         "dumpprivkey \"address\"\n"
         "Reveals the private key corresponding to 'address' in WIF and hex format.",
         "wallet"},

        {"importprivkey",
         [wallet](const RpcRequest& r) { return rpc_importprivkey(r, wallet); },
         "importprivkey \"privkey\" ( \"label\" rescan )\n"
         "Adds a private key (WIF format) to your wallet.\n"
         "rescan: rescan the blockchain for transactions (default true).",
         "wallet"},

        {"rescanwallet",
         [wallet](const RpcRequest& r) { return rpc_rescanwallet(r, wallet); },
         "rescanwallet ( start_height )\n"
         "Rescans the blockchain for wallet transactions starting from the given height (default 0).",
         "wallet"},
    });
}

} // namespace rpc
