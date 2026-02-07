// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/rawtransaction.h"
#include "rpc/util.h"

#include "chain/chainstate.h"
#include "chain/utxo/cache.h"
#include "core/hex.h"
#include "core/logging.h"
#include "core/stream.h"
#include "core/time.h"
#include "core/types.h"
#include "crypto/secp256k1.h"
#include "mempool/entry.h"
#include "mempool/mempool.h"
#include "primitives/address.h"
#include "primitives/amount.h"
#include "primitives/outpoint.h"
#include "primitives/script/script.h"
#include "primitives/script/sign.h"
#include "primitives/transaction.h"
#include "primitives/txin.h"
#include "primitives/txout.h"
#include "wallet/keys.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace rpc {

namespace {

/// Convert a Transaction to a detailed JSON object.
JsonValue tx_to_verbose_json(const primitives::Transaction& tx) {
    JsonValue obj(JsonValue::Object{});
    obj["txid"]     = JsonValue(tx.txid().to_hex());
    obj["hash"]     = JsonValue(tx.wtxid().to_hex());
    obj["version"]  = JsonValue(static_cast<int64_t>(tx.version()));
    obj["size"]     = JsonValue(static_cast<int64_t>(tx.total_size()));
    obj["vsize"]    = JsonValue(static_cast<int64_t>(tx.vsize()));
    obj["weight"]   = JsonValue(static_cast<int64_t>(tx.weight()));
    obj["locktime"] = JsonValue(static_cast<int64_t>(tx.locktime()));

    // Inputs
    JsonValue::Array vin_arr;
    for (size_t i = 0; i < tx.vin().size(); ++i) {
        const auto& input = tx.vin()[i];
        JsonValue in_obj(JsonValue::Object{});

        if (tx.is_coinbase()) {
            in_obj["coinbase"] = JsonValue(hex_encode(
                input.script_sig.data(), input.script_sig.size()));
        } else {
            in_obj["txid"] = JsonValue(input.prevout.txid.to_hex());
            in_obj["vout"] = JsonValue(static_cast<int64_t>(input.prevout.n));

            JsonValue script_sig(JsonValue::Object{});
            script_sig["asm"] = JsonValue("");
            script_sig["hex"] = JsonValue(hex_encode(
                input.script_sig.data(), input.script_sig.size()));
            in_obj["scriptSig"] = std::move(script_sig);
        }
        in_obj["sequence"] = JsonValue(static_cast<int64_t>(input.sequence));

        if (input.has_witness()) {
            JsonValue::Array wit_arr;
            for (const auto& item : input.witness) {
                wit_arr.push_back(JsonValue(hex_encode(item.data(), item.size())));
            }
            in_obj["txinwitness"] = JsonValue(std::move(wit_arr));
        }
        vin_arr.push_back(std::move(in_obj));
    }
    obj["vin"] = JsonValue(std::move(vin_arr));

    // Outputs
    JsonValue::Array vout_arr;
    for (size_t i = 0; i < tx.vout().size(); ++i) {
        const auto& output = tx.vout()[i];
        JsonValue out_obj(JsonValue::Object{});
        out_obj["value"] = JsonValue(format_amount(output.amount.value()));
        out_obj["n"]     = JsonValue(static_cast<int64_t>(i));

        JsonValue script_pk(JsonValue::Object{});
        script_pk["asm"] = JsonValue("");
        script_pk["hex"] = JsonValue(hex_encode(
            output.script_pubkey.data(), output.script_pubkey.size()));
        script_pk["type"] = JsonValue("unknown");
        out_obj["scriptPubKey"] = std::move(script_pk);

        vout_arr.push_back(std::move(out_obj));
    }
    obj["vout"] = JsonValue(std::move(vout_arr));

    return obj;
}

/// Deserialize a transaction from a hex string.
primitives::Transaction deserialize_tx_hex(const std::string& hex_str) {
    auto bytes = hex_decode(hex_str);
    if (bytes.empty()) {
        throw std::runtime_error("Empty transaction data");
    }
    core::DataStream stream(std::move(bytes));
    auto result = primitives::Transaction::deserialize(stream);
    if (!result.ok()) {
        throw std::runtime_error(
            "TX deserialization failed: " + result.error().message());
    }
    return std::move(result).value();
}

} // anonymous namespace

// ===========================================================================
// getrawtransaction
// ===========================================================================

RpcResponse rpc_getrawtransaction(const RpcRequest& req,
                                   chain::ChainstateManager& chainstate,
                                   mempool::Mempool& mempool) {
    std::string txid_hex = param_string(req.params, 0);
    bool verbose = param_bool(req.params, 1, false);

    if (!is_valid_hex(txid_hex, 32)) {
        return make_error(RpcError::INVALID_PARAMS,
                          "Invalid txid", req.id);
    }

    core::uint256 txid = core::uint256::from_hex(txid_hex);

    // Check mempool first
    const auto* entry = mempool.get(txid);
    if (entry) {
        if (!verbose) {
            auto serialized = entry->tx.serialize();
            return make_result(
                JsonValue(hex_encode(serialized.data(), serialized.size())),
                req.id);
        }

        JsonValue result = tx_to_verbose_json(entry->tx);
        // Add mempool-specific info
        result["confirmations"] = JsonValue(static_cast<int64_t>(0));
        result["time"]          = JsonValue(entry->time);
        result["blocktime"]     = JsonValue(static_cast<int64_t>(0));
        return make_result(std::move(result), req.id);
    }

    // Transaction not in mempool; in a full implementation we would search
    // the UTXO set or a transaction index. For now, report not found.
    return make_error(RpcError::INVALID_PARAMS,
                      "Transaction not found: " + txid_hex, req.id);
}

// ===========================================================================
// decoderawtransaction
// ===========================================================================

RpcResponse rpc_decoderawtransaction(const RpcRequest& req) {
    std::string hex_str = param_string(req.params, 0);

    primitives::Transaction tx;
    try {
        tx = deserialize_tx_hex(hex_str);
    } catch (const std::exception& e) {
        return make_error(RpcError::DESERIALIZATION_ERROR, e.what(), req.id);
    }

    return make_result(tx_to_verbose_json(tx), req.id);
}

// ===========================================================================
// sendrawtransaction
// ===========================================================================

RpcResponse rpc_sendrawtransaction(const RpcRequest& req,
                                    chain::ChainstateManager& chainstate,
                                    mempool::Mempool& mempool) {
    std::string hex_str = param_string(req.params, 0);

    primitives::Transaction tx;
    try {
        tx = deserialize_tx_hex(hex_str);
    } catch (const std::exception& e) {
        return make_error(RpcError::DESERIALIZATION_ERROR, e.what(), req.id);
    }

    core::uint256 txid = tx.txid();

    // Check if already in mempool
    if (mempool.exists(txid)) {
        return make_error(RpcError::VERIFY_ALREADY_IN_CHAIN,
                          "Transaction already in mempool", req.id);
    }

    // Compute fee: sum(inputs) - sum(outputs)
    std::lock_guard<std::recursive_mutex> cs_lock(chainstate.cs_main());

    int64_t input_total = 0;
    for (const auto& input : tx.vin()) {
        const auto* coin = chainstate.utxo_set().get_coin(input.prevout);
        if (!coin || coin->is_spent()) {
            return make_error(RpcError::VERIFY_REJECTED,
                              "Input not found in UTXO set: " +
                              input.prevout.txid.to_hex() + ":" +
                              std::to_string(input.prevout.n), req.id);
        }
        input_total += coin->out.amount.value();
    }

    int64_t output_total = 0;
    for (const auto& output : tx.vout()) {
        output_total += output.amount.value();
    }

    int64_t fee = input_total - output_total;
    if (fee < 0) {
        return make_error(RpcError::VERIFY_REJECTED,
                          "Transaction outputs exceed inputs", req.id);
    }

    int chain_height = chainstate.active_chain().height();

    auto entry = mempool::MempoolEntry::from_tx(
        tx, primitives::Amount(fee),
        chain_height,
        core::get_time());

    auto result = mempool.add(std::move(entry));
    if (!result.ok()) {
        return make_error(RpcError::VERIFY_REJECTED,
                          "Transaction rejected: " + result.error().message(),
                          req.id);
    }

    LOG_INFO(core::LogCategory::RPC,
             "sendrawtransaction: " + txid.to_hex() +
             " fee=" + std::to_string(fee) + " sat");

    return make_result(JsonValue(txid.to_hex()), req.id);
}

// ===========================================================================
// createrawtransaction
// ===========================================================================

RpcResponse rpc_createrawtransaction(const RpcRequest& req) {
    // params[0] = inputs: [{"txid":"hex","vout":n}, ...]
    // params[1] = outputs: {"address":amount, ...} or [{"address":amount}, ...]
    // params[2] = locktime (optional, default 0)

    const auto& inputs_val = param_value(req.params, 0);
    const auto& outputs_val = param_value(req.params, 1);
    int64_t locktime = param_int(req.params, 2, 0);

    if (!inputs_val.is_array()) {
        return make_error(RpcError::INVALID_PARAMS,
                          "Inputs must be an array", req.id);
    }

    // Parse inputs
    std::vector<primitives::TxInput> vin;
    for (const auto& inp : inputs_val.get_array()) {
        if (!inp.is_object()) {
            return make_error(RpcError::INVALID_PARAMS,
                              "Each input must be an object", req.id);
        }
        const auto& txid_val = inp["txid"];
        const auto& vout_val = inp["vout"];

        if (!txid_val.is_string() || !vout_val.is_int()) {
            return make_error(RpcError::INVALID_PARAMS,
                              "Input must have 'txid' (string) and 'vout' (int)",
                              req.id);
        }

        std::string txid_hex = txid_val.get_string();
        if (!is_valid_hex(txid_hex, 32)) {
            return make_error(RpcError::INVALID_PARAMS,
                              "Invalid txid in input", req.id);
        }

        primitives::OutPoint outpoint;
        outpoint.txid = core::uint256::from_hex(txid_hex);
        outpoint.n = static_cast<uint32_t>(vout_val.get_int());

        primitives::TxInput input;
        input.prevout = outpoint;
        input.sequence = inp.has_key("sequence")
            ? static_cast<uint32_t>(inp["sequence"].get_int())
            : 0xFFFFFFFE; // enable RBF by default

        vin.push_back(std::move(input));
    }

    // Parse outputs
    std::vector<primitives::TxOutput> vout;

    if (outputs_val.is_object()) {
        for (const auto& [addr, amount_val] : outputs_val.get_object()) {
            int64_t satoshis = parse_amount(amount_val);
            primitives::TxOutput output;
            output.amount = primitives::Amount(satoshis);
            // The script_pubkey would be derived from the address in a full
            // implementation. For raw transaction creation, we store a
            // placeholder. The actual address-to-script conversion should use
            // primitives::Address::from_string().
            // For now, if the key is "data", treat the value as an OP_RETURN
            if (addr == "data") {
                // OP_RETURN output
                std::string data_hex = amount_val.get_string();
                auto data_bytes = hex_decode(data_hex);
                output.amount = primitives::Amount(0);
                output.script_pubkey.push_back(0x6a); // OP_RETURN
                output.script_pubkey.push_back(
                    static_cast<uint8_t>(data_bytes.size()));
                output.script_pubkey.insert(output.script_pubkey.end(),
                    data_bytes.begin(), data_bytes.end());
            } else {
                // Normal output -- convert address to scriptPubKey
                auto addr_result = primitives::Address::from_string(addr);
                if (!addr_result.ok()) {
                    return make_error(RpcError::INVALID_PARAMS,
                                      "Invalid address: " + addr, req.id);
                }
                auto script = addr_result.value().to_script();
                output.script_pubkey = script.data();
            }
            vout.push_back(std::move(output));
        }
    } else if (outputs_val.is_array()) {
        for (const auto& out_item : outputs_val.get_array()) {
            if (!out_item.is_object()) {
                return make_error(RpcError::INVALID_PARAMS,
                                  "Each output must be an object", req.id);
            }
            for (const auto& [addr, amount_val] : out_item.get_object()) {
                int64_t satoshis = parse_amount(amount_val);
                primitives::TxOutput output;
                output.amount = primitives::Amount(satoshis);
                auto addr_result = primitives::Address::from_string(addr);
                if (!addr_result.ok()) {
                    return make_error(RpcError::INVALID_PARAMS,
                                      "Invalid address: " + addr, req.id);
                }
                auto script = addr_result.value().to_script();
                output.script_pubkey = script.data();
                vout.push_back(std::move(output));
            }
        }
    } else {
        return make_error(RpcError::INVALID_PARAMS,
                          "Outputs must be an object or array", req.id);
    }

    // Build the transaction
    primitives::Transaction tx(std::move(vin), std::move(vout),
                                2, static_cast<uint32_t>(locktime));

    // Serialize
    auto serialized = tx.serialize();
    return make_result(
        JsonValue(hex_encode(serialized.data(), serialized.size())),
        req.id);
}

// ===========================================================================
// signrawtransactionwithkey
// ===========================================================================

RpcResponse rpc_signrawtransactionwithkey(const RpcRequest& req,
                                           chain::ChainstateManager& chainstate) {
    // params[0] = hex-encoded raw transaction
    // params[1] = array of private keys (WIF or 64-char hex)
    std::string hex_str = param_string(req.params, 0);
    const auto& keys_val = param_value(req.params, 1);

    if (!keys_val.is_array()) {
        return make_error(RpcError::INVALID_PARAMS,
                          "Private keys must be an array", req.id);
    }

    // Deserialize the transaction
    primitives::Transaction tx;
    try {
        tx = deserialize_tx_hex(hex_str);
    } catch (const std::exception& e) {
        return make_error(RpcError::DESERIALIZATION_ERROR, e.what(), req.id);
    }

    // Build a signing provider with the provided keys.
    primitives::script::SimpleSigningProvider provider;

    for (const auto& key_val : keys_val.get_array()) {
        if (!key_val.is_string()) {
            return make_error(RpcError::INVALID_PARAMS,
                              "Each key must be a string (WIF or hex)", req.id);
        }
        std::string key_str = key_val.get_string();

        std::array<uint8_t, 32> secret{};

        if (key_str.size() == 64) {
            // Raw hex private key (32 bytes = 64 hex chars)
            auto bytes = hex_decode(key_str);
            if (bytes.size() != 32) {
                return make_error(RpcError::INVALID_PARAMS,
                                  "Invalid hex private key", req.id);
            }
            std::copy(bytes.begin(), bytes.end(), secret.begin());
        } else {
            // Try WIF decoding
            auto wif_result = wallet::KeyManager::decode_wif(key_str);
            if (!wif_result.ok()) {
                return make_error(RpcError::INVALID_PARAMS,
                                  "Invalid private key: " +
                                  wif_result.error().message(), req.id);
            }
            secret = wif_result.value();
        }

        // Create ECKey from the secret bytes
        std::span<const uint8_t, 32> secret_span(secret.data(), 32);
        auto ec_result = crypto::ECKey::from_secret(secret_span);
        if (!ec_result.ok()) {
            return make_error(RpcError::INVALID_PARAMS,
                              "Failed to create key: " +
                              ec_result.error().message(), req.id);
        }
        provider.add_key(ec_result.value());
    }

    // Lock chainstate to look up prevout scripts/amounts from UTXO set.
    std::lock_guard<std::recursive_mutex> cs_lock(chainstate.cs_main());

    // Sign each input
    bool complete = true;
    JsonValue::Array errors;

    for (size_t i = 0; i < tx.vin().size(); ++i) {
        // Skip inputs that are already signed
        if (!tx.vin()[i].script_sig.empty() || tx.vin()[i].has_witness()) {
            continue;
        }

        const auto& prevout = tx.vin()[i].prevout;

        // Look up the prevout in the UTXO set
        const auto* coin = chainstate.utxo_set().get_coin(prevout);
        if (!coin || coin->is_spent()) {
            JsonValue err(JsonValue::Object{});
            err["txid"]  = JsonValue(prevout.txid.to_hex());
            err["vout"]  = JsonValue(static_cast<int64_t>(prevout.n));
            err["error"] = JsonValue("Input not found in UTXO set");
            errors.push_back(std::move(err));
            complete = false;
            continue;
        }

        primitives::script::Script script_pubkey(coin->out.script_pubkey);
        primitives::Amount amount = coin->out.amount;

        bool signed_ok = primitives::script::sign_input(
            provider, tx, i, script_pubkey, amount);

        if (!signed_ok) {
            JsonValue err(JsonValue::Object{});
            err["txid"]  = JsonValue(prevout.txid.to_hex());
            err["vout"]  = JsonValue(static_cast<int64_t>(prevout.n));
            err["error"] = JsonValue("Signing failed (no matching key?)");
            errors.push_back(std::move(err));
            complete = false;
        }
    }

    auto serialized = tx.serialize();

    JsonValue result(JsonValue::Object{});
    result["hex"]      = JsonValue(hex_encode(serialized.data(), serialized.size()));
    result["complete"] = JsonValue(complete);
    if (!errors.empty()) {
        result["errors"] = JsonValue(std::move(errors));
    }

    return make_result(std::move(result), req.id);
}

// ===========================================================================
// Registration
// ===========================================================================

void register_rawtransaction_rpcs(RpcServer& server,
                                   chain::ChainstateManager& chainstate,
                                   mempool::Mempool& mempool) {
    server.register_commands({
        {"getrawtransaction",
         [&](const RpcRequest& r) {
             return rpc_getrawtransaction(r, chainstate, mempool);
         },
         "getrawtransaction \"txid\" ( verbose )\n"
         "Return the raw transaction data.\n"
         "If verbose is false, returns hex-encoded data.\n"
         "If verbose is true, returns a JSON object.",
         "rawtransactions"},

        {"decoderawtransaction",
         [](const RpcRequest& r) { return rpc_decoderawtransaction(r); },
         "decoderawtransaction \"hexstring\"\n"
         "Return a JSON object representing the serialized, hex-encoded transaction.",
         "rawtransactions"},

        {"sendrawtransaction",
         [&](const RpcRequest& r) { return rpc_sendrawtransaction(r, chainstate, mempool); },
         "sendrawtransaction \"hexstring\"\n"
         "Submit a raw transaction (serialized, hex-encoded) to the network.",
         "rawtransactions"},

        {"createrawtransaction",
         [](const RpcRequest& r) { return rpc_createrawtransaction(r); },
         "createrawtransaction [{\"txid\":\"id\",\"vout\":n},...] {\"address\":amount,...} ( locktime )\n"
         "Create a transaction spending the given inputs and creating new outputs.\n"
         "Returns hex-encoded raw transaction. Note: the transaction is NOT signed.",
         "rawtransactions"},

        {"signrawtransactionwithkey",
         [&](const RpcRequest& r) { return rpc_signrawtransactionwithkey(r, chainstate); },
         "signrawtransactionwithkey \"hexstring\" [\"privatekey\",...]\n"
         "Sign inputs for raw transaction (serialized, hex-encoded).\n"
         "Provide private keys in WIF or hex format.",
         "rawtransactions"},
    });
}

} // namespace rpc
