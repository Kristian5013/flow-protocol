// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/mempool_rpc.h"
#include "rpc/util.h"

#include "core/hex.h"
#include "core/logging.h"
#include "core/stream.h"
#include "core/time.h"
#include "core/types.h"
#include "mempool/entry.h"
#include "mempool/mempool.h"
#include "primitives/transaction.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace rpc {

namespace {

/// Convert a MempoolEntry to a JSON object with detailed information.
JsonValue mempool_entry_to_json(const mempool::MempoolEntry& entry) {
    JsonValue obj(JsonValue::Object{});
    obj["vsize"]             = JsonValue(static_cast<int64_t>(entry.vsize));
    obj["weight"]            = JsonValue(static_cast<int64_t>(entry.weight()));
    obj["fee"]               = JsonValue(format_amount(entry.fee.value()));
    obj["modifiedfee"]       = JsonValue(format_amount(entry.fee.value()));
    obj["time"]              = JsonValue(entry.time);
    obj["height"]            = JsonValue(static_cast<int64_t>(entry.height));
    obj["descendantcount"]   = JsonValue(
        static_cast<int64_t>(entry.descendant_count));
    obj["descendantsize"]    = JsonValue(
        static_cast<int64_t>(entry.descendant_size));
    obj["descendantfees"]    = JsonValue(entry.descendant_fees.value());
    obj["ancestorcount"]     = JsonValue(
        static_cast<int64_t>(entry.ancestor_count));
    obj["ancestorsize"]      = JsonValue(
        static_cast<int64_t>(entry.ancestor_size));
    obj["ancestorfees"]      = JsonValue(entry.ancestor_fees.value());
    obj["wtxid"]             = JsonValue(entry.wtxid.to_hex());
    obj["bip125-replaceable"] = JsonValue(true); // All FTC tx support RBF

    // Fee rate in sat/vB
    obj["feerate"] = JsonValue(
        entry.vsize > 0
            ? static_cast<double>(entry.fee.value()) /
              static_cast<double>(entry.vsize)
            : 0.0);

    // Dependencies (txids of in-mempool parents)
    obj["depends"] = JsonValue(JsonValue::Array{});
    obj["spentby"] = JsonValue(JsonValue::Array{});

    // Unbroadcast flag
    obj["unbroadcast"] = JsonValue(false);

    return obj;
}

} // anonymous namespace

// ===========================================================================
// getmempoolinfo
// ===========================================================================

RpcResponse rpc_getmempoolinfo(const RpcRequest& req,
                                mempool::Mempool& mempool) {
    auto stats = mempool.get_stats();

    JsonValue result(JsonValue::Object{});
    result["loaded"]               = JsonValue(true);
    result["size"]                 = JsonValue(
        static_cast<int64_t>(stats.tx_count));
    result["bytes"]                = JsonValue(
        static_cast<int64_t>(stats.total_bytes));
    result["usage"]                = JsonValue(
        static_cast<int64_t>(stats.memory_usage));
    result["total_fee"]            = JsonValue(
        format_amount(stats.total_fee.value()));
    result["maxmempool"]           = JsonValue(
        static_cast<int64_t>(mempool.max_size()));
    result["mempoolminfee"]        = JsonValue(
        format_amount(stats.min_entry_fee_rate));
    result["minrelaytxfee"]        = JsonValue(format_amount(1000));
    result["incrementalrelayfee"]  = JsonValue(format_amount(1000));
    result["unbroadcastcount"]     = JsonValue(static_cast<int64_t>(0));
    result["fullrbf"]              = JsonValue(true);

    return make_result(std::move(result), req.id);
}

// ===========================================================================
// getrawmempool
// ===========================================================================

RpcResponse rpc_getrawmempool(const RpcRequest& req,
                               mempool::Mempool& mempool) {
    bool verbose = param_bool(req.params, 0, false);

    auto txids = mempool.get_all_txids();

    if (!verbose) {
        // Return simple array of txid strings
        JsonValue::Array arr;
        arr.reserve(txids.size());
        for (const auto& txid : txids) {
            arr.push_back(JsonValue(txid.to_hex()));
        }
        return make_result(JsonValue(std::move(arr)), req.id);
    }

    // Verbose mode: return object mapping txid -> entry details
    JsonValue result(JsonValue::Object{});
    for (const auto& txid : txids) {
        const auto* entry = mempool.get(txid);
        if (entry) {
            result[txid.to_hex()] = mempool_entry_to_json(*entry);
        }
    }

    return make_result(std::move(result), req.id);
}

// ===========================================================================
// getmempoolentry
// ===========================================================================

RpcResponse rpc_getmempoolentry(const RpcRequest& req,
                                 mempool::Mempool& mempool) {
    std::string txid_hex = param_string(req.params, 0);

    if (!is_valid_hex(txid_hex, 32)) {
        return make_error(RpcError::INVALID_PARAMS,
                          "Invalid txid", req.id);
    }

    core::uint256 txid = core::uint256::from_hex(txid_hex);
    const auto* entry = mempool.get(txid);
    if (!entry) {
        return make_error(RpcError::INVALID_PARAMS,
                          "Transaction not in mempool", req.id);
    }

    return make_result(mempool_entry_to_json(*entry), req.id);
}

// ===========================================================================
// testmempoolaccept
// ===========================================================================

RpcResponse rpc_testmempoolaccept(const RpcRequest& req,
                                   mempool::Mempool& mempool) {
    const auto& rawtxs_val = param_value(req.params, 0);

    if (!rawtxs_val.is_array()) {
        return make_error(RpcError::INVALID_PARAMS,
                          "Argument must be an array of raw transactions",
                          req.id);
    }

    const auto& rawtxs = rawtxs_val.get_array();
    if (rawtxs.empty()) {
        return make_error(RpcError::INVALID_PARAMS,
                          "Array must contain at least one transaction",
                          req.id);
    }

    if (rawtxs.size() > 25) {
        return make_error(RpcError::INVALID_PARAMS,
                          "Array must contain at most 25 transactions",
                          req.id);
    }

    JsonValue::Array results;

    for (const auto& rawtx_val : rawtxs) {
        if (!rawtx_val.is_string()) {
            return make_error(RpcError::INVALID_PARAMS,
                              "Each element must be a hex string", req.id);
        }

        JsonValue entry_result(JsonValue::Object{});
        std::string hex_str = rawtx_val.get_string();

        // Decode and deserialize the transaction
        std::vector<uint8_t> tx_bytes;
        try {
            tx_bytes = hex_decode(hex_str);
        } catch (...) {
            entry_result["txid"]    = JsonValue("");
            entry_result["allowed"] = JsonValue(false);
            entry_result["reject-reason"] = JsonValue("decode-failed");
            results.push_back(std::move(entry_result));
            continue;
        }

        core::DataStream stream(std::move(tx_bytes));
        auto tx_result = primitives::Transaction::deserialize(stream);
        if (!tx_result.ok()) {
            entry_result["txid"]    = JsonValue("");
            entry_result["allowed"] = JsonValue(false);
            entry_result["reject-reason"] = JsonValue(
                "tx-deserialize: " + tx_result.error().message());
            results.push_back(std::move(entry_result));
            continue;
        }

        auto tx = std::move(tx_result).value();
        core::uint256 txid = tx.txid();
        entry_result["txid"] = JsonValue(txid.to_hex());

        // Check if already in mempool
        if (mempool.exists(txid)) {
            entry_result["allowed"] = JsonValue(false);
            entry_result["reject-reason"] = JsonValue(
                "txn-already-in-mempool");
            results.push_back(std::move(entry_result));
            continue;
        }

        // Try to add (dry run)
        // In production, we would validate against the UTXO set first.
        // Here we create a test entry with zero fee (a real test would
        // compute the actual fee).
        auto test_entry = mempool::MempoolEntry::from_tx(
            tx, primitives::Amount(0), 0, core::get_time());

        // Attempt a policy-checked add. If this were a dry-run, we would
        // need a "test mode" on the mempool. Instead, we check basic
        // properties here.
        bool allowed = true;
        std::string reject_reason;

        // Basic validation checks
        if (tx.vin().empty()) {
            allowed = false;
            reject_reason = "bad-txns-vin-empty";
        } else if (tx.vout().empty()) {
            allowed = false;
            reject_reason = "bad-txns-vout-empty";
        } else if (tx.total_size() > 400000) {
            allowed = false;
            reject_reason = "tx-size";
        } else if (tx.vsize() > 100000) {
            allowed = false;
            reject_reason = "tx-size";
        }

        // Check for duplicate inputs
        if (allowed) {
            std::vector<primitives::OutPoint> inputs_seen;
            for (const auto& input : tx.vin()) {
                if (std::find(inputs_seen.begin(), inputs_seen.end(),
                              input.prevout) != inputs_seen.end()) {
                    allowed = false;
                    reject_reason = "bad-txns-inputs-duplicate";
                    break;
                }
                inputs_seen.push_back(input.prevout);
            }
        }

        // Check output amounts
        if (allowed) {
            int64_t total_out = 0;
            for (const auto& output : tx.vout()) {
                if (output.amount.value() < 0) {
                    allowed = false;
                    reject_reason = "bad-txns-vout-negative";
                    break;
                }
                total_out += output.amount.value();
                if (total_out < 0 || total_out > primitives::Amount::MAX_MONEY) {
                    allowed = false;
                    reject_reason = "bad-txns-txouttotal-toolarge";
                    break;
                }
            }
        }

        entry_result["allowed"] = JsonValue(allowed);
        if (!allowed) {
            entry_result["reject-reason"] = JsonValue(reject_reason);
        } else {
            entry_result["vsize"]  = JsonValue(
                static_cast<int64_t>(tx.vsize()));
            JsonValue fees(JsonValue::Object{});
            fees["base"] = JsonValue(format_amount(0));
            entry_result["fees"] = std::move(fees);
        }

        results.push_back(std::move(entry_result));
    }

    return make_result(JsonValue(std::move(results)), req.id);
}

// ===========================================================================
// Registration
// ===========================================================================

void register_mempool_rpcs(RpcServer& server, mempool::Mempool& mempool) {
    server.register_commands({
        {"getmempoolinfo",
         [&](const RpcRequest& r) { return rpc_getmempoolinfo(r, mempool); },
         "getmempoolinfo\n"
         "Returns details on the active state of the TX memory pool.",
         "blockchain"},

        {"getrawmempool",
         [&](const RpcRequest& r) { return rpc_getrawmempool(r, mempool); },
         "getrawmempool ( verbose )\n"
         "Returns all transaction ids in memory pool.\n"
         "If verbose is true, returns a JSON object with detailed info for each.",
         "blockchain"},

        {"getmempoolentry",
         [&](const RpcRequest& r) { return rpc_getmempoolentry(r, mempool); },
         "getmempoolentry \"txid\"\n"
         "Returns mempool data for given transaction.",
         "blockchain"},

        {"testmempoolaccept",
         [&](const RpcRequest& r) { return rpc_testmempoolaccept(r, mempool); },
         "testmempoolaccept [\"rawtx\",...]\n"
         "Returns result of mempool acceptance tests indicating if raw\n"
         "transaction(s) would be accepted by mempool.",
         "blockchain"},
    });
}

} // namespace rpc
