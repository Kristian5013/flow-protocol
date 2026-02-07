// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/blockchain.h"
#include "rpc/util.h"

#include "chain/block_index.h"
#include "chain/chain.h"
#include "chain/chainstate.h"
#include "chain/coins.h"
#include "chain/utxo/cache.h"
#include "core/hex.h"
#include "core/logging.h"
#include "core/stream.h"
#include "core/types.h"
#include "primitives/address.h"
#include "primitives/block.h"
#include "primitives/block_header.h"
#include "primitives/outpoint.h"
#include "primitives/transaction.h"

#include <algorithm>
#include <cmath>
#include <string>
#include <vector>

namespace rpc {

// ===========================================================================
// Helper: compute difficulty from compact bits
// ===========================================================================

namespace {

double get_difficulty(uint32_t bits) {
    // Difficulty 1 target: 0x1d00ffff in compact form
    // difficulty = diff1_target / current_target
    int shift = (bits >> 24) & 0xFF;
    double diff = static_cast<double>(0x0000FFFF) /
                  static_cast<double>(bits & 0x00FFFFFF);

    while (shift < 29) {
        diff *= 256.0;
        ++shift;
    }
    while (shift > 29) {
        diff /= 256.0;
        --shift;
    }
    return diff;
}

JsonValue block_header_to_json(const chain::BlockIndex* pindex,
                                const chain::Chain& active_chain) {
    JsonValue obj(JsonValue::Object{});
    obj["hash"]          = JsonValue(pindex->block_hash.to_hex());
    obj["confirmations"] = JsonValue(
        active_chain.contains(pindex)
            ? static_cast<int64_t>(active_chain.height() - pindex->height + 1)
            : static_cast<int64_t>(-1));
    obj["height"]        = JsonValue(static_cast<int64_t>(pindex->height));
    obj["version"]       = JsonValue(static_cast<int64_t>(pindex->version));
    obj["merkleroot"]    = JsonValue(pindex->hash_merkle_root.to_hex());
    obj["time"]          = JsonValue(static_cast<int64_t>(pindex->time));
    obj["mediantime"]    = JsonValue(pindex->get_median_time_past());
    obj["nonce"]         = JsonValue(static_cast<int64_t>(pindex->nonce));
    obj["bits"]          = JsonValue(hex_encode(
        reinterpret_cast<const uint8_t*>(&pindex->bits), 4));
    obj["difficulty"]    = JsonValue(get_difficulty(pindex->bits));
    obj["chainwork"]     = JsonValue(pindex->chain_work.to_hex());
    obj["nTx"]           = JsonValue(static_cast<int64_t>(pindex->tx_count));

    if (pindex->prev) {
        obj["previousblockhash"] = JsonValue(pindex->prev->block_hash.to_hex());
    }

    // Next block hash (if on active chain and not tip)
    if (active_chain.contains(pindex) &&
        pindex->height < active_chain.height()) {
        auto* next = active_chain.at(pindex->height + 1);
        if (next) {
            obj["nextblockhash"] = JsonValue(next->block_hash.to_hex());
        }
    }

    return obj;
}

JsonValue tx_to_json_brief(const primitives::Transaction& tx) {
    return JsonValue(tx.txid().to_hex());
}

JsonValue tx_to_json_verbose(const primitives::Transaction& tx) {
    JsonValue obj(JsonValue::Object{});
    obj["txid"]     = JsonValue(tx.txid().to_hex());
    obj["wtxid"]    = JsonValue(tx.wtxid().to_hex());
    obj["version"]  = JsonValue(static_cast<int64_t>(tx.version()));
    obj["locktime"] = JsonValue(static_cast<int64_t>(tx.locktime()));
    obj["size"]     = JsonValue(static_cast<int64_t>(tx.total_size()));
    obj["vsize"]    = JsonValue(static_cast<int64_t>(tx.vsize()));
    obj["weight"]   = JsonValue(static_cast<int64_t>(tx.weight()));

    // Inputs
    JsonValue::Array vin_arr;
    for (size_t i = 0; i < tx.vin().size(); ++i) {
        const auto& input = tx.vin()[i];
        JsonValue in_obj(JsonValue::Object{});
        if (tx.is_coinbase()) {
            in_obj["coinbase"] = JsonValue(hex_encode(
                input.script_sig.data(), input.script_sig.size()));
        } else {
            in_obj["txid"]     = JsonValue(input.prevout.txid.to_hex());
            in_obj["vout"]     = JsonValue(static_cast<int64_t>(input.prevout.n));
            JsonValue script_sig(JsonValue::Object{});
            script_sig["hex"]  = JsonValue(hex_encode(
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
        script_pk["hex"] = JsonValue(hex_encode(
            output.script_pubkey.data(), output.script_pubkey.size()));
        out_obj["scriptPubKey"] = std::move(script_pk);

        vout_arr.push_back(std::move(out_obj));
    }
    obj["vout"] = JsonValue(std::move(vout_arr));

    // Hex serialization
    auto serialized = tx.serialize();
    obj["hex"] = JsonValue(hex_encode(serialized.data(), serialized.size()));

    return obj;
}

} // anonymous namespace

// ===========================================================================
// getblockchaininfo
// ===========================================================================

RpcResponse rpc_getblockchaininfo(const RpcRequest& req,
                                   chain::ChainstateManager& chainstate) {
    const auto& chain = chainstate.active_chain();
    const auto* tip = chain.tip();

    JsonValue result(JsonValue::Object{});
    result["chain"]                 = JsonValue("main");
    result["blocks"]                = JsonValue(
        static_cast<int64_t>(tip ? tip->height : -1));
    result["headers"]               = JsonValue(
        static_cast<int64_t>(chainstate.best_header()
            ? chainstate.best_header()->height : -1));
    result["bestblockhash"]         = JsonValue(
        tip ? tip->block_hash.to_hex() : std::string(64, '0'));
    result["difficulty"]            = JsonValue(
        tip ? get_difficulty(tip->bits) : 0.0);
    result["time"]                  = JsonValue(
        static_cast<int64_t>(tip ? tip->time : 0));
    result["mediantime"]            = JsonValue(
        tip ? tip->get_median_time_past() : static_cast<int64_t>(0));

    // Verification progress: ratio of current tip height to best header height
    double progress = 0.0;
    if (chainstate.best_header() && chainstate.best_header()->height > 0 && tip) {
        progress = static_cast<double>(tip->height) /
                   static_cast<double>(chainstate.best_header()->height);
        if (progress > 1.0) progress = 1.0;
    }
    result["verificationprogress"]  = JsonValue(progress);
    result["chainwork"]             = JsonValue(
        tip ? tip->chain_work.to_hex() : std::string(64, '0'));
    result["pruned"]                = JsonValue(false);
    result["initialblockdownload"]  = JsonValue(progress < 0.999);

    return make_result(std::move(result), req.id);
}

// ===========================================================================
// getblock
// ===========================================================================

RpcResponse rpc_getblock(const RpcRequest& req,
                          chain::ChainstateManager& chainstate) {
    std::string hash_hex = param_string(req.params, 0);
    int64_t verbosity = param_int(req.params, 1, 1);

    if (!is_valid_hex(hash_hex, 32)) {
        return make_error(RpcError::INVALID_PARAMS,
                          "Invalid block hash", req.id);
    }

    core::uint256 hash = core::uint256::from_hex(hash_hex);
    const chain::BlockIndex* pindex = chainstate.lookup_block_index(hash);
    if (!pindex) {
        return make_error(RpcError::INVALID_PARAMS,
                          "Block not found", req.id);
    }

    if (!pindex->has_data()) {
        return make_error(RpcError::MISC_ERROR,
                          "Block data not available", req.id);
    }

    // Read the full block from storage.
    auto block_result = chainstate.read_block(pindex);
    if (!block_result.ok()) {
        return make_error(RpcError::MISC_ERROR,
                          "Failed to read block data: " +
                          block_result.error().message(), req.id);
    }
    auto block = std::move(block_result).value();

    // For verbosity 0, return hex-encoded serialized block
    if (verbosity == 0) {
        auto block_bytes = block.serialize();
        return make_result(
            JsonValue(hex_encode(block_bytes.data(), block_bytes.size())),
            req.id);
    }

    const auto& active = chainstate.active_chain();

    // Build JSON block representation
    JsonValue result = block_header_to_json(pindex, active);

    const auto& txs = block.transactions();
    result["nTx"] = JsonValue(static_cast<int64_t>(txs.size()));

    // Compute block size from serialized data
    auto block_bytes = block.serialize();
    result["size"]         = JsonValue(static_cast<int64_t>(block_bytes.size()));
    result["strippedsize"] = JsonValue(static_cast<int64_t>(block_bytes.size()));
    result["weight"]       = JsonValue(static_cast<int64_t>(block_bytes.size() * 4));

    // Transaction list
    JsonValue::Array tx_arr;
    for (const auto& tx : txs) {
        if (verbosity >= 2) {
            tx_arr.push_back(tx_to_json_verbose(tx));
        } else {
            tx_arr.push_back(tx_to_json_brief(tx));
        }
    }
    result["tx"] = JsonValue(std::move(tx_arr));

    return make_result(std::move(result), req.id);
}

// ===========================================================================
// getblockhash
// ===========================================================================

RpcResponse rpc_getblockhash(const RpcRequest& req,
                              chain::ChainstateManager& chainstate) {
    int64_t height = param_int(req.params, 0);

    const auto& chain = chainstate.active_chain();
    if (height < 0 || height > chain.height()) {
        return make_error(RpcError::INVALID_PARAMS,
                          "Block height out of range", req.id);
    }

    const auto* pindex = chain.at(static_cast<int>(height));
    if (!pindex) {
        return make_error(RpcError::INTERNAL_ERROR,
                          "Block index not found at height", req.id);
    }

    return make_result(JsonValue(pindex->block_hash.to_hex()), req.id);
}

// ===========================================================================
// getblockheader
// ===========================================================================

RpcResponse rpc_getblockheader(const RpcRequest& req,
                                chain::ChainstateManager& chainstate) {
    std::string hash_hex = param_string(req.params, 0);
    bool verbose = param_bool(req.params, 1, true);

    if (!is_valid_hex(hash_hex, 32)) {
        return make_error(RpcError::INVALID_PARAMS,
                          "Invalid block hash", req.id);
    }

    core::uint256 hash = core::uint256::from_hex(hash_hex);
    const chain::BlockIndex* pindex = chainstate.lookup_block_index(hash);
    if (!pindex) {
        return make_error(RpcError::INVALID_PARAMS,
                          "Block not found", req.id);
    }

    if (!verbose) {
        auto header = pindex->get_block_header();
        auto bytes = header.serialize_array();
        return make_result(
            JsonValue(hex_encode(bytes.data(), bytes.size())), req.id);
    }

    const auto& active = chainstate.active_chain();
    return make_result(block_header_to_json(pindex, active), req.id);
}

// ===========================================================================
// getblockcount
// ===========================================================================

RpcResponse rpc_getblockcount(const RpcRequest& req,
                               chain::ChainstateManager& chainstate) {
    return make_result(
        JsonValue(static_cast<int64_t>(chainstate.active_chain().height())),
        req.id);
}

// ===========================================================================
// getdifficulty
// ===========================================================================

RpcResponse rpc_getdifficulty(const RpcRequest& req,
                               chain::ChainstateManager& chainstate) {
    const auto* tip = chainstate.active_chain().tip();
    double diff = tip ? get_difficulty(tip->bits) : 0.0;
    return make_result(JsonValue(diff), req.id);
}

// ===========================================================================
// getchaintips
// ===========================================================================

RpcResponse rpc_getchaintips(const RpcRequest& req,
                              chain::ChainstateManager& chainstate) {
    // Return active chain tip as the primary chain tip.
    // A full implementation would iterate all block indices to find
    // non-active chain tips. For now, report the active tip.
    const auto& active = chainstate.active_chain();
    const auto* tip = active.tip();

    JsonValue::Array tips_arr;
    if (tip) {
        JsonValue tip_obj(JsonValue::Object{});
        tip_obj["height"]    = JsonValue(static_cast<int64_t>(tip->height));
        tip_obj["hash"]      = JsonValue(tip->block_hash.to_hex());
        tip_obj["branchlen"] = JsonValue(static_cast<int64_t>(0));
        tip_obj["status"]    = JsonValue("active");
        tips_arr.push_back(std::move(tip_obj));
    }

    // Check best_header for a header-only tip ahead of active chain
    const auto* best_hdr = chainstate.best_header();
    if (best_hdr && tip && best_hdr->height > tip->height) {
        JsonValue hdr_tip(JsonValue::Object{});
        hdr_tip["height"]    = JsonValue(static_cast<int64_t>(best_hdr->height));
        hdr_tip["hash"]      = JsonValue(best_hdr->block_hash.to_hex());
        hdr_tip["branchlen"] = JsonValue(
            static_cast<int64_t>(best_hdr->height - tip->height));
        hdr_tip["status"]    = JsonValue("headers-only");
        tips_arr.push_back(std::move(hdr_tip));
    }

    return make_result(JsonValue(std::move(tips_arr)), req.id);
}

// ===========================================================================
// getbestblockhash
// ===========================================================================

RpcResponse rpc_getbestblockhash(const RpcRequest& req,
                                  chain::ChainstateManager& chainstate) {
    const auto* tip = chainstate.active_chain().tip();
    if (!tip) {
        return make_result(JsonValue(std::string(64, '0')), req.id);
    }
    return make_result(JsonValue(tip->block_hash.to_hex()), req.id);
}

// ===========================================================================
// gettxout
// ===========================================================================

RpcResponse rpc_gettxout(const RpcRequest& req,
                           chain::ChainstateManager& chainstate) {
    std::string txid_hex = param_string(req.params, 0);
    int64_t n = param_int(req.params, 1);

    if (!is_valid_hex(txid_hex, 32)) {
        return make_error(RpcError::INVALID_PARAMS,
                          "Invalid txid", req.id);
    }

    core::uint256 txid = core::uint256::from_hex(txid_hex);
    primitives::OutPoint outpoint(txid, static_cast<uint32_t>(n));

    const auto* coin = chainstate.utxo_set().get_coin(outpoint);
    if (!coin || coin->is_spent()) {
        // Return null (empty result) when UTXO not found
        return make_result(JsonValue(), req.id);
    }

    const auto& active = chainstate.active_chain();
    const auto* tip = active.tip();

    JsonValue result(JsonValue::Object{});
    result["bestblock"] = JsonValue(
        tip ? tip->block_hash.to_hex() : std::string(64, '0'));
    result["confirmations"] = JsonValue(
        static_cast<int64_t>(tip ? tip->height - coin->height + 1 : 0));
    result["value"] = JsonValue(format_amount(coin->out.amount.value()));
    result["coinbase"] = JsonValue(coin->is_coinbase);

    JsonValue script_pk(JsonValue::Object{});
    script_pk["hex"] = JsonValue(hex_encode(
        coin->out.script_pubkey.data(), coin->out.script_pubkey.size()));
    result["scriptPubKey"] = std::move(script_pk);

    return make_result(std::move(result), req.id);
}

// ===========================================================================
// scantxoutset
// ===========================================================================

RpcResponse rpc_scantxoutset(const RpcRequest& req,
                               chain::ChainstateManager& chainstate) {
    // params[0] = "start" (action string)
    // params[1] = array of scan descriptors: [{"address":"..."}, ...]
    //             or simply ["addr1", "addr2", ...]
    // params[2] = (optional) bool verbose — if true, include full unspents array

    const auto& descriptors = param_value(req.params, 1);
    if (!descriptors.is_array()) {
        return make_error(RpcError::INVALID_PARAMS,
                          "Scan descriptors must be an array", req.id);
    }

    // Check optional verbose flag (default: false)
    bool verbose = false;
    if (req.params.size() > 2 && req.params[2].is_bool()) {
        verbose = req.params[2].get_bool();
    }

    // Collect target scripts from addresses
    std::vector<std::vector<uint8_t>> target_scripts;

    for (const auto& desc : descriptors.get_array()) {
        std::string addr_str;
        if (desc.is_object() && desc.has_key("address")) {
            addr_str = desc["address"].get_string();
        } else if (desc.is_string()) {
            addr_str = desc.get_string();
        } else {
            continue;
        }

        auto addr_result = primitives::Address::from_string(addr_str);
        if (addr_result.ok()) {
            auto script = addr_result.value().to_script();
            target_scripts.push_back(script.data());
        }
    }

    if (target_scripts.empty()) {
        return make_error(RpcError::INVALID_PARAMS,
                          "No valid addresses provided", req.id);
    }

    // Lock chainstate while scanning UTXO set.
    std::lock_guard<std::recursive_mutex> cs_lock(chainstate.cs_main());

    // Scan UTXO set
    auto outpoints = chainstate.utxo_set().get_all_outpoints();

    JsonValue::Array unspents;
    int64_t total_amount = 0;
    int64_t utxo_count = 0;

    for (const auto& op : outpoints) {
        const auto* coin = chainstate.utxo_set().get_coin(op);
        if (!coin || coin->is_spent()) continue;

        for (const auto& target : target_scripts) {
            if (coin->out.script_pubkey == target) {
                ++utxo_count;
                total_amount += coin->out.amount.value();

                if (verbose) {
                    JsonValue entry(JsonValue::Object{});
                    entry["txid"]     = JsonValue(op.txid.to_hex());
                    entry["vout"]     = JsonValue(static_cast<int64_t>(op.n));
                    entry["amount"]   = JsonValue(
                        format_amount(coin->out.amount.value()));
                    entry["height"]   = JsonValue(
                        static_cast<int64_t>(coin->height));
                    entry["coinbase"] = JsonValue(coin->is_coinbase);
                    entry["scriptPubKey"] = JsonValue(hex_encode(
                        coin->out.script_pubkey.data(),
                        coin->out.script_pubkey.size()));

                    unspents.push_back(std::move(entry));
                }
                break;
            }
        }
    }

    JsonValue result(JsonValue::Object{});
    result["success"]        = JsonValue(true);
    result["total_amount"]   = JsonValue(format_amount(total_amount));
    result["utxo_count"]     = JsonValue(utxo_count);
    result["searched_items"] = JsonValue(
        static_cast<int64_t>(outpoints.size()));

    if (verbose) {
        result["unspents"] = JsonValue(std::move(unspents));
    }

    return make_result(std::move(result), req.id);
}

// ===========================================================================
// Registration
// ===========================================================================

void register_blockchain_rpcs(RpcServer& server,
                               chain::ChainstateManager& chainstate) {
    server.register_commands({
        {"getblockchaininfo",
         [&](const RpcRequest& r) { return rpc_getblockchaininfo(r, chainstate); },
         "getblockchaininfo\n"
         "Returns an object containing various state info regarding blockchain processing.",
         "blockchain"},

        {"getblock",
         [&](const RpcRequest& r) { return rpc_getblock(r, chainstate); },
         "getblock \"blockhash\" ( verbosity )\n"
         "Returns block data. verbosity: 0=hex, 1=json, 2=json+tx details.",
         "blockchain"},

        {"getblockhash",
         [&](const RpcRequest& r) { return rpc_getblockhash(r, chainstate); },
         "getblockhash height\n"
         "Returns hash of block in best-block-chain at height provided.",
         "blockchain"},

        {"getblockheader",
         [&](const RpcRequest& r) { return rpc_getblockheader(r, chainstate); },
         "getblockheader \"blockhash\" ( verbose )\n"
         "Returns information about a block header.",
         "blockchain"},

        {"getblockcount",
         [&](const RpcRequest& r) { return rpc_getblockcount(r, chainstate); },
         "getblockcount\n"
         "Returns the height of the most-work fully-validated chain.",
         "blockchain"},

        {"getdifficulty",
         [&](const RpcRequest& r) { return rpc_getdifficulty(r, chainstate); },
         "getdifficulty\n"
         "Returns the proof-of-work difficulty as a multiple of the minimum difficulty.",
         "blockchain"},

        {"getchaintips",
         [&](const RpcRequest& r) { return rpc_getchaintips(r, chainstate); },
         "getchaintips\n"
         "Return information about all known tips in the block tree.",
         "blockchain"},

        {"getbestblockhash",
         [&](const RpcRequest& r) { return rpc_getbestblockhash(r, chainstate); },
         "getbestblockhash\n"
         "Returns the hash of the best (tip) block in the most-work fully-validated chain.",
         "blockchain"},

        {"gettxout",
         [&](const RpcRequest& r) { return rpc_gettxout(r, chainstate); },
         "gettxout \"txid\" n\n"
         "Returns details about an unspent transaction output.",
         "blockchain"},

        {"scantxoutset",
         [&](const RpcRequest& r) { return rpc_scantxoutset(r, chainstate); },
         "scantxoutset \"action\" [scanobjects,...]\n"
         "Scan the UTXO set for outputs matching the given addresses.\n"
         "action: \"start\"\n"
         "scanobjects: [{\"address\":\"addr\"}, ...] or [\"addr\", ...]",
         "blockchain"},
    });
}

} // namespace rpc
