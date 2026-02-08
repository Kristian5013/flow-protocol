// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/mining.h"
#include "rpc/util.h"

#include "chain/block_index.h"
#include "chain/chain.h"
#include "chain/chainstate.h"
#include "core/hex.h"
#include "core/logging.h"
#include "core/stream.h"
#include "core/time.h"
#include "core/types.h"
#include "mempool/mempool.h"
#include "primitives/block.h"
#include "primitives/block_header.h"
#include "primitives/transaction.h"

#include "miner/block_template.h"
#include "miner/solver.h"
#include "net/manager/net_manager.h"
#include "primitives/address.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <string>
#include <vector>

namespace rpc {

namespace {

double get_difficulty(uint32_t bits) {
    int shift = (bits >> 24) & 0xFF;
    double diff = static_cast<double>(0x0000FFFF) /
                  static_cast<double>(bits & 0x00FFFFFF);
    while (shift < 29) { diff *= 256.0; ++shift; }
    while (shift > 29) { diff /= 256.0; --shift; }
    return diff;
}

/// Estimate network hash rate by looking at how many blocks were solved
/// over a given period relative to the expected time per block.
double estimate_network_hashps(const chain::Chain& chain,
                                int nblocks, int height) {
    if (height < 0 || height > chain.height()) {
        height = chain.height();
    }

    // If the chain is too short, return 0
    if (height <= 0) return 0.0;

    // Default: use the last 120 blocks (roughly 20 hours)
    if (nblocks <= 0) nblocks = 120;
    if (nblocks > height) nblocks = height;

    const auto* tip_index = chain.at(height);
    const auto* start_index = chain.at(height - nblocks);

    if (!tip_index || !start_index) return 0.0;

    // Time span in seconds
    int64_t time_diff = static_cast<int64_t>(tip_index->time) -
                        static_cast<int64_t>(start_index->time);
    if (time_diff <= 0) return 0.0;

    // The chain work difference between start and end
    // We approximate: work = difficulty * 2^32 per block
    // Total hash rate = total_work / time_in_seconds

    // Use a simpler estimate: hash_rate = nblocks * difficulty * 2^32 / time_diff
    double difficulty = get_difficulty(tip_index->bits);
    double work_per_block = difficulty * 4294967296.0; // 2^32
    double total_work = work_per_block * nblocks;

    return total_work / static_cast<double>(time_diff);
}

// Cached block templates for getwork/submitwork external mining flow.
// Keyed by work_id so multiple miners can work concurrently without
// overwriting each other's templates.
std::mutex g_work_mutex;
std::atomic<int64_t> g_next_work_id{1};
std::unordered_map<int64_t, miner::BlockTemplate> g_cached_work;
static constexpr size_t MAX_CACHED_TEMPLATES = 64;

// Evict oldest templates when the cache is full.
void evict_stale_work() {
    while (g_cached_work.size() > MAX_CACHED_TEMPLATES) {
        // Find the lowest work_id (oldest)
        int64_t oldest = g_cached_work.begin()->first;
        for (auto& [id, _] : g_cached_work) {
            if (id < oldest) oldest = id;
        }
        g_cached_work.erase(oldest);
    }
}

} // anonymous namespace

// ===========================================================================
// getblocktemplate
// ===========================================================================

RpcResponse rpc_getblocktemplate(const RpcRequest& req,
                                  chain::ChainstateManager& chainstate,
                                  mempool::Mempool& mempool) {
    const auto& chain = chainstate.active_chain();
    const auto* tip = chain.tip();
    if (!tip) {
        return make_error(RpcError::MISC_ERROR,
                          "Chain not initialized", req.id);
    }

    // Select transactions for the block
    constexpr size_t MAX_BLOCK_WEIGHT = 4'000'000;
    auto selected = mempool.select_for_block(MAX_BLOCK_WEIGHT);

    JsonValue result(JsonValue::Object{});
    result["version"]            = JsonValue(static_cast<int64_t>(tip->version));
    result["previousblockhash"]  = JsonValue(tip->block_hash.to_hex());
    result["target"]             = JsonValue(hex_encode(
        reinterpret_cast<const uint8_t*>(&tip->bits), 4));
    result["bits"]               = JsonValue(hex_encode(
        reinterpret_cast<const uint8_t*>(&tip->bits), 4));
    result["curtime"]            = JsonValue(core::get_time());
    result["height"]             = JsonValue(
        static_cast<int64_t>(tip->height + 1));
    result["mintime"]            = JsonValue(tip->get_median_time_past() + 1);

    // Mutable fields that miners can change
    JsonValue::Array mutable_arr;
    mutable_arr.push_back(JsonValue("time"));
    mutable_arr.push_back(JsonValue("transactions"));
    mutable_arr.push_back(JsonValue("prevblock"));
    result["mutable"] = JsonValue(std::move(mutable_arr));

    // Non-witness commitment (coinbase commitment)
    result["default_witness_commitment"] = JsonValue(
        std::string(64, '0'));

    // Coinbase value (subsidy + fees)
    int64_t total_fees = 0;
    for (const auto& entry : selected) {
        total_fees += entry.fee.value();
    }

    // Calculate subsidy for next block
    int next_height = tip->height + 1;
    int halvings = next_height / chainstate.params().subsidy_halving_interval;
    int64_t subsidy = 50LL * 100'000'000LL; // 50 FTC initial
    if (halvings < 64) {
        subsidy >>= halvings;
    } else {
        subsidy = 0;
    }
    result["coinbasevalue"] = JsonValue(subsidy + total_fees);

    // Transactions for the template
    JsonValue::Array tx_arr;
    for (const auto& entry : selected) {
        JsonValue tx_obj(JsonValue::Object{});
        auto serialized = entry.tx.serialize();
        tx_obj["data"] = JsonValue(hex_encode(serialized.data(), serialized.size()));
        tx_obj["txid"] = JsonValue(entry.txid.to_hex());
        tx_obj["hash"] = JsonValue(entry.wtxid.to_hex());
        tx_obj["fee"]  = JsonValue(entry.fee.value());
        tx_obj["sigops"]  = JsonValue(static_cast<int64_t>(0));
        tx_obj["weight"]  = JsonValue(static_cast<int64_t>(entry.weight()));

        // Dependencies: list indices of parent transactions in the template
        JsonValue::Array depends;
        tx_obj["depends"] = JsonValue(std::move(depends));

        tx_arr.push_back(std::move(tx_obj));
    }
    result["transactions"] = JsonValue(std::move(tx_arr));

    // Capabilities and rules
    JsonValue::Array cap_arr;
    cap_arr.push_back(JsonValue("proposal"));
    result["capabilities"] = JsonValue(std::move(cap_arr));

    JsonValue::Array rules_arr;
    rules_arr.push_back(JsonValue("segwit"));
    result["rules"] = JsonValue(std::move(rules_arr));

    // Weight/size limits
    result["weightlimit"]    = JsonValue(static_cast<int64_t>(MAX_BLOCK_WEIGHT));
    result["sizelimit"]      = JsonValue(static_cast<int64_t>(4'000'000));
    result["sigoplimit"]     = JsonValue(static_cast<int64_t>(80'000));

    LOG_DEBUG(core::LogCategory::RPC,
              "getblocktemplate: " + std::to_string(selected.size()) +
              " txs, fees=" + std::to_string(total_fees));

    return make_result(std::move(result), req.id);
}

// ===========================================================================
// submitblock
// ===========================================================================

RpcResponse rpc_submitblock(const RpcRequest& req,
                             chain::ChainstateManager& chainstate,
                             mempool::Mempool& mempool,
                             net::NetManager* net_manager) {
    std::string hex_data = param_string(req.params, 0);

    // Decode block hex
    std::vector<uint8_t> block_bytes;
    try {
        block_bytes = hex_decode(hex_data);
    } catch (const std::exception& e) {
        return make_error(RpcError::DESERIALIZATION_ERROR,
                          std::string("Invalid hex: ") + e.what(), req.id);
    }

    if (block_bytes.empty()) {
        return make_error(RpcError::DESERIALIZATION_ERROR,
                          "Empty block data", req.id);
    }

    // Deserialize the block
    core::DataStream stream(std::move(block_bytes));
    auto block_result = primitives::Block::deserialize(stream);
    if (!block_result.ok()) {
        return make_error(RpcError::DESERIALIZATION_ERROR,
                          "Block deserialization failed: " +
                          block_result.error().message(), req.id);
    }

    auto block = std::move(block_result).value();

    LOG_INFO(core::LogCategory::RPC,
             "submitblock: hash=" + block.hash().to_hex());

    // Accept the block
    auto accept_result = chainstate.accept_block(block);
    if (!accept_result.ok()) {
        return make_error(RpcError::VERIFY_REJECTED,
                          "Block rejected: " + accept_result.error().message(),
                          req.id);
    }

    // Try to activate the new chain
    auto activate_result = chainstate.activate_best_chain();
    if (!activate_result.ok()) {
        return make_error(RpcError::VERIFY_ERROR,
                          "Chain activation failed: " +
                          activate_result.error().message(), req.id);
    }

    // Remove mined transactions from the mempool.
    int height = chainstate.active_chain().height();
    mempool.remove_for_block(block, height);

    // Flush block index and UTXO set to disk so data survives restarts.
    chainstate.flush();

    // Broadcast to P2P peers.
    if (net_manager) {
        net_manager->broadcast_block(block);
    }

    // Success
    return make_result(JsonValue(nullptr), req.id);
}

// ===========================================================================
// getmininginfo
// ===========================================================================

RpcResponse rpc_getmininginfo(const RpcRequest& req,
                               chain::ChainstateManager& chainstate,
                               mempool::Mempool& mempool) {
    const auto& chain = chainstate.active_chain();
    const auto* tip = chain.tip();

    JsonValue result(JsonValue::Object{});
    result["blocks"]         = JsonValue(
        static_cast<int64_t>(tip ? tip->height : 0));
    result["difficulty"]     = JsonValue(
        tip ? get_difficulty(tip->bits) : 0.0);
    result["networkhashps"]  = JsonValue(
        estimate_network_hashps(chain, 120, chain.height()));
    result["pooledtx"]       = JsonValue(
        static_cast<int64_t>(mempool.size()));
    result["chain"]          = JsonValue("main");

    return make_result(std::move(result), req.id);
}

// ===========================================================================
// getnetworkhashps
// ===========================================================================

RpcResponse rpc_getnetworkhashps(const RpcRequest& req,
                                  chain::ChainstateManager& chainstate) {
    int64_t nblocks = param_int(req.params, 0, 120);
    int64_t height  = param_int(req.params, 1, -1);

    double hashps = estimate_network_hashps(
        chainstate.active_chain(),
        static_cast<int>(nblocks),
        static_cast<int>(height));

    return make_result(JsonValue(hashps), req.id);
}

// ===========================================================================
// generate
// ===========================================================================

RpcResponse rpc_generate(const RpcRequest& req,
                          chain::ChainstateManager& chainstate,
                          mempool::Mempool& mempool,
                          net::NetManager* net_manager) {
    int64_t nblocks = param_int(req.params, 0, 1);
    std::string addr_str = param_string(req.params, 1);

    if (nblocks < 1 || nblocks > 1000) {
        return make_error(RpcError::INVALID_PARAMETER,
                          "nblocks must be between 1 and 1000", req.id);
    }
    if (addr_str.empty()) {
        return make_error(RpcError::INVALID_PARAMETER,
                          "address is required", req.id);
    }

    auto addr_result = primitives::Address::from_string(addr_str);
    if (!addr_result.ok()) {
        return make_error(RpcError::INVALID_ADDRESS,
                          "Invalid address: " + addr_result.error().message(),
                          req.id);
    }

    JsonValue::Array hashes;

    for (int64_t i = 0; i < nblocks; ++i) {
        auto tmpl_result = miner::create_block_template(
            chainstate, mempool, addr_result.value(),
            static_cast<uint32_t>(i));
        if (!tmpl_result.ok()) {
            return make_error(RpcError::MISC_ERROR,
                              "Failed to create block template: " +
                              tmpl_result.error().message(), req.id);
        }
        auto& tmpl = tmpl_result.value();

        miner::EquihashSolver solver;
        std::atomic<bool> cancel{false};
        auto solve_result = solver.solve(tmpl.header, tmpl.target, cancel);
        if (!solve_result) {
            return make_error(RpcError::MISC_ERROR,
                              "Mining failed: no solution found", req.id);
        }

        tmpl.header.nonce = solve_result->nonce;
        auto block = tmpl.to_block();

        auto accept = chainstate.accept_block(block);
        if (!accept.ok()) {
            return make_error(RpcError::VERIFY_REJECTED,
                              "Block rejected: " + accept.error().message(),
                              req.id);
        }

        auto activate = chainstate.activate_best_chain();
        if (!activate.ok()) {
            return make_error(RpcError::VERIFY_ERROR,
                              "Chain activation failed: " +
                              activate.error().message(), req.id);
        }

        // Remove mined transactions from the mempool.
        mempool.remove_for_block(block, tmpl.height);

        // Broadcast to P2P peers
        if (net_manager) {
            net_manager->broadcast_block(block);
        } else {
            LOG_WARN(core::LogCategory::RPC,
                     "generate: net_manager is null, cannot broadcast");
        }

        hashes.push_back(JsonValue(block.hash().to_hex()));

        LOG_INFO(core::LogCategory::RPC,
                 "generate: mined block " + std::to_string(i + 1) + "/" +
                 std::to_string(nblocks) + " hash=" +
                 block.hash().to_hex());
    }

    // Flush block index and UTXO set to disk so data survives restarts.
    chainstate.flush();

    return make_result(JsonValue(std::move(hashes)), req.id);
}

// ===========================================================================
// getwork
// ===========================================================================

RpcResponse rpc_getwork(const RpcRequest& req,
                        chain::ChainstateManager& chainstate,
                        mempool::Mempool& mempool) {
    std::string addr_str = param_string(req.params, 0);
    if (addr_str.empty()) {
        return make_error(RpcError::INVALID_PARAMETER,
                          "address is required", req.id);
    }

    auto addr_result = primitives::Address::from_string(addr_str);
    if (!addr_result.ok()) {
        return make_error(RpcError::INVALID_ADDRESS,
                          "Invalid address: " + addr_result.error().message(),
                          req.id);
    }

    // Use current time as extra_nonce for uniqueness
    uint64_t extra_nonce = static_cast<uint64_t>(core::get_time());

    auto tmpl_result = miner::create_block_template(
        chainstate, mempool, addr_result.value(), extra_nonce);
    if (!tmpl_result.ok()) {
        return make_error(RpcError::MISC_ERROR,
                          "Failed to create block template: " +
                          tmpl_result.error().message(), req.id);
    }

    auto tmpl = std::move(tmpl_result).value();

    // Serialize header to hex (80 bytes)
    auto header_arr = tmpl.header.serialize_array();
    std::string header_hex = hex_encode(header_arr.data(), header_arr.size());

    // Target to hex (32 bytes, big-endian display)
    std::string target_hex = tmpl.target.to_hex();

    int height = tmpl.height;

    // Assign a unique work_id and cache the template for submitwork
    int64_t work_id = g_next_work_id.fetch_add(1);
    {
        std::lock_guard<std::mutex> lock(g_work_mutex);
        evict_stale_work();
        g_cached_work[work_id] = std::move(tmpl);
    }

    JsonValue result(JsonValue::Object{});
    result["header"] = JsonValue(header_hex);
    result["target"] = JsonValue(target_hex);
    result["height"] = JsonValue(static_cast<int64_t>(height));
    result["work_id"] = JsonValue(work_id);

    LOG_INFO(core::LogCategory::RPC,
             "getwork: height=" + std::to_string(height) +
             " work_id=" + std::to_string(work_id));

    return make_result(std::move(result), req.id);
}

// ===========================================================================
// submitwork
// ===========================================================================

RpcResponse rpc_submitwork(const RpcRequest& req,
                            chain::ChainstateManager& chainstate,
                            mempool::Mempool& mempool,
                            net::NetManager* net_manager) {
    int64_t nonce = param_int(req.params, 0, 0);
    int64_t work_id = param_int(req.params, 1, 0);

    std::unique_lock<std::mutex> lock(g_work_mutex);

    if (g_cached_work.empty()) {
        return make_error(RpcError::MISC_ERROR,
                          "No work available. Call getwork first.", req.id);
    }

    // Look up the template by work_id, or use the most recent one if
    // work_id is 0 (backward compatibility with older miners).
    // Templates are NOT erased on use — they persist until evicted by
    // new getwork calls.  This prevents one miner's submitwork from
    // stealing another miner's template.
    miner::BlockTemplate tmpl;
    if (work_id > 0) {
        auto it = g_cached_work.find(work_id);
        if (it == g_cached_work.end()) {
            lock.unlock();
            return make_error(RpcError::MISC_ERROR,
                              "Work ID " + std::to_string(work_id) +
                              " not found (stale or already submitted). "
                              "Call getwork again.", req.id);
        }
        tmpl = it->second;  // copy, don't erase
    } else {
        // Backward compat: use the highest (most recent) work_id
        auto it = g_cached_work.begin();
        for (auto jt = g_cached_work.begin(); jt != g_cached_work.end(); ++jt) {
            if (jt->first > it->first) it = jt;
        }
        tmpl = it->second;  // copy, don't erase
    }
    lock.unlock();

    tmpl.header.nonce = static_cast<uint32_t>(nonce);
    auto block = tmpl.to_block();

    LOG_INFO(core::LogCategory::RPC,
             "submitwork: nonce=" + std::to_string(nonce) +
             " hash=" + block.hash().to_hex());

    auto accept = chainstate.accept_block(block);
    if (!accept.ok()) {
        return make_error(RpcError::VERIFY_REJECTED,
                          "Block rejected: " + accept.error().message(),
                          req.id);
    }

    auto activate = chainstate.activate_best_chain();
    if (!activate.ok()) {
        return make_error(RpcError::VERIFY_ERROR,
                          "Chain activation failed: " +
                          activate.error().message(), req.id);
    }

    // Remove mined transactions from the mempool.
    mempool.remove_for_block(block, tmpl.height);

    // Flush block index and UTXO set to disk so data survives restarts.
    chainstate.flush();

    // Broadcast to P2P peers
    if (net_manager) {
        net_manager->broadcast_block(block);
    }

    std::string hash_hex = block.hash().to_hex();
    LOG_INFO(core::LogCategory::RPC,
             "submitwork: block accepted, hash=" + hash_hex);

    return make_result(JsonValue(hash_hex), req.id);
}

// ===========================================================================
// Registration
// ===========================================================================

void register_mining_rpcs(RpcServer& server,
                           chain::ChainstateManager& chainstate,
                           mempool::Mempool& mempool,
                           net::NetManager** net_manager_ptr) {
    // Capture net_manager_ptr by value (it points to ctx.net_manager which
    // outlives the server).  Dereference at call time to get the live pointer.
    server.register_commands({
        {"getblocktemplate",
         [&](const RpcRequest& r) { return rpc_getblocktemplate(r, chainstate, mempool); },
         "getblocktemplate ( \"template_request\" )\n"
         "Returns data needed to construct a block to work on.\n"
         "Returns a block template for mining.",
         "mining"},

        {"submitblock",
         [&, net_manager_ptr](const RpcRequest& r) {
             net::NetManager* nm = net_manager_ptr ? *net_manager_ptr : nullptr;
             return rpc_submitblock(r, chainstate, mempool, nm);
         },
         "submitblock \"hexdata\"\n"
         "Attempts to submit new block to network.\n"
         "The block hex data must include all transactions.",
         "mining"},

        {"getmininginfo",
         [&](const RpcRequest& r) { return rpc_getmininginfo(r, chainstate, mempool); },
         "getmininginfo\n"
         "Returns a json object containing mining-related information.",
         "mining"},

        {"getnetworkhashps",
         [&](const RpcRequest& r) { return rpc_getnetworkhashps(r, chainstate); },
         "getnetworkhashps ( nblocks height )\n"
         "Returns the estimated network hashes per second.\n"
         "nblocks: number of blocks to use for estimate (default 120).\n"
         "height: to estimate at a particular height (-1 for tip).",
         "mining"},

        {"generate",
         [&, net_manager_ptr](const RpcRequest& r) {
             net::NetManager* nm = net_manager_ptr ? *net_manager_ptr : nullptr;
             return rpc_generate(r, chainstate, mempool, nm);
         },
         "generate nblocks \"address\"\n"
         "Mine nblocks blocks with coinbase reward sent to address.\n"
         "Returns array of block hashes.",
         "mining"},

        {"getwork",
         [&](const RpcRequest& r) { return rpc_getwork(r, chainstate, mempool); },
         "getwork \"address\"\n"
         "Returns mining work (header + target) for external miners.\n"
         "The miner solves Equihash locally and submits via submitwork.",
         "mining"},

        {"submitwork",
         [&, net_manager_ptr](const RpcRequest& r) {
             net::NetManager* nm = net_manager_ptr ? *net_manager_ptr : nullptr;
             return rpc_submitwork(r, chainstate, mempool, nm);
         },
         "submitwork nonce [work_id]\n"
         "Submit a solved nonce from an external miner.\n"
         "Call getwork first to obtain the work.\n"
         "work_id is returned by getwork and identifies the template.",
         "mining"},
    });
}

} // namespace rpc
