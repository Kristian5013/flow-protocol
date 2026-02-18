// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/fees.h"
#include "rpc/util.h"

#include "core/logging.h"
#include "mempool/fee_estimator.h"

#include <algorithm>
#include <cstdint>
#include <string>

namespace rpc {

// ===========================================================================
// estimatesmartfee
// ===========================================================================

RpcResponse rpc_estimatesmartfee(const RpcRequest& req,
                                  const mempool::FeeEstimator& fee_estimator) {
    int64_t conf_target = param_int(req.params, 0);

    // Validate target range
    if (conf_target < 1) {
        conf_target = 1;
    }
    if (conf_target > mempool::MAX_TARGET) {
        conf_target = mempool::MAX_TARGET;
    }

    // Optional estimate_mode parameter (conservative or economical)
    std::string mode = param_string(req.params, 1, "conservative");

    // Get the estimate
    int64_t fee_rate_kvb = fee_estimator.estimate_fee(
        static_cast<int>(conf_target));

    JsonValue result(JsonValue::Object{});

    if (fee_rate_kvb <= 0) {
        // No estimate available; return fallback
        result["feerate"] = JsonValue(
            format_amount(mempool::FALLBACK_FEE));
        result["blocks"]  = JsonValue(conf_target);

        JsonValue::Array errors;
        errors.push_back(JsonValue(
            "Insufficient data or no feerate found"));
        result["errors"] = JsonValue(std::move(errors));
    } else {
        // Convert sat/kvB to FTC/kvB
        result["feerate"] = JsonValue(format_amount(fee_rate_kvb));
        result["blocks"]  = JsonValue(conf_target);
    }

    return make_result(std::move(result), req.id);
}

// ===========================================================================
// estimaterawfee
// ===========================================================================

RpcResponse rpc_estimaterawfee(const RpcRequest& req,
                                const mempool::FeeEstimator& fee_estimator) {
    int64_t conf_target = param_int(req.params, 0);

    if (conf_target < 1) {
        conf_target = 1;
    }
    if (conf_target > mempool::MAX_TARGET) {
        conf_target = mempool::MAX_TARGET;
    }

    JsonValue result(JsonValue::Object{});

    // Short horizon estimate
    {
        JsonValue short_obj(JsonValue::Object{});
        auto short_est = fee_estimator.estimate_fee_detailed(
            std::min(static_cast<int>(conf_target), mempool::SHORT_TARGET));

        if (short_est.fee_rate > 0) {
            short_obj["feerate"]     = JsonValue(
                format_amount(short_est.fee_rate));
            short_obj["decay"]       = JsonValue(mempool::DECAY_FACTOR);
            short_obj["scale"]       = JsonValue(static_cast<int64_t>(1));
            short_obj["pass"]        = JsonValue(JsonValue::Object{});

            JsonValue pass(JsonValue::Object{});
            pass["startrange"]    = JsonValue(static_cast<int64_t>(0));
            pass["endrange"]      = JsonValue(static_cast<int64_t>(0));
            pass["withintarget"]  = JsonValue(short_est.confidence);
            pass["totalconfirmed"]= JsonValue(
                static_cast<int64_t>(short_est.sample_count));
            pass["inmempool"]     = JsonValue(static_cast<int64_t>(0));
            pass["leftmempool"]   = JsonValue(static_cast<int64_t>(0));
            short_obj["pass"] = std::move(pass);

            short_obj["fail"]     = JsonValue(JsonValue::Object{});
        } else {
            short_obj["feerate"]  = JsonValue(static_cast<int64_t>(0));
            short_obj["decay"]    = JsonValue(mempool::DECAY_FACTOR);
            short_obj["scale"]    = JsonValue(static_cast<int64_t>(1));
        }
        result["short"] = std::move(short_obj);
    }

    // Medium horizon estimate
    {
        JsonValue med_obj(JsonValue::Object{});
        auto med_est = fee_estimator.estimate_fee_detailed(
            std::min(static_cast<int>(conf_target), mempool::MED_TARGET));

        if (med_est.fee_rate > 0) {
            med_obj["feerate"]    = JsonValue(
                format_amount(med_est.fee_rate));
            med_obj["decay"]      = JsonValue(mempool::DECAY_FACTOR);
            med_obj["scale"]      = JsonValue(static_cast<int64_t>(2));

            JsonValue pass(JsonValue::Object{});
            pass["startrange"]    = JsonValue(static_cast<int64_t>(0));
            pass["endrange"]      = JsonValue(static_cast<int64_t>(0));
            pass["withintarget"]  = JsonValue(med_est.confidence);
            pass["totalconfirmed"]= JsonValue(
                static_cast<int64_t>(med_est.sample_count));
            pass["inmempool"]     = JsonValue(static_cast<int64_t>(0));
            pass["leftmempool"]   = JsonValue(static_cast<int64_t>(0));
            med_obj["pass"] = std::move(pass);

            med_obj["fail"]       = JsonValue(JsonValue::Object{});
        } else {
            med_obj["feerate"]    = JsonValue(static_cast<int64_t>(0));
            med_obj["decay"]      = JsonValue(mempool::DECAY_FACTOR);
            med_obj["scale"]      = JsonValue(static_cast<int64_t>(2));
        }
        result["medium"] = std::move(med_obj);
    }

    // Long horizon estimate
    {
        JsonValue long_obj(JsonValue::Object{});
        auto long_est = fee_estimator.estimate_fee_detailed(
            static_cast<int>(conf_target));

        if (long_est.fee_rate > 0) {
            long_obj["feerate"]   = JsonValue(
                format_amount(long_est.fee_rate));
            long_obj["decay"]     = JsonValue(mempool::DECAY_FACTOR);
            long_obj["scale"]     = JsonValue(static_cast<int64_t>(24));

            JsonValue pass(JsonValue::Object{});
            pass["startrange"]    = JsonValue(static_cast<int64_t>(0));
            pass["endrange"]      = JsonValue(static_cast<int64_t>(0));
            pass["withintarget"]  = JsonValue(long_est.confidence);
            pass["totalconfirmed"]= JsonValue(
                static_cast<int64_t>(long_est.sample_count));
            pass["inmempool"]     = JsonValue(static_cast<int64_t>(0));
            pass["leftmempool"]   = JsonValue(static_cast<int64_t>(0));
            long_obj["pass"] = std::move(pass);

            long_obj["fail"]      = JsonValue(JsonValue::Object{});
        } else {
            long_obj["feerate"]   = JsonValue(static_cast<int64_t>(0));
            long_obj["decay"]     = JsonValue(mempool::DECAY_FACTOR);
            long_obj["scale"]     = JsonValue(static_cast<int64_t>(24));
        }
        result["long"] = std::move(long_obj);
    }

    return make_result(std::move(result), req.id);
}

// ===========================================================================
// Registration
// ===========================================================================

void register_fee_rpcs(RpcServer& server,
                        const mempool::FeeEstimator& fee_estimator) {
    server.register_commands({
        {"estimatesmartfee",
         [&](const RpcRequest& r) {
             return rpc_estimatesmartfee(r, fee_estimator);
         },
         "estimatesmartfee conf_target ( \"estimate_mode\" )\n"
         "Estimates the approximate fee per kilobyte needed for a transaction\n"
         "to begin confirmation within conf_target blocks.\n"
         "estimate_mode: \"unset\", \"economical\", or \"conservative\" (default).\n"
         "\nResult:\n"
         "{\n"
         "  \"feerate\" : x.x,     (numeric) estimate fee rate in FTC/kvB\n"
         "  \"errors\" : [ ... ],   (array, optional) errors encountered\n"
         "  \"blocks\" : n          (numeric) block number where estimate was found\n"
         "}",
         "util"},

        {"estimaterawfee",
         [&](const RpcRequest& r) {
             return rpc_estimaterawfee(r, fee_estimator);
         },
         "estimaterawfee conf_target ( threshold )\n"
         "Returns raw fee estimation data for each tracking horizon.\n"
         "conf_target: confirmation target in blocks.\n"
         "\nResult:\n"
         "{\n"
         "  \"short\" : { ... },   (object) short-horizon estimate\n"
         "  \"medium\" : { ... },  (object) medium-horizon estimate\n"
         "  \"long\" : { ... }     (object) long-horizon estimate\n"
         "}",
         "util"},
    });
}

} // namespace rpc
