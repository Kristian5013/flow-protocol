#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FTC_RPC_FEES_H
#define FTC_RPC_FEES_H

#include "rpc/request.h"
#include "rpc/server.h"

// Forward declarations
namespace mempool {
    class FeeEstimator;
} // namespace mempool

namespace rpc {

/// estimatesmartfee(conf_target): estimated fee rate for confirmation target.
RpcResponse rpc_estimatesmartfee(const RpcRequest& req,
                                  const mempool::FeeEstimator& fee_estimator);

/// estimaterawfee(conf_target): raw fee estimation data.
RpcResponse rpc_estimaterawfee(const RpcRequest& req,
                                const mempool::FeeEstimator& fee_estimator);

/// Register all fee estimation RPC commands with the server.
void register_fee_rpcs(RpcServer& server,
                        const mempool::FeeEstimator& fee_estimator);

} // namespace rpc

#endif // FTC_RPC_FEES_H
