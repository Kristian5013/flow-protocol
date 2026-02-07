#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FTC_RPC_RAWTRANSACTION_H
#define FTC_RPC_RAWTRANSACTION_H

#include "rpc/request.h"
#include "rpc/server.h"

// Forward declarations
namespace chain {
    class ChainstateManager;
} // namespace chain
namespace mempool {
    class Mempool;
} // namespace mempool

namespace rpc {

/// getrawtransaction(txid, verbose): get transaction hex or JSON.
RpcResponse rpc_getrawtransaction(const RpcRequest& req,
                                   chain::ChainstateManager& chainstate,
                                   mempool::Mempool& mempool);

/// decoderawtransaction(hex): decode a raw transaction from hex.
RpcResponse rpc_decoderawtransaction(const RpcRequest& req);

/// sendrawtransaction(hex): submit a raw transaction to the mempool.
RpcResponse rpc_sendrawtransaction(const RpcRequest& req,
                                    chain::ChainstateManager& chainstate,
                                    mempool::Mempool& mempool);

/// createrawtransaction(inputs, outputs): create an unsigned raw transaction.
RpcResponse rpc_createrawtransaction(const RpcRequest& req);

/// signrawtransactionwithkey(hex, privkeys): sign with provided keys.
RpcResponse rpc_signrawtransactionwithkey(const RpcRequest& req,
                                           chain::ChainstateManager& chainstate);

/// Register all raw transaction RPC commands with the server.
void register_rawtransaction_rpcs(RpcServer& server,
                                   chain::ChainstateManager& chainstate,
                                   mempool::Mempool& mempool);

} // namespace rpc

#endif // FTC_RPC_RAWTRANSACTION_H
