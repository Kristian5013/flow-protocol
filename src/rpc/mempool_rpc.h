#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FTC_RPC_MEMPOOL_RPC_H
#define FTC_RPC_MEMPOOL_RPC_H

#include "rpc/request.h"
#include "rpc/server.h"

// Forward declarations
namespace mempool {
    class Mempool;
} // namespace mempool

namespace rpc {

/// getmempoolinfo: mempool stats (size, bytes, usage, etc.).
RpcResponse rpc_getmempoolinfo(const RpcRequest& req,
                                mempool::Mempool& mempool);

/// getrawmempool(verbose): list mempool txids or detailed info.
RpcResponse rpc_getrawmempool(const RpcRequest& req,
                               mempool::Mempool& mempool);

/// getmempoolentry(txid): get info about a single mempool entry.
RpcResponse rpc_getmempoolentry(const RpcRequest& req,
                                 mempool::Mempool& mempool);

/// testmempoolaccept(rawtxs): test if transactions would be accepted.
RpcResponse rpc_testmempoolaccept(const RpcRequest& req,
                                   mempool::Mempool& mempool);

/// Register all mempool RPC commands with the server.
void register_mempool_rpcs(RpcServer& server, mempool::Mempool& mempool);

} // namespace rpc

#endif // FTC_RPC_MEMPOOL_RPC_H
