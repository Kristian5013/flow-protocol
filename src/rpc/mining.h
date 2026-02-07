#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FTC_RPC_MINING_H
#define FTC_RPC_MINING_H

#include "rpc/request.h"
#include "rpc/server.h"

#include <vector>

// Forward declarations
namespace chain {
    class ChainstateManager;
} // namespace chain
namespace mempool {
    class Mempool;
} // namespace mempool
namespace net {
    class NetManager;
} // namespace net

namespace rpc {

/// getblocktemplate: return a block template for external miners.
RpcResponse rpc_getblocktemplate(const RpcRequest& req,
                                  chain::ChainstateManager& chainstate,
                                  mempool::Mempool& mempool);

/// submitblock(hex): submit a solved block to the network.
RpcResponse rpc_submitblock(const RpcRequest& req,
                             chain::ChainstateManager& chainstate,
                             mempool::Mempool& mempool,
                             net::NetManager* net_manager);

/// getmininginfo: return mining-related information.
RpcResponse rpc_getmininginfo(const RpcRequest& req,
                               chain::ChainstateManager& chainstate,
                               mempool::Mempool& mempool);

/// getnetworkhashps(nblocks, height): estimated network hash rate.
RpcResponse rpc_getnetworkhashps(const RpcRequest& req,
                                  chain::ChainstateManager& chainstate);

/// getwork: create a block template and return header + target for external miners.
RpcResponse rpc_getwork(const RpcRequest& req,
                        chain::ChainstateManager& chainstate,
                        mempool::Mempool& mempool);

/// submitwork: accept a solved nonce from an external miner.
RpcResponse rpc_submitwork(const RpcRequest& req,
                           chain::ChainstateManager& chainstate,
                           mempool::Mempool& mempool,
                           net::NetManager* net_manager);

/// Register all mining RPC commands with the server.
/// net_manager_ptr is a pointer to the context's net_manager field,
/// allowing lambdas to always read the current (possibly late-bound) value.
void register_mining_rpcs(RpcServer& server,
                           chain::ChainstateManager& chainstate,
                           mempool::Mempool& mempool,
                           net::NetManager** net_manager_ptr = nullptr);

} // namespace rpc

#endif // FTC_RPC_MINING_H
