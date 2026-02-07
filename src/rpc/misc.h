#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FTC_RPC_MISC_H
#define FTC_RPC_MISC_H

#include "rpc/request.h"
#include "rpc/server.h"

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

/// validateaddress(addr): check if an address is valid.
RpcResponse rpc_validateaddress(const RpcRequest& req);

/// createmultisig(nrequired, keys): create a multisig address.
RpcResponse rpc_createmultisig(const RpcRequest& req);

/// verifymessage(addr, sig, message): verify a signed message.
RpcResponse rpc_verifymessage(const RpcRequest& req);

/// signmessagewithprivkey(key, message): sign a message with a private key.
RpcResponse rpc_signmessagewithprivkey(const RpcRequest& req);

/// getinfo: general node info (deprecated but useful).
RpcResponse rpc_getinfo(const RpcRequest& req,
                         chain::ChainstateManager& chainstate,
                         mempool::Mempool& mempool,
                         net::NetManager& netmgr);

/// Register all misc RPC commands with the server.
void register_misc_rpcs(RpcServer& server,
                         chain::ChainstateManager& chainstate,
                         mempool::Mempool& mempool,
                         net::NetManager& netmgr);

} // namespace rpc

#endif // FTC_RPC_MISC_H
