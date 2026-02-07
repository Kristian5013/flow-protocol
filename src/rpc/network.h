#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FTC_RPC_NETWORK_H
#define FTC_RPC_NETWORK_H

#include "rpc/request.h"
#include "rpc/server.h"

// Forward declarations
namespace net {
    class NetManager;
} // namespace net

namespace rpc {

/// getpeerinfo: list connected peers with stats.
RpcResponse rpc_getpeerinfo(const RpcRequest& req,
                             net::NetManager& netmgr);

/// getconnectioncount: number of connections.
RpcResponse rpc_getconnectioncount(const RpcRequest& req,
                                    net::NetManager& netmgr);

/// getnettotals: total bytes sent/received.
RpcResponse rpc_getnettotals(const RpcRequest& req,
                              net::NetManager& netmgr);

/// addnode(addr, command): add/remove/onetry a node.
RpcResponse rpc_addnode(const RpcRequest& req,
                         net::NetManager& netmgr);

/// disconnectnode(addr_or_id): disconnect a peer.
RpcResponse rpc_disconnectnode(const RpcRequest& req,
                                net::NetManager& netmgr);

/// getnetworkinfo: protocol version, connections, local addresses.
RpcResponse rpc_getnetworkinfo(const RpcRequest& req,
                                net::NetManager& netmgr);

/// Register all network RPC commands with the server.
void register_network_rpcs(RpcServer& server, net::NetManager& netmgr);

} // namespace rpc

#endif // FTC_RPC_NETWORK_H
