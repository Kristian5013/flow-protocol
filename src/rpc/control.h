#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FTC_RPC_CONTROL_H
#define FTC_RPC_CONTROL_H

#include "rpc/request.h"
#include "rpc/server.h"

#include <atomic>
#include <cstdint>
#include <functional>

namespace rpc {

// ---------------------------------------------------------------------------
// NodeContext -- opaque reference to the node for control commands
// ---------------------------------------------------------------------------
// The control RPC commands need access to the node's lifecycle and logging.
// This struct bundles the necessary callbacks/state without creating a
// circular dependency on the full node implementation.
// ---------------------------------------------------------------------------

struct NodeContext {
    /// Callback to request a clean shutdown of the node.
    std::function<void()> request_shutdown;

    /// The Unix timestamp when the node started.
    int64_t startup_time = 0;

    /// Whether the node is currently in warmup/IBD mode.
    std::atomic<bool>* in_warmup = nullptr;
};

// ---------------------------------------------------------------------------
// Control RPC command handlers
// ---------------------------------------------------------------------------

/// stop: request a clean shutdown of the node.
RpcResponse rpc_stop(const RpcRequest& req, NodeContext& ctx);

/// uptime: return the node uptime in seconds.
RpcResponse rpc_uptime(const RpcRequest& req, const NodeContext& ctx);

/// help(command?): list all commands or show help for one.
RpcResponse rpc_help(const RpcRequest& req, RpcServer& server);

/// getmemoryinfo: return memory usage stats.
RpcResponse rpc_getmemoryinfo(const RpcRequest& req);

/// logging(include, exclude): get/set log categories.
RpcResponse rpc_logging(const RpcRequest& req);

/// Register all control RPC commands with the server.
void register_control_rpcs(RpcServer& server, NodeContext& ctx);

} // namespace rpc

#endif // FTC_RPC_CONTROL_H
