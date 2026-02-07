#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Graceful shutdown for the FTC node.
//
// This module provides:
//   - A thread-safe shutdown signalling mechanism (delegates to core::signal).
//   - Per-subsystem shutdown functions that flush state and release resources.
//   - OS signal handler registration for SIGINT/SIGTERM (POSIX) or
//     SetConsoleCtrlHandler (Windows).
//
// Shutdown order is the reverse of initialization:
//   miner -> wallet -> rpc -> network -> mempool -> chainstate
//
// Each shutdown function is safe to call even if the subsystem was never
// initialized (the pointer in NodeContext will be nullptr).
// ---------------------------------------------------------------------------

#ifndef FTC_NODE_SHUTDOWN_H
#define FTC_NODE_SHUTDOWN_H

#include <atomic>
#include <condition_variable>
#include <mutex>

// Forward declarations -- subsystem types.
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
    class RpcServer;
} // namespace rpc

namespace wallet {
    class Wallet;
} // namespace wallet

namespace miner {
    class Miner;
} // namespace miner

// Forward declaration of NodeContext (defined in init.h).
namespace node {
    struct NodeContext;
} // namespace node

namespace node {

// ---------------------------------------------------------------------------
// Shutdown signalling
// ---------------------------------------------------------------------------

/// Signal the node to stop.  Thread-safe; idempotent.
///
/// Sets an internal atomic flag and wakes any threads blocked in
/// wait_for_shutdown().  Delegates to core::request_shutdown().
void request_shutdown();

/// Check whether a shutdown has been requested.
///
/// Lock-free; safe to call from any thread including signal handlers.
[[nodiscard]] bool shutdown_requested() noexcept;

/// Block the calling thread until shutdown_requested() becomes true.
///
/// Uses a condition variable so the thread sleeps efficiently.
/// Delegates to core::wait_for_shutdown().
void wait_for_shutdown();

// ---------------------------------------------------------------------------
// Signal handler registration
// ---------------------------------------------------------------------------

/// Install OS-level signal handlers for graceful shutdown.
///
/// On POSIX: SIGINT, SIGTERM, SIGHUP.
/// On Windows: SetConsoleCtrlHandler for CTRL_C, CTRL_BREAK, CTRL_CLOSE.
///
/// Safe to call multiple times (subsequent calls are no-ops).
/// Delegates to core::init_signal_handlers().
void install_signal_handlers();

// ---------------------------------------------------------------------------
// Per-subsystem shutdown functions
// ---------------------------------------------------------------------------

/// Shut down the miner subsystem.
///
/// Stops all mining threads and waits for them to finish.
/// Safe to call if ctx.miner is nullptr.
void shutdown_miner(NodeContext& ctx);

/// Shut down the wallet subsystem.
///
/// Flushes the wallet database to disk and releases resources.
/// Safe to call if ctx.wallet is nullptr.
void shutdown_wallet(NodeContext& ctx);

/// Shut down the RPC server.
///
/// Stops accepting new connections and drains in-flight requests.
/// Safe to call if ctx.rpc_server is nullptr.
void shutdown_rpc(NodeContext& ctx);

/// Shut down the network subsystem.
///
/// Disconnects all peers, stops the event loop, and joins all I/O threads.
/// Safe to call if ctx.net_manager is nullptr.
void shutdown_network(NodeContext& ctx);

/// Shut down the mempool.
///
/// Clears all unconfirmed transactions from memory.
/// Safe to call if ctx.mempool is nullptr.
void shutdown_mempool(NodeContext& ctx);

/// Shut down the chainstate manager.
///
/// Flushes the UTXO cache and block index to disk, closes all file handles.
/// Safe to call if ctx.chainstate is nullptr.
void shutdown_chainstate(NodeContext& ctx);

// ---------------------------------------------------------------------------
// Full shutdown sequence
// ---------------------------------------------------------------------------

/// Execute the full shutdown sequence on all subsystems in reverse
/// initialization order.
///
/// Calls each per-subsystem shutdown function in order:
///   miner -> wallet -> rpc -> network -> mempool -> chainstate
///
/// After completion, all subsystem pointers in ctx are set to nullptr.
///
/// @param ctx  The node context with pointers to active subsystems.
void shutdown_all(NodeContext& ctx);

/// Flush all logging buffers and close the log file.
///
/// Should be called as the very last step before process exit.
void shutdown_logging();

} // namespace node

#endif // FTC_NODE_SHUTDOWN_H
