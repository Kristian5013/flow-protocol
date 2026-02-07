#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Node -- top-level orchestrator for the FTC node.
//
// The Node class owns all subsystems via unique_ptr and coordinates their
// lifecycle:
//
//   1. Construction:  Stores the NodeConfig.  No subsystem is created yet.
//   2. init():        Creates and starts all subsystems in dependency order.
//   3. run():         Blocks the calling thread until a shutdown signal
//                     is received (SIGINT, SIGTERM, or programmatic).
//   4. shutdown():    Tears down all subsystems in reverse order, flushing
//                     persistent state to disk.
//
// Initialization order:
//   logging -> data directory -> chainstate -> mempool -> network
//   -> RPC (conditional) -> wallet (conditional) -> miner (conditional)
//
// Shutdown order (reverse):
//   miner -> wallet -> RPC -> network -> mempool -> chainstate -> logging
//
// Thread safety:
//   - init() and shutdown() must be called from the same thread (typically
//     main).
//   - run() blocks the calling thread.
//   - is_running() is safe to call from any thread (atomic).
// ---------------------------------------------------------------------------

#ifndef FTC_NODE_NODE_H
#define FTC_NODE_NODE_H

#include "core/error.h"
#include "node/context.h"
#include "node/init.h"

#include <atomic>
#include <memory>

// Forward declarations.  Full headers are included only in node.cpp.
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

namespace node {

class Node {
public:
    // -- Lifecycle -----------------------------------------------------------

    /// Construct a Node with the given configuration.
    ///
    /// No subsystems are created during construction.  Call init() to
    /// start the node.
    explicit Node(NodeConfig config);

    /// Destructor.  Calls shutdown() if the node is still running.
    ~Node();

    // Non-copyable, non-movable.
    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;
    Node(Node&&) = delete;
    Node& operator=(Node&&) = delete;

    /// Initialize all subsystems in order.
    ///
    /// Steps:
    ///   1. Install signal handlers.
    ///   2. Initialize logging.
    ///   3. Create the data directory structure.
    ///   4. Initialize chainstate (load block index, verify chain).
    ///   5. Initialize mempool.
    ///   6. Initialize network (start listener and event loop).
    ///   7. Initialize RPC server (if enabled).
    ///   8. Initialize wallet (if enabled).
    ///   9. Initialize miner (if enabled).
    ///
    /// On failure, any already-initialized subsystems are torn down
    /// before the error is returned.
    ///
    /// @returns core::make_ok() on success, or an error.
    [[nodiscard]] core::Result<void> init();

    /// Block the calling thread until a shutdown signal is received.
    ///
    /// The node enters its steady-state operation: all subsystems run on
    /// their own threads, and this function simply waits for the global
    /// shutdown flag to be set (via OS signal or programmatic call).
    ///
    /// After run() returns, call shutdown() to tear down subsystems.
    void run();

    /// Gracefully shut down all subsystems in reverse initialization order.
    ///
    /// It is safe to call shutdown() multiple times; subsequent calls are
    /// no-ops.
    void shutdown();

    /// Returns true if the node has been initialized and has not yet been
    /// shut down.  Thread-safe (atomic).
    [[nodiscard]] bool is_running() const noexcept;

    // -- Accessors -----------------------------------------------------------

    /// Returns a const reference to the node configuration.
    [[nodiscard]] const NodeConfig& config() const noexcept;

    /// Returns a reference to the NodeContext (non-owning pointers to all
    /// subsystems).  Valid only while the node is running.
    [[nodiscard]] NodeContext& context() noexcept;
    [[nodiscard]] const NodeContext& context() const noexcept;

    /// Returns the chainstate manager, or nullptr if not initialized.
    [[nodiscard]] chain::ChainstateManager* chainstate() const noexcept;

    /// Returns the mempool, or nullptr if not initialized.
    [[nodiscard]] mempool::Mempool* mempool() const noexcept;

    /// Returns the net manager, or nullptr if not initialized.
    [[nodiscard]] net::NetManager* net_manager() const noexcept;

    /// Returns the RPC server, or nullptr if not initialized/enabled.
    [[nodiscard]] rpc::RpcServer* rpc_server() const noexcept;

    /// Returns the wallet, or nullptr if not initialized/enabled.
    [[nodiscard]] wallet::Wallet* wallet() const noexcept;

    /// Returns the miner, or nullptr if not initialized/enabled.
    [[nodiscard]] miner::Miner* miner() const noexcept;

private:
    // -- Configuration -------------------------------------------------------
    NodeConfig config_;

    // -- Node context (non-owning observation pointers) ----------------------
    NodeContext ctx_;

    // -- Owned subsystem instances -------------------------------------------
    std::unique_ptr<chain::ChainstateManager> chainstate_;
    std::unique_ptr<mempool::Mempool>         mempool_;
    std::unique_ptr<net::NetManager>          net_manager_;
    std::unique_ptr<rpc::RpcServer>           rpc_server_;
    std::unique_ptr<wallet::Wallet>           wallet_;
    std::unique_ptr<miner::Miner>             miner_;

    // -- State ---------------------------------------------------------------
    std::atomic<bool> running_{false};
    std::atomic<bool> initialized_{false};
};

} // namespace node

#endif // FTC_NODE_NODE_H
