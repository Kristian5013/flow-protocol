#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Node initialization -- subsystem creation and startup.
//
// Each init_* function is responsible for creating one subsystem, validating
// its initial state, and storing a raw pointer into the NodeContext.  The
// actual ownership (unique_ptr) lives in the Node class; the NodeContext
// only holds non-owning observation pointers so that init/shutdown helpers
// can reference all subsystems without coupling to the Node class.
//
// Initialization order:
//   1. Data directory
//   2. Logging  (handled separately via logging_init.h)
//   3. Chainstate
//   4. Mempool
//   5. Network
//   6. RPC      (conditional on config)
//   7. Wallet   (conditional on config)
//   8. Miner    (conditional on config)
//
// On failure, each function returns a core::Error with a descriptive
// message.  The caller (Node::init) should abort startup and unwind.
// ---------------------------------------------------------------------------

#ifndef FTC_NODE_INIT_H
#define FTC_NODE_INIT_H

#include "core/error.h"
#include "node/context.h"

#include <cstdint>
#include <filesystem>
#include <functional>

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

namespace consensus {
    struct ConsensusParams;
} // namespace consensus

namespace node {

// ---------------------------------------------------------------------------
// NodeContext -- lightweight observation struct referencing all subsystems
// ---------------------------------------------------------------------------

struct NodeContext {
    /// Reference to the node configuration (always valid).
    NodeConfig& config;

    /// Raw (non-owning) pointers to subsystems.  Null until the
    /// corresponding init_* function completes successfully.
    chain::ChainstateManager* chainstate = nullptr;
    mempool::Mempool*         mempool    = nullptr;
    net::NetManager*          net_manager = nullptr;
    rpc::RpcServer*           rpc_server = nullptr;
    wallet::Wallet*           wallet     = nullptr;
    miner::Miner*             miner      = nullptr;

    /// Unix timestamp when the node started (set during init).
    int64_t startup_time = 0;

    /// Callback to request a clean shutdown (set during init).
    std::function<void()> request_shutdown;

    /// Explicit constructor (config is a required reference).
    explicit NodeContext(NodeConfig& cfg) : config(cfg) {}
};

// ---------------------------------------------------------------------------
// Data directory initialization
// ---------------------------------------------------------------------------

/// Create the data directory and its standard subdirectories.
///
/// Directory layout:
///   datadir/blocks/       -- blockchain.dat, undo files
///   datadir/chainstate/   -- UTXO snapshot, block index database
///   datadir/wallet/       -- wallet.dat
///   datadir/peers.dat     -- (future) peer address database
///   datadir/debug.log     -- log file
///
/// @param datadir  The resolved data directory path.
/// @returns core::make_ok() on success, or an error.
[[nodiscard]] core::Result<void>
init_data_directory(const std::filesystem::path& datadir);

// ---------------------------------------------------------------------------
// Subsystem initialization functions
// ---------------------------------------------------------------------------

/// Initialize the chainstate manager.
///
/// Creates a ChainstateManager, loads the block index from disk, and
/// verifies the integrity of the active chain.
///
/// @param ctx  The node context.  On success, ctx.chainstate is set.
/// @returns core::make_ok() on success, or an error.
[[nodiscard]] core::Result<void> init_chainstate(NodeContext& ctx);

/// Initialize the transaction mempool.
///
/// Creates a Mempool with the default or configured maximum size.
///
/// @param ctx  The node context.  On success, ctx.mempool is set.
/// @returns core::make_ok() on success, or an error.
[[nodiscard]] core::Result<void> init_mempool(NodeContext& ctx);

/// Initialize the P2P network manager.
///
/// Creates a NetManager with the configured connection parameters
/// and starts the networking subsystem (listener, event loop, peer
/// discovery).
///
/// Requires: ctx.chainstate and ctx.mempool must be initialized.
///
/// @param ctx  The node context.  On success, ctx.net_manager is set.
/// @returns core::make_ok() on success, or an error.
[[nodiscard]] core::Result<void> init_network(NodeContext& ctx);

/// Initialize the JSON-RPC server.
///
/// Creates and starts the RPC server on the configured bind address
/// and port.  Only called if config.rpc_enabled is true.
///
/// @param ctx  The node context.  On success, ctx.rpc_server is set.
/// @returns core::make_ok() on success, or an error.
[[nodiscard]] core::Result<void> init_rpc(NodeContext& ctx);

/// Initialize the wallet subsystem.
///
/// Loads an existing wallet file or creates a new one.  Only called if
/// config.wallet_enabled is true.
///
/// @param ctx  The node context.  On success, ctx.wallet is set.
/// @returns core::make_ok() on success, or an error.
[[nodiscard]] core::Result<void> init_wallet(NodeContext& ctx);

/// Initialize the miner subsystem.
///
/// Creates a miner with the configured number of threads.  Only called
/// if config.mine is true.
///
/// Requires: ctx.chainstate and ctx.mempool must be initialized.
///
/// @param ctx  The node context.  On success, ctx.miner is set.
/// @returns core::make_ok() on success, or an error.
[[nodiscard]] core::Result<void> init_miner(NodeContext& ctx);

// ---------------------------------------------------------------------------
// Consensus parameter selection
// ---------------------------------------------------------------------------

/// Select the appropriate consensus parameters based on the node config
/// (mainnet, testnet, or regtest).
///
/// @param config  The node configuration.
/// @returns Reference to the static consensus parameters.
[[nodiscard]] const consensus::ConsensusParams&
select_consensus_params(const NodeConfig& config);

} // namespace node

#endif // FTC_NODE_INIT_H
