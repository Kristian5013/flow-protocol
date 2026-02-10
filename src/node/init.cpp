// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "node/init.h"
#include "node/config.h"
#include "node/context.h"

#include "chain/chainstate.h"
#include "consensus/params.h"
#include "core/error.h"
#include "core/fs.h"
#include "core/logging.h"
#include "core/thread.h"
#include "core/time.h"
#include "mempool/mempool.h"
#include "mempool/policy.h"
#include "net/address/subnet.h"
#include "net/manager/net_manager.h"

#include "rpc/server.h"
#include "rpc/blockchain.h"
#include "rpc/mempool_rpc.h"
#include "rpc/network.h"
#include "rpc/rawtransaction.h"
#include "rpc/mining.h"
#include "rpc/misc.h"
#include "rpc/control.h"
#include "rpc/wallet_rpc.h"

#include "wallet/wallet.h"

#include <filesystem>
#include <memory>
#include <string>

namespace node {

// ---------------------------------------------------------------------------
// Consensus parameter selection
// ---------------------------------------------------------------------------

const consensus::ConsensusParams&
select_consensus_params(const NodeConfig& config) {
    if (config.regtest) {
        return consensus::ConsensusParams::regtest_params();
    }
    if (config.testnet) {
        return consensus::ConsensusParams::testnet_params();
    }
    return consensus::ConsensusParams::mainnet_params();
}

// ---------------------------------------------------------------------------
// init_data_directory
// ---------------------------------------------------------------------------

core::Result<void>
init_data_directory(const std::filesystem::path& datadir) {
    LOG_INFO(core::LogCategory::NONE,
             "Initializing data directory: " + datadir.string());

    // Validate the path.
    auto validate_result = validate_datadir(datadir);
    if (!validate_result.ok()) {
        return validate_result.error();
    }

    // Create the directory structure.
    auto create_result = ensure_datadir_exists(datadir);
    if (!create_result.ok()) {
        return create_result.error();
    }

    // Create additional files/markers if they don't exist.
    // Write a .cookie file for RPC authentication if no rpcpassword is set.
    // (This would be expanded in the RPC module.)

    LOG_INFO(core::LogCategory::NONE,
             "Data directory ready: " + datadir.string());

    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// init_chainstate
// ---------------------------------------------------------------------------

core::Result<void> init_chainstate(NodeContext& ctx) {
    LOG_INFO(core::LogCategory::CHAIN, "Initializing chainstate manager...");
    core::StopWatch sw;

    // Select consensus parameters for the active network.
    const auto& params = select_consensus_params(ctx.config);

    // Resolve the data directory.
    std::filesystem::path datadir = ctx.config.resolved_datadir();

    // Create the chainstate manager.
    // The ChainstateManager constructor takes consensus params and data dir.
    auto chainstate = std::make_unique<chain::ChainstateManager>(
        params, datadir);

    // Initialize: load block index, replay UTXO set, verify consistency.
    auto init_result = chainstate->init();
    if (!init_result.ok()) {
        return core::Error(
            core::ErrorCode::STORAGE_ERROR,
            "Failed to initialize chainstate: " +
            init_result.error().message());
    }

    // Report chain state.
    const auto& active = chainstate->active_chain();
    int height = active.height();
    LOG_INFO(core::LogCategory::CHAIN,
             "Chainstate initialized: height=" + std::to_string(height) +
             " (" + std::to_string(sw.elapsed_ms()) + " ms)");

    // Transfer ownership: the raw pointer goes into the context for
    // cross-subsystem access.  The unique_ptr stays in Node.
    ctx.chainstate = chainstate.release();

    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// init_mempool
// ---------------------------------------------------------------------------

core::Result<void> init_mempool(NodeContext& ctx) {
    LOG_INFO(core::LogCategory::MEMPOOL, "Initializing transaction mempool...");
    core::StopWatch sw;

    // Use the default maximum mempool size.
    size_t max_size = mempool::DEFAULT_MAX_MEMPOOL_SIZE;

    auto pool = std::make_unique<mempool::Mempool>(max_size);

    LOG_INFO(core::LogCategory::MEMPOOL,
             "Mempool initialized: max_size=" +
             std::to_string(max_size / (1024 * 1024)) + " MB (" +
             std::to_string(sw.elapsed_ms()) + " ms)");

    ctx.mempool = pool.release();

    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// init_network
// ---------------------------------------------------------------------------

core::Result<void> init_network(NodeContext& ctx) {
    LOG_INFO(core::LogCategory::NET, "Initializing network manager...");
    core::StopWatch sw;

    // Verify prerequisites.
    if (!ctx.chainstate) {
        return core::Error(
            core::ErrorCode::INTERNAL_ERROR,
            "Cannot initialize network: chainstate not ready");
    }
    if (!ctx.mempool) {
        return core::Error(
            core::ErrorCode::INTERNAL_ERROR,
            "Cannot initialize network: mempool not ready");
    }

    // Build the network configuration.
    net::ConnManager::Config conn_cfg;
    conn_cfg.port = ctx.config.p2p_port;
    conn_cfg.listen = ctx.config.listen;
    conn_cfg.max_outbound = ctx.config.max_outbound;
    conn_cfg.max_inbound = ctx.config.max_inbound;

    net::NetManager::Config net_cfg;
    net_cfg.conn_config = conn_cfg;
    net_cfg.connect_nodes = ctx.config.connect_nodes;
    net_cfg.add_nodes = ctx.config.add_nodes;
    net_cfg.dns_seed = ctx.config.dns_seed;

    // Create the NetManager.
    auto net_mgr = std::make_unique<net::NetManager>(
        std::move(net_cfg),
        *ctx.chainstate,
        *ctx.mempool);

    // Start the network: bind listener, launch event loop, seed peers.
    auto start_result = net_mgr->start();
    if (!start_result.ok()) {
        return core::Error(
            core::ErrorCode::NETWORK_ERROR,
            "Failed to start network: " + start_result.error().message());
    }

    LOG_INFO(core::LogCategory::NET,
             "Network started: port=" + std::to_string(ctx.config.p2p_port) +
             " listen=" + (ctx.config.listen ? "yes" : "no") +
             " max_out=" + std::to_string(ctx.config.max_outbound) +
             " max_in=" + std::to_string(ctx.config.max_inbound) +
             " (" + std::to_string(sw.elapsed_ms()) + " ms)");

    ctx.net_manager = net_mgr.release();

    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// init_rpc
// ---------------------------------------------------------------------------

core::Result<void> init_rpc(NodeContext& ctx) {
    if (!ctx.config.rpc_enabled) {
        LOG_INFO(core::LogCategory::RPC, "RPC server disabled by configuration");
        return core::Result<void>{};
    }

    LOG_INFO(core::LogCategory::RPC, "Initializing RPC server...");
    core::StopWatch sw;

    // Warn if no authentication is configured and binding non-localhost.
    if (ctx.config.rpc_user.empty() && ctx.config.rpc_password.empty()) {
        if (ctx.config.rpc_bind != "127.0.0.1" && ctx.config.rpc_bind != "::1") {
            LOG_WARN(core::LogCategory::RPC,
                     "RPC server has no authentication configured with non-localhost bind. "
                     "Cookie auth will be used. Set -rpcuser and -rpcpassword for explicit control.");
        } else {
            LOG_INFO(core::LogCategory::RPC,
                     "Using cookie-based RPC authentication");
        }
    }

    // Build RPC server configuration from node config.
    rpc::RpcServer::Config rpc_cfg;
    rpc_cfg.bind_address = ctx.config.rpc_bind;
    rpc_cfg.port = ctx.config.rpc_port;
    rpc_cfg.rpc_user = ctx.config.rpc_user;
    rpc_cfg.rpc_password = ctx.config.rpc_password;
    rpc_cfg.data_dir = ctx.config.resolved_datadir().string();

    // Parse rpcallowip subnets.
    for (const auto& allowip : ctx.config.rpc_allowip) {
        auto subnet_result = net::Subnet::from_string(allowip);
        if (subnet_result.ok()) {
            rpc_cfg.allowed_subnets.push_back(subnet_result.value());
            LOG_INFO(core::LogCategory::RPC,
                     "RPC allowip: " + allowip);
        } else {
            LOG_WARN(core::LogCategory::RPC,
                     "Invalid rpcallowip value: " + allowip);
        }
    }

    auto server = std::make_unique<rpc::RpcServer>(rpc_cfg);

    // Register RPC command handlers for available subsystems.
    if (ctx.chainstate) {
        rpc::register_blockchain_rpcs(*server, *ctx.chainstate);
    }
    if (ctx.mempool) {
        rpc::register_mempool_rpcs(*server, *ctx.mempool);
    }
    if (ctx.chainstate && ctx.mempool) {
        rpc::register_rawtransaction_rpcs(*server, *ctx.chainstate, *ctx.mempool);
        rpc::register_mining_rpcs(*server, *ctx.chainstate, *ctx.mempool, &ctx.net_manager);
    }
    if (ctx.net_manager) {
        rpc::register_network_rpcs(*server, *ctx.net_manager);
    }
    if (ctx.chainstate && ctx.mempool && ctx.net_manager) {
        rpc::register_misc_rpcs(*server, *ctx.chainstate, *ctx.mempool, *ctx.net_manager);
    }

    // Register control RPCs (stop, uptime, help, getmemoryinfo, logging).
    // The rpc::NodeContext is static because the lambdas capture it by
    // reference and must outlive the server.
    static rpc::NodeContext rpc_ctx;
    rpc_ctx.startup_time = ctx.startup_time;
    rpc_ctx.request_shutdown = ctx.request_shutdown;
    rpc::register_control_rpcs(*server, rpc_ctx);

    // Start the server (bind, listen, launch threads).
    auto start_result = server->start();
    if (!start_result.ok()) {
        return core::Error(
            core::ErrorCode::RPC_ERROR,
            "Failed to start RPC server: " + start_result.error().message());
    }

    LOG_INFO(core::LogCategory::RPC,
             "RPC server started on " + ctx.config.rpc_bind +
             ":" + std::to_string(ctx.config.rpc_port) +
             " (" + std::to_string(sw.elapsed_ms()) + " ms)");

    ctx.rpc_server = server.release();
    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// init_wallet
// ---------------------------------------------------------------------------

core::Result<void> init_wallet(NodeContext& ctx) {
    if (!ctx.config.wallet_enabled) {
        LOG_INFO(core::LogCategory::WALLET,
                 "Wallet disabled by configuration");
        return core::Result<void>{};
    }

    if (!ctx.chainstate) {
        return core::Error(
            core::ErrorCode::INTERNAL_ERROR,
            "Cannot initialize wallet: chainstate not ready");
    }

    LOG_INFO(core::LogCategory::WALLET, "Initializing wallet...");
    core::StopWatch sw;

    // Resolve the wallet file path.
    std::filesystem::path wallet_path = ctx.config.wallet_file_path();

    // Ensure the wallet directory exists.
    if (wallet_path.has_parent_path()) {
        core::fs::ensure_directory(wallet_path.parent_path());
    }

    bool wallet_exists = core::fs::file_exists(wallet_path);
    LOG_INFO(core::LogCategory::WALLET,
             (wallet_exists ? "Loading existing wallet from "
                            : "Creating new wallet at ") +
             wallet_path.string());

    // Create the wallet and open/create the database.
    auto wallet_ptr = std::make_unique<wallet::Wallet>(*ctx.chainstate);
    auto open_result = wallet_ptr->open(wallet_path);
    if (!open_result.ok()) {
        return core::Error(
            core::ErrorCode::WALLET_ERROR,
            "Failed to open wallet: " + open_result.error().message());
    }

    LOG_INFO(core::LogCategory::WALLET,
             "Wallet initialized (" +
             std::to_string(sw.elapsed_ms()) + " ms)");

    ctx.wallet = wallet_ptr.release();

    // Register wallet RPC commands if the RPC server is available.
    if (ctx.rpc_server) {
        rpc::register_wallet_rpcs(*ctx.rpc_server, ctx.wallet);
        LOG_INFO(core::LogCategory::WALLET, "Wallet RPC commands registered");
    }

    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// init_miner
// ---------------------------------------------------------------------------

core::Result<void> init_miner(NodeContext& ctx) {
    if (!ctx.config.mine) {
        LOG_DEBUG(core::LogCategory::MINING, "Mining disabled");
        return core::Result<void>{};
    }

    LOG_INFO(core::LogCategory::MINING, "Initializing miner...");
    core::StopWatch sw;

    // Verify prerequisites.
    if (!ctx.chainstate) {
        return core::Error(
            core::ErrorCode::INTERNAL_ERROR,
            "Cannot initialize miner: chainstate not ready");
    }
    if (!ctx.mempool) {
        return core::Error(
            core::ErrorCode::INTERNAL_ERROR,
            "Cannot initialize miner: mempool not ready");
    }

    // Determine the number of mining threads.
    int num_threads = ctx.config.mine_threads;
    if (num_threads <= 0) {
        num_threads = core::get_num_cores();
        if (num_threads <= 0) num_threads = 1;
    }

    // Validate the mining address if provided.
    if (ctx.config.mine_address.empty()) {
        LOG_WARN(core::LogCategory::MINING,
                 "No mining address configured (-mineaddress). "
                 "Mining rewards will be lost unless a wallet is available.");
    }

    // The Miner class is not yet fully implemented.  When it becomes
    // available, the initialization would look like:
    //
    //   miner::Miner::Config miner_cfg;
    //   miner_cfg.num_threads = num_threads;
    //   miner_cfg.coinbase_address = ctx.config.mine_address;
    //
    //   auto miner_ptr = std::make_unique<miner::Miner>(
    //       miner_cfg, *ctx.chainstate, *ctx.mempool);
    //   miner_ptr->start();
    //   ctx.miner = miner_ptr.release();

    LOG_INFO(core::LogCategory::MINING,
             "Miner initialized: threads=" + std::to_string(num_threads) +
             " address=" +
             (ctx.config.mine_address.empty() ? "(none)" :
              ctx.config.mine_address) +
             " (" + std::to_string(sw.elapsed_ms()) + " ms)");

    // ctx.miner remains nullptr until the miner module is implemented.
    return core::Result<void>{};
}

} // namespace node
