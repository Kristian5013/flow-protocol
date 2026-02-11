// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "node/node.h"

#include "node/config.h"
#include "node/context.h"
#include "node/init.h"
#include "node/logging_init.h"
#include "node/shutdown.h"

#include "chain/chainstate.h"
#include "core/error.h"
#include "core/logging.h"
#include "core/signal.h"
#include "core/time.h"
#include "mempool/mempool.h"
#include "miner/miner.h"
#include "net/manager/net_manager.h"
#include "rpc/server.h"
#include "wallet/wallet.h"

#include <memory>
#include <string>

namespace node {

// ---------------------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------------------

Node::Node(NodeConfig config)
    : config_(std::move(config))
    , ctx_(config_)
{
}

Node::~Node() {
    if (running_.load(std::memory_order_acquire)) {
        shutdown();
    }
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

core::Result<void> Node::init() {
    if (initialized_.load(std::memory_order_acquire)) {
        return core::Error(
            core::ErrorCode::INTERNAL_ERROR,
            "Node is already initialized");
    }

    core::StopWatch total_sw;

    // -----------------------------------------------------------------------
    // Step 1: Install signal handlers
    // -----------------------------------------------------------------------
    install_signal_handlers();

    // -----------------------------------------------------------------------
    // Step 2: Initialize logging
    // -----------------------------------------------------------------------
    // Enable console logging so early messages are visible.
    init_console_logging();

    auto log_result = init_logging(config_);
    if (!log_result.ok()) {
        // Log to stderr since file logging failed.
        LOG_ERROR(core::LogCategory::NONE,
                  "Failed to initialize logging: " +
                  log_result.error().message());
        // Continue anyway -- we can still log to the console.
    }

    LOG_INFO(core::LogCategory::NONE, "Starting FTC node initialization...");

    // -----------------------------------------------------------------------
    // Step 3: Data directory
    // -----------------------------------------------------------------------
    std::filesystem::path datadir = config_.resolved_datadir();
    auto dir_result = init_data_directory(datadir);
    if (!dir_result.ok()) {
        LOG_ERROR(core::LogCategory::NONE,
                  "Data directory initialization failed: " +
                  dir_result.error().message());
        return dir_result.error();
    }

    // -----------------------------------------------------------------------
    // Step 4: Chainstate
    // -----------------------------------------------------------------------
    auto cs_result = init_chainstate(ctx_);
    if (!cs_result.ok()) {
        LOG_ERROR(core::LogCategory::CHAIN,
                  "Chainstate initialization failed: " +
                  cs_result.error().message());
        shutdown_all(ctx_);
        return cs_result.error();
    }
    // Take ownership of the raw pointer returned by init_chainstate.
    chainstate_.reset(ctx_.chainstate);

    // -----------------------------------------------------------------------
    // Step 5: Mempool
    // -----------------------------------------------------------------------
    auto mp_result = init_mempool(ctx_);
    if (!mp_result.ok()) {
        LOG_ERROR(core::LogCategory::MEMPOOL,
                  "Mempool initialization failed: " +
                  mp_result.error().message());
        shutdown_all(ctx_);
        return mp_result.error();
    }
    mempool_.reset(ctx_.mempool);

    // -----------------------------------------------------------------------
    // Step 6: Network
    // -----------------------------------------------------------------------
    auto net_result = init_network(ctx_);
    if (!net_result.ok()) {
        LOG_ERROR(core::LogCategory::NET,
                  "Network initialization failed: " +
                  net_result.error().message());
        shutdown_all(ctx_);
        return net_result.error();
    }
    net_manager_.reset(ctx_.net_manager);

    // -----------------------------------------------------------------------
    // Set lifecycle fields used by control RPCs (stop, uptime).
    // -----------------------------------------------------------------------
    ctx_.startup_time = core::get_time();
    ctx_.request_shutdown = []() { node::request_shutdown(); };

    // -----------------------------------------------------------------------
    // Step 7: RPC (conditional)
    // -----------------------------------------------------------------------
    if (config_.rpc_enabled) {
        auto rpc_result = init_rpc(ctx_);
        if (!rpc_result.ok()) {
            LOG_ERROR(core::LogCategory::RPC,
                      "RPC initialization failed: " +
                      rpc_result.error().message());
            shutdown_all(ctx_);
            return rpc_result.error();
        }
        if (ctx_.rpc_server) {
            rpc_server_.reset(ctx_.rpc_server);
        }
    }

    // -----------------------------------------------------------------------
    // Step 8: Wallet (conditional)
    // -----------------------------------------------------------------------
    if (config_.wallet_enabled) {
        auto wallet_result = init_wallet(ctx_);
        if (!wallet_result.ok()) {
            LOG_WARN(core::LogCategory::WALLET,
                     "Wallet initialization failed, continuing without wallet: " +
                     wallet_result.error().message());
        }
        if (ctx_.wallet) {
            wallet_.reset(ctx_.wallet);
        }
    }

    // -----------------------------------------------------------------------
    // Step 9: Miner (conditional)
    // -----------------------------------------------------------------------
    if (config_.mine) {
        auto miner_result = init_miner(ctx_);
        if (!miner_result.ok()) {
            LOG_ERROR(core::LogCategory::MINING,
                      "Miner initialization failed: " +
                      miner_result.error().message());
            shutdown_all(ctx_);
            return miner_result.error();
        }
        if (ctx_.miner) {
            miner_.reset(ctx_.miner);
        }
    }

    // -----------------------------------------------------------------------
    // Done
    // -----------------------------------------------------------------------
    initialized_.store(true, std::memory_order_release);
    running_.store(true, std::memory_order_release);

    LOG_INFO(core::LogCategory::NONE,
             "Node initialization complete (" +
             std::to_string(total_sw.elapsed_ms()) + " ms)");

    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

void Node::run() {
    if (!running_.load(std::memory_order_acquire)) {
        LOG_WARN(core::LogCategory::NONE,
                 "Node::run() called but node is not running");
        return;
    }

    LOG_INFO(core::LogCategory::NONE,
             "Node is running. Press Ctrl+C to stop.");

    // Block until a shutdown signal is received.
    // This uses core::wait_for_shutdown() which waits on a condition
    // variable that is notified by the signal handler.
    wait_for_shutdown();

    LOG_INFO(core::LogCategory::NONE, "Shutdown signal received.");
}

// ---------------------------------------------------------------------------
// shutdown
// ---------------------------------------------------------------------------

void Node::shutdown() {
    // Check if we are actually running.
    bool was_running = running_.exchange(false, std::memory_order_acq_rel);
    if (!was_running) {
        return;  // Already shut down or never started.
    }

    LOG_INFO(core::LogCategory::NONE, "Node shutting down...");
    core::StopWatch total_sw;

    // Flush chainstate FIRST to ensure block index and UTXO set are
    // persisted even if subsequent shutdown steps hang or get killed.
    if (chainstate_) {
        LOG_INFO(core::LogCategory::CHAIN,
                 "Early chainstate flush before subsystem shutdown...");
        auto flush_result = chainstate_->flush();
        if (!flush_result.ok()) {
            LOG_ERROR(core::LogCategory::CHAIN,
                      "Error during early chainstate flush: " +
                      flush_result.error().message());
        }
    }

    // Shut down subsystems in reverse initialization order.
    // We null out the context pointers but keep the unique_ptrs alive
    // until the end of this function.

    // Miner
    if (miner_) {
        ctx_.miner = miner_.get();
        shutdown_miner(ctx_);
        miner_.reset();
    }

    // Wallet
    if (wallet_) {
        ctx_.wallet = wallet_.get();
        shutdown_wallet(ctx_);
        wallet_.reset();
    }

    // RPC
    if (rpc_server_) {
        ctx_.rpc_server = rpc_server_.get();
        shutdown_rpc(ctx_);
        rpc_server_.reset();
    }

    // Network
    if (net_manager_) {
        ctx_.net_manager = net_manager_.get();
        shutdown_network(ctx_);
        net_manager_.reset();
    }

    // Mempool
    if (mempool_) {
        ctx_.mempool = mempool_.get();
        shutdown_mempool(ctx_);
        mempool_.reset();
    }

    // Chainstate
    if (chainstate_) {
        ctx_.chainstate = chainstate_.get();
        shutdown_chainstate(ctx_);
        chainstate_.reset();
    }

    initialized_.store(false, std::memory_order_release);

    LOG_INFO(core::LogCategory::NONE,
             "Node shutdown complete (" +
             std::to_string(total_sw.elapsed_ms()) + " ms)");

    // Flush and close logging as the very last step.
    shutdown_logging();
}

// ---------------------------------------------------------------------------
// is_running
// ---------------------------------------------------------------------------

bool Node::is_running() const noexcept {
    return running_.load(std::memory_order_acquire);
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

const NodeConfig& Node::config() const noexcept {
    return config_;
}

NodeContext& Node::context() noexcept {
    return ctx_;
}

const NodeContext& Node::context() const noexcept {
    return ctx_;
}

chain::ChainstateManager* Node::chainstate() const noexcept {
    return chainstate_.get();
}

mempool::Mempool* Node::mempool() const noexcept {
    return mempool_.get();
}

net::NetManager* Node::net_manager() const noexcept {
    return net_manager_.get();
}

rpc::RpcServer* Node::rpc_server() const noexcept {
    return rpc_server_.get();
}

wallet::Wallet* Node::wallet() const noexcept {
    return wallet_.get();
}

miner::Miner* Node::miner() const noexcept {
    return miner_.get();
}

} // namespace node
