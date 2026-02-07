// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "node/shutdown.h"
#include "node/init.h"

#include "chain/chainstate.h"
#include "core/logging.h"
#include "core/signal.h"
#include "core/time.h"
#include "mempool/mempool.h"
#include "net/manager/net_manager.h"

// RPC, wallet, and miner headers -- these modules may not be fully
// implemented yet.  We forward-declared the types in the header; here
// we include what is available and handle the rest with nullptr guards.
// If a header is not yet available, the forward declaration suffices
// because we only call methods through a pointer (and we guard on nullptr).

#include <string>

namespace node {

// ---------------------------------------------------------------------------
// Shutdown signalling -- thin wrappers around core::signal
// ---------------------------------------------------------------------------

void request_shutdown() {
    core::request_shutdown();
}

bool shutdown_requested() noexcept {
    return core::shutdown_requested();
}

void wait_for_shutdown() {
    core::wait_for_shutdown();
}

// ---------------------------------------------------------------------------
// Signal handler installation
// ---------------------------------------------------------------------------

void install_signal_handlers() {
    core::init_signal_handlers();
}

// ---------------------------------------------------------------------------
// Per-subsystem shutdown functions
// ---------------------------------------------------------------------------

void shutdown_miner(NodeContext& ctx) {
    if (!ctx.miner) return;

    LOG_INFO(core::LogCategory::MINING, "Stopping miner...");
    core::StopWatch sw;

    // The Miner class is expected to have a stop() method that halts all
    // mining threads.  Since the miner module is not yet fully implemented,
    // we guard the call.  The unique_ptr in Node will handle destruction.
    // When the Miner class is available, uncomment:
    // ctx.miner->stop();

    ctx.miner = nullptr;

    LOG_INFO(core::LogCategory::MINING,
             "Miner stopped (" + std::to_string(sw.elapsed_ms()) + " ms)");
}

void shutdown_wallet(NodeContext& ctx) {
    if (!ctx.wallet) return;

    LOG_INFO(core::LogCategory::WALLET, "Flushing and closing wallet...");
    core::StopWatch sw;

    // The Wallet class is expected to have flush() and close() methods.
    // When the wallet module is available, uncomment:
    // ctx.wallet->flush();

    ctx.wallet = nullptr;

    LOG_INFO(core::LogCategory::WALLET,
             "Wallet closed (" + std::to_string(sw.elapsed_ms()) + " ms)");
}

void shutdown_rpc(NodeContext& ctx) {
    if (!ctx.rpc_server) return;

    LOG_INFO(core::LogCategory::RPC, "Stopping RPC server...");
    core::StopWatch sw;

    // The RpcServer class is expected to have a stop() method.
    // When the RPC module is available, uncomment:
    // ctx.rpc_server->stop();

    ctx.rpc_server = nullptr;

    LOG_INFO(core::LogCategory::RPC,
             "RPC server stopped (" + std::to_string(sw.elapsed_ms()) + " ms)");
}

void shutdown_network(NodeContext& ctx) {
    if (!ctx.net_manager) return;

    LOG_INFO(core::LogCategory::NET, "Stopping network manager...");
    core::StopWatch sw;

    ctx.net_manager->stop();
    ctx.net_manager = nullptr;

    LOG_INFO(core::LogCategory::NET,
             "Network stopped (" + std::to_string(sw.elapsed_ms()) + " ms)");
}

void shutdown_mempool(NodeContext& ctx) {
    if (!ctx.mempool) return;

    LOG_INFO(core::LogCategory::MEMPOOL, "Clearing mempool...");
    core::StopWatch sw;

    // Log stats before clearing.
    size_t tx_count = ctx.mempool->size();
    ctx.mempool->clear();
    ctx.mempool = nullptr;

    LOG_INFO(core::LogCategory::MEMPOOL,
             "Mempool cleared (" + std::to_string(tx_count) +
             " transactions removed, " +
             std::to_string(sw.elapsed_ms()) + " ms)");
}

void shutdown_chainstate(NodeContext& ctx) {
    if (!ctx.chainstate) return;

    LOG_INFO(core::LogCategory::CHAIN, "Flushing chainstate to disk...");
    core::StopWatch sw;

    // Flush the UTXO cache and block index.
    auto flush_result = ctx.chainstate->flush();
    if (!flush_result.ok()) {
        LOG_ERROR(core::LogCategory::CHAIN,
                  "Error flushing chainstate: " +
                  flush_result.error().message());
    }

    // Orderly shutdown of the chainstate manager.
    auto shutdown_result = ctx.chainstate->shutdown();
    if (!shutdown_result.ok()) {
        LOG_ERROR(core::LogCategory::CHAIN,
                  "Error during chainstate shutdown: " +
                  shutdown_result.error().message());
    }

    ctx.chainstate = nullptr;

    LOG_INFO(core::LogCategory::CHAIN,
             "Chainstate shutdown complete (" +
             std::to_string(sw.elapsed_ms()) + " ms)");
}

// ---------------------------------------------------------------------------
// Full shutdown sequence
// ---------------------------------------------------------------------------

void shutdown_all(NodeContext& ctx) {
    LOG_INFO(core::LogCategory::NONE, "Beginning graceful shutdown...");
    core::StopWatch total_sw;

    // Shutdown in reverse initialization order.
    shutdown_miner(ctx);
    shutdown_wallet(ctx);
    shutdown_rpc(ctx);
    shutdown_network(ctx);
    shutdown_mempool(ctx);
    shutdown_chainstate(ctx);

    LOG_INFO(core::LogCategory::NONE,
             "All subsystems shut down successfully (" +
             std::to_string(total_sw.elapsed_ms()) + " ms)");
}

// ---------------------------------------------------------------------------
// Logging shutdown
// ---------------------------------------------------------------------------

void shutdown_logging() {
    LOG_INFO(core::LogCategory::NONE, "Shutting down logging...");

    auto& logger = core::Logger::instance();
    logger.flush();

    // Close the log file by setting an empty path.
    logger.set_log_file(std::filesystem::path{});
    logger.set_print_to_file(false);
}

} // namespace node
