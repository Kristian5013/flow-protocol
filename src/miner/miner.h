#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Miner -- top-level mining coordinator for FTC.
//
// Orchestrates all mining operations: block template creation, work
// distribution across worker threads, solution verification, and block
// submission. Listens for new chain tips to reset mining to the latest
// block, and manages the lifecycle of worker threads.
//
// The Miner operates in an event-driven fashion using a Channel<MinerEvent>
// for coordination between the main mining loop and external components
// (new tip notifications, user commands, etc.).
// ---------------------------------------------------------------------------

#include "chain/chainstate.h"
#include "core/channel.h"
#include "core/error.h"
#include "core/types.h"
#include "mempool/mempool.h"
#include "miner/block_template.h"
#include "miner/stratum.h"
#include "miner/worker.h"
#include "primitives/address.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace miner {

// ---------------------------------------------------------------------------
// MinerEvent -- events that drive the mining loop
// ---------------------------------------------------------------------------

/// Events consumed by the Miner's main coordination loop.
enum class MinerEvent {
    /// A new chain tip has been activated; reset mining to build on it.
    NEW_TIP,

    /// A valid block has been found by one of the worker threads.
    BLOCK_FOUND,

    /// Mining has been stopped (user requested or shutdown).
    STOPPED,

    /// The mempool has been updated; optionally refresh the template.
    MEMPOOL_UPDATED,

    /// A Stratum worker submitted a block-level share.
    STRATUM_BLOCK,
};

// ---------------------------------------------------------------------------
// MinerStats -- aggregate mining statistics
// ---------------------------------------------------------------------------

/// Snapshot of current mining statistics.
struct MinerStats {
    /// Whether the miner is currently active.
    bool mining = false;

    /// Number of active worker threads.
    int num_threads = 0;

    /// Estimated aggregate hash rate (nonces/second across all workers).
    double hashrate = 0.0;

    /// Total number of blocks found since the miner was started.
    uint64_t blocks_found = 0;

    /// Height of the block currently being mined.
    int current_height = 0;

    /// Current difficulty as a human-readable number.
    double difficulty = 0.0;

    /// Number of transactions in the current block template.
    size_t template_tx_count = 0;

    /// Total fees in the current block template (satoshis).
    int64_t template_fees = 0;

    /// Uptime in seconds since mining started.
    int64_t uptime_seconds = 0;
};

// ---------------------------------------------------------------------------
// Miner
// ---------------------------------------------------------------------------

/// Top-level mining coordinator that manages the complete mining pipeline:
/// template creation, nonce distribution, worker management, and block
/// submission.
///
/// Usage:
///   Miner miner(chainstate, mempool);
///   miner.set_coinbase_address(address);
///   miner.start(4);  // mine with 4 threads
///   // ...
///   miner.stop();
class Miner {
public:
    /// Construct a miner connected to the given chainstate and mempool.
    ///
    /// @param chainstate  The chainstate manager (for chain tip info and
    ///                    block submission).
    /// @param mempool     The transaction mempool (for block template txs).
    Miner(chain::ChainstateManager& chainstate,
          mempool::Mempool& mempool);

    ~Miner();

    // Non-copyable, non-movable.
    Miner(const Miner&) = delete;
    Miner& operator=(const Miner&) = delete;
    Miner(Miner&&) = delete;
    Miner& operator=(Miner&&) = delete;

    // -- Lifecycle ----------------------------------------------------------

    /// Start mining with the specified number of worker threads.
    ///
    /// Creates a block template from the current chain state and mempool,
    /// partitions the nonce space among workers, and launches them.
    /// The coordination loop runs in a dedicated thread, listening for
    /// events (new tip, block found, etc.).
    ///
    /// @param num_threads  Number of worker threads (default: hardware
    ///                     concurrency).
    /// @returns            core::make_ok() on success, or an error.
    [[nodiscard]] core::Result<void> start(
        int num_threads = 0);

    /// Stop all mining activity.
    ///
    /// Signals all workers to stop, joins their threads, and shuts down
    /// the coordination loop. Blocks until everything is cleanly stopped.
    void stop();

    /// Check if the miner is currently active.
    [[nodiscard]] bool is_mining() const {
        return mining_.load(std::memory_order_relaxed);
    }

    // -- Configuration -----------------------------------------------------

    /// Set the coinbase payout address.
    ///
    /// @param address  The address where block rewards will be sent.
    void set_coinbase_address(const primitives::Address& address);

    /// Get the current coinbase address.
    [[nodiscard]] primitives::Address get_coinbase_address() const;

    // -- Statistics ---------------------------------------------------------

    /// Get the estimated aggregate hash rate (nonces/second).
    [[nodiscard]] double get_hashrate() const;

    /// Get the total number of blocks found since the miner started.
    [[nodiscard]] uint64_t get_blocks_found() const {
        return blocks_found_.load(std::memory_order_relaxed);
    }

    /// Get a comprehensive statistics snapshot.
    [[nodiscard]] MinerStats get_stats() const;

    // -- Event injection ---------------------------------------------------

    /// Notify the miner that a new chain tip has been activated.
    ///
    /// This causes the miner to abort current work, create a new block
    /// template based on the new tip, and restart all workers.
    void notify_new_tip();

    /// Notify the miner that the mempool has been updated.
    ///
    /// The miner may optionally refresh the block template to include
    /// new higher-fee transactions.
    void notify_mempool_updated();

    // -- Stratum -----------------------------------------------------------

    /// Get the Stratum server (for external configuration/monitoring).
    /// Returns nullptr if Stratum is not enabled.
    [[nodiscard]] StratumServer* stratum_server() {
        return stratum_.get();
    }

    /// Enable the Stratum pool mining server.
    ///
    /// @param port  The TCP port for the Stratum server.
    /// @returns     core::make_ok() on success, or an error.
    [[nodiscard]] core::Result<void> enable_stratum(
        uint16_t port = DEFAULT_STRATUM_PORT);

    /// Disable the Stratum server.
    void disable_stratum();

private:
    // -- Internal helpers ---------------------------------------------------

    /// The main coordination loop (runs in its own thread).
    /// Processes events from the event channel and manages workers.
    void coordination_loop();

    /// Create a new block template and distribute work to all workers.
    void reset_mining();

    /// Stop all worker threads (without stopping the coordination loop).
    void stop_workers();

    /// Start worker threads with the current template.
    void start_workers();

    /// Handle a found block: verify, submit, and restart mining.
    void handle_block_found(const WorkerResult& result);

    /// Submit a mined block to the chainstate manager.
    core::Result<void> submit_block(
        const primitives::BlockHeader& header);

    // -- Data members -------------------------------------------------------

    chain::ChainstateManager& chainstate_;
    mempool::Mempool& mempool_;

    /// Event channel for the coordination loop.
    core::Channel<MinerEvent> event_channel_;

    /// Channel for worker results.
    core::Channel<WorkerResult> result_channel_;

    /// Coordination thread.
    std::thread coord_thread_;

    /// Worker threads.
    std::vector<std::thread> worker_threads_;

    /// Worker objects.
    std::vector<std::unique_ptr<MinerWorker>> workers_;

    /// Cancel token shared by all workers.
    std::atomic<bool> cancel_token_{false};

    /// Whether mining is active.
    std::atomic<bool> mining_{false};

    /// Whether the miner is shutting down.
    std::atomic<bool> shutting_down_{false};

    /// Number of worker threads.
    int num_threads_ = 0;

    /// Current block template.
    mutable std::mutex template_mutex_;
    std::unique_ptr<BlockTemplate> current_template_;

    /// Coinbase address.
    mutable std::mutex address_mutex_;
    primitives::Address coinbase_address_;

    /// Extra nonce counter (incremented for each template).
    std::atomic<uint64_t> extra_nonce_{0};

    /// Statistics.
    std::atomic<uint64_t> blocks_found_{0};
    std::atomic<int64_t> start_time_{0};

    /// Last worker result (for block submission).
    mutable std::mutex result_mutex_;
    std::unique_ptr<WorkerResult> last_result_;

    /// Stratum server (optional).
    std::unique_ptr<StratumServer> stratum_;
};

} // namespace miner
