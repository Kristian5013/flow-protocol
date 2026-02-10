#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// MinerWorker -- single mining thread for the FTC miner.
//
// Each MinerWorker owns a PowSolver and processes a designated
// range of nonces. Multiple workers run in parallel to utilise all
// available CPU cores. Workers communicate results back to the Miner
// coordinator through a callback or channel.
// ---------------------------------------------------------------------------

#include "core/channel.h"
#include "core/types.h"
#include "miner/block_template.h"
#include "miner/solver.h"
#include "primitives/block_header.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <thread>
#include <vector>

namespace miner {

// ---------------------------------------------------------------------------
// WorkerResult -- result of a mining attempt
// ---------------------------------------------------------------------------

/// Describes the outcome of a mining worker's run.
struct WorkerResult {
    /// Whether a valid block was found.
    bool found = false;

    /// The block header with the winning nonce (only valid if found == true).
    primitives::BlockHeader header;

    /// The number of nonces tried during this run.
    uint64_t nonces_tried = 0;

    /// Wall-clock time spent mining (milliseconds).
    int64_t elapsed_ms = 0;

    /// The worker ID that produced this result.
    int worker_id = -1;
};

// ---------------------------------------------------------------------------
// NonceRange -- defines the nonce range for a worker
// ---------------------------------------------------------------------------

/// A half-open range of nonces [start, end) for a worker to iterate.
struct NonceRange {
    uint32_t start = 0;
    uint32_t end = 0;

    /// Number of nonces in this range.
    [[nodiscard]] uint64_t size() const {
        return static_cast<uint64_t>(end) - static_cast<uint64_t>(start);
    }
};

/// Divide the full 32-bit nonce space into N non-overlapping ranges.
///
/// @param num_workers  Number of workers (ranges to create).
/// @returns            A vector of NonceRange, one per worker.
[[nodiscard]] std::vector<NonceRange> partition_nonce_space(int num_workers);

// ---------------------------------------------------------------------------
// WorkerCallback
// ---------------------------------------------------------------------------

/// Callback type for reporting worker results.
using WorkerCallback = std::function<void(WorkerResult)>;

// ---------------------------------------------------------------------------
// MinerWorker
// ---------------------------------------------------------------------------

/// A single mining thread that iterates nonces and searches for valid
/// keccak256d proof-of-work solutions.
///
/// Usage:
///   MinerWorker worker(0);
///   worker.set_callback([](WorkerResult r) { ... });
///   worker.run(block_template, nonce_range, cancel_token);
class MinerWorker {
public:
    /// Construct a worker with the given ID.
    ///
    /// @param worker_id  A unique identifier for this worker (0-based).
    explicit MinerWorker(int worker_id);

    // -- Configuration -----------------------------------------------------

    /// Set the callback function for result reporting.
    /// The callback is invoked from the worker thread when a solution is
    /// found or when the worker finishes its nonce range.
    void set_callback(WorkerCallback callback);

    /// Set the result channel (alternative to callback).
    /// When set, results are sent to this channel instead of the callback.
    void set_result_channel(core::Channel<WorkerResult>* channel);

    // -- Mining ------------------------------------------------------------

    /// Run the mining loop for the given template and nonce range.
    ///
    /// This method blocks until:
    ///   - A valid solution is found and reported.
    ///   - The nonce range is exhausted.
    ///   - The cancel token is set to true.
    ///
    /// Each worker gets a non-overlapping portion of the nonce space,
    /// ensuring no duplicate work across workers.
    ///
    /// @param tmpl         The block template to mine.
    /// @param range        The nonce range to iterate.
    /// @param cancel_token Atomic flag for cooperative cancellation.
    void run(const BlockTemplate& tmpl,
             NonceRange range,
             std::atomic<bool>& cancel_token);

    // -- Statistics --------------------------------------------------------

    /// Get the estimated hash rate (nonces/second) from the last run.
    [[nodiscard]] double get_hashrate() const;

    /// Get the total number of nonces tried across all runs.
    [[nodiscard]] uint64_t get_total_nonces() const;

    /// Get the worker ID.
    [[nodiscard]] int id() const { return worker_id_; }

    /// Check if the worker is currently running.
    [[nodiscard]] bool is_running() const {
        return running_.load(std::memory_order_relaxed);
    }

private:
    int worker_id_;
    PowSolver solver_;
    WorkerCallback callback_;
    core::Channel<WorkerResult>* result_channel_ = nullptr;

    // Statistics.
    std::atomic<uint64_t> total_nonces_{0};
    std::atomic<double> hashrate_{0.0};
    std::atomic<bool> running_{false};

    /// Report a result via callback or channel.
    void report_result(WorkerResult result);
};

} // namespace miner
