// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner/worker.h"

#include "core/logging.h"
#include "core/time.h"

#include <algorithm>
#include <cstring>

namespace miner {

// ---------------------------------------------------------------------------
// partition_nonce_space
// ---------------------------------------------------------------------------

std::vector<NonceRange> partition_nonce_space(int num_workers) {
    std::vector<NonceRange> ranges;

    if (num_workers <= 0) {
        return ranges;
    }

    ranges.reserve(static_cast<size_t>(num_workers));

    // The full nonce space is [0, 2^32).
    // We divide it into num_workers equal (or near-equal) ranges.
    uint64_t total = static_cast<uint64_t>(1) << 32;  // 4294967296
    uint64_t per_worker = total / static_cast<uint64_t>(num_workers);
    uint64_t remainder = total % static_cast<uint64_t>(num_workers);

    uint64_t current = 0;
    for (int i = 0; i < num_workers; ++i) {
        NonceRange range;
        range.start = static_cast<uint32_t>(current);

        // Distribute the remainder among the first 'remainder' workers.
        uint64_t this_count = per_worker + (static_cast<uint64_t>(i) < remainder ? 1 : 0);
        current += this_count;

        // Clamp to uint32_t max. The last range's end may wrap to 0,
        // which represents the exclusive upper bound of the full 32-bit space.
        range.end = static_cast<uint32_t>(current & 0xFFFFFFFF);

        // Special case: if current == 2^32, end wraps to 0.
        // We use 0 to represent "past the end of the nonce space".
        if (current == total) {
            range.end = 0;
        }

        ranges.push_back(range);
    }

    return ranges;
}

// ---------------------------------------------------------------------------
// MinerWorker construction
// ---------------------------------------------------------------------------

MinerWorker::MinerWorker(int worker_id)
    : worker_id_(worker_id) {}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

void MinerWorker::set_callback(WorkerCallback callback) {
    callback_ = std::move(callback);
}

void MinerWorker::set_result_channel(core::Channel<WorkerResult>* channel) {
    result_channel_ = channel;
}

// ---------------------------------------------------------------------------
// report_result
// ---------------------------------------------------------------------------

void MinerWorker::report_result(WorkerResult result) {
    result.worker_id = worker_id_;

    if (result_channel_) {
        result_channel_->send(std::move(result));
    } else if (callback_) {
        callback_(std::move(result));
    }
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

void MinerWorker::run(
    const BlockTemplate& tmpl,
    NonceRange range,
    std::atomic<bool>& cancel_token) {

    running_.store(true, std::memory_order_relaxed);

    LOG_DEBUG(core::LogCategory::MINING,
        "Worker " + std::to_string(worker_id_) +
        " starting: nonce range [" +
        std::to_string(range.start) + ", " +
        std::to_string(range.end) + ")");

    auto start_time = std::chrono::steady_clock::now();
    uint64_t nonces_tried = 0;

    // Prepare the header for mining.
    primitives::BlockHeader header = tmpl.header;

    // Iterate through our nonce range.
    uint32_t nonce = range.start;

    // Determine the end condition. If range.end == 0 and range.start != 0,
    // it means we go all the way to 2^32 (i.e., we wrap around).
    // If range.end == 0 and range.start == 0, we cover the full space.
    bool wraps = (range.end == 0) && (range.start != 0 || range.size() == (uint64_t(1) << 32));

    while (true) {
        if (cancel_token.load(std::memory_order_relaxed)) {
            LOG_DEBUG(core::LogCategory::MINING,
                "Worker " + std::to_string(worker_id_) + " cancelled after " +
                std::to_string(nonces_tried) + " nonces");
            break;
        }

        header.nonce = nonce;
        core::uint256 block_hash = header.hash();
        ++nonces_tried;

        if (block_hash <= tmpl.target) {
            auto end_time = std::chrono::steady_clock::now();
            int64_t elapsed_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    end_time - start_time).count();

            LOG_INFO(core::LogCategory::MINING,
                "Worker " + std::to_string(worker_id_) +
                " FOUND BLOCK! nonce=" + std::to_string(nonce) +
                " hash=" + block_hash.to_hex() +
                " elapsed=" + std::to_string(elapsed_ms) + "ms");

            total_nonces_.fetch_add(nonces_tried, std::memory_order_relaxed);
            if (elapsed_ms > 0) {
                hashrate_.store(
                    static_cast<double>(nonces_tried) * 1000.0 /
                    static_cast<double>(elapsed_ms),
                    std::memory_order_relaxed);
            }

            WorkerResult result;
            result.found = true;
            result.header = header;
            result.nonces_tried = nonces_tried;
            result.elapsed_ms = elapsed_ms;
            report_result(std::move(result));

            running_.store(false, std::memory_order_relaxed);
            return;
        }

        ++nonce;

        if (wraps) {
            if (nonce == range.start) break;
        } else {
            if (nonce == range.end) break;
        }

        if (nonces_tried % 10000 == 0) {
            auto now = std::chrono::steady_clock::now();
            int64_t elapsed_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - start_time).count();
            if (elapsed_ms > 0) {
                hashrate_.store(
                    static_cast<double>(nonces_tried) * 1000.0 /
                    static_cast<double>(elapsed_ms),
                    std::memory_order_relaxed);
            }
        }
    }

    // Worker finished without finding a solution.
    auto end_time = std::chrono::steady_clock::now();
    int64_t elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time).count();

    total_nonces_.fetch_add(nonces_tried, std::memory_order_relaxed);
    if (elapsed_ms > 0) {
        hashrate_.store(
            static_cast<double>(nonces_tried) * 1000.0 /
            static_cast<double>(elapsed_ms),
            std::memory_order_relaxed);
    }

    LOG_DEBUG(core::LogCategory::MINING,
        "Worker " + std::to_string(worker_id_) +
        " finished range without solution. nonces=" +
        std::to_string(nonces_tried) +
        " elapsed=" + std::to_string(elapsed_ms) + "ms" +
        " rate=" + std::to_string(get_hashrate()) + " nonces/s");

    // Report the non-finding result.
    WorkerResult result;
    result.found = false;
    result.nonces_tried = nonces_tried;
    result.elapsed_ms = elapsed_ms;
    report_result(std::move(result));

    running_.store(false, std::memory_order_relaxed);
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

double MinerWorker::get_hashrate() const {
    return hashrate_.load(std::memory_order_relaxed);
}

uint64_t MinerWorker::get_total_nonces() const {
    return total_nonces_.load(std::memory_order_relaxed);
}

} // namespace miner
