// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner/miner.h"

#include "consensus/merkle.h"
#include "core/logging.h"
#include "core/time.h"
#include "crypto/keccak.h"
#include "miner/difficulty.h"

#include <algorithm>
#include <chrono>

namespace miner {

// ---------------------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------------------

Miner::Miner(chain::ChainstateManager& chainstate,
             mempool::Mempool& mempool)
    : chainstate_(chainstate),
      mempool_(mempool),
      event_channel_(64),
      result_channel_(64) {}

Miner::~Miner() {
    if (mining_.load(std::memory_order_relaxed)) {
        stop();
    }
}

// ---------------------------------------------------------------------------
// start
// ---------------------------------------------------------------------------

core::Result<void> Miner::start(int num_threads) {
    if (mining_.load(std::memory_order_relaxed)) {
        return core::Error(core::ErrorCode::INTERNAL_ERROR,
            "Miner is already running");
    }

    // Validate coinbase address.
    {
        std::lock_guard lock(address_mutex_);
        if (!coinbase_address_.is_valid()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "Coinbase address not set or invalid. "
                "Call set_coinbase_address() before starting.");
        }
    }

    // Determine the number of threads.
    if (num_threads <= 0) {
        num_threads = static_cast<int>(
            std::thread::hardware_concurrency());
        if (num_threads <= 0) {
            num_threads = 1;
        }
    }
    num_threads_ = num_threads;

    LOG_INFO(core::LogCategory::MINING,
        "Starting miner with " + std::to_string(num_threads_) + " threads");

    // Reset state.
    shutting_down_.store(false, std::memory_order_relaxed);
    cancel_token_.store(false, std::memory_order_relaxed);
    start_time_.store(core::get_time(), std::memory_order_relaxed);
    mining_.store(true, std::memory_order_relaxed);

    // Start the coordination loop.
    coord_thread_ = std::thread([this] { coordination_loop(); });

    // Trigger initial template creation and worker start.
    event_channel_.send(MinerEvent::NEW_TIP);

    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// stop
// ---------------------------------------------------------------------------

void Miner::stop() {
    if (!mining_.load(std::memory_order_relaxed)) {
        return;
    }

    LOG_INFO(core::LogCategory::MINING, "Stopping miner");

    shutting_down_.store(true, std::memory_order_relaxed);
    mining_.store(false, std::memory_order_relaxed);

    // Signal workers to stop.
    stop_workers();

    // Send STOPPED event to unblock the coordination loop.
    event_channel_.send(MinerEvent::STOPPED);

    // Close channels to ensure the coordination loop can exit.
    event_channel_.close();
    result_channel_.close();

    // Join the coordination thread.
    if (coord_thread_.joinable()) {
        coord_thread_.join();
    }

    // Disable Stratum if running.
    if (stratum_) {
        stratum_->stop();
    }

    LOG_INFO(core::LogCategory::MINING,
        "Miner stopped. Blocks found: " +
        std::to_string(blocks_found_.load(std::memory_order_relaxed)));
}

// ---------------------------------------------------------------------------
// set_coinbase_address
// ---------------------------------------------------------------------------

void Miner::set_coinbase_address(const primitives::Address& address) {
    std::lock_guard lock(address_mutex_);
    coinbase_address_ = address;

    LOG_INFO(core::LogCategory::MINING,
        "Coinbase address set to " + address.to_string());
}

primitives::Address Miner::get_coinbase_address() const {
    std::lock_guard lock(address_mutex_);
    return coinbase_address_;
}

// ---------------------------------------------------------------------------
// get_hashrate
// ---------------------------------------------------------------------------

double Miner::get_hashrate() const {
    double total = 0.0;
    for (const auto& worker : workers_) {
        total += worker->get_hashrate();
    }
    return total;
}

// ---------------------------------------------------------------------------
// get_stats
// ---------------------------------------------------------------------------

MinerStats Miner::get_stats() const {
    MinerStats stats;
    stats.mining = mining_.load(std::memory_order_relaxed);
    stats.num_threads = num_threads_;
    stats.hashrate = get_hashrate();
    stats.blocks_found = blocks_found_.load(std::memory_order_relaxed);

    {
        std::lock_guard lock(template_mutex_);
        if (current_template_) {
            stats.current_height = current_template_->height;
            stats.difficulty = get_difficulty(current_template_->bits);
            stats.template_tx_count = current_template_->tx_count();
            stats.template_fees = current_template_->fees.value();
        }
    }

    int64_t start = start_time_.load(std::memory_order_relaxed);
    if (start > 0) {
        stats.uptime_seconds = core::get_time() - start;
    }

    return stats;
}

// ---------------------------------------------------------------------------
// notify_new_tip
// ---------------------------------------------------------------------------

void Miner::notify_new_tip() {
    if (mining_.load(std::memory_order_relaxed)) {
        event_channel_.send(MinerEvent::NEW_TIP);
    }
}

// ---------------------------------------------------------------------------
// notify_mempool_updated
// ---------------------------------------------------------------------------

void Miner::notify_mempool_updated() {
    if (mining_.load(std::memory_order_relaxed)) {
        event_channel_.try_send(MinerEvent::MEMPOOL_UPDATED);
    }
}

// ---------------------------------------------------------------------------
// enable_stratum
// ---------------------------------------------------------------------------

core::Result<void> Miner::enable_stratum(uint16_t port) {
    if (stratum_) {
        return core::Error(core::ErrorCode::INTERNAL_ERROR,
            "Stratum server is already enabled");
    }

    stratum_ = std::make_unique<StratumServer>();

    // Set up the share callback to detect block-level solutions.
    stratum_->set_share_callback(
        [this](const primitives::BlockHeader& header,
               const std::vector<uint8_t>& solution) {
            LOG_INFO(core::LogCategory::MINING,
                "Stratum worker found a block!");

            // Store the result and signal the coordination loop.
            {
                std::lock_guard lock(result_mutex_);
                last_result_ = std::make_unique<WorkerResult>();
                last_result_->found = true;
                last_result_->header = header;
                last_result_->solution = solution;
                last_result_->worker_id = -1;  // Stratum worker
            }
            event_channel_.send(MinerEvent::STRATUM_BLOCK);
        });

    auto result = stratum_->start(port);
    if (!result.ok()) {
        stratum_.reset();
        return result;
    }

    LOG_INFO(core::LogCategory::MINING,
        "Stratum server enabled on port " + std::to_string(port));

    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// disable_stratum
// ---------------------------------------------------------------------------

void Miner::disable_stratum() {
    if (stratum_) {
        stratum_->stop();
        stratum_.reset();
        LOG_INFO(core::LogCategory::MINING, "Stratum server disabled");
    }
}

// ---------------------------------------------------------------------------
// coordination_loop
// ---------------------------------------------------------------------------

void Miner::coordination_loop() {
    LOG_DEBUG(core::LogCategory::MINING, "Mining coordination loop started");

    while (!shutting_down_.load(std::memory_order_relaxed)) {
        // Wait for events from the channel or worker results.
        // We use select() to monitor both channels.
        size_t ready = core::select(event_channel_, result_channel_);

        if (ready == SIZE_MAX) {
            // All channels closed.
            break;
        }

        if (ready == 0) {
            // Event channel has data.
            auto event_opt = event_channel_.try_receive();
            if (!event_opt.has_value()) continue;

            MinerEvent event = event_opt.value();

            switch (event) {
                case MinerEvent::NEW_TIP:
                    LOG_INFO(core::LogCategory::MINING,
                        "New chain tip detected, resetting mining");
                    reset_mining();
                    break;

                case MinerEvent::BLOCK_FOUND:
                    // Handled via the result channel.
                    break;

                case MinerEvent::STOPPED:
                    LOG_DEBUG(core::LogCategory::MINING,
                        "Received STOPPED event");
                    return;

                case MinerEvent::MEMPOOL_UPDATED: {
                    // Optionally update the template with new mempool txs.
                    // Only do this if we have a current template and the
                    // update would be meaningful (e.g., significant fee
                    // increase).
                    std::lock_guard lock(template_mutex_);
                    if (current_template_) {
                        primitives::Address addr;
                        {
                            std::lock_guard alock(address_mutex_);
                            addr = coinbase_address_;
                        }
                        uint64_t en = extra_nonce_.load(
                            std::memory_order_relaxed);
                        auto update_result = update_block_template(
                            *current_template_,
                            chainstate_,
                            mempool_,
                            addr, en);

                        if (update_result.ok()) {
                            LOG_DEBUG(core::LogCategory::MINING,
                                "Block template updated with new mempool txs");
                            // Notify Stratum clients of the new job.
                            if (stratum_ && stratum_->is_running()) {
                                stratum_->notify_new_job(*current_template_);
                            }
                        }
                    }
                    break;
                }

                case MinerEvent::STRATUM_BLOCK: {
                    // A Stratum worker submitted a block-level share.
                    std::unique_ptr<WorkerResult> res;
                    {
                        std::lock_guard lock(result_mutex_);
                        res = std::move(last_result_);
                    }
                    if (res && res->found) {
                        handle_block_found(*res);
                    }
                    break;
                }
            }
        } else if (ready == 1) {
            // Result channel has data from a local worker.
            auto result_opt = result_channel_.try_receive();
            if (!result_opt.has_value()) continue;

            WorkerResult result = std::move(result_opt.value());

            if (result.found) {
                LOG_INFO(core::LogCategory::MINING,
                    "Worker " + std::to_string(result.worker_id) +
                    " found a block!");
                handle_block_found(result);
            }
        }
    }

    LOG_DEBUG(core::LogCategory::MINING, "Mining coordination loop exiting");
}

// ---------------------------------------------------------------------------
// reset_mining
// ---------------------------------------------------------------------------

void Miner::reset_mining() {
    // Stop existing workers.
    stop_workers();

    // Get the coinbase address.
    primitives::Address addr;
    {
        std::lock_guard lock(address_mutex_);
        addr = coinbase_address_;
    }

    if (!addr.is_valid()) {
        LOG_ERROR(core::LogCategory::MINING,
            "Cannot reset mining: coinbase address is not set");
        return;
    }

    // Increment the extra nonce.
    uint64_t en = extra_nonce_.fetch_add(1, std::memory_order_relaxed);

    // Create a new block template.
    auto template_result = create_block_template(
        chainstate_, mempool_, addr, en);

    if (!template_result.ok()) {
        LOG_ERROR(core::LogCategory::MINING,
            "Failed to create block template: " +
            template_result.error().message());
        return;
    }

    {
        std::lock_guard lock(template_mutex_);
        current_template_ =
            std::make_unique<BlockTemplate>(std::move(template_result.value()));
    }

    // Notify Stratum clients of the new job.
    if (stratum_ && stratum_->is_running()) {
        std::lock_guard lock(template_mutex_);
        stratum_->notify_new_job(*current_template_);
    }

    // Start workers with the new template.
    start_workers();
}

// ---------------------------------------------------------------------------
// stop_workers
// ---------------------------------------------------------------------------

void Miner::stop_workers() {
    // Signal all workers to stop.
    cancel_token_.store(true, std::memory_order_relaxed);

    // Join all worker threads.
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    worker_threads_.clear();
    workers_.clear();

    // Reset the cancel token for the next run.
    cancel_token_.store(false, std::memory_order_relaxed);
}

// ---------------------------------------------------------------------------
// start_workers
// ---------------------------------------------------------------------------

void Miner::start_workers() {
    BlockTemplate tmpl;
    {
        std::lock_guard lock(template_mutex_);
        if (!current_template_) {
            LOG_ERROR(core::LogCategory::MINING,
                "Cannot start workers: no block template");
            return;
        }
        tmpl = *current_template_;
    }

    // Partition the nonce space.
    auto ranges = partition_nonce_space(num_threads_);

    LOG_INFO(core::LogCategory::MINING,
        "Starting " + std::to_string(num_threads_) +
        " workers for height " + std::to_string(tmpl.height));

    // Create and launch workers.
    workers_.clear();
    workers_.reserve(static_cast<size_t>(num_threads_));
    worker_threads_.clear();
    worker_threads_.reserve(static_cast<size_t>(num_threads_));

    for (int i = 0; i < num_threads_; ++i) {
        auto worker = std::make_unique<MinerWorker>(i);
        worker->set_result_channel(&result_channel_);

        // Capture the worker pointer before moving the unique_ptr.
        MinerWorker* worker_ptr = worker.get();
        workers_.push_back(std::move(worker));

        NonceRange range = ranges[static_cast<size_t>(i)];

        // Launch the worker in a dedicated thread.
        worker_threads_.emplace_back(
            [worker_ptr, tmpl, range, this]() {
                worker_ptr->run(tmpl, range, cancel_token_);
            });
    }
}

// ---------------------------------------------------------------------------
// handle_block_found
// ---------------------------------------------------------------------------

void Miner::handle_block_found(const WorkerResult& result) {
    if (!result.found) return;

    // Submit the block.
    auto submit_result = submit_block(result.header, result.solution);

    if (submit_result.ok()) {
        blocks_found_.fetch_add(1, std::memory_order_relaxed);

        LOG_INFO(core::LogCategory::MINING,
            "Block accepted! hash=" + result.header.hash().to_hex() +
            " height=" + std::to_string(result.header.version) +
            " total_blocks_found=" +
            std::to_string(blocks_found_.load(std::memory_order_relaxed)));
    } else {
        LOG_ERROR(core::LogCategory::MINING,
            "Block rejected: " + submit_result.error().message());
    }

    // Regardless of acceptance, reset mining (the chain may have moved).
    if (mining_.load(std::memory_order_relaxed)) {
        reset_mining();
    }
}

// ---------------------------------------------------------------------------
// submit_block
// ---------------------------------------------------------------------------

core::Result<void> Miner::submit_block(
    const primitives::BlockHeader& header,
    const std::vector<uint8_t>& solution) {

    // Build the full block from the current template.
    std::vector<primitives::Transaction> txs;
    {
        std::lock_guard lock(template_mutex_);
        if (!current_template_) {
            return core::Error(core::ErrorCode::INTERNAL_ERROR,
                "No current template for block submission");
        }
        txs = current_template_->txs;
    }

    // Create the block with the solved header.
    primitives::BlockHeader solved_header = header;
    primitives::Block block(solved_header, std::move(txs));

    // Verify the merkle root.
    if (!block.is_valid_merkle_root()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Block merkle root mismatch after solving");
    }

    // Verify proof-of-work.
    auto block_serialized = EquihashSolver::serialize_header(solved_header);
    std::vector<uint8_t> block_data;
    block_data.reserve(block_serialized.size() + solution.size());
    block_data.insert(block_data.end(),
        block_serialized.begin(), block_serialized.end());
    block_data.insert(block_data.end(),
        solution.begin(), solution.end());

    core::uint256 block_hash = crypto::keccak256d(
        std::span<const uint8_t>(block_data.data(), block_data.size()));

    core::uint256 target;
    {
        std::lock_guard lock(template_mutex_);
        target = current_template_->target;
    }

    if (!(block_hash <= target)) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Block hash does not meet difficulty target");
    }

    LOG_INFO(core::LogCategory::MINING,
        "Submitting block: hash=" + block_hash.to_hex() +
        " height=" + std::to_string(solved_header.version));

    // Submit to the chainstate manager.
    auto accept_result = chainstate_.accept_block(block);
    if (!accept_result.ok()) {
        return core::Error(accept_result.error().code(),
            "Block rejected by chainstate: " +
            accept_result.error().message());
    }

    // Activate the best chain (this block should become the new tip).
    auto activate_result = chainstate_.activate_best_chain();
    if (!activate_result.ok()) {
        return core::Error(activate_result.error().code(),
            "Failed to activate chain after block submission: " +
            activate_result.error().message());
    }

    LOG_INFO(core::LogCategory::MINING,
        "Block successfully submitted and activated");

    return core::Result<void>{};
}

} // namespace miner
