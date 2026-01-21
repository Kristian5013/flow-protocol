#include "cpu_miner.h"
#include <random>
#include <iostream>

namespace mining {

CPUMiner::CPUMiner()
    : thread_count_(std::thread::hardware_concurrency())
    , running_(false)
    , paused_(false)
    , work_manager_(nullptr)
    , total_hashes_(0)
    , max_threads_(0)
{
    if (thread_count_ == 0) thread_count_ = 1;
}

CPUMiner::~CPUMiner() {
    stop();
}

void CPUMiner::setThreadCount(int threads) {
    if (threads > 0) {
        thread_count_ = threads;
    }
}

void CPUMiner::setWorkManager(WorkManager* manager) {
    work_manager_ = manager;
}

void CPUMiner::setSolutionCallback(SolutionCallback callback) {
    solution_callback_ = callback;
}

void CPUMiner::setHashrateCallback(HashrateCallback callback) {
    hashrate_callback_ = callback;
}

bool CPUMiner::start() {
    if (running_) return true;
    if (!work_manager_) return false;

    running_ = true;
    paused_ = false;
    total_hashes_ = 0;
    start_time_ = std::chrono::steady_clock::now();

    // Initialize thread hashrates
    max_threads_ = thread_count_;
    thread_hashrates_ = std::make_unique<std::atomic<double>[]>(max_threads_);
    for (int i = 0; i < max_threads_; ++i) {
        thread_hashrates_[i] = 0.0;
    }

    // Start mining threads
    threads_.clear();
    for (int i = 0; i < thread_count_; ++i) {
        threads_.emplace_back(&CPUMiner::miningThread, this, i);
    }

    return true;
}

void CPUMiner::stop() {
    if (!running_) return;

    running_ = false;
    paused_ = false;

    for (auto& t : threads_) {
        if (t.joinable()) {
            t.join();
        }
    }
    threads_.clear();
}

void CPUMiner::pause() {
    paused_ = true;
}

void CPUMiner::resume() {
    paused_ = false;
}

double CPUMiner::getTotalHashrate() const {
    double total = 0.0;
    for (int i = 0; i < max_threads_; ++i) {
        total += thread_hashrates_[i].load();
    }
    return total;
}

void CPUMiner::miningThread(int thread_id) {
    // Random starting nonce for this thread
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis;

    uint32_t nonce = dis(gen);
    const uint32_t nonce_stride = thread_count_;

    std::vector<uint8_t> header;
    Hash256 target;
    std::string job_id;
    uint32_t height = 0;

    uint64_t local_hashes = 0;
    auto last_stats_time = std::chrono::steady_clock::now();

    constexpr int BATCH_SIZE = 65536;

    while (running_) {
        // Check for pause
        while (paused_ && running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (!running_) break;

        // Check for new work
        if (!work_manager_->hasWork()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        if (work_manager_->isNewWork() || header.empty()) {
            Work work = work_manager_->getWork();
            header = work.buildHeader();
            target = work.target;
            job_id = work.job_id;
            height = work.height;

            // Reset nonce with new random start
            nonce = dis(gen);

            if (thread_id == 0) {
                work_manager_->clearNewWork();
            }
        }

        if (header.size() < 76) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        // Mine a batch
        for (int i = 0; i < BATCH_SIZE && running_ && !paused_; ++i) {
            Hash256 hash = Keccak256::hashHeader(header.data(), nonce);

            if (Keccak256::meetsTarget(hash, target)) {
                // Found a solution!
                Solution sol;
                sol.job_id = job_id;
                sol.nonce = nonce;
                sol.hash = hash;
                sol.height = height;

                work_manager_->submitSolution(sol);

                if (solution_callback_) {
                    solution_callback_(sol);
                }
            }

            nonce += nonce_stride;
            local_hashes++;
        }

        // Update stats periodically
        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_stats_time).count();

        if (elapsed_ms >= 1000) {
            // Calculate hashrate
            double hashrate = local_hashes * 1000.0 / elapsed_ms;
            thread_hashrates_[thread_id] = hashrate;

            // Update global counter
            total_hashes_ += local_hashes;

            // Report hashrate
            if (hashrate_callback_) {
                hashrate_callback_(thread_id, hashrate);
            }

            local_hashes = 0;
            last_stats_time = now;
        }
    }

    // Final stats update
    total_hashes_ += local_hashes;
}

double CPUMiner::benchmark(int seconds) {
    // Create temporary work for benchmarking
    Work work;
    work.height = 1;
    work.version = 1;
    work.timestamp = static_cast<uint32_t>(std::time(nullptr));
    work.bits = 0x1f00ffff;  // Easy target for benchmark
    work.target = Keccak256::bitsToTarget(work.bits);

    WorkManager temp_manager;
    temp_manager.setWork(work);

    // Temporarily replace work manager
    WorkManager* original = work_manager_;
    work_manager_ = &temp_manager;

    // Start mining
    start();

    // Wait for benchmark duration
    std::this_thread::sleep_for(std::chrono::seconds(seconds));

    // Stop and calculate result
    stop();

    work_manager_ = original;

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time_).count();

    if (elapsed > 0) {
        return total_hashes_ * 1000.0 / elapsed;
    }

    return 0.0;
}

} // namespace mining
