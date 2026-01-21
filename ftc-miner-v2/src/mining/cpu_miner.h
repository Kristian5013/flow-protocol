#ifndef FTC_MINER_MINING_CPU_MINER_H
#define FTC_MINER_MINING_CPU_MINER_H

#include "work.h"
#include "keccak256.h"
#include <thread>
#include <vector>
#include <atomic>
#include <functional>
#include <chrono>
#include <memory>

namespace mining {

// Callback for found solutions
using SolutionCallback = std::function<void(const Solution&)>;

// Callback for hashrate updates
using HashrateCallback = std::function<void(int thread_id, double hashrate)>;

class CPUMiner {
public:
    CPUMiner();
    ~CPUMiner();

    // Configuration
    void setThreadCount(int threads);
    void setWorkManager(WorkManager* manager);
    void setSolutionCallback(SolutionCallback callback);
    void setHashrateCallback(HashrateCallback callback);

    // Control
    bool start();
    void stop();
    bool isRunning() const { return running_; }
    void pause();
    void resume();
    bool isPaused() const { return paused_; }

    // Stats
    double getTotalHashrate() const;
    uint64_t getTotalHashes() const { return total_hashes_; }
    int getThreadCount() const { return thread_count_; }

    // Benchmark
    double benchmark(int seconds = 10);

private:
    void miningThread(int thread_id);

    int thread_count_;
    std::vector<std::thread> threads_;
    std::atomic<bool> running_;
    std::atomic<bool> paused_;

    WorkManager* work_manager_;
    SolutionCallback solution_callback_;
    HashrateCallback hashrate_callback_;

    std::atomic<uint64_t> total_hashes_;
    std::unique_ptr<std::atomic<double>[]> thread_hashrates_;
    int max_threads_;

    std::chrono::steady_clock::time_point start_time_;
};

} // namespace mining

#endif // FTC_MINER_MINING_CPU_MINER_H
