#ifndef FTC_MINER_AUTOTUNE_TUNER_H
#define FTC_MINER_AUTOTUNE_TUNER_H

#include <vector>
#include <string>
#include <functional>
#include <memory>
#include <atomic>
#include <mutex>

namespace autotune {

// Mining parameters that can be tuned
struct MiningParams {
    int intensity = 15;        // Work intensity (8-31 for GPU, affects memory)
    int worksize = 256;        // OpenCL workgroup size (64, 128, 256, 512)
    int threads = 1;           // GPU threads per device
    int lookup_gap = 2;        // Memory optimization parameter
    int cpu_threads = 0;       // CPU threads (0 = auto)

    // Temperature/power limits
    int max_temp = 85;
    int target_temp = 75;
    int max_power = 0;         // 0 = unlimited

    bool operator==(const MiningParams& other) const;
    std::string toString() const;
};

// Result of a benchmark run
struct BenchmarkResult {
    MiningParams params;
    double hashrate;
    double power_consumption;
    double temperature;
    double efficiency;         // hashrate / power
    bool stable;               // No crashes or errors
    int runtime_ms;
};

// Callback for progress updates
using ProgressCallback = std::function<void(int progress, const std::string& status)>;

// Callback for benchmark execution
using BenchmarkCallback = std::function<BenchmarkResult(const MiningParams& params, int duration_ms)>;

/**
 * AI Auto-Tune System
 *
 * Uses a combination of:
 * 1. Grid search for initial exploration
 * 2. Bayesian optimization for fine-tuning
 * 3. Simulated annealing for escaping local optima
 *
 * Goals:
 * - Maximize hashrate
 * - Stay within temperature limits
 * - Optimize efficiency (H/W) when power-constrained
 */
class AutoTuner {
public:
    AutoTuner();
    ~AutoTuner();

    // Set device-specific constraints
    void setDeviceType(const std::string& type);  // "CPU" or "GPU"
    void setMemorySize(uint64_t bytes);
    void setComputeUnits(int units);

    // Set optimization targets
    void setMaxTemperature(int celsius);
    void setMaxPower(int watts);
    void setOptimizeFor(const std::string& target);  // "hashrate", "efficiency", "balanced"

    // Set callbacks
    void setProgressCallback(ProgressCallback callback);
    void setBenchmarkCallback(BenchmarkCallback callback);

    // Run auto-tune
    bool start();
    void stop();
    bool isRunning() const { return running_; }

    // Get results
    MiningParams getBestParams() const;
    std::vector<BenchmarkResult> getAllResults() const;

    // Suggest params without full tune (quick estimate based on device)
    static MiningParams suggestParams(const std::string& device_type,
                                       uint64_t memory_bytes,
                                       int compute_units);

private:
    // Tuning phases
    void phaseGridSearch();
    void phaseBayesianOptimization();
    void phaseFineTune();

    // Helper functions
    double evaluateParams(const MiningParams& params);
    MiningParams perturbParams(const MiningParams& params, double temperature);
    bool isWithinConstraints(const BenchmarkResult& result) const;

    // Bayesian optimization helpers
    double acquisitionFunction(const MiningParams& params) const;
    MiningParams sampleNextPoint() const;

    std::string device_type_;
    uint64_t memory_size_;
    int compute_units_;

    int max_temp_;
    int max_power_;
    std::string optimize_target_;

    ProgressCallback progress_callback_;
    BenchmarkCallback benchmark_callback_;

    std::atomic<bool> running_;
    std::atomic<bool> stop_requested_;

    std::vector<BenchmarkResult> results_;
    MiningParams best_params_;
    double best_score_;

    mutable std::mutex mutex_;

    // Tuning parameters
    static constexpr int GRID_SEARCH_ITERATIONS = 20;
    static constexpr int BAYESIAN_ITERATIONS = 30;
    static constexpr int FINE_TUNE_ITERATIONS = 10;
    static constexpr int BENCHMARK_DURATION_MS = 10000;  // 10 seconds per test
};

} // namespace autotune

#endif // FTC_MINER_AUTOTUNE_TUNER_H
