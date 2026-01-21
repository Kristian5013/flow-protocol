#ifndef FTC_MINER_AUTOTUNE_BENCHMARK_H
#define FTC_MINER_AUTOTUNE_BENCHMARK_H

#include "tuner.h"
#include <chrono>
#include <atomic>

namespace autotune {

class Benchmarker {
public:
    Benchmarker();

    // Run benchmark with given parameters
    BenchmarkResult run(const MiningParams& params, int duration_ms);

    // Quick hashrate test (1 second)
    double quickHashrateTest();

    // Get current device metrics
    double getCurrentTemperature() const;
    double getCurrentPower() const;
    int getCurrentFanSpeed() const;

private:
    std::atomic<double> current_hashrate_;
    std::atomic<double> current_temp_;
    std::atomic<double> current_power_;
};

} // namespace autotune

#endif // FTC_MINER_AUTOTUNE_BENCHMARK_H
