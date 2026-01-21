#include "tuner.h"
#include <random>
#include <algorithm>
#include <cmath>
#include <sstream>
#include <thread>
#include <chrono>

namespace autotune {

bool MiningParams::operator==(const MiningParams& other) const {
    return intensity == other.intensity &&
           worksize == other.worksize &&
           threads == other.threads &&
           lookup_gap == other.lookup_gap &&
           cpu_threads == other.cpu_threads;
}

std::string MiningParams::toString() const {
    std::ostringstream ss;
    ss << "I:" << intensity << " W:" << worksize << " T:" << threads;
    return ss.str();
}

AutoTuner::AutoTuner()
    : memory_size_(0)
    , compute_units_(0)
    , max_temp_(85)
    , max_power_(0)
    , optimize_target_("hashrate")
    , running_(false)
    , stop_requested_(false)
    , best_score_(0.0)
{}

AutoTuner::~AutoTuner() {
    stop();
}

void AutoTuner::setDeviceType(const std::string& type) {
    device_type_ = type;
}

void AutoTuner::setMemorySize(uint64_t bytes) {
    memory_size_ = bytes;
}

void AutoTuner::setComputeUnits(int units) {
    compute_units_ = units;
}

void AutoTuner::setMaxTemperature(int celsius) {
    max_temp_ = celsius;
}

void AutoTuner::setMaxPower(int watts) {
    max_power_ = watts;
}

void AutoTuner::setOptimizeFor(const std::string& target) {
    optimize_target_ = target;
}

void AutoTuner::setProgressCallback(ProgressCallback callback) {
    progress_callback_ = callback;
}

void AutoTuner::setBenchmarkCallback(BenchmarkCallback callback) {
    benchmark_callback_ = callback;
}

bool AutoTuner::start() {
    if (running_) return false;
    if (!benchmark_callback_) return false;

    running_ = true;
    stop_requested_ = false;
    results_.clear();
    best_score_ = 0.0;

    // Start tuning thread
    std::thread([this]() {
        try {
            // Phase 1: Grid Search (0-40%)
            if (progress_callback_) {
                progress_callback_(0, "Phase 1: Grid Search");
            }
            phaseGridSearch();

            if (stop_requested_) {
                running_ = false;
                return;
            }

            // Phase 2: Bayesian Optimization (40-80%)
            if (progress_callback_) {
                progress_callback_(40, "Phase 2: Bayesian Optimization");
            }
            phaseBayesianOptimization();

            if (stop_requested_) {
                running_ = false;
                return;
            }

            // Phase 3: Fine Tune (80-100%)
            if (progress_callback_) {
                progress_callback_(80, "Phase 3: Fine Tuning");
            }
            phaseFineTune();

            if (progress_callback_) {
                progress_callback_(100, "Complete!");
            }

        } catch (...) {
            // Handle errors
        }

        running_ = false;
    }).detach();

    return true;
}

void AutoTuner::stop() {
    stop_requested_ = true;
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

MiningParams AutoTuner::getBestParams() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return best_params_;
}

std::vector<BenchmarkResult> AutoTuner::getAllResults() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return results_;
}

void AutoTuner::phaseGridSearch() {
    // Define search grid based on device type
    std::vector<int> intensities;
    std::vector<int> worksizes;
    std::vector<int> thread_counts;

    if (device_type_ == "GPU") {
        intensities = {12, 15, 18, 21};
        worksizes = {64, 128, 256, 512};
        thread_counts = {1, 2};
    } else {
        // CPU - fewer parameters
        intensities = {1};
        worksizes = {256};
        thread_counts = {2, 4, 8, 16};  // CPU thread counts
    }

    int total = static_cast<int>(intensities.size() * worksizes.size() * thread_counts.size());
    int current = 0;

    for (int intensity : intensities) {
        for (int worksize : worksizes) {
            for (int threads : thread_counts) {
                if (stop_requested_) return;

                MiningParams params;
                params.intensity = intensity;
                params.worksize = worksize;
                params.threads = threads;
                params.max_temp = max_temp_;

                double score = evaluateParams(params);

                current++;
                int progress = current * 40 / total;

                if (progress_callback_) {
                    progress_callback_(progress, "Testing: " + params.toString());
                }
            }
        }
    }
}

void AutoTuner::phaseBayesianOptimization() {
    std::random_device rd;
    std::mt19937 gen(rd());

    for (int i = 0; i < BAYESIAN_ITERATIONS && !stop_requested_; ++i) {
        // Sample next point based on acquisition function
        MiningParams params = sampleNextPoint();

        double score = evaluateParams(params);

        int progress = 40 + (i * 40 / BAYESIAN_ITERATIONS);
        if (progress_callback_) {
            progress_callback_(progress, "Optimizing: " + params.toString());
        }
    }
}

void AutoTuner::phaseFineTune() {
    // Fine-tune around the best found parameters using simulated annealing
    MiningParams current = best_params_;
    double current_score = best_score_;
    double temperature = 1.0;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dist(0.0, 1.0);

    for (int i = 0; i < FINE_TUNE_ITERATIONS && !stop_requested_; ++i) {
        MiningParams neighbor = perturbParams(current, temperature);
        double neighbor_score = evaluateParams(neighbor);

        // Accept if better, or with probability based on temperature
        double delta = neighbor_score - current_score;
        if (delta > 0 || dist(gen) < std::exp(delta / temperature)) {
            current = neighbor;
            current_score = neighbor_score;
        }

        // Cool down
        temperature *= 0.9;

        int progress = 80 + (i * 20 / FINE_TUNE_ITERATIONS);
        if (progress_callback_) {
            progress_callback_(progress, "Fine-tuning: " + current.toString());
        }
    }
}

double AutoTuner::evaluateParams(const MiningParams& params) {
    if (!benchmark_callback_) return 0.0;

    BenchmarkResult result = benchmark_callback_(params, BENCHMARK_DURATION_MS);
    result.params = params;

    // Calculate score based on optimization target
    double score = 0.0;

    if (!result.stable) {
        score = 0.0;  // Unstable configs get zero score
    } else if (!isWithinConstraints(result)) {
        score = result.hashrate * 0.1;  // Penalize constraint violations
    } else {
        if (optimize_target_ == "hashrate") {
            score = result.hashrate;
        } else if (optimize_target_ == "efficiency") {
            score = result.efficiency;
        } else {  // balanced
            // Weighted combination
            double normalized_hashrate = result.hashrate / 1e6;  // Normalize to MH/s
            double normalized_efficiency = result.efficiency;
            score = normalized_hashrate * 0.7 + normalized_efficiency * 0.3;
        }
    }

    // Store result
    {
        std::lock_guard<std::mutex> lock(mutex_);
        results_.push_back(result);

        if (score > best_score_) {
            best_score_ = score;
            best_params_ = params;
        }
    }

    return score;
}

MiningParams AutoTuner::perturbParams(const MiningParams& params, double temperature) {
    std::random_device rd;
    std::mt19937 gen(rd());

    MiningParams result = params;

    // Small random perturbations scaled by temperature
    std::normal_distribution<> dist(0.0, temperature * 2);

    int delta_intensity = static_cast<int>(std::round(dist(gen)));
    result.intensity = std::clamp(params.intensity + delta_intensity, 8, 31);

    // Worksize must be power of 2
    std::uniform_int_distribution<> ws_dist(-1, 1);
    int ws_idx = 0;
    if (params.worksize == 64) ws_idx = 0;
    else if (params.worksize == 128) ws_idx = 1;
    else if (params.worksize == 256) ws_idx = 2;
    else if (params.worksize == 512) ws_idx = 3;

    ws_idx = std::clamp(ws_idx + ws_dist(gen), 0, 3);
    static const int worksizes[] = {64, 128, 256, 512};
    result.worksize = worksizes[ws_idx];

    int delta_threads = static_cast<int>(std::round(dist(gen) * 0.5));
    result.threads = std::clamp(params.threads + delta_threads, 1, 4);

    return result;
}

bool AutoTuner::isWithinConstraints(const BenchmarkResult& result) const {
    if (result.temperature > max_temp_) return false;
    if (max_power_ > 0 && result.power_consumption > max_power_) return false;
    return true;
}

double AutoTuner::acquisitionFunction(const MiningParams& params) const {
    // Upper Confidence Bound (UCB) acquisition function
    // UCB = mean + kappa * std

    // Simple heuristic based on parameter proximity to known good points
    double score = 0.0;

    std::lock_guard<std::mutex> lock(mutex_);
    if (results_.empty()) return 1.0;  // Encourage exploration

    // Find similar tested parameters
    double min_dist = 1e9;
    double nearest_score = 0.0;

    for (const auto& result : results_) {
        double dist = std::abs(result.params.intensity - params.intensity) +
                     std::abs(result.params.worksize - params.worksize) / 100.0 +
                     std::abs(result.params.threads - params.threads);

        if (dist < min_dist) {
            min_dist = dist;
            nearest_score = result.hashrate;
        }
    }

    // UCB: exploit (nearest score) + explore (distance bonus)
    double kappa = 2.0;
    score = nearest_score + kappa * min_dist;

    return score;
}

MiningParams AutoTuner::sampleNextPoint() const {
    // Sample multiple candidates and pick the one with highest acquisition value
    std::random_device rd;
    std::mt19937 gen(rd());

    MiningParams best_candidate;
    double best_acq = -1e9;

    for (int i = 0; i < 20; ++i) {
        MiningParams candidate;

        if (device_type_ == "GPU") {
            std::uniform_int_distribution<> int_dist(8, 24);
            std::uniform_int_distribution<> ws_idx(0, 3);
            std::uniform_int_distribution<> th_dist(1, 3);

            candidate.intensity = int_dist(gen);
            static const int worksizes[] = {64, 128, 256, 512};
            candidate.worksize = worksizes[ws_idx(gen)];
            candidate.threads = th_dist(gen);
        } else {
            std::uniform_int_distribution<> th_dist(1, 32);
            candidate.cpu_threads = th_dist(gen);
        }

        double acq = acquisitionFunction(candidate);
        if (acq > best_acq) {
            best_acq = acq;
            best_candidate = candidate;
        }
    }

    return best_candidate;
}

MiningParams AutoTuner::suggestParams(const std::string& device_type,
                                       uint64_t memory_bytes,
                                       int compute_units) {
    MiningParams params;

    if (device_type == "GPU") {
        // Heuristics based on GPU specifications
        uint64_t memory_mb = memory_bytes / (1024 * 1024);

        if (memory_mb >= 8192) {
            params.intensity = 21;
            params.worksize = 256;
            params.threads = 2;
        } else if (memory_mb >= 4096) {
            params.intensity = 18;
            params.worksize = 256;
            params.threads = 1;
        } else {
            params.intensity = 15;
            params.worksize = 128;
            params.threads = 1;
        }

        // Adjust for compute units
        if (compute_units >= 64) {
            params.intensity += 2;
        } else if (compute_units < 32) {
            params.intensity -= 2;
        }

        params.intensity = std::clamp(params.intensity, 8, 24);
    } else {
        // CPU - use number of cores
        params.cpu_threads = std::max(1, compute_units - 1);  // Leave 1 core free
    }

    return params;
}

} // namespace autotune
