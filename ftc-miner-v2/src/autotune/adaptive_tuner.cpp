#include "adaptive_tuner.h"
#include <algorithm>
#include <numeric>
#include <sstream>
#include <iomanip>

namespace autotune {

AdaptiveTuner::AdaptiveTuner() {}

AdaptiveTuner::~AdaptiveTuner() {
    stop();
}

void AdaptiveTuner::setGPUMonitor(mining::GPUMonitorManager* monitor) {
    gpu_monitor_ = monitor;
}

void AdaptiveTuner::setIntensityCallback(IntensityCallback callback) {
    intensity_callback_ = callback;
}

void AdaptiveTuner::setStatusCallback(StatusCallback callback) {
    status_callback_ = callback;
}

void AdaptiveTuner::setDeviceCount(int count) {
    device_states_.resize(count);
    for (int i = 0; i < count; ++i) {
        device_states_[i].device_id = i;
    }
}

void AdaptiveTuner::setInitialIntensity(int device_id, int intensity) {
    if (device_id >= 0 && device_id < static_cast<int>(device_states_.size())) {
        device_states_[device_id].current_intensity = intensity;
    }
}

void AdaptiveTuner::setMaxTemperature(int device_id, int temp) {
    if (device_id >= 0 && device_id < static_cast<int>(device_states_.size())) {
        device_states_[device_id].max_temp = temp;
        device_states_[device_id].throttle_temp = temp - 5;
    }
}

void AdaptiveTuner::setTargetUtilization(int device_id, int min_util, int max_util) {
    if (device_id >= 0 && device_id < static_cast<int>(device_states_.size())) {
        device_states_[device_id].target_util_min = min_util;
        device_states_[device_id].target_util_max = max_util;
    }
}

void AdaptiveTuner::start() {
    if (running_) return;
    running_ = true;
    tuning_thread_ = std::thread(&AdaptiveTuner::tuningLoop, this);
}

void AdaptiveTuner::stop() {
    running_ = false;
    if (tuning_thread_.joinable()) {
        tuning_thread_.join();
    }
}

int AdaptiveTuner::getCurrentIntensity(int device_id) const {
    if (device_id >= 0 && device_id < static_cast<int>(device_states_.size())) {
        return device_states_[device_id].current_intensity;
    }
    return 20;
}

DeviceAdaptiveState AdaptiveTuner::getDeviceState(int device_id) const {
    if (device_id >= 0 && device_id < static_cast<int>(device_states_.size())) {
        return device_states_[device_id];
    }
    return DeviceAdaptiveState();
}

void AdaptiveTuner::tuningLoop() {
    while (running_) {
        if (gpu_monitor_) {
            for (size_t i = 0; i < device_states_.size(); ++i) {
                auto metrics = gpu_monitor_->getMetrics(static_cast<int>(i));
                processDevice(static_cast<int>(i), metrics);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(UPDATE_INTERVAL_MS));
    }
}

void AdaptiveTuner::processDevice(int device_id, const mining::GPUMetrics& metrics) {
    if (device_id < 0 || device_id >= static_cast<int>(device_states_.size())) return;

    auto& state = device_states_[device_id];

    // Add to history
    state.util_history.push_back(metrics.gpu_utilization);
    state.temp_history.push_back(metrics.temperature);

    // Keep history bounded
    while (state.util_history.size() > HISTORY_SIZE) {
        state.util_history.pop_front();
    }
    while (state.temp_history.size() > HISTORY_SIZE) {
        state.temp_history.pop_front();
    }

    // Decrement cooldown
    if (state.adjustment_cooldown > 0) {
        state.adjustment_cooldown--;
        return;
    }

    // Get smoothed values
    double smoothed_util = getSmoothedUtilization(state);
    double smoothed_temp = getSmoothedTemperature(state);

    // Calculate new intensity
    int new_intensity = calculateNewIntensity(state,
                                               static_cast<int>(smoothed_util),
                                               smoothed_temp);

    // Apply change if different
    if (new_intensity != state.current_intensity) {
        int old_intensity = state.current_intensity;
        state.current_intensity = new_intensity;
        state.adjustment_cooldown = COOLDOWN_TICKS;
        state.stable_count = 0;

        if (new_intensity > old_intensity) {
            state.adjustments_up++;
        } else {
            state.adjustments_down++;
        }

        // Notify miner
        if (intensity_callback_) {
            intensity_callback_(device_id, new_intensity);
        }

        // Status update
        if (status_callback_) {
            std::ostringstream ss;
            ss << "GPU " << device_id << ": intensity " << old_intensity
               << " -> " << new_intensity
               << " (util: " << static_cast<int>(smoothed_util) << "%"
               << ", temp: " << std::fixed << std::setprecision(0) << smoothed_temp << "C)";
            status_callback_(device_id, ss.str());
        }
    } else {
        // Track stability
        state.stable_count++;
    }
}

int AdaptiveTuner::calculateNewIntensity(DeviceAdaptiveState& state,
                                          int current_util,
                                          double current_temp) {
    int intensity = state.current_intensity;

    // PRIORITY 1: Temperature safety
    if (current_temp >= state.max_temp) {
        // Emergency: immediate reduction
        state.throttled = true;
        return std::max(state.min_intensity, intensity - 2);
    }

    if (current_temp >= state.throttle_temp) {
        // Throttling zone: gradual reduction
        state.throttled = true;
        return std::max(state.min_intensity, intensity - 1);
    }

    // Temperature is safe, reset throttle flag
    state.throttled = false;

    // PRIORITY 2: Utilization optimization
    if (current_util < state.target_util_min) {
        // Underutilized - increase intensity aggressively
        if (current_util < 40) {
            // Severely underutilized (<40%) - jump up fast, no waiting
            return std::min(state.max_intensity, intensity + 3);
        }
        if (current_util < 60) {
            // Very underutilized (<60%) - increase quickly
            return std::min(state.max_intensity, intensity + 2);
        }
        if (current_util < 80 && state.stable_count >= 1) {
            // Moderately underutilized
            return std::min(state.max_intensity, intensity + 1);
        }
        if (state.stable_count >= STABLE_THRESHOLD) {
            // Slightly underutilized, careful increase
            return std::min(state.max_intensity, intensity + 1);
        }
    }

    if (current_util > state.target_util_max) {
        // Over target but not overheating - this is fine, no change
        // Only reduce if approaching instability (which we detect via throttling)
    }

    // In target range - maintain
    return intensity;
}

double AdaptiveTuner::getSmoothedUtilization(const DeviceAdaptiveState& state) const {
    if (state.util_history.empty()) return 0.0;

    double sum = std::accumulate(state.util_history.begin(),
                                  state.util_history.end(), 0);
    return sum / state.util_history.size();
}

double AdaptiveTuner::getSmoothedTemperature(const DeviceAdaptiveState& state) const {
    if (state.temp_history.empty()) return 0.0;

    double sum = std::accumulate(state.temp_history.begin(),
                                  state.temp_history.end(), 0.0);
    return sum / state.temp_history.size();
}

} // namespace autotune
