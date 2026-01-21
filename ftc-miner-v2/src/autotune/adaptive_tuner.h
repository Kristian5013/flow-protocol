#ifndef FTC_MINER_AUTOTUNE_ADAPTIVE_TUNER_H
#define FTC_MINER_AUTOTUNE_ADAPTIVE_TUNER_H

#include "../mining/gpu_monitor.h"
#include <vector>
#include <functional>
#include <atomic>
#include <thread>
#include <chrono>
#include <deque>

namespace autotune {

// Per-device adaptive state
struct DeviceAdaptiveState {
    int device_id = 0;
    int current_intensity = 20;
    int min_intensity = 8;
    int max_intensity = 27;  // Cap at 27 for stability (128M work items max)

    // Target utilization range
    int target_util_min = 85;
    int target_util_max = 95;

    // Safety limits
    int max_temp = 83;
    int throttle_temp = 78;

    // History for smoothing
    std::deque<int> util_history;
    std::deque<double> temp_history;

    // State
    bool throttled = false;
    int stable_count = 0;
    int adjustment_cooldown = 0;

    // Stats
    int adjustments_up = 0;
    int adjustments_down = 0;
};

// Callback to apply intensity change
using IntensityCallback = std::function<void(int device_id, int new_intensity)>;
using StatusCallback = std::function<void(int device_id, const std::string& status)>;

/**
 * Real-Time Adaptive Auto-Tuner
 *
 * Continuously monitors GPU utilization and adjusts intensity to reach
 * target utilization (90-100%) while respecting temperature limits.
 *
 * Features:
 * - Fast response to underutilization (increase intensity)
 * - Immediate response to thermal throttling (decrease intensity)
 * - Smoothing to avoid oscillation
 * - Per-device independent tuning
 */
class AdaptiveTuner {
public:
    AdaptiveTuner();
    ~AdaptiveTuner();

    // Configuration
    void setGPUMonitor(mining::GPUMonitorManager* monitor);
    void setIntensityCallback(IntensityCallback callback);
    void setStatusCallback(StatusCallback callback);

    // Per-device settings
    void setDeviceCount(int count);
    void setInitialIntensity(int device_id, int intensity);
    void setMaxTemperature(int device_id, int temp);
    void setTargetUtilization(int device_id, int min_util, int max_util);

    // Control
    void start();
    void stop();
    bool isRunning() const { return running_; }

    // Get current state
    int getCurrentIntensity(int device_id) const;
    DeviceAdaptiveState getDeviceState(int device_id) const;

private:
    void tuningLoop();
    void processDevice(int device_id, const mining::GPUMetrics& metrics);
    int calculateNewIntensity(DeviceAdaptiveState& state, int current_util, double current_temp);
    double getSmoothedUtilization(const DeviceAdaptiveState& state) const;
    double getSmoothedTemperature(const DeviceAdaptiveState& state) const;

    mining::GPUMonitorManager* gpu_monitor_ = nullptr;
    IntensityCallback intensity_callback_;
    StatusCallback status_callback_;

    std::vector<DeviceAdaptiveState> device_states_;

    std::atomic<bool> running_{false};
    std::thread tuning_thread_;

    // Tuning parameters - aggressive ramp-up for high-end GPUs
    static constexpr int HISTORY_SIZE = 3;          // Samples to average (faster response)
    static constexpr int UPDATE_INTERVAL_MS = 250;  // Check every 250ms
    static constexpr int COOLDOWN_TICKS = 2;        // Wait 0.5 seconds between adjustments
    static constexpr int STABLE_THRESHOLD = 2;      // 0.5 seconds of stability before increase
};

} // namespace autotune

#endif // FTC_MINER_AUTOTUNE_ADAPTIVE_TUNER_H
