#ifndef FTC_MINER_MINING_GPU_MONITOR_H
#define FTC_MINER_MINING_GPU_MONITOR_H

#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <thread>
#include <chrono>
#include <functional>

#ifdef _WIN32
#include <windows.h>
#endif

namespace mining {

// GPU metrics
struct GPUMetrics {
    int device_id = 0;
    double temperature = 0.0;      // Celsius
    int fan_speed = 0;             // Percentage
    double power_usage = 0.0;      // Watts
    double power_limit = 0.0;      // Watts
    int gpu_utilization = 0;       // Percentage
    int memory_utilization = 0;    // Percentage
    uint64_t memory_used = 0;      // Bytes
    uint64_t memory_total = 0;     // Bytes
    int core_clock = 0;            // MHz
    int memory_clock = 0;          // MHz
    bool throttling = false;
    std::string vendor;            // "NVIDIA", "AMD", "Intel"
};

// Abstract GPU monitor interface
class IGPUMonitor {
public:
    virtual ~IGPUMonitor() = default;
    virtual bool init() = 0;
    virtual void shutdown() = 0;
    virtual bool isAvailable() const = 0;
    virtual int getDeviceCount() const = 0;
    virtual GPUMetrics getMetrics(int device_id) = 0;
    virtual std::string getVendor() const = 0;
};

// NVIDIA NVML Monitor
class NVMLMonitor : public IGPUMonitor {
public:
    NVMLMonitor();
    ~NVMLMonitor() override;

    bool init() override;
    void shutdown() override;
    bool isAvailable() const override { return available_; }
    int getDeviceCount() const override { return device_count_; }
    GPUMetrics getMetrics(int device_id) override;
    std::string getVendor() const override { return "NVIDIA"; }

private:
    bool available_ = false;
    int device_count_ = 0;

#ifdef _WIN32
    HMODULE nvml_lib_ = nullptr;
#else
    void* nvml_lib_ = nullptr;
#endif

    // NVML function pointers
    void* nvmlInit_v2_ = nullptr;
    void* nvmlShutdown_ = nullptr;
    void* nvmlDeviceGetCount_v2_ = nullptr;
    void* nvmlDeviceGetHandleByIndex_v2_ = nullptr;
    void* nvmlDeviceGetTemperature_ = nullptr;
    void* nvmlDeviceGetFanSpeed_ = nullptr;
    void* nvmlDeviceGetPowerUsage_ = nullptr;
    void* nvmlDeviceGetPowerManagementLimit_ = nullptr;
    void* nvmlDeviceGetUtilizationRates_ = nullptr;
    void* nvmlDeviceGetMemoryInfo_ = nullptr;
    void* nvmlDeviceGetClockInfo_ = nullptr;
    void* nvmlDeviceGetCurrentClocksThrottleReasons_ = nullptr;

    std::vector<void*> device_handles_;
};

// AMD ADL Monitor
class ADLMonitor : public IGPUMonitor {
public:
    ADLMonitor();
    ~ADLMonitor() override;

    bool init() override;
    void shutdown() override;
    bool isAvailable() const override { return available_; }
    int getDeviceCount() const override { return device_count_; }
    GPUMetrics getMetrics(int device_id) override;
    std::string getVendor() const override { return "AMD"; }

private:
    bool available_ = false;
    int device_count_ = 0;

#ifdef _WIN32
    HMODULE adl_lib_ = nullptr;
#else
    void* adl_lib_ = nullptr;
#endif

    void* context_ = nullptr;
    std::vector<int> adapter_indices_;
};

// Intel GPU Monitor (using OpenCL extensions)
class IntelMonitor : public IGPUMonitor {
public:
    IntelMonitor();
    ~IntelMonitor() override;

    bool init() override;
    void shutdown() override;
    bool isAvailable() const override { return available_; }
    int getDeviceCount() const override { return device_count_; }
    GPUMetrics getMetrics(int device_id) override;
    std::string getVendor() const override { return "Intel"; }

private:
    bool available_ = false;
    int device_count_ = 0;
};

// Combined GPU Monitor Manager
class GPUMonitorManager {
public:
    GPUMonitorManager();
    ~GPUMonitorManager();

    bool init();
    void shutdown();

    GPUMetrics getMetrics(int device_id);
    GPUMetrics getMetricsByVendor(const std::string& vendor, int local_id);
    int getTotalDeviceCount() const;

    // Direct access to monitors for vendor-specific queries
    NVMLMonitor* getNVML() { return nvml_.get(); }
    ADLMonitor* getADL() { return adl_.get(); }
    IntelMonitor* getIntel() { return intel_.get(); }

    // Real-time monitoring thread
    void startMonitoring(std::function<void(int, const GPUMetrics&)> callback, int interval_ms = 1000);
    void stopMonitoring();

private:
    std::unique_ptr<NVMLMonitor> nvml_;
    std::unique_ptr<ADLMonitor> adl_;
    std::unique_ptr<IntelMonitor> intel_;

    std::atomic<bool> monitoring_;
    std::thread monitor_thread_;
    std::function<void(int, const GPUMetrics&)> metrics_callback_;
    int monitor_interval_ms_ = 1000;

    // Device mapping: global_id -> (monitor, local_id)
    struct DeviceMapping {
        IGPUMonitor* monitor;
        int local_id;
    };
    std::vector<DeviceMapping> device_map_;
};

} // namespace mining

#endif // FTC_MINER_MINING_GPU_MONITOR_H
