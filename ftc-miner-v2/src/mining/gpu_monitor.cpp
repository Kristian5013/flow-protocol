#include "gpu_monitor.h"
#include <iostream>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#define LOAD_LIB(name) LoadLibraryA(name)
#define GET_PROC(lib, name) GetProcAddress((HMODULE)lib, name)
#define FREE_LIB(lib) FreeLibrary((HMODULE)lib)
#else
#include <dlfcn.h>
#define LOAD_LIB(name) dlopen(name, RTLD_NOW)
#define GET_PROC(lib, name) dlsym(lib, name)
#define FREE_LIB(lib) dlclose(lib)
#endif

namespace mining {

// ============================================================================
// NVML Monitor Implementation
// ============================================================================

// NVML types and constants
typedef void* nvmlDevice_t;
typedef int nvmlReturn_t;
#define NVML_SUCCESS 0
#define NVML_TEMPERATURE_GPU 0
#define NVML_CLOCK_GRAPHICS 0
#define NVML_CLOCK_MEM 2

typedef struct {
    unsigned int gpu;
    unsigned int memory;
} nvmlUtilization_t;

typedef struct {
    unsigned long long total;
    unsigned long long free;
    unsigned long long used;
} nvmlMemory_t;

// Function pointer types
typedef nvmlReturn_t (*nvmlInit_v2_t)();
typedef nvmlReturn_t (*nvmlShutdown_t)();
typedef nvmlReturn_t (*nvmlDeviceGetCount_v2_t)(unsigned int*);
typedef nvmlReturn_t (*nvmlDeviceGetHandleByIndex_v2_t)(unsigned int, nvmlDevice_t*);
typedef nvmlReturn_t (*nvmlDeviceGetTemperature_t)(nvmlDevice_t, int, unsigned int*);
typedef nvmlReturn_t (*nvmlDeviceGetFanSpeed_t)(nvmlDevice_t, unsigned int*);
typedef nvmlReturn_t (*nvmlDeviceGetPowerUsage_t)(nvmlDevice_t, unsigned int*);
typedef nvmlReturn_t (*nvmlDeviceGetPowerManagementLimit_t)(nvmlDevice_t, unsigned int*);
typedef nvmlReturn_t (*nvmlDeviceGetUtilizationRates_t)(nvmlDevice_t, nvmlUtilization_t*);
typedef nvmlReturn_t (*nvmlDeviceGetMemoryInfo_t)(nvmlDevice_t, nvmlMemory_t*);
typedef nvmlReturn_t (*nvmlDeviceGetClockInfo_t)(nvmlDevice_t, int, unsigned int*);
typedef nvmlReturn_t (*nvmlDeviceGetCurrentClocksThrottleReasons_t)(nvmlDevice_t, unsigned long long*);

NVMLMonitor::NVMLMonitor() {}

NVMLMonitor::~NVMLMonitor() {
    shutdown();
}

bool NVMLMonitor::init() {
    // Try to load NVML library
#ifdef _WIN32
    // Try different NVML locations (including CUDA toolkit paths)
    const char* nvml_paths[] = {
        "nvml.dll",
        "C:\\Windows\\System32\\nvml.dll",
        "C:\\Program Files\\NVIDIA Corporation\\NVSMI\\nvml.dll",
        "C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA\\v12.8\\bin\\nvml.dll",
        "C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA\\v12.6\\bin\\nvml.dll",
        "C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA\\v12.4\\bin\\nvml.dll",
        "C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA\\v12.0\\bin\\nvml.dll",
        "C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA\\v11.8\\bin\\nvml.dll"
    };

    for (const char* path : nvml_paths) {
        nvml_lib_ = LoadLibraryA(path);
        if (nvml_lib_) break;
    }
#else
    nvml_lib_ = dlopen("libnvidia-ml.so.1", RTLD_NOW);
    if (!nvml_lib_) {
        nvml_lib_ = dlopen("libnvidia-ml.so", RTLD_NOW);
    }
#endif

    if (!nvml_lib_) {
        std::cerr << "[NVML] Failed to load nvml.dll from any location\n";
        return false;
    }
    std::cerr << "[NVML] Library loaded successfully\n";

    // Load function pointers
    nvmlInit_v2_ = GET_PROC(nvml_lib_, "nvmlInit_v2");
    nvmlShutdown_ = GET_PROC(nvml_lib_, "nvmlShutdown");
    nvmlDeviceGetCount_v2_ = GET_PROC(nvml_lib_, "nvmlDeviceGetCount_v2");
    nvmlDeviceGetHandleByIndex_v2_ = GET_PROC(nvml_lib_, "nvmlDeviceGetHandleByIndex_v2");
    nvmlDeviceGetTemperature_ = GET_PROC(nvml_lib_, "nvmlDeviceGetTemperature");
    nvmlDeviceGetFanSpeed_ = GET_PROC(nvml_lib_, "nvmlDeviceGetFanSpeed");
    nvmlDeviceGetPowerUsage_ = GET_PROC(nvml_lib_, "nvmlDeviceGetPowerUsage");
    nvmlDeviceGetPowerManagementLimit_ = GET_PROC(nvml_lib_, "nvmlDeviceGetPowerManagementLimit");
    nvmlDeviceGetUtilizationRates_ = GET_PROC(nvml_lib_, "nvmlDeviceGetUtilizationRates");
    nvmlDeviceGetMemoryInfo_ = GET_PROC(nvml_lib_, "nvmlDeviceGetMemoryInfo");
    nvmlDeviceGetClockInfo_ = GET_PROC(nvml_lib_, "nvmlDeviceGetClockInfo");
    nvmlDeviceGetCurrentClocksThrottleReasons_ = GET_PROC(nvml_lib_, "nvmlDeviceGetCurrentClocksThrottleReasons");

    if (!nvmlInit_v2_ || !nvmlDeviceGetCount_v2_ || !nvmlDeviceGetHandleByIndex_v2_) {
        std::cerr << "[NVML] Failed to load required functions\n";
        FREE_LIB(nvml_lib_);
        nvml_lib_ = nullptr;
        return false;
    }

    // Initialize NVML
    nvmlReturn_t ret = ((nvmlInit_v2_t)nvmlInit_v2_)();
    if (ret != NVML_SUCCESS) {
        std::cerr << "[NVML] nvmlInit_v2 failed with code: " << ret << "\n";
        FREE_LIB(nvml_lib_);
        nvml_lib_ = nullptr;
        return false;
    }
    std::cerr << "[NVML] Initialized successfully\n";

    // Get device count
    unsigned int count = 0;
    if (((nvmlDeviceGetCount_v2_t)nvmlDeviceGetCount_v2_)(&count) != NVML_SUCCESS) {
        std::cerr << "[NVML] Failed to get device count\n";
        ((nvmlShutdown_t)nvmlShutdown_)();
        FREE_LIB(nvml_lib_);
        nvml_lib_ = nullptr;
        return false;
    }

    device_count_ = static_cast<int>(count);
    std::cerr << "[NVML] Found " << device_count_ << " NVIDIA device(s)\n";

    // Get device handles
    device_handles_.resize(device_count_);
    for (int i = 0; i < device_count_; ++i) {
        nvmlDevice_t handle;
        if (((nvmlDeviceGetHandleByIndex_v2_t)nvmlDeviceGetHandleByIndex_v2_)(i, &handle) == NVML_SUCCESS) {
            device_handles_[i] = handle;
        }
    }

    available_ = true;
    return true;
}

void NVMLMonitor::shutdown() {
    if (available_ && nvmlShutdown_) {
        ((nvmlShutdown_t)nvmlShutdown_)();
    }
    if (nvml_lib_) {
        FREE_LIB(nvml_lib_);
        nvml_lib_ = nullptr;
    }
    available_ = false;
    device_count_ = 0;
    device_handles_.clear();
}

GPUMetrics NVMLMonitor::getMetrics(int device_id) {
    GPUMetrics metrics;
    metrics.device_id = device_id;
    metrics.vendor = "NVIDIA";

    if (!available_ || device_id < 0 || device_id >= device_count_) {
        return metrics;
    }

    nvmlDevice_t device = (nvmlDevice_t)device_handles_[device_id];

    // Temperature
    if (nvmlDeviceGetTemperature_) {
        unsigned int temp = 0;
        if (((nvmlDeviceGetTemperature_t)nvmlDeviceGetTemperature_)(device, NVML_TEMPERATURE_GPU, &temp) == NVML_SUCCESS) {
            metrics.temperature = static_cast<double>(temp);
        }
    }

    // Fan speed
    if (nvmlDeviceGetFanSpeed_) {
        unsigned int fan = 0;
        if (((nvmlDeviceGetFanSpeed_t)nvmlDeviceGetFanSpeed_)(device, &fan) == NVML_SUCCESS) {
            metrics.fan_speed = static_cast<int>(fan);
        }
    }

    // Power usage (returned in milliwatts)
    if (nvmlDeviceGetPowerUsage_) {
        unsigned int power = 0;
        if (((nvmlDeviceGetPowerUsage_t)nvmlDeviceGetPowerUsage_)(device, &power) == NVML_SUCCESS) {
            metrics.power_usage = static_cast<double>(power) / 1000.0;
        }
    }

    // Power limit
    if (nvmlDeviceGetPowerManagementLimit_) {
        unsigned int limit = 0;
        if (((nvmlDeviceGetPowerManagementLimit_t)nvmlDeviceGetPowerManagementLimit_)(device, &limit) == NVML_SUCCESS) {
            metrics.power_limit = static_cast<double>(limit) / 1000.0;
        }
    }

    // Utilization
    if (nvmlDeviceGetUtilizationRates_) {
        nvmlUtilization_t util;
        if (((nvmlDeviceGetUtilizationRates_t)nvmlDeviceGetUtilizationRates_)(device, &util) == NVML_SUCCESS) {
            metrics.gpu_utilization = static_cast<int>(util.gpu);
            metrics.memory_utilization = static_cast<int>(util.memory);
        }
    }

    // Memory info
    if (nvmlDeviceGetMemoryInfo_) {
        nvmlMemory_t mem;
        if (((nvmlDeviceGetMemoryInfo_t)nvmlDeviceGetMemoryInfo_)(device, &mem) == NVML_SUCCESS) {
            metrics.memory_used = mem.used;
            metrics.memory_total = mem.total;
        }
    }

    // Clock info
    if (nvmlDeviceGetClockInfo_) {
        unsigned int clock = 0;
        if (((nvmlDeviceGetClockInfo_t)nvmlDeviceGetClockInfo_)(device, NVML_CLOCK_GRAPHICS, &clock) == NVML_SUCCESS) {
            metrics.core_clock = static_cast<int>(clock);
        }
        if (((nvmlDeviceGetClockInfo_t)nvmlDeviceGetClockInfo_)(device, NVML_CLOCK_MEM, &clock) == NVML_SUCCESS) {
            metrics.memory_clock = static_cast<int>(clock);
        }
    }

    // Throttling
    if (nvmlDeviceGetCurrentClocksThrottleReasons_) {
        unsigned long long reasons = 0;
        if (((nvmlDeviceGetCurrentClocksThrottleReasons_t)nvmlDeviceGetCurrentClocksThrottleReasons_)(device, &reasons) == NVML_SUCCESS) {
            // Check for thermal or power throttling
            metrics.throttling = (reasons != 0);
        }
    }

    return metrics;
}

// ============================================================================
// AMD ADL Monitor Implementation
// ============================================================================

ADLMonitor::ADLMonitor() {}

ADLMonitor::~ADLMonitor() {
    shutdown();
}

bool ADLMonitor::init() {
    // Try to load ADL library
#ifdef _WIN32
    adl_lib_ = LoadLibraryA("atiadlxx.dll");
    if (!adl_lib_) {
        adl_lib_ = LoadLibraryA("atiadlxy.dll");
    }
#else
    adl_lib_ = dlopen("libatiadlxx.so", RTLD_NOW);
#endif

    if (!adl_lib_) {
        return false;
    }

    // AMD ADL is complex - simplified implementation
    // Real implementation would need full ADL SDK integration
    available_ = false;  // Disable for now until properly implemented
    return false;
}

void ADLMonitor::shutdown() {
    if (adl_lib_) {
        FREE_LIB(adl_lib_);
        adl_lib_ = nullptr;
    }
    available_ = false;
    device_count_ = 0;
}

GPUMetrics ADLMonitor::getMetrics(int device_id) {
    GPUMetrics metrics;
    metrics.device_id = device_id;
    metrics.vendor = "AMD";
    // Placeholder - would need full ADL implementation
    return metrics;
}

// ============================================================================
// Intel Monitor Implementation
// ============================================================================

IntelMonitor::IntelMonitor() {}

IntelMonitor::~IntelMonitor() {
    shutdown();
}

bool IntelMonitor::init() {
    // Intel GPU monitoring via Level Zero or OneAPI
    // Simplified - needs proper implementation
    available_ = false;
    return false;
}

void IntelMonitor::shutdown() {
    available_ = false;
    device_count_ = 0;
}

GPUMetrics IntelMonitor::getMetrics(int device_id) {
    GPUMetrics metrics;
    metrics.device_id = device_id;
    metrics.vendor = "Intel";
    return metrics;
}

// ============================================================================
// GPU Monitor Manager Implementation
// ============================================================================

GPUMonitorManager::GPUMonitorManager()
    : monitoring_(false)
    , monitor_interval_ms_(1000)
{
}

GPUMonitorManager::~GPUMonitorManager() {
    stopMonitoring();
    shutdown();
}

bool GPUMonitorManager::init() {
    std::cerr << "[GPUMonitor] Initializing GPU monitoring...\n";

    // Initialize all available monitors
    nvml_ = std::make_unique<NVMLMonitor>();
    adl_ = std::make_unique<ADLMonitor>();
    intel_ = std::make_unique<IntelMonitor>();

    bool any_available = false;

    if (nvml_->init()) {
        any_available = true;
        std::cerr << "[GPUMonitor] NVML initialized with " << nvml_->getDeviceCount() << " device(s)\n";
        // Add NVIDIA devices to map
        for (int i = 0; i < nvml_->getDeviceCount(); ++i) {
            device_map_.push_back({nvml_.get(), i});
        }
    } else {
        std::cerr << "[GPUMonitor] NVML initialization failed\n";
    }

    if (adl_->init()) {
        any_available = true;
        std::cerr << "[GPUMonitor] ADL initialized with " << adl_->getDeviceCount() << " device(s)\n";
        // Add AMD devices to map
        for (int i = 0; i < adl_->getDeviceCount(); ++i) {
            device_map_.push_back({adl_.get(), i});
        }
    }

    if (intel_->init()) {
        any_available = true;
        std::cerr << "[GPUMonitor] Intel initialized with " << intel_->getDeviceCount() << " device(s)\n";
        // Add Intel devices to map
        for (int i = 0; i < intel_->getDeviceCount(); ++i) {
            device_map_.push_back({intel_.get(), i});
        }
    }

    std::cerr << "[GPUMonitor] Total monitored devices: " << device_map_.size() << "\n";
    return any_available;
}

void GPUMonitorManager::shutdown() {
    stopMonitoring();

    if (nvml_) nvml_->shutdown();
    if (adl_) adl_->shutdown();
    if (intel_) intel_->shutdown();

    device_map_.clear();
}

GPUMetrics GPUMonitorManager::getMetrics(int device_id) {
    if (device_id < 0 || device_id >= static_cast<int>(device_map_.size())) {
        // Device not in monitor map - return empty metrics
        return GPUMetrics();
    }

    auto& mapping = device_map_[device_id];
    GPUMetrics metrics = mapping.monitor->getMetrics(mapping.local_id);
    metrics.device_id = device_id;  // Use global ID
    return metrics;
}

GPUMetrics GPUMonitorManager::getMetricsByVendor(const std::string& vendor, int local_id) {
    // Get metrics for NVIDIA device regardless of monitor device index
    if (vendor == "NVIDIA" && nvml_ && nvml_->isAvailable()) {
        return nvml_->getMetrics(local_id);
    }
    if (vendor == "AMD" && adl_ && adl_->isAvailable()) {
        return adl_->getMetrics(local_id);
    }
    if (vendor == "Intel" && intel_ && intel_->isAvailable()) {
        return intel_->getMetrics(local_id);
    }
    return GPUMetrics();
}

int GPUMonitorManager::getTotalDeviceCount() const {
    return static_cast<int>(device_map_.size());
}

void GPUMonitorManager::startMonitoring(std::function<void(int, const GPUMetrics&)> callback, int interval_ms) {
    if (monitoring_) return;

    metrics_callback_ = callback;
    monitor_interval_ms_ = interval_ms;
    monitoring_ = true;

    monitor_thread_ = std::thread([this]() {
        while (monitoring_) {
            for (int i = 0; i < getTotalDeviceCount(); ++i) {
                if (!monitoring_) break;
                auto metrics = getMetrics(i);
                if (metrics_callback_) {
                    metrics_callback_(i, metrics);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(monitor_interval_ms_));
        }
    });
}

void GPUMonitorManager::stopMonitoring() {
    monitoring_ = false;
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

} // namespace mining
