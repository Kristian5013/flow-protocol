#ifndef FTC_MINER_MINING_GPU_MINER_H
#define FTC_MINER_MINING_GPU_MINER_H

#include "work.h"
#include "keccak256.h"

#ifdef _WIN32
#define CL_TARGET_OPENCL_VERSION 120
#endif

#include <CL/cl.h>
#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <functional>
#include <chrono>
#include <memory>

namespace mining {

// GPU device info
struct GPUDevice {
    int id = 0;
    std::string name;
    std::string vendor;
    uint64_t global_mem = 0;
    uint64_t max_alloc = 0;
    uint32_t compute_units = 0;
    uint32_t max_workgroup = 0;
    bool enabled = true;

    // Mining params
    int intensity = 20;      // 8-31
    size_t worksize = 256;   // Local work size
    size_t batch_size = 0;   // Global work size

    // Stats
    double hashrate = 0.0;
    double temperature = 0.0;
    int fan_speed = 0;
    double power = 0.0;
    uint64_t accepted = 0;
    uint64_t rejected = 0;
};

// Solution callback
using SolutionCallback = std::function<void(const Solution&)>;
using HashrateCallback = std::function<void(int device_id, double hashrate)>;

class GPUMiner {
public:
    GPUMiner();
    ~GPUMiner();

    // Device enumeration
    bool detectDevices();
    std::vector<GPUDevice>& getDevices() { return devices_; }
    const std::vector<GPUDevice>& getDevices() const { return devices_; }
    int getDeviceCount() const { return static_cast<int>(devices_.size()); }

    // Configuration
    void setWorkManager(WorkManager* manager) { work_manager_ = manager; }
    void setSolutionCallback(SolutionCallback cb) { solution_callback_ = cb; }
    void setHashrateCallback(HashrateCallback cb) { hashrate_callback_ = cb; }
    void setIntensity(int device_id, int intensity);
    void setWorksize(int device_id, size_t worksize);
    void enableDevice(int device_id, bool enable);

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

private:
    // OpenCL context per device
    struct DeviceContext {
        cl_device_id device;
        cl_context context;
        cl_command_queue queue;
        cl_program program;
        cl_kernel kernel;

        // Buffers
        cl_mem header_buf;
        cl_mem target_buf;
        cl_mem result_buf;
        cl_mem count_buf;

        // Mining state
        std::thread thread;
        std::atomic<double> hashrate;
        std::atomic<bool> active;
    };

    bool initDevice(int device_id);
    void cleanupDevice(int device_id);
    void miningThread(int device_id);
    std::string loadKernel();

    std::vector<GPUDevice> devices_;
    std::vector<std::unique_ptr<DeviceContext>> contexts_;

    cl_platform_id platform_;
    std::string kernel_source_;

    WorkManager* work_manager_;
    SolutionCallback solution_callback_;
    HashrateCallback hashrate_callback_;

    std::atomic<bool> running_;
    std::atomic<bool> paused_;
    std::atomic<uint64_t> total_hashes_;

    std::chrono::steady_clock::time_point start_time_;
};

} // namespace mining

#endif // FTC_MINER_MINING_GPU_MINER_H
