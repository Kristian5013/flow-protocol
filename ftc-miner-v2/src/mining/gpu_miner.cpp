#include "gpu_miner.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <random>

namespace mining {

// Embedded kernel source - EXACT COPY of node's Keccak implementation
static const char* KECCAK_KERNEL_SOURCE = R"(
// Kernel version 8 - production ready
#define KECCAK_ROUNDS 24

__constant ulong RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL,
    0x8000000080008000UL, 0x000000000000808bUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008aUL,
    0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL,
    0x8000000000008003UL, 0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800aUL, 0x800000008000000aUL, 0x8000000080008081UL,
    0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};

// Rotation offsets - SAME as node
__constant int ROTATIONS[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

// Pi permutation indices - SAME as node
__constant int PI[25] = {
     0, 6, 12, 18, 24,
     3, 9, 10, 16, 22,
     1, 7, 13, 19, 20,
     4, 5, 11, 17, 23,
     2, 8, 14, 15, 21
};

inline ulong rotl64(ulong x, int n) {
    return (x << n) | (x >> (64 - n));
}

// Keccak-f[1600] permutation - EXACT COPY from node
void keccak_f1600(ulong* state) {
    ulong C[5], D[5], temp[25];

    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        // Theta step
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^
                   state[x + 15] ^ state[x + 20];
        }

        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }

        for (int i = 0; i < 25; i++) {
            state[i] ^= D[i % 5];
        }

        // Rho and Pi steps combined - SAME as node
        for (int i = 0; i < 25; i++) {
            temp[PI[i]] = rotl64(state[i], ROTATIONS[i]);
        }

        // Chi step
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                int i = y * 5 + x;
                state[i] = temp[i] ^ ((~temp[y * 5 + (x + 1) % 5]) &
                                        temp[y * 5 + (x + 2) % 5]);
            }
        }

        // Iota step
        state[0] ^= RC[round];
    }
}

void keccak256_80(const uchar* input, ulong nonce, uchar* output) {
    ulong state[25];

    for (int i = 0; i < 25; i++) {
        state[i] = 0;
    }

    for (int i = 0; i < 9; i++) {
        ulong val = 0;
        for (int j = 0; j < 8; j++) {
            val |= ((ulong)input[i * 8 + j]) << (j * 8);
        }
        state[i] ^= val;
    }

    ulong last_block = 0;
    for (int j = 0; j < 4; j++) {
        last_block |= ((ulong)input[72 + j]) << (j * 8);
    }
    last_block |= (nonce & 0xFFFFFFFF) << 32;
    state[9] ^= last_block;

    state[10] ^= 0x01UL;
    state[16] ^= 0x8000000000000000UL;

    keccak_f1600(state);

    for (int i = 0; i < 4; i++) {
        ulong val = state[i];
        for (int j = 0; j < 8; j++) {
            output[i * 8 + j] = (uchar)(val >> (j * 8));
        }
    }
}

int compare_hash(const uchar* hash, __global const uchar* target) {
    // Simple check: first 4 bytes of hash must be <= first 4 bytes of target
    // For difficulty 1: target[0-3] = 0, so hash[0-3] must all be 0

    // Quick reject: if any of first 4 bytes > target, invalid
    if (hash[0] > target[0]) return 0;
    if (hash[0] < target[0]) return 1;

    if (hash[1] > target[1]) return 0;
    if (hash[1] < target[1]) return 1;

    if (hash[2] > target[2]) return 0;
    if (hash[2] < target[2]) return 1;

    if (hash[3] > target[3]) return 0;
    if (hash[3] < target[3]) return 1;

    // First 4 bytes equal, check rest
    for (int i = 4; i < 32; i++) {
        if (hash[i] < target[i]) return 1;
        if (hash[i] > target[i]) return 0;
    }
    return 1;
}

__kernel void mine_batch(
    __global const uchar* header,
    __global const uchar* target,
    const ulong nonce_start,
    __global ulong* results,
    __global volatile uint* result_count
) {
    uint gid = get_global_id(0);

    // Copy 76 bytes header
    uchar local_header[76];
    for (int i = 0; i < 76; i++) {
        local_header[i] = header[i];
    }

    ulong nonce = nonce_start + gid;
    uchar hash[32];

    keccak256_80(local_header, nonce, hash);

    if (compare_hash(hash, target)) {
        uint idx = atomic_inc(result_count);
        if (idx < 16) {
            results[idx] = nonce;
        }
    }
}
)";

GPUMiner::GPUMiner()
    : platform_(nullptr)
    , work_manager_(nullptr)
    , running_(false)
    , paused_(false)
    , total_hashes_(0)
{
    kernel_source_ = KECCAK_KERNEL_SOURCE;
}

GPUMiner::~GPUMiner() {
    stop();
    for (size_t i = 0; i < contexts_.size(); ++i) {
        cleanupDevice(static_cast<int>(i));
    }
}

bool GPUMiner::detectDevices() {
    devices_.clear();
    contexts_.clear();

    // Get platform
    cl_uint num_platforms = 0;
    cl_int err = clGetPlatformIDs(0, nullptr, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0) {
        return false;
    }

    std::vector<cl_platform_id> platforms(num_platforms);
    clGetPlatformIDs(num_platforms, platforms.data(), nullptr);

    int device_id = 0;

    for (cl_platform_id plat : platforms) {
        // Get platform name
        char plat_name[256];
        clGetPlatformInfo(plat, CL_PLATFORM_NAME, sizeof(plat_name), plat_name, nullptr);

        // Get GPU devices
        cl_uint num_devices = 0;
        err = clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU, 0, nullptr, &num_devices);
        if (err != CL_SUCCESS || num_devices == 0) {
            continue;
        }

        std::vector<cl_device_id> cl_devices(num_devices);
        clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU, num_devices, cl_devices.data(), nullptr);

        for (cl_device_id dev : cl_devices) {
            GPUDevice gpu;
            gpu.id = device_id++;
            gpu.enabled = true;
            gpu.intensity = 20;  // Default intensity
            gpu.worksize = 256;
            gpu.hashrate = 0.0;
            gpu.temperature = 0.0;
            gpu.fan_speed = 0;
            gpu.power = 0.0;
            gpu.accepted = 0;
            gpu.rejected = 0;

            char name[256], vendor[256];
            clGetDeviceInfo(dev, CL_DEVICE_NAME, sizeof(name), name, nullptr);
            clGetDeviceInfo(dev, CL_DEVICE_VENDOR, sizeof(vendor), vendor, nullptr);
            clGetDeviceInfo(dev, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(gpu.global_mem), &gpu.global_mem, nullptr);
            clGetDeviceInfo(dev, CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof(gpu.max_alloc), &gpu.max_alloc, nullptr);
            clGetDeviceInfo(dev, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(gpu.compute_units), &gpu.compute_units, nullptr);

            size_t max_wg;
            clGetDeviceInfo(dev, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(max_wg), &max_wg, nullptr);
            gpu.max_workgroup = static_cast<uint32_t>(max_wg);

            gpu.name = name;
            gpu.vendor = vendor;

            // Skip Intel integrated GPUs (they're slow and needed for display)
            std::string vendor_lower = vendor;
            for (auto& c : vendor_lower) c = std::tolower(c);

            if (vendor_lower.find("intel") != std::string::npos) {
                device_id--;
                continue;
            }

            // Calculate batch size based on intensity
            // intensity 20 = 2^20 = 1M work items
            gpu.batch_size = 1ULL << gpu.intensity;

            devices_.push_back(gpu);

            // Create context for this device
            auto ctx = std::make_unique<DeviceContext>();
            ctx->device = nullptr;
            ctx->context = nullptr;
            ctx->queue = nullptr;
            ctx->program = nullptr;
            ctx->kernel = nullptr;
            ctx->header_buf = nullptr;
            ctx->target_buf = nullptr;
            ctx->result_buf = nullptr;
            ctx->count_buf = nullptr;
            ctx->hashrate = 0.0;
            ctx->active = false;
            contexts_.push_back(std::move(ctx));

            // Store platform for first device
            if (platform_ == nullptr) {
                platform_ = plat;
            }
        }
    }

    return !devices_.empty();
}

bool GPUMiner::initDevice(int device_id) {
    if (device_id < 0 || device_id >= static_cast<int>(devices_.size())) {
        return false;
    }

    DeviceContext& ctx = *contexts_[device_id];
    GPUDevice& dev = devices_[device_id];

    // Get device handle
    cl_uint num_devices = 0;
    std::vector<cl_platform_id> platforms(16);
    cl_uint num_platforms;
    clGetPlatformIDs(16, platforms.data(), &num_platforms);

    int current_id = 0;
    for (cl_uint p = 0; p < num_platforms; ++p) {
        cl_uint nd = 0;
        clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_GPU, 0, nullptr, &nd);
        if (nd == 0) continue;

        std::vector<cl_device_id> devices(nd);
        clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_GPU, nd, devices.data(), nullptr);

        for (cl_uint d = 0; d < nd; ++d) {
            if (current_id == device_id) {
                ctx.device = devices[d];
                break;
            }
            current_id++;
        }
        if (ctx.device) break;
    }

    if (!ctx.device) {
        return false;
    }

    cl_int err;

    // Create context
    ctx.context = clCreateContext(nullptr, 1, &ctx.device, nullptr, nullptr, &err);
    if (err != CL_SUCCESS) {
        return false;
    }

    // Create command queue
    ctx.queue = clCreateCommandQueue(ctx.context, ctx.device, 0, &err);
    if (err != CL_SUCCESS) {
        clReleaseContext(ctx.context);
        return false;
    }

    // Build program
    const char* source = kernel_source_.c_str();
    size_t source_len = kernel_source_.length();
    ctx.program = clCreateProgramWithSource(ctx.context, 1, &source, &source_len, &err);
    if (err != CL_SUCCESS) {
        clReleaseCommandQueue(ctx.queue);
        clReleaseContext(ctx.context);
        return false;
    }

    err = clBuildProgram(ctx.program, 1, &ctx.device, "-cl-std=CL1.2", nullptr, nullptr);
    if (err != CL_SUCCESS) {
        // Get build log
        size_t log_size;
        clGetProgramBuildInfo(ctx.program, ctx.device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
        std::string log(log_size, '\0');
        clGetProgramBuildInfo(ctx.program, ctx.device, CL_PROGRAM_BUILD_LOG, log_size, &log[0], nullptr);
        std::cerr << "OpenCL build error on device " << device_id << ":\n" << log << std::endl;

        clReleaseProgram(ctx.program);
        clReleaseCommandQueue(ctx.queue);
        clReleaseContext(ctx.context);
        return false;
    }

    // Create kernel
    ctx.kernel = clCreateKernel(ctx.program, "mine_batch", &err);
    if (err != CL_SUCCESS) {
        clReleaseProgram(ctx.program);
        clReleaseCommandQueue(ctx.queue);
        clReleaseContext(ctx.context);
        return false;
    }

    // Create buffers for mine_batch kernel
    ctx.header_buf = clCreateBuffer(ctx.context, CL_MEM_READ_ONLY, 76, nullptr, &err);
    ctx.target_buf = clCreateBuffer(ctx.context, CL_MEM_READ_ONLY, 32, nullptr, &err);
    ctx.result_buf = clCreateBuffer(ctx.context, CL_MEM_WRITE_ONLY, 16 * sizeof(uint64_t), nullptr, &err);
    ctx.count_buf = clCreateBuffer(ctx.context, CL_MEM_READ_WRITE, sizeof(uint32_t), nullptr, &err);

    if (!ctx.header_buf || !ctx.target_buf || !ctx.result_buf || !ctx.count_buf) {
        cleanupDevice(device_id);
        return false;
    }

    ctx.active = true;
    return true;
}

void GPUMiner::cleanupDevice(int device_id) {
    if (device_id < 0 || device_id >= static_cast<int>(contexts_.size())) {
        return;
    }

    if (!contexts_[device_id]) return;

    DeviceContext& ctx = *contexts_[device_id];
    ctx.active = false;

    if (ctx.count_buf) clReleaseMemObject(ctx.count_buf);
    if (ctx.result_buf) clReleaseMemObject(ctx.result_buf);
    if (ctx.target_buf) clReleaseMemObject(ctx.target_buf);
    if (ctx.header_buf) clReleaseMemObject(ctx.header_buf);
    if (ctx.kernel) clReleaseKernel(ctx.kernel);
    if (ctx.program) clReleaseProgram(ctx.program);
    if (ctx.queue) clReleaseCommandQueue(ctx.queue);
    if (ctx.context) clReleaseContext(ctx.context);

    ctx.header_buf = nullptr;
    ctx.target_buf = nullptr;
    ctx.result_buf = nullptr;
    ctx.count_buf = nullptr;
    ctx.kernel = nullptr;
    ctx.program = nullptr;
    ctx.queue = nullptr;
    ctx.context = nullptr;
}

void GPUMiner::setIntensity(int device_id, int intensity) {
    if (device_id >= 0 && device_id < static_cast<int>(devices_.size())) {
        intensity = std::max(8, std::min(31, intensity));
        devices_[device_id].intensity = intensity;
        devices_[device_id].batch_size = 1ULL << intensity;
    }
}

void GPUMiner::setWorksize(int device_id, size_t worksize) {
    if (device_id >= 0 && device_id < static_cast<int>(devices_.size())) {
        devices_[device_id].worksize = worksize;
    }
}

void GPUMiner::enableDevice(int device_id, bool enable) {
    if (device_id >= 0 && device_id < static_cast<int>(devices_.size())) {
        devices_[device_id].enabled = enable;
    }
}

bool GPUMiner::start() {
    if (running_) return true;
    if (!work_manager_) return false;
    if (devices_.empty()) return false;

    running_ = true;
    paused_ = false;
    total_hashes_ = 0;
    start_time_ = std::chrono::steady_clock::now();

    // Initialize and start each enabled device
    for (size_t i = 0; i < devices_.size(); ++i) {
        if (!devices_[i].enabled) continue;

        if (!initDevice(static_cast<int>(i))) {
            std::cerr << "Failed to initialize GPU " << i << std::endl;
            continue;
        }

        contexts_[i]->thread = std::thread(&GPUMiner::miningThread, this, static_cast<int>(i));
    }

    return true;
}

void GPUMiner::stop() {
    if (!running_) return;

    running_ = false;
    paused_ = false;

    // Wait for threads
    for (size_t i = 0; i < contexts_.size(); ++i) {
        if (contexts_[i] && contexts_[i]->thread.joinable()) {
            contexts_[i]->thread.join();
        }
        cleanupDevice(static_cast<int>(i));
    }
}

void GPUMiner::pause() {
    paused_ = true;
}

void GPUMiner::resume() {
    paused_ = false;
}

double GPUMiner::getTotalHashrate() const {
    double total = 0.0;
    for (const auto& ctx : contexts_) {
        if (ctx) {
            total += ctx->hashrate.load();
        }
    }
    return total;
}

void GPUMiner::miningThread(int device_id) {
    DeviceContext& ctx = *contexts_[device_id];
    GPUDevice& dev = devices_[device_id];

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    std::vector<uint8_t> header;
    Hash256 target;
    std::string job_id;
    uint32_t height = 0;

    uint64_t local_hashes = 0;
    auto last_stats_time = std::chrono::steady_clock::now();

    uint64_t nonce = dis(gen);

    while (running_) {
        // Check for pause
        while (paused_ && running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (!running_) break;

        // Check for work
        if (!work_manager_->hasWork()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        // Get new work
        if (work_manager_->isNewWork() || header.empty()) {
            Work work = work_manager_->getWork();
            header = work.buildHeader();
            target = work.target;
            job_id = work.job_id;
            height = work.height;

            nonce = dis(gen);

            if (device_id == 0) {
                work_manager_->clearNewWork();
            }

            // Upload header (76 bytes) and target (32 bytes)
            // Note: kernel only uses 76 bytes + nonce, nonce is passed separately
            clEnqueueWriteBuffer(ctx.queue, ctx.header_buf, CL_FALSE, 0, header.size(), header.data(), 0, nullptr, nullptr);
            clEnqueueWriteBuffer(ctx.queue, ctx.target_buf, CL_FALSE, 0, 32, target.data(), 0, nullptr, nullptr);
            clFinish(ctx.queue);
        }

        if (header.size() < 76) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        // Reset result count (blocking to ensure it's done before kernel)
        uint32_t zero = 0;
        clEnqueueWriteBuffer(ctx.queue, ctx.count_buf, CL_TRUE, 0, sizeof(uint32_t), &zero, 0, nullptr, nullptr);

        // Set kernel arguments
        clSetKernelArg(ctx.kernel, 0, sizeof(cl_mem), &ctx.header_buf);
        clSetKernelArg(ctx.kernel, 1, sizeof(cl_mem), &ctx.target_buf);
        clSetKernelArg(ctx.kernel, 2, sizeof(uint64_t), &nonce);
        clSetKernelArg(ctx.kernel, 3, sizeof(cl_mem), &ctx.result_buf);
        clSetKernelArg(ctx.kernel, 4, sizeof(cl_mem), &ctx.count_buf);

        // Execute kernel
        size_t global_size = dev.batch_size;
        size_t local_size = std::min(dev.worksize, static_cast<size_t>(dev.max_workgroup));

        // Round up global size to multiple of local size
        if (global_size % local_size != 0) {
            global_size = ((global_size / local_size) + 1) * local_size;
        }

        cl_int err = clEnqueueNDRangeKernel(ctx.queue, ctx.kernel, 1, nullptr, &global_size, &local_size, 0, nullptr, nullptr);
        if (err != CL_SUCCESS) {
            std::cerr << "Kernel execution failed on GPU " << device_id << ": " << err << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            continue;
        }

        clFinish(ctx.queue);

        // Check results
        uint32_t result_count = 0;
        clEnqueueReadBuffer(ctx.queue, ctx.count_buf, CL_TRUE, 0, sizeof(uint32_t), &result_count, 0, nullptr, nullptr);

        if (result_count > 0) {

            std::vector<uint64_t> results(std::min(result_count, 16u));
            clEnqueueReadBuffer(ctx.queue, ctx.result_buf, CL_TRUE, 0, results.size() * sizeof(uint64_t), results.data(), 0, nullptr, nullptr);

            for (uint64_t found_nonce : results) {
                // Verify and submit
                uint32_t nonce32 = static_cast<uint32_t>(found_nonce);
                Hash256 hash = Keccak256::hashHeader(header.data(), nonce32);

                if (Keccak256::meetsTarget(hash, target)) {
                    Solution sol;
                    sol.job_id = job_id;
                    sol.nonce = nonce32;
                    sol.hash = hash;
                    sol.height = height;

                    work_manager_->submitSolution(sol);
                    dev.accepted++;

                    if (solution_callback_) {
                        solution_callback_(sol);
                    }
                }
            }
        }

        // Update counters
        local_hashes += global_size;
        nonce += global_size;

        // Update stats periodically
        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_stats_time).count();

        if (elapsed_ms >= 1000) {
            double hashrate = local_hashes * 1000.0 / elapsed_ms;
            ctx.hashrate = hashrate;
            dev.hashrate = hashrate;

            total_hashes_ += local_hashes;

            if (hashrate_callback_) {
                hashrate_callback_(device_id, hashrate);
            }

            local_hashes = 0;
            last_stats_time = now;
        }
    }

    total_hashes_ += local_hashes;
}

std::string GPUMiner::loadKernel() {
    // Try to load from file first
    std::ifstream file("kernels/keccak256.cl");
    if (file.is_open()) {
        std::stringstream ss;
        ss << file.rdbuf();
        return ss.str();
    }
    return KECCAK_KERNEL_SOURCE;
}

} // namespace mining
