// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gpu/gpu_miner.h"
#include "kernel_source.h"

#include <CL/cl.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <string>

namespace gpu {

// =========================================================================
// Construction / destruction
// =========================================================================

GpuMiner::GpuMiner(OpenCLContext& ctx) : ctx_(ctx) {}

GpuMiner::~GpuMiner() {
    if (kernel_)            clReleaseKernel(static_cast<cl_kernel>(kernel_));
    if (buf_header_lanes_)  clReleaseMemObject(static_cast<cl_mem>(buf_header_lanes_));
    if (buf_target_lanes_)  clReleaseMemObject(static_cast<cl_mem>(buf_target_lanes_));
    if (buf_result_nonces_) clReleaseMemObject(static_cast<cl_mem>(buf_result_nonces_));
    if (buf_result_count_)  clReleaseMemObject(static_cast<cl_mem>(buf_result_count_));
}

// =========================================================================
// init
// =========================================================================

bool GpuMiner::init() {
    // Build the mining kernel program.
    // The keccak_mine.cl kernel includes keccak256.cl via #include,
    // but since we embed sources as string literals, we concatenate them.
    std::string source;
    source += kernels::KECCAK256_CL;
    source += "\n";
    source += kernels::KECCAK_MINE_CL;
    source += "\n";

    // -cl-opt-disable: NVIDIA's OpenCL compiler on Ada Lovelace (RTX 4090)
    // silently eliminates the keccak_f1600 loop body when optimizations are
    // enabled, producing phantom 500 GH/s with zero blocks found.
    // Disabling optimizations fixes correctness; real hashrate is ~3-5 GH/s.
    if (!ctx_.build_program(source, "-cl-std=CL1.2 -cl-opt-disable")) {
        std::fprintf(stderr, "  [gpu] Mining kernel build failed:\n%s\n",
                     ctx_.get_build_log().c_str());
        return false;
    }

    auto context = static_cast<cl_context>(ctx_.context());
    auto program = static_cast<cl_program>(ctx_.program());
    cl_int err;

    // Create kernel
    kernel_ = clCreateKernel(program, "keccak256d_mine", &err);
    if (err != CL_SUCCESS) {
        std::fprintf(stderr, "  [gpu] Failed to create keccak256d_mine kernel: %d\n", err);
        return false;
    }

    // Allocate buffers
    buf_header_lanes_ = clCreateBuffer(context, CL_MEM_READ_ONLY,
                                        10 * sizeof(uint64_t), nullptr, &err);
    if (err != CL_SUCCESS) return false;

    buf_target_lanes_ = clCreateBuffer(context, CL_MEM_READ_ONLY,
                                        4 * sizeof(uint64_t), nullptr, &err);
    if (err != CL_SUCCESS) return false;

    buf_result_nonces_ = clCreateBuffer(context, CL_MEM_WRITE_ONLY,
                                         MAX_RESULTS * sizeof(uint32_t), nullptr, &err);
    if (err != CL_SUCCESS) return false;

    buf_result_count_ = clCreateBuffer(context, CL_MEM_READ_WRITE,
                                        sizeof(uint32_t), nullptr, &err);
    if (err != CL_SUCCESS) return false;

    // Set constant kernel arguments (buffers don't change)
    auto kernel = static_cast<cl_kernel>(kernel_);
    clSetKernelArg(kernel, 0, sizeof(cl_mem), &buf_header_lanes_);
    // arg 1 (base_nonce) set per batch
    clSetKernelArg(kernel, 2, sizeof(cl_mem), &buf_target_lanes_);
    clSetKernelArg(kernel, 3, sizeof(cl_mem), &buf_result_nonces_);
    clSetKernelArg(kernel, 4, sizeof(cl_mem), &buf_result_count_);

    initialized_ = true;
    return true;
}

// =========================================================================
// set_header -- precompute sponge lanes from 80-byte header
// =========================================================================

void GpuMiner::set_header(std::span<const uint8_t> header80) {
    if (header80.size() < 80) return;

    // Convert 80 bytes into 10 little-endian uint64_t lanes.
    // Lane i = le64(header[i*8 .. i*8+7])
    std::array<uint64_t, 10> lanes{};
    for (int i = 0; i < 10; ++i) {
        uint64_t v = 0;
        for (int j = 0; j < 8; ++j) {
            v |= static_cast<uint64_t>(header80[i * 8 + j]) << (j * 8);
        }
        lanes[i] = v;
    }

    // Clear the nonce portion of lane 9 (high 32 bits).
    // The kernel will OR in the actual nonce per work item.
    lanes[9] &= 0xFFFFFFFFULL;

    auto queue = static_cast<cl_command_queue>(ctx_.queue());
    clEnqueueWriteBuffer(queue, static_cast<cl_mem>(buf_header_lanes_),
                         CL_TRUE, 0, 10 * sizeof(uint64_t),
                         lanes.data(), 0, nullptr, nullptr);
}

// =========================================================================
// set_target -- upload 32-byte target as 4 ulong lanes
// =========================================================================

void GpuMiner::set_target(std::span<const uint8_t> target32) {
    if (target32.size() < 32) return;

    // Convert 32 bytes into 4 little-endian uint64_t lanes.
    // This matches the uint256 internal layout (bytes_[0] = LSB).
    std::array<uint64_t, 4> lanes{};
    for (int i = 0; i < 4; ++i) {
        uint64_t v = 0;
        for (int j = 0; j < 8; ++j) {
            v |= static_cast<uint64_t>(target32[i * 8 + j]) << (j * 8);
        }
        lanes[i] = v;
    }

    auto queue = static_cast<cl_command_queue>(ctx_.queue());
    clEnqueueWriteBuffer(queue, static_cast<cl_mem>(buf_target_lanes_),
                         CL_TRUE, 0, 4 * sizeof(uint64_t),
                         lanes.data(), 0, nullptr, nullptr);
}

// =========================================================================
// mine_batch -- run the kernel for a range of nonces
// =========================================================================

std::vector<uint32_t> GpuMiner::mine_batch(uint32_t base_nonce,
                                             uint32_t batch_size) {
    auto queue = static_cast<cl_command_queue>(ctx_.queue());
    auto kernel = static_cast<cl_kernel>(kernel_);

    // Zero the result counter
    uint32_t zero = 0;
    clEnqueueWriteBuffer(queue, static_cast<cl_mem>(buf_result_count_),
                         CL_TRUE, 0, sizeof(uint32_t),
                         &zero, 0, nullptr, nullptr);

    // Set base_nonce argument
    clSetKernelArg(kernel, 1, sizeof(uint32_t), &base_nonce);

    // Dispatch
    size_t global_size = batch_size;
    size_t local_size = 256;
    // Round up to multiple of local_size
    if (global_size % local_size != 0) {
        global_size = ((global_size + local_size - 1) / local_size) * local_size;
    }

    cl_int kernel_err = clEnqueueNDRangeKernel(queue, kernel, 1, nullptr,
                           &global_size, &local_size,
                           0, nullptr, nullptr);
    if (kernel_err != CL_SUCCESS) {
        last_kernel_error_ = static_cast<int32_t>(kernel_err);
        // Try falling back to a smaller local_size (GPU may not support 256)
        if (kernel_err == CL_INVALID_WORK_GROUP_SIZE && local_size > 64) {
            local_size = 64;
            if (global_size % local_size != 0)
                global_size = ((global_size + local_size - 1) / local_size) * local_size;
            kernel_err = clEnqueueNDRangeKernel(queue, kernel, 1, nullptr,
                               &global_size, &local_size,
                               0, nullptr, nullptr);
        }
        if (kernel_err != CL_SUCCESS) {
            last_kernel_error_ = static_cast<int32_t>(kernel_err);
            return {};
        }
    }
    last_kernel_error_ = 0;

    // Read back result count
    uint32_t count = 0;
    clEnqueueReadBuffer(queue, static_cast<cl_mem>(buf_result_count_),
                        CL_TRUE, 0, sizeof(uint32_t),
                        &count, 0, nullptr, nullptr);

    std::vector<uint32_t> results;
    if (count > 0) {
        if (count > MAX_RESULTS) count = MAX_RESULTS;
        results.resize(count);
        clEnqueueReadBuffer(queue, static_cast<cl_mem>(buf_result_nonces_),
                            CL_TRUE, 0, count * sizeof(uint32_t),
                            results.data(), 0, nullptr, nullptr);
    }

    return results;
}

} // namespace gpu
