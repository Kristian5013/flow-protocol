// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gpu/gpu_equihash.h"
#include "kernel_source.h"

#define CL_TARGET_OPENCL_VERSION 120
#include <CL/cl.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>

namespace gpu {

// ===================================================================
// Helpers
// ===================================================================

/// Translate an OpenCL error code to a human-readable string.
static const char* cl_err(cl_int err) {
    switch (err) {
    case CL_SUCCESS:                        return "CL_SUCCESS";
    case CL_DEVICE_NOT_FOUND:               return "CL_DEVICE_NOT_FOUND";
    case CL_DEVICE_NOT_AVAILABLE:           return "CL_DEVICE_NOT_AVAILABLE";
    case CL_MEM_OBJECT_ALLOCATION_FAILURE:  return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
    case CL_OUT_OF_RESOURCES:               return "CL_OUT_OF_RESOURCES";
    case CL_OUT_OF_HOST_MEMORY:             return "CL_OUT_OF_HOST_MEMORY";
    case CL_INVALID_VALUE:                  return "CL_INVALID_VALUE";
    case CL_INVALID_MEM_OBJECT:             return "CL_INVALID_MEM_OBJECT";
    case CL_INVALID_COMMAND_QUEUE:          return "CL_INVALID_COMMAND_QUEUE";
    case CL_INVALID_CONTEXT:                return "CL_INVALID_CONTEXT";
    case CL_INVALID_KERNEL:                 return "CL_INVALID_KERNEL";
    case CL_INVALID_KERNEL_ARGS:            return "CL_INVALID_KERNEL_ARGS";
    case CL_INVALID_WORK_DIMENSION:         return "CL_INVALID_WORK_DIMENSION";
    case CL_INVALID_WORK_GROUP_SIZE:        return "CL_INVALID_WORK_GROUP_SIZE";
    case CL_INVALID_WORK_ITEM_SIZE:         return "CL_INVALID_WORK_ITEM_SIZE";
    case CL_INVALID_GLOBAL_OFFSET:          return "CL_INVALID_GLOBAL_OFFSET";
    case CL_INVALID_ARG_INDEX:              return "CL_INVALID_ARG_INDEX";
    case CL_INVALID_ARG_VALUE:              return "CL_INVALID_ARG_VALUE";
    case CL_INVALID_ARG_SIZE:               return "CL_INVALID_ARG_SIZE";
    case CL_INVALID_BUFFER_SIZE:            return "CL_INVALID_BUFFER_SIZE";
    case CL_INVALID_EVENT_WAIT_LIST:        return "CL_INVALID_EVENT_WAIT_LIST";
    case CL_INVALID_PROGRAM_EXECUTABLE:     return "CL_INVALID_PROGRAM_EXECUTABLE";
    default:                                return "CL_UNKNOWN_ERROR";
    }
}

/// Convenience macro for checking OpenCL calls.  Logs the file/line on
/// failure and returns false from the enclosing function.
#define CL_CHECK(call, msg) \
    do { \
        cl_int _err = (call); \
        if (_err != CL_SUCCESS) { \
            std::fprintf(stderr, "GPU Equihash: %s: %s (line %d)\n", \
                         (msg), cl_err(_err), __LINE__); \
            return false; \
        } \
    } while (0)

/// Same but for void-returning functions.
#define CL_CHECK_VOID(call, msg) \
    do { \
        cl_int _err = (call); \
        if (_err != CL_SUCCESS) { \
            std::fprintf(stderr, "GPU Equihash: %s: %s (line %d)\n", \
                         (msg), cl_err(_err), __LINE__); \
            return; \
        } \
    } while (0)

// ===================================================================
// Construction / destruction
// ===================================================================

GpuEquihashSolver::GpuEquihashSolver(OpenCLContext& ctx)
    : ctx_(ctx) {
    std::memset(buf_ht_,     0, sizeof(buf_ht_));
    std::memset(buf_counts_, 0, sizeof(buf_counts_));
}

GpuEquihashSolver::~GpuEquihashSolver() {
    release_buffers();

    if (kernel_init_)
        clReleaseKernel(reinterpret_cast<cl_kernel>(kernel_init_));
    if (kernel_round_)
        clReleaseKernel(reinterpret_cast<cl_kernel>(kernel_round_));
    if (kernel_sols_)
        clReleaseKernel(reinterpret_cast<cl_kernel>(kernel_sols_));
}

// ===================================================================
// release_buffers
// ===================================================================

void GpuEquihashSolver::release_buffers() {
    auto release = [](void*& p) {
        if (p) {
            clReleaseMemObject(reinterpret_cast<cl_mem>(p));
            p = nullptr;
        }
    };

    release(buf_input_);
    for (int i = 0; i < 10; ++i) {
        release(buf_ht_[i]);
        release(buf_counts_[i]);
    }
    release(buf_solutions_);
    release(buf_sol_count_);
    release(buf_diag_);
}

// ===================================================================
// allocate_buffers
// ===================================================================

void GpuEquihashSolver::allocate_buffers() {
    release_buffers();

    cl_context ctx = reinterpret_cast<cl_context>(ctx_.context());
    cl_int err = CL_SUCCESS;

    // Input buffer: 32 bytes, read-only from GPU perspective.
    cl_mem inp = clCreateBuffer(ctx, CL_MEM_READ_ONLY,
                                32, nullptr, &err);
    if (err != CL_SUCCESS || inp == nullptr) {
        std::fprintf(stderr,
            "GPU Equihash: failed to allocate input buffer: %s\n",
            cl_err(err));
        return;
    }
    buf_input_ = reinterpret_cast<void*>(inp);

    // Hash tables (10 = init output + 9 round outputs).
    for (int i = 0; i < 10; ++i) {
        cl_mem ht = clCreateBuffer(ctx, CL_MEM_READ_WRITE,
                                   HT_SIZE, nullptr, &err);
        if (err != CL_SUCCESS || ht == nullptr) {
            std::fprintf(stderr,
                "GPU Equihash: failed to allocate HT[%d] (%zu bytes): %s\n",
                i, HT_SIZE, cl_err(err));
            return;
        }
        buf_ht_[i] = reinterpret_cast<void*>(ht);

        // Bucket counters: NUM_BUCKETS * uint32_t.
        size_t cnt_size = static_cast<size_t>(NUM_BUCKETS) * sizeof(uint32_t);
        cl_mem cnt = clCreateBuffer(ctx, CL_MEM_READ_WRITE,
                                    cnt_size, nullptr, &err);
        if (err != CL_SUCCESS || cnt == nullptr) {
            std::fprintf(stderr,
                "GPU Equihash: failed to allocate counts[%d]: %s\n",
                i, cl_err(err));
            return;
        }
        buf_counts_[i] = reinterpret_cast<void*>(cnt);
    }

    // Solutions buffer.
    size_t sol_buf_size =
        static_cast<size_t>(MAX_SOLUTIONS) * SOLUTION_SIZE;
    cl_mem sol = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY,
                                sol_buf_size, nullptr, &err);
    if (err != CL_SUCCESS || sol == nullptr) {
        std::fprintf(stderr,
            "GPU Equihash: failed to allocate solutions buffer: %s\n",
            cl_err(err));
        return;
    }
    buf_solutions_ = reinterpret_cast<void*>(sol);

    // Solution count: single uint32_t.
    cl_mem scnt = clCreateBuffer(ctx, CL_MEM_READ_WRITE,
                                 sizeof(uint32_t), nullptr, &err);
    if (err != CL_SUCCESS || scnt == nullptr) {
        std::fprintf(stderr,
            "GPU Equihash: failed to allocate sol_count buffer: %s\n",
            cl_err(err));
        return;
    }
    buf_sol_count_ = reinterpret_cast<void*>(scnt);

    // Diagnostic counters: 8 uint32_t values.
    cl_mem diag = clCreateBuffer(ctx, CL_MEM_READ_WRITE,
                                 8 * sizeof(uint32_t), nullptr, &err);
    if (err != CL_SUCCESS || diag == nullptr) {
        std::fprintf(stderr,
            "GPU Equihash: failed to allocate diag buffer: %s\n",
            cl_err(err));
        return;
    }
    buf_diag_ = reinterpret_cast<void*>(diag);
}

// ===================================================================
// init -- allocate buffers, compile kernels
// ===================================================================

bool GpuEquihashSolver::init() {
    if (!ctx_.is_initialized()) {
        std::fprintf(stderr,
            "GPU Equihash: OpenCL context not initialized\n");
        return false;
    }

    // Build the combined kernel program if not already built.
    if (ctx_.program() == nullptr) {
        std::string combined;
        combined += kernels::COMMON_CL;
        combined += "\n";
        combined += kernels::KECCAK256_CL;
        combined += "\n";
        combined += kernels::EQUIHASH_INIT_CL;
        combined += "\n";
        combined += kernels::EQUIHASH_ROUND_CL;
        combined += "\n";
        combined += kernels::EQUIHASH_SOLS_CL;
        combined += "\n";

        if (!ctx_.build_program(combined, "-cl-std=CL1.2")) {
            std::fprintf(stderr,
                "GPU Equihash: kernel build failed:\n%s\n",
                ctx_.get_build_log().c_str());
            return false;
        }
    }

    cl_program prog = reinterpret_cast<cl_program>(ctx_.program());
    cl_int err = CL_SUCCESS;

    // Create kernel objects.
    cl_kernel k_init = clCreateKernel(prog, "equihash_init", &err);
    if (err != CL_SUCCESS || k_init == nullptr) {
        std::fprintf(stderr,
            "GPU Equihash: clCreateKernel(equihash_init) failed: %s\n",
            cl_err(err));
        return false;
    }
    kernel_init_ = reinterpret_cast<void*>(k_init);

    cl_kernel k_round = clCreateKernel(prog, "equihash_round", &err);
    if (err != CL_SUCCESS || k_round == nullptr) {
        std::fprintf(stderr,
            "GPU Equihash: clCreateKernel(equihash_round) failed: %s\n",
            cl_err(err));
        return false;
    }
    kernel_round_ = reinterpret_cast<void*>(k_round);

    cl_kernel k_sols = clCreateKernel(prog, "equihash_sols", &err);
    if (err != CL_SUCCESS || k_sols == nullptr) {
        std::fprintf(stderr,
            "GPU Equihash: clCreateKernel(equihash_sols) failed: %s\n",
            cl_err(err));
        return false;
    }
    kernel_sols_ = reinterpret_cast<void*>(k_sols);

    // Allocate GPU memory.
    allocate_buffers();

    // Verify all buffers were allocated.
    if (buf_input_ == nullptr || buf_solutions_ == nullptr ||
        buf_sol_count_ == nullptr) {
        std::fprintf(stderr,
            "GPU Equihash: buffer allocation incomplete\n");
        return false;
    }
    for (int i = 0; i < 10; ++i) {
        if (buf_ht_[i] == nullptr || buf_counts_[i] == nullptr) {
            std::fprintf(stderr,
                "GPU Equihash: HT/counts buffer %d not allocated\n", i);
            return false;
        }
    }

    initialized_ = true;
    return true;
}

// ===================================================================
// execute_init -- run the hash-generation kernel
// ===================================================================

void GpuEquihashSolver::execute_init(std::span<const uint8_t> input32) {
    cl_command_queue q = reinterpret_cast<cl_command_queue>(ctx_.queue());
    cl_kernel k = reinterpret_cast<cl_kernel>(kernel_init_);

    // Upload the 32-byte input.
    cl_mem inp = reinterpret_cast<cl_mem>(buf_input_);
    CL_CHECK_VOID(
        clEnqueueWriteBuffer(q, inp, CL_TRUE, 0, 32,
                             input32.data(), 0, nullptr, nullptr),
        "write input buffer");

    // Zero bucket counters for table 0.
    cl_mem cnt0 = reinterpret_cast<cl_mem>(buf_counts_[0]);
    uint32_t zero = 0;
    CL_CHECK_VOID(
        clEnqueueFillBuffer(q, cnt0, &zero, sizeof(zero),
                            0, static_cast<size_t>(NUM_BUCKETS) * sizeof(uint32_t),
                            0, nullptr, nullptr),
        "zero counts[0]");

    // Set kernel arguments.
    cl_mem ht0 = reinterpret_cast<cl_mem>(buf_ht_[0]);
    CL_CHECK_VOID(clSetKernelArg(k, 0, sizeof(cl_mem), &inp),
                   "init arg0 (input)");
    CL_CHECK_VOID(clSetKernelArg(k, 1, sizeof(cl_mem), &ht0),
                   "init arg1 (ht0)");
    CL_CHECK_VOID(clSetKernelArg(k, 2, sizeof(cl_mem), &cnt0),
                   "init arg2 (counts0)");

    // Dispatch: one work-item per index.
    size_t global = NUM_INDICES;
    size_t local  = 256;
    CL_CHECK_VOID(
        clEnqueueNDRangeKernel(q, k, 1, nullptr,
                               &global, &local,
                               0, nullptr, nullptr),
        "enqueue init kernel");
}

// ===================================================================
// execute_round -- run one collision-search round
// ===================================================================

void GpuEquihashSolver::execute_round(int round) {
    cl_command_queue q = reinterpret_cast<cl_command_queue>(ctx_.queue());
    cl_kernel k = reinterpret_cast<cl_kernel>(kernel_round_);

    // Zero destination bucket counters.
    cl_mem cnt_dst = reinterpret_cast<cl_mem>(buf_counts_[round + 1]);
    uint32_t zero = 0;
    CL_CHECK_VOID(
        clEnqueueFillBuffer(q, cnt_dst, &zero, sizeof(zero),
                            0, static_cast<size_t>(NUM_BUCKETS) * sizeof(uint32_t),
                            0, nullptr, nullptr),
        "zero counts[round+1]");

    // Kernel arguments -- must match kernel signature:
    //   (uint round, src_slots, src_bucket_counts, dst_slots, dst_bucket_counts)
    cl_mem ht_src  = reinterpret_cast<cl_mem>(buf_ht_[round]);
    cl_mem cnt_src = reinterpret_cast<cl_mem>(buf_counts_[round]);
    cl_mem ht_dst  = reinterpret_cast<cl_mem>(buf_ht_[round + 1]);
    cl_uint rnd    = static_cast<cl_uint>(round);

    CL_CHECK_VOID(clSetKernelArg(k, 0, sizeof(cl_uint), &rnd),
                   "round arg0 (round)");
    CL_CHECK_VOID(clSetKernelArg(k, 1, sizeof(cl_mem), &ht_src),
                   "round arg1 (src_slots)");
    CL_CHECK_VOID(clSetKernelArg(k, 2, sizeof(cl_mem), &cnt_src),
                   "round arg2 (src_counts)");
    CL_CHECK_VOID(clSetKernelArg(k, 3, sizeof(cl_mem), &ht_dst),
                   "round arg3 (dst_slots)");
    CL_CHECK_VOID(clSetKernelArg(k, 4, sizeof(cl_mem), &cnt_dst),
                   "round arg4 (dst_counts)");

    // Dispatch: one work-item per bucket.
    size_t global = NUM_BUCKETS;
    size_t local  = 1;
    CL_CHECK_VOID(
        clEnqueueNDRangeKernel(q, k, 1, nullptr,
                               &global, &local,
                               0, nullptr, nullptr),
        "enqueue round kernel");
}

// ===================================================================
// extract_solutions -- run the solution-extraction kernel and read back
// ===================================================================

int GpuEquihashSolver::extract_solutions(
    std::vector<std::vector<uint8_t>>& out) {

    cl_command_queue q = reinterpret_cast<cl_command_queue>(ctx_.queue());
    cl_kernel k = reinterpret_cast<cl_kernel>(kernel_sols_);

    // Zero solution count.
    cl_mem scnt = reinterpret_cast<cl_mem>(buf_sol_count_);
    uint32_t zero = 0;
    cl_int err = clEnqueueFillBuffer(
        q, scnt, &zero, sizeof(zero),
        0, sizeof(uint32_t), 0, nullptr, nullptr);
    if (err != CL_SUCCESS) {
        std::fprintf(stderr,
            "GPU Equihash: zero sol_count failed: %s\n",
            cl_err(err));
        return 0;
    }

    // Set kernel arguments matching kernel signature:
    //   table0..table8 (9 table buffers, NOT table9)
    //   table9 (the final table)
    //   final_bucket_counts (only table 9's bucket counts)
    //   solutions
    //   solution_count
    // Total: 13 args
    cl_uint arg_idx = 0;

    // Args 0..8: table0 through table8 (used for backtracing)
    for (int i = 0; i < 9; ++i) {
        cl_mem ht = reinterpret_cast<cl_mem>(buf_ht_[i]);
        err = clSetKernelArg(k, arg_idx++, sizeof(cl_mem), &ht);
        if (err != CL_SUCCESS) {
            std::fprintf(stderr,
                "GPU Equihash: sols arg (table%d) failed: %s\n",
                i, cl_err(err));
            return 0;
        }
    }

    // Arg 9: table9 (final collision table)
    cl_mem ht9 = reinterpret_cast<cl_mem>(buf_ht_[9]);
    err = clSetKernelArg(k, arg_idx++, sizeof(cl_mem), &ht9);
    if (err != CL_SUCCESS) {
        std::fprintf(stderr,
            "GPU Equihash: sols arg (table9) failed: %s\n",
            cl_err(err));
        return 0;
    }

    // Arg 10: final_bucket_counts (table 9's counts only)
    cl_mem cnt9 = reinterpret_cast<cl_mem>(buf_counts_[9]);
    err = clSetKernelArg(k, arg_idx++, sizeof(cl_mem), &cnt9);
    if (err != CL_SUCCESS) {
        std::fprintf(stderr,
            "GPU Equihash: sols arg (final_counts) failed: %s\n",
            cl_err(err));
        return 0;
    }

    // Arg 11: solutions output buffer
    cl_mem sol_buf = reinterpret_cast<cl_mem>(buf_solutions_);
    err = clSetKernelArg(k, arg_idx++, sizeof(cl_mem), &sol_buf);
    if (err != CL_SUCCESS) {
        std::fprintf(stderr,
            "GPU Equihash: sols arg (solutions) failed: %s\n",
            cl_err(err));
        return 0;
    }

    // Arg 12: solution_count (atomic counter)
    err = clSetKernelArg(k, arg_idx++, sizeof(cl_mem), &scnt);
    if (err != CL_SUCCESS) {
        std::fprintf(stderr,
            "GPU Equihash: sols arg (sol_count) failed: %s\n",
            cl_err(err));
        return 0;
    }

    // Arg 13: diagnostic counters
    cl_mem diag = reinterpret_cast<cl_mem>(buf_diag_);
    uint32_t diag_zero[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    clEnqueueWriteBuffer(q, diag, CL_TRUE, 0, sizeof(diag_zero),
                         diag_zero, 0, nullptr, nullptr);
    err = clSetKernelArg(k, arg_idx++, sizeof(cl_mem), &diag);
    if (err != CL_SUCCESS) {
        std::fprintf(stderr,
            "GPU Equihash: sols arg (diag) failed: %s\n",
            cl_err(err));
        return 0;
    }

    // Dispatch: one work-group per bucket, single work-item each.
    size_t global = NUM_BUCKETS;
    size_t local  = 1;
    err = clEnqueueNDRangeKernel(q, k, 1, nullptr,
                                 &global, &local,
                                 0, nullptr, nullptr);
    if (err != CL_SUCCESS) {
        std::fprintf(stderr,
            "GPU Equihash: enqueue sols kernel failed: %s\n",
            cl_err(err));
        return 0;
    }

    // Wait for completion.
    err = clFinish(q);
    if (err != CL_SUCCESS) {
        std::fprintf(stderr,
            "GPU Equihash: clFinish (sols) failed: %s\n",
            cl_err(err));
        return 0;
    }

    // Read back diagnostic counters if debug mode.
    if (debug_) {
        uint32_t diag_vals[8] = {};
        clEnqueueReadBuffer(q, diag, CL_TRUE, 0, sizeof(diag_vals),
                            diag_vals, 0, nullptr, nullptr);
        std::fprintf(stderr,
            "  [debug] sols diag: hash_pass=%u trace_pass=%u "
            "distinct_pass=%u order_pass=%u  b24_zero=%u/%u  "
            "b24_first=0x%02x\n",
            diag_vals[0], diag_vals[1], diag_vals[2], diag_vals[3],
            diag_vals[5], diag_vals[6], diag_vals[4] & 0xFF);
    }

    // Read back solution count.
    uint32_t num_sols = 0;
    err = clEnqueueReadBuffer(q, scnt, CL_TRUE,
                              0, sizeof(uint32_t),
                              &num_sols, 0, nullptr, nullptr);
    if (err != CL_SUCCESS) {
        std::fprintf(stderr,
            "GPU Equihash: read sol_count failed: %s\n",
            cl_err(err));
        return 0;
    }

    if (num_sols == 0) {
        return 0;
    }
    if (num_sols > MAX_SOLUTIONS) {
        num_sols = MAX_SOLUTIONS;
    }

    // Read back solution data.
    size_t read_size = static_cast<size_t>(num_sols) * SOLUTION_SIZE;
    std::vector<uint8_t> raw(read_size);
    err = clEnqueueReadBuffer(q, sol_buf, CL_TRUE,
                              0, read_size,
                              raw.data(), 0, nullptr, nullptr);
    if (err != CL_SUCCESS) {
        std::fprintf(stderr,
            "GPU Equihash: read solutions failed: %s\n",
            cl_err(err));
        return 0;
    }

    // Split into individual solution vectors.
    for (uint32_t s = 0; s < num_sols; ++s) {
        size_t offset = static_cast<size_t>(s) * SOLUTION_SIZE;
        out.emplace_back(
            raw.begin() + static_cast<ptrdiff_t>(offset),
            raw.begin() + static_cast<ptrdiff_t>(offset + SOLUTION_SIZE));
    }

    return static_cast<int>(num_sols);
}

// ===================================================================
// debug_bucket_counts -- read back and log bucket count statistics
// ===================================================================

void GpuEquihashSolver::debug_bucket_counts(int table_idx,
                                             const char* label) {
    if (!debug_) return;

    cl_command_queue q = reinterpret_cast<cl_command_queue>(ctx_.queue());
    cl_mem cnt = reinterpret_cast<cl_mem>(buf_counts_[table_idx]);

    std::vector<uint32_t> counts(NUM_BUCKETS);
    cl_int err = clEnqueueReadBuffer(q, cnt, CL_TRUE, 0,
                                     NUM_BUCKETS * sizeof(uint32_t),
                                     counts.data(), 0, nullptr, nullptr);
    if (err != CL_SUCCESS) {
        std::fprintf(stderr, "  [debug] read counts[%d] failed: %s\n",
                     table_idx, cl_err(err));
        return;
    }

    uint64_t total = 0;
    uint32_t max_val = 0;
    uint32_t non_zero = 0;
    uint32_t overflow = 0;
    for (unsigned b = 0; b < NUM_BUCKETS; ++b) {
        total += counts[b];
        if (counts[b] > max_val) max_val = counts[b];
        if (counts[b] > 0) ++non_zero;
        if (counts[b] > MAX_SLOTS) ++overflow;
    }

    std::fprintf(stderr,
        "  [debug] %s (table %d): total=%llu  avg=%.1f  max=%u  "
        "non_zero=%u/%u  overflow=%u\n",
        label, table_idx,
        (unsigned long long)total,
        non_zero > 0 ? (double)total / non_zero : 0.0,
        max_val, non_zero, NUM_BUCKETS, overflow);
}

// ===================================================================
// solve -- full Equihash solve pipeline
// ===================================================================

std::vector<std::vector<uint8_t>> GpuEquihashSolver::solve(
    std::span<const uint8_t> input32) {

    std::vector<std::vector<uint8_t>> solutions;

    if (!initialized_) {
        std::fprintf(stderr,
            "GPU Equihash: solver not initialized\n");
        return solutions;
    }
    if (input32.size() < 32) {
        std::fprintf(stderr,
            "GPU Equihash: input must be at least 32 bytes\n");
        return solutions;
    }

    cl_command_queue q = reinterpret_cast<cl_command_queue>(ctx_.queue());

    // Phase 1: Hash generation (init kernel).
    execute_init(input32);
    clFinish(q);
    debug_bucket_counts(0, "after init");

    // Phase 2: Nine collision rounds.
    for (int r = 0; r < 9; ++r) {
        execute_round(r);
        clFinish(q);
        char label[32];
        std::snprintf(label, sizeof(label), "after round %d", r);
        debug_bucket_counts(r + 1, label);
    }

    // Debug: check if collision bits are actually zero in the final table.
    if (debug_) {
        cl_mem ht9 = reinterpret_cast<cl_mem>(buf_ht_[9]);
        cl_mem cnt9 = reinterpret_cast<cl_mem>(buf_counts_[9]);

        // Read bucket counts for table 9.
        std::vector<uint32_t> final_counts(NUM_BUCKETS);
        clEnqueueReadBuffer(q, cnt9, CL_TRUE, 0,
                            NUM_BUCKETS * sizeof(uint32_t),
                            final_counts.data(), 0, nullptr, nullptr);

        // Sample entries from first few buckets.
        int printed = 0;
        for (unsigned b = 0; b < NUM_BUCKETS && printed < 5; ++b) {
            uint32_t bc = final_counts[b];
            if (bc == 0) continue;
            if (bc > MAX_SLOTS) bc = MAX_SLOTS;

            for (unsigned s = 0; s < bc && s < 2 && printed < 5; ++s) {
                size_t offset = (static_cast<size_t>(b) * MAX_SLOTS + s) *
                                SLOT_SIZE;
                uint8_t slot[SLOT_SIZE];
                clEnqueueReadBuffer(q, ht9, CL_TRUE,
                                    offset, SLOT_SIZE,
                                    slot, 0, nullptr, nullptr);

                std::fprintf(stderr,
                    "  [debug] table9[%u][%u]: ", b, s);
                for (int i = 0; i < 24; ++i)
                    std::fprintf(stderr, "%02x", slot[i]);
                std::fprintf(stderr, " | ref0=%u ref1=%u\n",
                    slot[24] | (slot[25]<<8) | (slot[26]<<16) | (slot[27]<<24),
                    slot[28] | (slot[29]<<8) | (slot[30]<<16) | (slot[31]<<24));
                ++printed;
            }
        }
    }

    // Phase 3: Solution extraction.
    int nsols = extract_solutions(solutions);
    if (debug_) {
        std::fprintf(stderr, "  [debug] solutions extracted: %d\n", nsols);
    }

    // Ensure all GPU work is complete before returning.
    clFinish(q);

    return solutions;
}

// ===================================================================
// test_keccak -- diagnostic for verifying GPU Keccak against CPU
// ===================================================================

bool GpuEquihashSolver::test_keccak(
    std::span<const uint8_t> input32, uint32_t index,
    std::span<const uint8_t> expected25) {

    if (!initialized_) {
        std::fprintf(stderr,
            "GPU Equihash: solver not initialized\n");
        return false;
    }
    if (input32.size() < 32 || expected25.size() < 25) {
        return false;
    }

    cl_command_queue q = reinterpret_cast<cl_command_queue>(ctx_.queue());
    cl_kernel k = reinterpret_cast<cl_kernel>(kernel_init_);

    // Upload input.
    cl_mem inp = reinterpret_cast<cl_mem>(buf_input_);
    CL_CHECK(
        clEnqueueWriteBuffer(q, inp, CL_TRUE, 0, 32,
                             input32.data(), 0, nullptr, nullptr),
        "test_keccak: write input");

    // Zero counters for table 0.
    cl_mem cnt0 = reinterpret_cast<cl_mem>(buf_counts_[0]);
    uint32_t zero = 0;
    CL_CHECK(
        clEnqueueFillBuffer(q, cnt0, &zero, sizeof(zero),
                            0, static_cast<size_t>(NUM_BUCKETS) * sizeof(uint32_t),
                            0, nullptr, nullptr),
        "test_keccak: zero counts");

    cl_mem ht0 = reinterpret_cast<cl_mem>(buf_ht_[0]);
    CL_CHECK(clSetKernelArg(k, 0, sizeof(cl_mem), &inp),
             "test_keccak arg0");
    CL_CHECK(clSetKernelArg(k, 1, sizeof(cl_mem), &ht0),
             "test_keccak arg1");
    CL_CHECK(clSetKernelArg(k, 2, sizeof(cl_mem), &cnt0),
             "test_keccak arg2");

    // Run a single work-item to compute hash for `index`.
    // We run a range that includes the target index.  The init
    // kernel is designed so work-item gid computes hash for index=gid.
    size_t global_offset = static_cast<size_t>(index);
    size_t global = 1;
    size_t local  = 1;
    CL_CHECK(
        clEnqueueNDRangeKernel(q, k, 1, &global_offset,
                               &global, &local,
                               0, nullptr, nullptr),
        "test_keccak: enqueue");

    CL_CHECK(clFinish(q), "test_keccak: finish");

    // The init kernel writes the hash into the hash table at the
    // bucket determined by the first BUCKET_BITS of the hash.
    // For a simple test, we read the entire HT[0] and search, or
    // better: we rely on the kernel also writing to a known location.
    //
    // Since we cannot know the exact bucket/slot without running the
    // kernel logic on CPU, we read the bucket counter to find where
    // the entry was placed, then read it.
    //
    // For simplicity in this diagnostic, we read back the full
    // first bucket worth of slots and scan.  A production test
    // would use a dedicated test kernel.
    //
    // Alternative approach: read back all counters, find the one
    // bucket that has count=1 (since we only ran one work-item),
    // then read that slot.

    // Read all bucket counters.
    std::vector<uint32_t> counts(NUM_BUCKETS);
    CL_CHECK(
        clEnqueueReadBuffer(q, cnt0, CL_TRUE, 0,
                            NUM_BUCKETS * sizeof(uint32_t),
                            counts.data(), 0, nullptr, nullptr),
        "test_keccak: read counts");

    // Find the bucket with a non-zero count.
    int target_bucket = -1;
    for (unsigned b = 0; b < NUM_BUCKETS; ++b) {
        if (counts[b] > 0) {
            target_bucket = static_cast<int>(b);
            break;
        }
    }
    if (target_bucket < 0) {
        std::fprintf(stderr,
            "test_keccak: no bucket written (index=%u)\n", index);
        return false;
    }

    // Read the first slot of that bucket.
    // Slot layout: first HASH_LEN bytes are the hash fragment,
    // followed by the 4-byte index.  The exact layout depends on
    // the kernel implementation.  We read SLOT_SIZE bytes.
    size_t slot_offset = static_cast<size_t>(target_bucket) *
                         MAX_SLOTS * SLOT_SIZE;
    uint8_t slot[SLOT_SIZE];
    CL_CHECK(
        clEnqueueReadBuffer(q, ht0, CL_TRUE,
                            slot_offset, SLOT_SIZE,
                            slot, 0, nullptr, nullptr),
        "test_keccak: read slot");

    // Compare the first 25 bytes against expected.
    if (std::memcmp(slot, expected25.data(), 25) == 0) {
        return true;
    }

    // Diagnostic output on mismatch.
    std::fprintf(stderr, "test_keccak: mismatch for index %u\n", index);
    std::fprintf(stderr, "  GPU: ");
    for (int i = 0; i < 25; ++i) {
        std::fprintf(stderr, "%02x", slot[i]);
    }
    std::fprintf(stderr, "\n  CPU: ");
    for (int i = 0; i < 25; ++i) {
        std::fprintf(stderr, "%02x", expected25[i]);
    }
    std::fprintf(stderr, "\n");

    return false;
}

} // namespace gpu
