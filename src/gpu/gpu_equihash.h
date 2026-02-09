// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// GPU-accelerated Equihash (200,9) solver using OpenCL.
//
// The solver offloads all phases of Wagner's algorithm to the GPU:
//   1. Hash generation (init kernel)   -- Keccak-256 in counter mode
//   2. Collision search (round kernel) -- 9 rounds of pair-wise XOR
//   3. Solution extraction (sols kernel) -- backtrace to recover indices
//
// Each phase uses a bucketed hash table stored in GPU global memory.
// The host code manages buffer allocation, kernel dispatch, and
// solution readback.
// ---------------------------------------------------------------------------

#pragma once
#include "gpu/opencl_context.h"

#include <cstdint>
#include <span>
#include <vector>

namespace gpu {

// ===================================================================
// Equihash (200,9) constants
// ===================================================================

constexpr unsigned EQ_N = 200;
constexpr unsigned EQ_K = 9;
constexpr unsigned NUM_INDICES     = 1u << 21;  // 2097152
constexpr unsigned HASH_LEN        = 25;        // ceil(200/8)
constexpr unsigned COLLISION_BITS  = 20;        // n/(k+1)
constexpr unsigned INDEX_BITS      = 21;        // collision_bits + 1
constexpr unsigned SOLUTION_SIZE   = 1344;      // packed solution bytes
constexpr unsigned NUM_BUCKETS     = 4096;      // 2^BUCKET_BITS
constexpr unsigned BUCKET_BITS     = 12;
constexpr unsigned MAX_SLOTS       = 684;
constexpr unsigned SLOT_SIZE       = 32;        // bytes per slot
constexpr unsigned MAX_SOLUTIONS   = 8;

/// Total bytes for one hash table: NUM_BUCKETS * MAX_SLOTS * SLOT_SIZE.
constexpr size_t HT_SIZE =
    static_cast<size_t>(NUM_BUCKETS) * MAX_SLOTS * SLOT_SIZE;

// ===================================================================
// GpuEquihashSolver
// ===================================================================

/// GPU-accelerated Equihash (200,9) solver.
///
/// Requires an initialised OpenCLContext with a compiled program
/// containing the equihash kernels (init, round, sols).
class GpuEquihashSolver {
public:
    /// Construct a solver bound to the given OpenCL context.
    /// The context must remain alive for the lifetime of this object.
    explicit GpuEquihashSolver(OpenCLContext& ctx);
    ~GpuEquihashSolver();

    // Non-copyable, non-movable (holds GPU resources).
    GpuEquihashSolver(const GpuEquihashSolver&) = delete;
    GpuEquihashSolver& operator=(const GpuEquihashSolver&) = delete;

    /// Allocate GPU buffers and create kernel objects.
    bool init();

    /// Run the full Equihash solver for a 32-byte input.
    /// Returns zero or more solutions, each SOLUTION_SIZE bytes.
    std::vector<std::vector<uint8_t>> solve(
        std::span<const uint8_t> input32);

    /// Diagnostic: run the GPU Keccak-256 for a single index and
    /// compare against an expected 25-byte output.
    bool test_keccak(std::span<const uint8_t> input32, uint32_t index,
                     std::span<const uint8_t> expected25);

    /// Enable/disable debug logging.
    void set_debug(bool d) { debug_ = d; }

private:
    /// Read back bucket counts for a table and print statistics.
    void debug_bucket_counts(int table_idx, const char* label);
    void allocate_buffers();
    void release_buffers();
    void execute_init(std::span<const uint8_t> input32);
    void execute_round(int round);
    int  extract_solutions(std::vector<std::vector<uint8_t>>& out);

    OpenCLContext& ctx_;

    // -- GPU memory buffers (stored as void*, cast to cl_mem) ----------
    void* buf_input_        = nullptr;  // 32 bytes
    void* buf_ht_[10]       = {};       // hash tables (init + 9 rounds)
    void* buf_counts_[10]   = {};       // bucket counters per table
    void* buf_solutions_    = nullptr;  // MAX_SOLUTIONS * SOLUTION_SIZE
    void* buf_sol_count_    = nullptr;  // uint32_t

    // -- Kernel objects (stored as void*, cast to cl_kernel) -----------
    void* kernel_init_      = nullptr;
    void* kernel_round_     = nullptr;
    void* kernel_sols_      = nullptr;

    void* buf_diag_         = nullptr;  // diagnostic counters (4 uint32s)
    bool  initialized_      = false;
    bool  debug_            = false;
};

} // namespace gpu
