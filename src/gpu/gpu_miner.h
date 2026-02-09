// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// GPU-accelerated Keccak256d nonce-grinding miner.
//
// FTC PoW: keccak256d(serialize(header_80bytes)) <= target
//
// The GPU kernel parallelizes nonce search across millions of work items.
// Each work item computes keccak256d for one nonce and checks against
// the target.  Only matching nonces are returned to the host.
// ---------------------------------------------------------------------------

#pragma once
#include "gpu/opencl_context.h"

#include <cstdint>
#include <span>
#include <vector>

namespace gpu {

/// Maximum winning nonces per batch (kernel stores at most this many).
constexpr unsigned MAX_RESULTS = 8;

/// GPU-accelerated Keccak256d nonce miner.
///
/// Requires an initialised OpenCLContext with a compiled program
/// containing the keccak256d_mine kernel.
class GpuMiner {
public:
    /// Construct a miner bound to the given OpenCL context.
    /// The context must remain alive for the lifetime of this object.
    explicit GpuMiner(OpenCLContext& ctx);
    ~GpuMiner();

    // Non-copyable, non-movable (holds GPU resources).
    GpuMiner(const GpuMiner&) = delete;
    GpuMiner& operator=(const GpuMiner&) = delete;

    /// Allocate GPU buffers and create the kernel object.
    bool init();

    /// Set the block header (80 bytes).  Precomputes sponge lanes
    /// on the CPU and uploads to the GPU.
    void set_header(std::span<const uint8_t> header80);

    /// Set the difficulty target (32 bytes, same format as uint256).
    void set_target(std::span<const uint8_t> target32);

    /// Mine a batch of nonces starting from base_nonce.
    /// Returns any winning nonces found (hash <= target).
    std::vector<uint32_t> mine_batch(uint32_t base_nonce, uint32_t batch_size);

    /// Set the batch size hint (default: 2^22 = 4M).
    void set_batch_size(uint32_t size) { batch_size_ = size; }

    /// Get the current batch size.
    uint32_t batch_size() const { return batch_size_; }

private:
    OpenCLContext& ctx_;

    // GPU buffers (stored as void*, cast to cl_mem)
    void* buf_header_lanes_ = nullptr;  // 10 ulong = 80 bytes
    void* buf_target_lanes_ = nullptr;  // 4 ulong = 32 bytes
    void* buf_result_nonces_ = nullptr; // MAX_RESULTS * uint32_t
    void* buf_result_count_ = nullptr;  // 1 uint32_t

    // Kernel object
    void* kernel_ = nullptr;

    uint32_t batch_size_ = 1u << 22;  // 4M nonces per dispatch
    bool initialized_ = false;
};

} // namespace gpu
