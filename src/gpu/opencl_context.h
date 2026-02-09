// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// OpenCL context management for GPU mining.
//
// Wraps the OpenCL platform/device/context/queue/program lifecycle
// behind a simple C++ interface.  All cl_* types are stored as void*
// in the header to avoid propagating CL headers to all consumers.
// ---------------------------------------------------------------------------

#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace gpu {

/// Information about a single OpenCL GPU device.
struct DeviceInfo {
    int platform_index;
    int device_index;
    std::string name;
    std::string vendor;
    uint64_t global_mem;      // bytes
    uint32_t compute_units;
    uint32_t max_work_group;
    std::string driver_version;
};

/// Manages an OpenCL context, command queue, and compiled program
/// for a single GPU device.
class OpenCLContext {
public:
    OpenCLContext();
    ~OpenCLContext();

    // Non-copyable, movable.
    OpenCLContext(const OpenCLContext&) = delete;
    OpenCLContext& operator=(const OpenCLContext&) = delete;
    OpenCLContext(OpenCLContext&& other) noexcept;
    OpenCLContext& operator=(OpenCLContext&& other) noexcept;

    /// Enumerate all CL_DEVICE_TYPE_GPU devices across all platforms.
    static std::vector<DeviceInfo> list_devices();

    /// Create context and command queue for the given platform/device.
    bool init(int platform_index = 0, int device_index = 0);

    /// Compile an OpenCL program from source code.
    bool build_program(const std::string& source,
                       const std::string& options = "");

    /// Return the build log from the last build_program() call.
    std::string get_build_log() const;

    /// Query the device info for the initialised device.
    DeviceInfo device_info() const;

    /// True after a successful init() call.
    bool is_initialized() const { return initialized_; }

    // -- Raw handle accessors (cast to cl_* in .cpp) ----------------------
    void* context() const { return context_; }
    void* queue()   const { return queue_; }
    void* program() const { return program_; }
    void* device()  const { return device_; }

private:
    void cleanup();

    void* platform_ = nullptr;
    void* device_   = nullptr;
    void* context_  = nullptr;
    void* queue_    = nullptr;
    void* program_  = nullptr;
    bool  initialized_ = false;
    std::string build_log_;
};

} // namespace gpu
