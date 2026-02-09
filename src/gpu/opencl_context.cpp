// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gpu/opencl_context.h"

#define CL_TARGET_OPENCL_VERSION 120
#include <CL/cl.h>

#include <cstdio>
#include <cstring>
#include <utility>

namespace gpu {

// ===================================================================
// Error-code-to-string helper
// ===================================================================

static const char* cl_error_string(cl_int err) {
    switch (err) {
    case CL_SUCCESS:                        return "CL_SUCCESS";
    case CL_DEVICE_NOT_FOUND:               return "CL_DEVICE_NOT_FOUND";
    case CL_DEVICE_NOT_AVAILABLE:           return "CL_DEVICE_NOT_AVAILABLE";
    case CL_COMPILER_NOT_AVAILABLE:         return "CL_COMPILER_NOT_AVAILABLE";
    case CL_MEM_OBJECT_ALLOCATION_FAILURE:  return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
    case CL_OUT_OF_RESOURCES:               return "CL_OUT_OF_RESOURCES";
    case CL_OUT_OF_HOST_MEMORY:             return "CL_OUT_OF_HOST_MEMORY";
    case CL_PROFILING_INFO_NOT_AVAILABLE:   return "CL_PROFILING_INFO_NOT_AVAILABLE";
    case CL_MEM_COPY_OVERLAP:               return "CL_MEM_COPY_OVERLAP";
    case CL_IMAGE_FORMAT_MISMATCH:          return "CL_IMAGE_FORMAT_MISMATCH";
    case CL_IMAGE_FORMAT_NOT_SUPPORTED:     return "CL_IMAGE_FORMAT_NOT_SUPPORTED";
    case CL_BUILD_PROGRAM_FAILURE:          return "CL_BUILD_PROGRAM_FAILURE";
    case CL_MAP_FAILURE:                    return "CL_MAP_FAILURE";
    case CL_INVALID_VALUE:                  return "CL_INVALID_VALUE";
    case CL_INVALID_DEVICE_TYPE:            return "CL_INVALID_DEVICE_TYPE";
    case CL_INVALID_PLATFORM:               return "CL_INVALID_PLATFORM";
    case CL_INVALID_DEVICE:                 return "CL_INVALID_DEVICE";
    case CL_INVALID_CONTEXT:                return "CL_INVALID_CONTEXT";
    case CL_INVALID_QUEUE_PROPERTIES:       return "CL_INVALID_QUEUE_PROPERTIES";
    case CL_INVALID_COMMAND_QUEUE:          return "CL_INVALID_COMMAND_QUEUE";
    case CL_INVALID_HOST_PTR:               return "CL_INVALID_HOST_PTR";
    case CL_INVALID_MEM_OBJECT:             return "CL_INVALID_MEM_OBJECT";
    case CL_INVALID_IMAGE_FORMAT_DESCRIPTOR:return "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR";
    case CL_INVALID_IMAGE_SIZE:             return "CL_INVALID_IMAGE_SIZE";
    case CL_INVALID_SAMPLER:                return "CL_INVALID_SAMPLER";
    case CL_INVALID_BINARY:                 return "CL_INVALID_BINARY";
    case CL_INVALID_BUILD_OPTIONS:          return "CL_INVALID_BUILD_OPTIONS";
    case CL_INVALID_PROGRAM:                return "CL_INVALID_PROGRAM";
    case CL_INVALID_PROGRAM_EXECUTABLE:     return "CL_INVALID_PROGRAM_EXECUTABLE";
    case CL_INVALID_KERNEL_NAME:            return "CL_INVALID_KERNEL_NAME";
    case CL_INVALID_KERNEL_DEFINITION:      return "CL_INVALID_KERNEL_DEFINITION";
    case CL_INVALID_KERNEL:                 return "CL_INVALID_KERNEL";
    case CL_INVALID_ARG_INDEX:              return "CL_INVALID_ARG_INDEX";
    case CL_INVALID_ARG_VALUE:              return "CL_INVALID_ARG_VALUE";
    case CL_INVALID_ARG_SIZE:               return "CL_INVALID_ARG_SIZE";
    case CL_INVALID_KERNEL_ARGS:            return "CL_INVALID_KERNEL_ARGS";
    case CL_INVALID_WORK_DIMENSION:         return "CL_INVALID_WORK_DIMENSION";
    case CL_INVALID_WORK_GROUP_SIZE:        return "CL_INVALID_WORK_GROUP_SIZE";
    case CL_INVALID_WORK_ITEM_SIZE:         return "CL_INVALID_WORK_ITEM_SIZE";
    case CL_INVALID_GLOBAL_OFFSET:          return "CL_INVALID_GLOBAL_OFFSET";
    case CL_INVALID_EVENT_WAIT_LIST:        return "CL_INVALID_EVENT_WAIT_LIST";
    case CL_INVALID_EVENT:                  return "CL_INVALID_EVENT";
    case CL_INVALID_OPERATION:              return "CL_INVALID_OPERATION";
    case CL_INVALID_BUFFER_SIZE:            return "CL_INVALID_BUFFER_SIZE";
    default:                                return "CL_UNKNOWN_ERROR";
    }
}

// ===================================================================
// Construction / destruction / move
// ===================================================================

OpenCLContext::OpenCLContext() = default;

OpenCLContext::~OpenCLContext() {
    cleanup();
}

OpenCLContext::OpenCLContext(OpenCLContext&& other) noexcept
    : platform_(other.platform_)
    , device_(other.device_)
    , context_(other.context_)
    , queue_(other.queue_)
    , program_(other.program_)
    , initialized_(other.initialized_)
    , build_log_(std::move(other.build_log_)) {
    other.platform_    = nullptr;
    other.device_      = nullptr;
    other.context_     = nullptr;
    other.queue_       = nullptr;
    other.program_     = nullptr;
    other.initialized_ = false;
}

OpenCLContext& OpenCLContext::operator=(OpenCLContext&& other) noexcept {
    if (this != &other) {
        cleanup();
        platform_    = other.platform_;
        device_      = other.device_;
        context_     = other.context_;
        queue_       = other.queue_;
        program_     = other.program_;
        initialized_ = other.initialized_;
        build_log_   = std::move(other.build_log_);
        other.platform_    = nullptr;
        other.device_      = nullptr;
        other.context_     = nullptr;
        other.queue_       = nullptr;
        other.program_     = nullptr;
        other.initialized_ = false;
    }
    return *this;
}

// ===================================================================
// cleanup
// ===================================================================

void OpenCLContext::cleanup() {
    if (program_) {
        clReleaseProgram(reinterpret_cast<cl_program>(program_));
        program_ = nullptr;
    }
    if (queue_) {
        clReleaseCommandQueue(reinterpret_cast<cl_command_queue>(queue_));
        queue_ = nullptr;
    }
    if (context_) {
        clReleaseContext(reinterpret_cast<cl_context>(context_));
        context_ = nullptr;
    }
    // cl_device_id and cl_platform_id are not ref-counted; do not release.
    device_      = nullptr;
    platform_    = nullptr;
    initialized_ = false;
}

// ===================================================================
// list_devices -- enumerate all GPU devices across all platforms
// ===================================================================

std::vector<DeviceInfo> OpenCLContext::list_devices() {
    std::vector<DeviceInfo> result;

    cl_uint num_platforms = 0;
    cl_int err = clGetPlatformIDs(0, nullptr, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0) {
        return result;
    }

    std::vector<cl_platform_id> platforms(num_platforms);
    err = clGetPlatformIDs(num_platforms, platforms.data(), nullptr);
    if (err != CL_SUCCESS) {
        return result;
    }

    for (cl_uint pi = 0; pi < num_platforms; ++pi) {
        cl_uint num_devices = 0;
        err = clGetDeviceIDs(platforms[pi], CL_DEVICE_TYPE_GPU,
                             0, nullptr, &num_devices);
        if (err != CL_SUCCESS || num_devices == 0) {
            continue;
        }

        std::vector<cl_device_id> devices(num_devices);
        err = clGetDeviceIDs(platforms[pi], CL_DEVICE_TYPE_GPU,
                             num_devices, devices.data(), nullptr);
        if (err != CL_SUCCESS) {
            continue;
        }

        for (cl_uint di = 0; di < num_devices; ++di) {
            DeviceInfo info{};
            info.platform_index = static_cast<int>(pi);
            info.device_index   = static_cast<int>(di);

            // Device name.
            char buf[256] = {};
            clGetDeviceInfo(devices[di], CL_DEVICE_NAME,
                            sizeof(buf), buf, nullptr);
            info.name = buf;

            // Vendor.
            std::memset(buf, 0, sizeof(buf));
            clGetDeviceInfo(devices[di], CL_DEVICE_VENDOR,
                            sizeof(buf), buf, nullptr);
            info.vendor = buf;

            // Global memory.
            cl_ulong mem = 0;
            clGetDeviceInfo(devices[di], CL_DEVICE_GLOBAL_MEM_SIZE,
                            sizeof(mem), &mem, nullptr);
            info.global_mem = static_cast<uint64_t>(mem);

            // Compute units.
            cl_uint cu = 0;
            clGetDeviceInfo(devices[di], CL_DEVICE_MAX_COMPUTE_UNITS,
                            sizeof(cu), &cu, nullptr);
            info.compute_units = static_cast<uint32_t>(cu);

            // Max work-group size.
            size_t wgs = 0;
            clGetDeviceInfo(devices[di], CL_DEVICE_MAX_WORK_GROUP_SIZE,
                            sizeof(wgs), &wgs, nullptr);
            info.max_work_group = static_cast<uint32_t>(wgs);

            // Driver version.
            std::memset(buf, 0, sizeof(buf));
            clGetDeviceInfo(devices[di], CL_DRIVER_VERSION,
                            sizeof(buf), buf, nullptr);
            info.driver_version = buf;

            result.push_back(std::move(info));
        }
    }

    return result;
}

// ===================================================================
// init -- create context + command queue for one device
// ===================================================================

bool OpenCLContext::init(int platform_index, int device_index) {
    cleanup();

    // --- platforms -------------------------------------------------------
    cl_uint num_platforms = 0;
    cl_int err = clGetPlatformIDs(0, nullptr, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0) {
        std::fprintf(stderr, "OpenCL: no platforms found (%s)\n",
                     cl_error_string(err));
        return false;
    }

    std::vector<cl_platform_id> platforms(num_platforms);
    err = clGetPlatformIDs(num_platforms, platforms.data(), nullptr);
    if (err != CL_SUCCESS) {
        std::fprintf(stderr, "OpenCL: clGetPlatformIDs failed (%s)\n",
                     cl_error_string(err));
        return false;
    }

    if (platform_index < 0 ||
        static_cast<cl_uint>(platform_index) >= num_platforms) {
        std::fprintf(stderr,
            "OpenCL: platform index %d out of range (0..%u)\n",
            platform_index, num_platforms - 1);
        return false;
    }

    cl_platform_id plat = platforms[platform_index];
    platform_ = reinterpret_cast<void*>(plat);

    // --- devices ---------------------------------------------------------
    cl_uint num_devices = 0;
    err = clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU,
                         0, nullptr, &num_devices);
    if (err != CL_SUCCESS || num_devices == 0) {
        std::fprintf(stderr,
            "OpenCL: no GPU devices on platform %d (%s)\n",
            platform_index, cl_error_string(err));
        return false;
    }

    std::vector<cl_device_id> devices(num_devices);
    err = clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU,
                         num_devices, devices.data(), nullptr);
    if (err != CL_SUCCESS) {
        std::fprintf(stderr,
            "OpenCL: clGetDeviceIDs failed (%s)\n",
            cl_error_string(err));
        return false;
    }

    if (device_index < 0 ||
        static_cast<cl_uint>(device_index) >= num_devices) {
        std::fprintf(stderr,
            "OpenCL: device index %d out of range (0..%u)\n",
            device_index, num_devices - 1);
        return false;
    }

    cl_device_id dev = devices[device_index];
    device_ = reinterpret_cast<void*>(dev);

    // --- context ---------------------------------------------------------
    cl_context ctx = clCreateContext(
        nullptr, 1, &dev, nullptr, nullptr, &err);
    if (err != CL_SUCCESS || ctx == nullptr) {
        std::fprintf(stderr,
            "OpenCL: clCreateContext failed (%s)\n",
            cl_error_string(err));
        return false;
    }
    context_ = reinterpret_cast<void*>(ctx);

    // --- command queue (OpenCL 1.2 compatible) ---------------------------
    cl_command_queue q = clCreateCommandQueue(ctx, dev, 0, &err);
    if (err != CL_SUCCESS || q == nullptr) {
        std::fprintf(stderr,
            "OpenCL: clCreateCommandQueue failed (%s)\n",
            cl_error_string(err));
        cleanup();
        return false;
    }
    queue_ = reinterpret_cast<void*>(q);

    initialized_ = true;
    return true;
}

// ===================================================================
// build_program -- compile OpenCL C source into a program object
// ===================================================================

bool OpenCLContext::build_program(const std::string& source,
                                  const std::string& options) {
    build_log_.clear();

    if (!initialized_) {
        build_log_ = "OpenCL context not initialized";
        return false;
    }

    // Release any previous program.
    if (program_) {
        clReleaseProgram(reinterpret_cast<cl_program>(program_));
        program_ = nullptr;
    }

    cl_context   ctx = reinterpret_cast<cl_context>(context_);
    cl_device_id dev = reinterpret_cast<cl_device_id>(device_);

    const char* src_ptr = source.c_str();
    size_t      src_len = source.size();

    cl_int err = CL_SUCCESS;
    cl_program prog = clCreateProgramWithSource(
        ctx, 1, &src_ptr, &src_len, &err);
    if (err != CL_SUCCESS || prog == nullptr) {
        char msg[128];
        std::snprintf(msg, sizeof(msg),
            "clCreateProgramWithSource failed: %s",
            cl_error_string(err));
        build_log_ = msg;
        return false;
    }

    err = clBuildProgram(prog, 1, &dev,
                         options.empty() ? nullptr : options.c_str(),
                         nullptr, nullptr);

    // Always capture the build log (useful for warnings too).
    size_t log_size = 0;
    clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG,
                          0, nullptr, &log_size);
    if (log_size > 1) {
        std::string log(log_size, '\0');
        clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG,
                              log_size, log.data(), nullptr);
        // Trim trailing null / whitespace.
        while (!log.empty() &&
               (log.back() == '\0' || log.back() == '\n' ||
                log.back() == '\r' || log.back() == ' ')) {
            log.pop_back();
        }
        build_log_ = std::move(log);
    }

    if (err != CL_SUCCESS) {
        std::fprintf(stderr,
            "OpenCL: clBuildProgram failed (%s)\n%s\n",
            cl_error_string(err), build_log_.c_str());
        clReleaseProgram(prog);
        return false;
    }

    program_ = reinterpret_cast<void*>(prog);
    return true;
}

// ===================================================================
// get_build_log
// ===================================================================

std::string OpenCLContext::get_build_log() const {
    return build_log_;
}

// ===================================================================
// device_info
// ===================================================================

DeviceInfo OpenCLContext::device_info() const {
    DeviceInfo info{};
    if (!initialized_ || device_ == nullptr) {
        return info;
    }

    cl_device_id dev = reinterpret_cast<cl_device_id>(device_);

    // Re-use the list_devices approach for a single device.
    // We do not store the indices after init, so use -1 / -1 as
    // "already selected".
    info.platform_index = -1;
    info.device_index   = -1;

    char buf[256] = {};
    clGetDeviceInfo(dev, CL_DEVICE_NAME, sizeof(buf), buf, nullptr);
    info.name = buf;

    std::memset(buf, 0, sizeof(buf));
    clGetDeviceInfo(dev, CL_DEVICE_VENDOR, sizeof(buf), buf, nullptr);
    info.vendor = buf;

    cl_ulong mem = 0;
    clGetDeviceInfo(dev, CL_DEVICE_GLOBAL_MEM_SIZE,
                    sizeof(mem), &mem, nullptr);
    info.global_mem = static_cast<uint64_t>(mem);

    cl_uint cu = 0;
    clGetDeviceInfo(dev, CL_DEVICE_MAX_COMPUTE_UNITS,
                    sizeof(cu), &cu, nullptr);
    info.compute_units = static_cast<uint32_t>(cu);

    size_t wgs = 0;
    clGetDeviceInfo(dev, CL_DEVICE_MAX_WORK_GROUP_SIZE,
                    sizeof(wgs), &wgs, nullptr);
    info.max_work_group = static_cast<uint32_t>(wgs);

    std::memset(buf, 0, sizeof(buf));
    clGetDeviceInfo(dev, CL_DRIVER_VERSION, sizeof(buf), buf, nullptr);
    info.driver_version = buf;

    return info;
}

} // namespace gpu
