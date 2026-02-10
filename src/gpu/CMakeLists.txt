# GPU miner library (requires OpenCL)
find_package(OpenCL QUIET)

if(OpenCL_FOUND)
    message(STATUS "OpenCL found: building GPU miner")

    # Generate embedded kernel source header.
    # Each .cl file is read at configure time and substituted into
    # kernel_source.h via CMake's configure_file().
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/kernels/keccak256.cl" KERNEL_KECCAK)
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/kernels/keccak_mine.cl" KERNEL_KECCAK_MINE)

    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/kernel_source.h.in"
        "${CMAKE_CURRENT_BINARY_DIR}/kernel_source.h"
        @ONLY
    )

    add_library(ftc_gpu STATIC
        opencl_context.cpp
        gpu_miner.cpp
    )

    target_include_directories(ftc_gpu PUBLIC
        ${PROJECT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_BINARY_DIR}
    )

    target_link_libraries(ftc_gpu PUBLIC
        OpenCL::OpenCL
        ftc_crypto
        ftc_core
    )

    set(FTC_GPU_AVAILABLE TRUE PARENT_SCOPE)
else()
    message(STATUS "OpenCL not found: GPU miner will not be built")
    set(FTC_GPU_AVAILABLE FALSE PARENT_SCOPE)
endif()
