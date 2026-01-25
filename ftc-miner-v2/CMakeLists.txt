cmake_minimum_required(VERSION 3.16)
project(ftc-miner VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Platform detection
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
endif()

# MinGW static linking (no DLL dependencies)
if(MINGW)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -lpthread")
endif()

# Find OpenCL - try standard paths first, then CUDA
find_package(OpenCL QUIET)

if(NOT OpenCL_FOUND)
    # Try to find OpenCL in CUDA installation
    if(WIN32)
        # Common CUDA installation paths on Windows
        set(CUDA_PATHS
            "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v12.8"
            "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v12.6"
            "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v12.4"
            "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v12.0"
            "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v11.8"
            "$ENV{CUDA_PATH}"
        )

        foreach(CUDA_PATH ${CUDA_PATHS})
            if(EXISTS "${CUDA_PATH}/include/CL/cl.h")
                set(OpenCL_INCLUDE_DIR "${CUDA_PATH}/include")
                if(CMAKE_SIZEOF_VOID_P EQUAL 8)
                    set(OpenCL_LIBRARY "${CUDA_PATH}/lib/x64/OpenCL.lib")
                else()
                    set(OpenCL_LIBRARY "${CUDA_PATH}/lib/Win32/OpenCL.lib")
                endif()

                if(EXISTS "${OpenCL_LIBRARY}")
                    set(OpenCL_FOUND TRUE)
                    message(STATUS "Found OpenCL in CUDA: ${CUDA_PATH}")
                    break()
                endif()
            endif()
        endforeach()
    endif()
endif()

if(NOT OpenCL_FOUND)
    message(FATAL_ERROR "OpenCL not found! Please install NVIDIA CUDA Toolkit or AMD APP SDK.")
endif()

message(STATUS "OpenCL include: ${OpenCL_INCLUDE_DIR}")
message(STATUS "OpenCL library: ${OpenCL_LIBRARY}")

find_package(Threads REQUIRED)

# Source files
set(TUI_SOURCES
    src/tui/terminal.cpp
    src/tui/ui.cpp
    src/tui/widgets.cpp
)

set(MINING_SOURCES
    src/mining/keccak256.cpp
    src/mining/gpu_miner.cpp
    src/mining/gpu_monitor.cpp
    src/mining/work.cpp
)

set(AUTOTUNE_SOURCES
    src/autotune/tuner.cpp
    src/autotune/benchmark.cpp
    src/autotune/adaptive_tuner.cpp
)

set(NET_SOURCES
    src/net/api_client.cpp
    src/net/node_manager.cpp
    src/net/https_client.cpp
)

set(CONFIG_SOURCES
    src/config/config.cpp
)

# Main executable
add_executable(ftc-miner
    src/main.cpp
    ${TUI_SOURCES}
    ${MINING_SOURCES}
    ${AUTOTUNE_SOURCES}
    ${NET_SOURCES}
    ${CONFIG_SOURCES}
)

target_include_directories(ftc-miner PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${OpenCL_INCLUDE_DIR}
)

target_link_libraries(ftc-miner PRIVATE
    Threads::Threads
    ${OpenCL_LIBRARY}
)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(ftc-miner PRIVATE ws2_32 winhttp)
endif()

message(STATUS "FTC Miner ${PROJECT_VERSION} (GPU-only) - Kristian Pilatovich - First Real P2P")
message(STATUS "  Usage: ftc-miner -o <node:port> -a <ftc1q...>")
