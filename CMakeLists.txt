cmake_minimum_required(VERSION 3.20)
project(ftc VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_TESTS "Build unit tests" ON)
option(BUILD_BENCH "Build benchmarks" OFF)
option(ENABLE_WALLET "Enable wallet" ON)
option(ENABLE_STRATUM "Enable stratum server" ON)
option(ENABLE_GPU "Build GPU miner (requires OpenCL)" OFF)
option(USE_ASM "Use assembly optimizations" ON)

# Find OpenSSL 3.0+
find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)

# Platform-specific settings
if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_WIN32_WINNT=0x0A00)
    set(PLATFORM_LIBS ws2_32 mswsock)
else()
    set(PLATFORM_LIBS "")
endif()

# Compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-O2)
    endif()
endif()

add_subdirectory(src/core)
add_subdirectory(src/crypto)
add_subdirectory(src/primitives)
add_subdirectory(src/consensus)
add_subdirectory(src/chain)
add_subdirectory(src/mempool)
add_subdirectory(src/net)
add_subdirectory(src/rpc)
add_subdirectory(src/wallet)
add_subdirectory(src/miner)
add_subdirectory(src/node)

if(ENABLE_GPU)
    add_subdirectory(src/gpu)
endif()

# Tools (genesis miner, etc.)
add_subdirectory(tools)

# Main executable
add_executable(ftcd src/main.cpp)
target_include_directories(ftcd PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(ftcd PRIVATE
    ftc_node ftc_rpc ftc_miner ftc_wallet ftc_net
    ftc_mempool ftc_chain ftc_consensus ftc_primitives
    ftc_crypto ftc_core
    OpenSSL::SSL OpenSSL::Crypto Threads::Threads ${PLATFORM_LIBS}
)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
