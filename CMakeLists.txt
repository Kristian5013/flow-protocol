cmake_minimum_required(VERSION 3.16)
project(FTC VERSION 1.0.0 LANGUAGES CXX)

# Build options
option(BUILD_NODE "Build ftc-node" ON)
option(BUILD_MINER "Build ftc-miner" ON)
option(BUILD_WALLET "Build ftc-wallet" ON)
option(BUILD_KEYGEN "Build ftc-keygen" ON)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Add subdirectories
if(BUILD_NODE AND EXISTS "${CMAKE_SOURCE_DIR}/ftc-node/CMakeLists.txt")
    add_subdirectory(ftc-node)
endif()

if(BUILD_MINER AND EXISTS "${CMAKE_SOURCE_DIR}/ftc-miner-v2/CMakeLists.txt")
    add_subdirectory(ftc-miner-v2)
endif()

if(BUILD_WALLET AND EXISTS "${CMAKE_SOURCE_DIR}/ftc-wallet/CMakeLists.txt")
    add_subdirectory(ftc-wallet)
endif()

if(BUILD_KEYGEN AND EXISTS "${CMAKE_SOURCE_DIR}/ftc-keygen/CMakeLists.txt")
    add_subdirectory(ftc-keygen)
endif()

# Print build summary
message(STATUS "")
message(STATUS "FTC Build Configuration:")
message(STATUS "  ftc-node:   ${BUILD_NODE}")
message(STATUS "  ftc-miner:  ${BUILD_MINER}")
message(STATUS "  ftc-wallet: ${BUILD_WALLET}")
message(STATUS "  ftc-keygen: ${BUILD_KEYGEN}")
message(STATUS "")
