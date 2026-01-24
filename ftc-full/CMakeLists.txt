cmake_minimum_required(VERSION 3.16)
project(ftc-full VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Platform detection
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
endif()

# Main executable
add_executable(ftc-full
    src/main.cpp
)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(ftc-full PRIVATE winhttp)
endif()

message(STATUS "FTC Full ${PROJECT_VERSION} - Node + Miner Launcher")
message(STATUS "  Kristian Pilatovich 20091227 - First Real P2P")
