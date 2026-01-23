cmake_minimum_required(VERSION 3.16)
project(ftc-wallet VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows-specific
if(WIN32)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DNOMINMAX)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
endif()

# Source files
set(SOURCES
    src/main.cpp
)

# Executable
add_executable(ftc-wallet ${SOURCES})

# Link libraries
if(WIN32)
    target_link_libraries(ftc-wallet PRIVATE ws2_32)
endif()

# Release optimizations
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(MSVC)
        target_compile_options(ftc-wallet PRIVATE /O2)
    else()
        target_compile_options(ftc-wallet PRIVATE -O3)
    endif()
endif()
