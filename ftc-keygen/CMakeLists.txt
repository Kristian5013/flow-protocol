cmake_minimum_required(VERSION 3.16)
project(ftc-keygen VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Platform detection
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
endif()

# Single executable with embedded crypto
add_executable(ftc-keygen
    src/main.cpp
)

target_include_directories(ftc-keygen PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../ftc-node/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../ftc-node/include
)

# Install
install(TARGETS ftc-keygen RUNTIME DESTINATION bin)

message(STATUS "FTC Keygen ${PROJECT_VERSION}")
