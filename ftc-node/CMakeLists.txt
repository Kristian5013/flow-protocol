cmake_minimum_required(VERSION 3.16)
project(ftc-node VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Platform detection
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
endif()

# Options
option(FTC_BUILD_TESTS "Build tests" ON)
# IPv6 is always enabled (no IPv4-only mode)

# Find packages
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# MinGW pthread fix
if(MINGW)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -lpthread")
endif()

# Source files
set(CRYPTO_SOURCES
    src/crypto/keccak256.cpp
    src/crypto/secp256k1.cpp
    src/crypto/base58.cpp
    src/crypto/bech32.cpp
)

set(P2P_SOURCES
    src/p2p/protocol.cpp
    src/p2p/connection.cpp
    src/p2p/peer_manager.cpp
    src/p2p/message_handler.cpp
    src/p2p/sync_manager.cpp
)

set(CHAIN_SOURCES
    src/chain/block.cpp
    src/chain/transaction.cpp
    src/chain/chain.cpp
    src/chain/utxo_set.cpp
    src/chain/mempool.cpp
    src/chain/consensus.cpp
    src/chain/snapshot.cpp
)

set(SCRIPT_SOURCES
    src/script/script.cpp
    src/script/interpreter.cpp
)

set(P2POOL_SOURCES
    src/p2pool/sharechain.cpp
    src/p2pool/p2pool_net.cpp
)

set(STORAGE_SOURCES
    src/storage/database.cpp
    src/storage/block_store.cpp
)

set(API_SOURCES
    src/api/server.cpp
    src/api/handlers.cpp
    src/api/routes/status.cpp
    src/api/routes/chain.cpp
    src/api/routes/address.cpp
    src/api/routes/wallet.cpp
    src/api/routes/mining.cpp
    src/api/routes/p2pool.cpp
)

set(UTIL_SOURCES
    src/util/logging.cpp
    src/util/config.cpp
    src/util/time.cpp
    src/util/hex.cpp
)

# Main executable
add_executable(ftc-node
    src/main.cpp
    src/node.cpp
    ${CRYPTO_SOURCES}
    ${P2P_SOURCES}
    ${CHAIN_SOURCES}
    ${SCRIPT_SOURCES}
    ${P2POOL_SOURCES}
    ${STORAGE_SOURCES}
    ${API_SOURCES}
    ${UTIL_SOURCES}
)

target_include_directories(ftc-node PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(ftc-node PRIVATE
    Threads::Threads
)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(ftc-node PRIVATE ws2_32 iphlpapi winhttp)
elseif(UNIX)
    target_link_libraries(ftc-node PRIVATE dl)
endif()

# IPv6 is always enabled
target_compile_definitions(ftc-node PRIVATE FTC_ENABLE_IPV6=1)

# Tests
if(FTC_BUILD_TESTS)
    enable_testing()

    add_executable(test_crypto
        test/test_crypto.cpp
        ${CRYPTO_SOURCES}
        ${UTIL_SOURCES}
    )
    target_include_directories(test_crypto PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    add_test(NAME test_crypto COMMAND test_crypto)

    # Note: test_discovery removed (NTP discovery removed)
endif()

# Install
install(TARGETS ftc-node RUNTIME DESTINATION bin)

message(STATUS "FTC Node ${PROJECT_VERSION} - Kristian Pilatovich 20091227 - First Real P2P")
message(STATUS "  IPv6: ON (IPv6-only, no IPv4)")
message(STATUS "  Peers: peers.dat + P2P addr exchange")
message(STATUS "  Tests: ${FTC_BUILD_TESTS}")
