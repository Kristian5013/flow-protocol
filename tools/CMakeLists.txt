# Copyright (c) 2024-2026 The FTC Developers
# Distributed under the MIT software license.

add_executable(mine_genesis mine_genesis.cpp)

target_include_directories(mine_genesis PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(mine_genesis PRIVATE
    ftc_miner
    ftc_node
    ftc_wallet
    ftc_rpc
    ftc_net
    ftc_mempool
    ftc_chain
    ftc_consensus
    ftc_primitives
    ftc_crypto
    ftc_core
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    ${PLATFORM_LIBS}
)

# Standalone miner (runs on any PC, connects to node via RPC)
add_executable(ftc-miner miner.cpp)

target_include_directories(ftc-miner PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(ftc-miner PRIVATE
    ftc_miner
    ftc_rpc
    ftc_chain
    ftc_consensus
    ftc_primitives
    ftc_crypto
    ftc_core
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    ${PLATFORM_LIBS}
)

# Standalone wallet (manages keys locally, connects to node via RPC)
add_executable(ftc-wallet wallet.cpp)

target_include_directories(ftc-wallet PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(ftc-wallet PRIVATE
    ftc_rpc
    ftc_primitives
    ftc_crypto
    ftc_core
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    ${PLATFORM_LIBS}
)

# GPU miner (optional, requires OpenCL)
if(TARGET ftc_gpu)
    add_executable(ftc-miner-gpu miner_gpu.cpp)

    target_include_directories(ftc-miner-gpu PRIVATE
        ${CMAKE_SOURCE_DIR}/src
    )

    target_link_libraries(ftc-miner-gpu PRIVATE
        ftc_gpu
        ftc_miner
        ftc_rpc
        ftc_chain
        ftc_consensus
        ftc_primitives
        ftc_crypto
        ftc_core
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
        ${PLATFORM_LIBS}
    )
endif()

# Static link so tools run without MSYS2 DLLs
if(MINGW)
    target_link_options(ftc-miner PRIVATE -static)
    target_link_options(ftc-wallet PRIVATE -static)
    if(TARGET ftc-miner-gpu)
        target_link_options(ftc-miner-gpu PRIVATE -static)
    endif()
endif()
