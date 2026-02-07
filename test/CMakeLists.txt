# Copyright (c) 2024-2026 The FTC Developers
# Distributed under the MIT software license.

set(TEST_SOURCES
    main.cpp
    test_core.cpp
    test_crypto.cpp
    test_primitives.cpp
    test_consensus.cpp
    test_chain.cpp
    test_mempool.cpp
    test_net.cpp
    test_rpc.cpp
    test_wallet.cpp
    test_miner.cpp
    test_node.cpp
)

add_executable(ftc_tests ${TEST_SOURCES})

target_include_directories(ftc_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(ftc_tests PRIVATE
    ftc_node
    ftc_miner
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

add_test(NAME ftc_unit_tests COMMAND ftc_tests)
