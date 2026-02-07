add_library(ftc_rpc STATIC
    server.cpp
    request.cpp
    util.cpp
    blockchain.cpp
    mining.cpp
    network.cpp
    rawtransaction.cpp
    wallet_rpc.cpp
    misc.cpp
    mempool_rpc.cpp
    fees.cpp
    control.cpp
)

target_include_directories(ftc_rpc PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ftc_rpc PUBLIC
    ftc_net
    ftc_mempool
    ftc_chain
    ftc_consensus
    ftc_primitives
    ftc_crypto
    ftc_core
    OpenSSL::Crypto
    Threads::Threads
    ${PLATFORM_LIBS}
)
