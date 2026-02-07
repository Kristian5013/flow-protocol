add_library(ftc_miner STATIC
    miner.cpp
    block_template.cpp
    block_assembler.cpp
    coinbase.cpp
    solver.cpp
    worker.cpp
    stratum.cpp
    difficulty.cpp
)

target_include_directories(ftc_miner PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ftc_miner PUBLIC
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
