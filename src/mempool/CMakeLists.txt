add_library(ftc_mempool STATIC
    entry.cpp
    policy.cpp
    ancestor.cpp
    orphan.cpp
    rbf.cpp
    fee_estimator.cpp
    mempool.cpp
)

target_include_directories(ftc_mempool PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ftc_mempool PUBLIC
    ftc_chain
    ftc_consensus
    ftc_primitives
    ftc_crypto
    ftc_core
    OpenSSL::Crypto
    Threads::Threads
    ${PLATFORM_LIBS}
)
