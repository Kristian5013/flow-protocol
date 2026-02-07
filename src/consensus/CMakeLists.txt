add_library(ftc_consensus STATIC
    params.cpp
    amount.cpp
    subsidy.cpp
    time.cpp
    merkle.cpp
    pow.cpp
    sigcache.cpp
    script_check.cpp
    tx_verify.cpp
    block_verify.cpp
    validation.cpp
)

target_include_directories(ftc_consensus PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ftc_consensus PUBLIC
    ftc_primitives
    ftc_crypto
    ftc_core
    OpenSSL::Crypto
    Threads::Threads
)
