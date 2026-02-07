add_library(ftc_node STATIC
    node.cpp
    init.cpp
    shutdown.cpp
    context.cpp
    config.cpp
    logging_init.cpp
)

target_include_directories(ftc_node PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ftc_node PUBLIC
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
