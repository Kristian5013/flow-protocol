add_library(ftc_chain STATIC
    block_index.cpp
    chain.cpp
    coins.cpp
    chainstate.cpp
    reorg.cpp
    snapshot.cpp
    utxo/view.cpp
    utxo/cache.cpp
    utxo/db.cpp
    utxo/diff.cpp
    storage/flatfile.cpp
    storage/block_store.cpp
    storage/undo.cpp
    storage/index_db.cpp
)

target_include_directories(ftc_chain PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ftc_chain PUBLIC
    ftc_consensus
    ftc_primitives
    ftc_crypto
    ftc_core
    OpenSSL::Crypto
    Threads::Threads
    ${PLATFORM_LIBS}
)
