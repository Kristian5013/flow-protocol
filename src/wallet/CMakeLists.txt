add_library(ftc_wallet STATIC
    wallet.cpp
    walletdb.cpp
    keys.cpp
    hd.cpp
    addresses.cpp
    coins.cpp
    spend.cpp
    create_tx.cpp
    sign_tx.cpp
    fees.cpp
    backup.cpp
    encrypt.cpp
    notify.cpp
    balance.cpp
    history.cpp
)

target_include_directories(ftc_wallet PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ftc_wallet PUBLIC
    ftc_chain
    ftc_consensus
    ftc_primitives
    ftc_crypto
    ftc_core
    OpenSSL::Crypto
    Threads::Threads
    ${PLATFORM_LIBS}
)
