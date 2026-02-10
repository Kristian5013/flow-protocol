add_library(ftc_crypto STATIC
    keccak.cpp
    hash.cpp
    merkle.cpp
    secp256k1.cpp
    schnorr.cpp
    musig2.cpp
    bip32.cpp
    bip39.cpp
    aes.cpp
    chacha20.cpp
    siphash.cpp
)

target_include_directories(ftc_crypto PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(ftc_crypto PUBLIC
    ftc_core
    OpenSSL::Crypto
)

target_compile_features(ftc_crypto PUBLIC cxx_std_20)
