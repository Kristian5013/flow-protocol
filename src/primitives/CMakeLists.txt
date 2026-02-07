add_library(ftc_primitives STATIC
    amount.cpp
    outpoint.cpp
    txin.cpp
    txout.cpp
    witness.cpp
    transaction.cpp
    block_header.cpp
    block.cpp
    script/opcodes.cpp
    script/script.cpp
    script/interpreter.cpp
    script/standard.cpp
    script/sign.cpp
    script/verify.cpp
    address.cpp
    fees.cpp
)

target_include_directories(ftc_primitives PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(ftc_primitives PUBLIC
    ftc_crypto
    ftc_core
)

target_compile_features(ftc_primitives PUBLIC cxx_std_20)
