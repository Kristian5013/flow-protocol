add_library(ftc_core STATIC
    error.cpp
    types.cpp
    serialize.cpp
    stream.cpp
    varint.cpp
    hex.cpp
    base58.cpp
    bech32.cpp
    random.cpp
    time.cpp
    fs.cpp
    logging.cpp
    config.cpp
    signal.cpp
    thread.cpp
    sync.cpp
    channel.cpp
    arena.cpp
)

target_include_directories(ftc_core PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(ftc_core PUBLIC
    OpenSSL::Crypto
    Threads::Threads
    ${PLATFORM_LIBS}
)

target_compile_features(ftc_core PUBLIC cxx_std_20)
