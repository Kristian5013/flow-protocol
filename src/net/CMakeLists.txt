add_library(ftc_net STATIC
    dns_seeds.cpp
    address/netaddress.cpp
    address/addrman.cpp
    address/banman.cpp
    address/subnet.cpp
    transport/socket.cpp
    transport/connection.cpp
    transport/message.cpp
    transport/crypto.cpp
    protocol/version.cpp
    protocol/inventory.cpp
    protocol/blocks.cpp
    protocol/transactions.cpp
    protocol/addr.cpp
    protocol/ping.cpp
    protocol/headers.cpp
    protocol/compact.cpp
    protocol/fee_filter.cpp
    peer/peer.cpp
    peer/peer_info.cpp
    peer/peer_state.cpp
    sync/headers_sync.cpp
    sync/block_sync.cpp
    sync/orphan.cpp
    sync/stale_tip.cpp
    manager/net_manager.cpp
    manager/conn_manager.cpp
    manager/msg_processor.cpp
)

target_include_directories(ftc_net PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ftc_net PUBLIC
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
