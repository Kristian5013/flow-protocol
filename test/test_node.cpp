// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_framework.h"

#include "node/context.h"

// ===========================================================================
// Node :: NodeConfig default construction
// ===========================================================================

TEST_CASE(Node, ConfigDefaults) {
    node::NodeConfig cfg;

    // Network defaults.
    CHECK(cfg.listen);
    CHECK_EQ(cfg.p2p_port, uint16_t{9333});
    CHECK_EQ(cfg.rpc_port, uint16_t{9332});
    CHECK_EQ(cfg.max_outbound, 8);
    CHECK_EQ(cfg.max_inbound, 117);
    CHECK(cfg.dns_seed);
    CHECK(cfg.connect_nodes.empty());
    CHECK(cfg.add_nodes.empty());

    // RPC defaults.
    CHECK(cfg.rpc_enabled);
    CHECK(cfg.rpc_user.empty());
    CHECK(cfg.rpc_password.empty());
    CHECK_EQ(cfg.rpc_bind, std::string("127.0.0.1"));

    // Wallet defaults.
    CHECK(!cfg.wallet_enabled);
    CHECK_EQ(cfg.wallet_file, std::string("wallet.dat"));

    // Mining defaults.
    CHECK_EQ(cfg.mine, false);
    CHECK_EQ(cfg.mine_threads, 0);
    CHECK(cfg.mine_address.empty());

    // Logging defaults.
    CHECK_EQ(static_cast<int>(cfg.log_level), static_cast<int>(core::LogLevel::INFO));
    CHECK_EQ(cfg.log_file, std::string("debug.log"));

    // Network mode defaults.
    CHECK_EQ(cfg.testnet, false);
    CHECK_EQ(cfg.regtest, false);
}

// ===========================================================================
// Node :: NodeConfig setting values
// ===========================================================================

TEST_CASE(Node, ConfigSetValues) {
    node::NodeConfig cfg;

    // Override network settings.
    cfg.listen = false;
    cfg.p2p_port = 18333;
    cfg.rpc_port = 18332;
    cfg.max_outbound = 4;
    cfg.dns_seed = false;

    CHECK_EQ(cfg.listen, false);
    CHECK_EQ(cfg.p2p_port, uint16_t{18333});
    CHECK_EQ(cfg.rpc_port, uint16_t{18332});
    CHECK_EQ(cfg.max_outbound, 4);
    CHECK_EQ(cfg.dns_seed, false);

    // Override mining settings.
    cfg.mine = true;
    cfg.mine_threads = 4;
    cfg.mine_address = "fc1qmineraddress";

    CHECK(cfg.mine);
    CHECK_EQ(cfg.mine_threads, 4);
    CHECK_EQ(cfg.mine_address, std::string("fc1qmineraddress"));

    // Override network mode.
    cfg.testnet = true;
    CHECK(cfg.testnet);
    CHECK_EQ(cfg.regtest, false);
}

// ===========================================================================
// Node :: NodeConfig network_name helper
// ===========================================================================

TEST_CASE(Node, ConfigNetworkName) {
    node::NodeConfig cfg;

    // Default is mainnet.
    CHECK_EQ(cfg.network_name(), std::string("main"));

    // Testnet mode.
    cfg.testnet = true;
    CHECK_EQ(cfg.network_name(), std::string("testnet"));
    cfg.testnet = false;

    // Regtest mode.
    cfg.regtest = true;
    CHECK_EQ(cfg.network_name(), std::string("regtest"));
}
