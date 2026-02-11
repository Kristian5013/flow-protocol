#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// NodeConfig -- all configuration options for the FTC node.
//
// Parsed from command-line arguments and/or a configuration file.  The
// NodeConfig struct is the single authoritative source of truth for every
// runtime-tuneable parameter in the node process.
// ---------------------------------------------------------------------------

#ifndef FTC_NODE_CONTEXT_H
#define FTC_NODE_CONTEXT_H

#include "core/logging.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace node {

// ---------------------------------------------------------------------------
// Version constants
// ---------------------------------------------------------------------------

inline constexpr int VERSION_MAJOR = 0;
inline constexpr int VERSION_MINOR = 1;
inline constexpr int VERSION_PATCH = 0;
inline constexpr const char* VERSION_SUFFIX = "alpha";

/// Returns the full version string, e.g. "0.1.0-alpha".
std::string get_version_string();

/// Returns the full client name, e.g. "FTC Core v0.1.0-alpha".
std::string get_client_name();

// ---------------------------------------------------------------------------
// NodeConfig
// ---------------------------------------------------------------------------

struct NodeConfig {
    // -- Data directory ------------------------------------------------------
    std::filesystem::path datadir;  // resolved at parse time

    // -- Network -------------------------------------------------------------
    bool listen = true;
    uint16_t p2p_port = 9333;
    uint16_t rpc_port = 9332;
    int max_outbound = 8;
    int max_inbound = 117;
    bool dns_seed = true;
    std::vector<std::string> connect_nodes;
    std::vector<std::string> add_nodes;

    // -- RPC -----------------------------------------------------------------
    bool rpc_enabled = true;
    std::string rpc_user;
    std::string rpc_password;
    std::string rpc_bind = "127.0.0.1";
    std::vector<std::string> rpc_allowip; // CIDR subnets or bare IPs

    // -- Wallet --------------------------------------------------------------
    bool wallet_enabled = false;
    std::string wallet_file = "wallet.dat";

    // -- Mining --------------------------------------------------------------
    bool mine = false;
    int mine_threads = 0;  // 0 = auto (number of logical CPUs)
    std::string mine_address;

    // -- Logging -------------------------------------------------------------
    core::LogLevel log_level = core::LogLevel::INFO;
    uint32_t log_categories = static_cast<uint32_t>(core::LogCategory::ALL);
    std::string log_file = "debug.log";

    // -- Misc ----------------------------------------------------------------
    bool testnet = false;
    bool regtest = false;

    // -- Derived helpers -----------------------------------------------------

    /// Returns the active network name: "main", "testnet", or "regtest".
    [[nodiscard]] std::string network_name() const;

    /// Returns the resolved data directory path (with network subdirectory
    /// appended for testnet/regtest).
    [[nodiscard]] std::filesystem::path resolved_datadir() const;

    /// Returns the full path to the log file.
    [[nodiscard]] std::filesystem::path log_file_path() const;

    /// Returns the full path to the wallet file.
    [[nodiscard]] std::filesystem::path wallet_file_path() const;
};

// ---------------------------------------------------------------------------
// Argument / config file parsing
// ---------------------------------------------------------------------------

/// Parse command-line arguments into a NodeConfig.
///
/// Accepted flags (all with -- or - prefix):
///   -datadir=<path>       -listen=<0|1>          -port=<n>
///   -rpcport=<n>          -rpcuser=<user>        -rpcpassword=<pass>
///   -rpcbind=<addr>       -norpc                 -nowallet
///   -mine                 -minethreads=<n>       -mineaddress=<addr>
///   -testnet              -regtest               -loglevel=<level>
///   -connect=<addr>       -addnode=<addr>        -maxoutbound=<n>
///   -maxinbound=<n>       -dnsseed=<0|1>
///   -help / -h / -?       -version
///
/// @returns A populated NodeConfig.
NodeConfig parse_args(int argc, char** argv);

/// Load a configuration file and merge its values into an existing config.
///
/// @param path    Path to the .conf file.
/// @param config  The NodeConfig to update in place.
void load_config_file(const std::filesystem::path& path, NodeConfig& config);

/// Print a usage/help message to stdout.
void print_usage();

/// Print version information to stdout.
void print_version();

} // namespace node

#endif // FTC_NODE_CONTEXT_H
