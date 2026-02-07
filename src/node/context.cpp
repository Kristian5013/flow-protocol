// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "node/context.h"

#include "core/config.h"
#include "core/fs.h"
#include "core/logging.h"
#include "core/thread.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

namespace node {

// ---------------------------------------------------------------------------
// Version helpers
// ---------------------------------------------------------------------------

std::string get_version_string() {
    std::ostringstream ss;
    ss << VERSION_MAJOR << '.' << VERSION_MINOR << '.' << VERSION_PATCH;
    if (VERSION_SUFFIX[0] != '\0') {
        ss << '-' << VERSION_SUFFIX;
    }
    return ss.str();
}

std::string get_client_name() {
    return "FTC Core v" + get_version_string();
}

// ---------------------------------------------------------------------------
// NodeConfig -- derived helpers
// ---------------------------------------------------------------------------

std::string NodeConfig::network_name() const {
    if (regtest) return "regtest";
    if (testnet) return "testnet";
    return "main";
}

std::filesystem::path NodeConfig::resolved_datadir() const {
    std::filesystem::path base = datadir;
    if (base.empty()) {
        base = core::fs::get_default_data_dir();
    }
    // Append network-specific subdirectory for non-mainnet.
    if (regtest) {
        base /= "regtest";
    } else if (testnet) {
        base /= "testnet";
    }
    return base;
}

std::filesystem::path NodeConfig::log_file_path() const {
    return resolved_datadir() / log_file;
}

std::filesystem::path NodeConfig::wallet_file_path() const {
    return resolved_datadir() / "wallet" / wallet_file;
}

// ---------------------------------------------------------------------------
// Internal: string helpers
// ---------------------------------------------------------------------------

namespace {

/// Case-insensitive equality.
bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

/// Parse a string to a LogLevel enum value. Returns INFO on unrecognised input.
core::LogLevel parse_log_level(std::string_view sv) {
    if (iequals(sv, "trace"))  return core::LogLevel::TRACE;
    if (iequals(sv, "debug"))  return core::LogLevel::DEBUG;
    if (iequals(sv, "info"))   return core::LogLevel::INFO;
    if (iequals(sv, "warn") || iequals(sv, "warning"))
                               return core::LogLevel::WARN;
    if (iequals(sv, "error") || iequals(sv, "err"))
                               return core::LogLevel::ERR;
    if (iequals(sv, "fatal"))  return core::LogLevel::FATAL;
    if (iequals(sv, "off") || iequals(sv, "none"))
                               return core::LogLevel::OFF;
    return core::LogLevel::INFO;
}

/// Parse a boolean string.
bool parse_bool_str(std::string_view sv, bool default_val) {
    if (sv.empty()) return default_val;
    if (iequals(sv, "1") || iequals(sv, "true") ||
        iequals(sv, "yes") || iequals(sv, "on")) {
        return true;
    }
    if (iequals(sv, "0") || iequals(sv, "false") ||
        iequals(sv, "no") || iequals(sv, "off")) {
        return false;
    }
    return default_val;
}

/// Parse an integer from a core::Config, with a fallback.
int parse_int(const core::Config& cfg, std::string_view key, int default_val) {
    return static_cast<int>(cfg.get_int(key, default_val));
}

/// Apply a single key/value pair from core::Config to NodeConfig.
void apply_key(const core::Config& cfg, const std::string& key,
               NodeConfig& nc) {
    auto val = cfg.get(key);
    if (!val.has_value()) return;
    const std::string& v = *val;

    if (key == "datadir") {
        nc.datadir = v;
    } else if (key == "listen") {
        nc.listen = parse_bool_str(v, nc.listen);
    } else if (key == "port") {
        nc.p2p_port = static_cast<uint16_t>(cfg.get_int(key, nc.p2p_port));
    } else if (key == "rpcport") {
        nc.rpc_port = static_cast<uint16_t>(cfg.get_int(key, nc.rpc_port));
    } else if (key == "rpcuser") {
        nc.rpc_user = v;
    } else if (key == "rpcpassword") {
        nc.rpc_password = v;
    } else if (key == "rpcbind") {
        nc.rpc_bind = v;
    } else if (key == "norpc") {
        nc.rpc_enabled = false;
    } else if (key == "nowallet") {
        nc.wallet_enabled = false;
    } else if (key == "walletfile") {
        nc.wallet_file = v;
    } else if (key == "mine") {
        nc.mine = parse_bool_str(v, true);
    } else if (key == "minethreads") {
        nc.mine_threads = parse_int(cfg, key, nc.mine_threads);
    } else if (key == "mineaddress") {
        nc.mine_address = v;
    } else if (key == "testnet") {
        nc.testnet = parse_bool_str(v, true);
    } else if (key == "regtest") {
        nc.regtest = parse_bool_str(v, true);
    } else if (key == "loglevel") {
        nc.log_level = parse_log_level(v);
    } else if (key == "logfile") {
        nc.log_file = v;
    } else if (key == "maxoutbound") {
        nc.max_outbound = parse_int(cfg, key, nc.max_outbound);
    } else if (key == "maxinbound") {
        nc.max_inbound = parse_int(cfg, key, nc.max_inbound);
    } else if (key == "dnsseed") {
        nc.dns_seed = parse_bool_str(v, nc.dns_seed);
    }
}

/// List of all known config keys to iterate during application.
static constexpr const char* ALL_KEYS[] = {
    "datadir",     "listen",       "port",         "rpcport",
    "rpcuser",     "rpcpassword",  "rpcbind",      "norpc",
    "nowallet",    "walletfile",   "mine",         "minethreads",
    "mineaddress", "testnet",      "regtest",      "loglevel",
    "logfile",     "maxoutbound",  "maxinbound",   "dnsseed",
};

/// Apply all known keys from a core::Config to a NodeConfig.
void apply_config(const core::Config& cfg, NodeConfig& nc) {
    for (const char* key : ALL_KEYS) {
        apply_key(cfg, key, nc);
    }

    // Multi-value keys: -connect=<addr> and -addnode=<addr>
    auto connect_list = cfg.get_list("connect");
    if (!connect_list.empty()) {
        nc.connect_nodes = std::move(connect_list);
    }
    auto addnode_list = cfg.get_list("addnode");
    if (!addnode_list.empty()) {
        nc.add_nodes = std::move(addnode_list);
    }
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// parse_args
// ---------------------------------------------------------------------------

NodeConfig parse_args(int argc, char** argv) {
    NodeConfig config;

    // Use core::Config for robust argument parsing.
    core::Config raw;
    raw.parse_args(argc, argv);

    // Handle early-exit flags (help, version).
    if (raw.has("help") || raw.has("h") || raw.has("?")) {
        print_usage();
        std::exit(0);
    }
    if (raw.has("version")) {
        print_version();
        std::exit(0);
    }

    // Resolve the data directory first so we can locate the config file.
    if (auto dd = raw.get("datadir"); dd.has_value() && !dd->empty()) {
        config.datadir = std::filesystem::path{*dd};
    } else {
        config.datadir = core::fs::get_default_data_dir();
    }

    // Determine the config file path: -conf=<path> overrides the default
    // location of <datadir>/ftc.conf.
    std::filesystem::path conf_path;
    if (auto cf = raw.get("conf"); cf.has_value() && !cf->empty()) {
        conf_path = std::filesystem::path{*cf};
    } else {
        conf_path = config.datadir / "ftc.conf";
    }

    if (core::fs::file_exists(conf_path)) {
        core::Config file_cfg;
        file_cfg.parse_file(conf_path);
        // Apply file values first (lower priority).
        apply_config(file_cfg, config);
    }

    // Apply CLI values on top (higher priority).
    apply_config(raw, config);

    // Validate: testnet and regtest are mutually exclusive.
    if (config.testnet && config.regtest) {
        std::cerr << "Error: --testnet and --regtest are mutually exclusive.\n";
        std::exit(1);
    }

    // If mining is enabled but no threads specified, auto-detect.
    if (config.mine && config.mine_threads <= 0) {
        config.mine_threads = core::get_num_cores();
        if (config.mine_threads <= 0) {
            config.mine_threads = 1;
        }
    }

    // Resolve the datadir to an absolute path.
    config.datadir = core::fs::absolute(config.datadir);

    return config;
}

// ---------------------------------------------------------------------------
// load_config_file
// ---------------------------------------------------------------------------

void load_config_file(const std::filesystem::path& path, NodeConfig& config) {
    if (!core::fs::file_exists(path)) {
        LOG_WARN(core::LogCategory::NONE,
                 "Config file not found: " + path.string());
        return;
    }

    core::Config raw;
    raw.parse_file(path);
    apply_config(raw, config);

    LOG_INFO(core::LogCategory::NONE,
             "Loaded configuration from " + path.string());
}

// ---------------------------------------------------------------------------
// print_usage
// ---------------------------------------------------------------------------

void print_usage() {
    std::cout
        << "FTC Core v" << get_version_string() << "\n"
        << "\n"
        << "Usage:\n"
        << "  ftcd [options]\n"
        << "\n"
        << "Options:\n"
        << "  -h, -help, -?             Show this help message and exit\n"
        << "  -version                  Show version information and exit\n"
        << "\n"
        << "Data directory:\n"
        << "  -datadir=<dir>            Data directory path (default: platform-specific)\n"
        << "\n"
        << "Network:\n"
        << "  -testnet                  Use the test network\n"
        << "  -regtest                  Use the regression test network\n"
        << "  -listen=<0|1>             Accept incoming P2P connections (default: 1)\n"
        << "  -port=<port>              P2P listen port (default: 9333)\n"
        << "  -maxoutbound=<n>          Maximum outbound connections (default: 8)\n"
        << "  -maxinbound=<n>           Maximum inbound connections (default: 117)\n"
        << "  -connect=<addr>           Connect only to the specified peer\n"
        << "  -addnode=<addr>           Add a peer to connect to\n"
        << "  -dnsseed=<0|1>            Enable DNS seed lookup (default: 1)\n"
        << "\n"
        << "RPC server:\n"
        << "  -rpcport=<port>           JSON-RPC port (default: 9332)\n"
        << "  -rpcuser=<user>           RPC authentication username\n"
        << "  -rpcpassword=<pass>       RPC authentication password\n"
        << "  -rpcbind=<addr>           RPC bind address (default: 127.0.0.1)\n"
        << "  -norpc                    Disable the JSON-RPC server\n"
        << "\n"
        << "Wallet:\n"
        << "  -nowallet                 Disable the wallet subsystem\n"
        << "  -walletfile=<file>        Wallet filename (default: wallet.dat)\n"
        << "\n"
        << "Mining:\n"
        << "  -mine                     Enable CPU mining\n"
        << "  -minethreads=<n>          Number of mining threads (0 = auto)\n"
        << "  -mineaddress=<addr>       Address to receive mining rewards\n"
        << "\n"
        << "Logging:\n"
        << "  -loglevel=<level>         Log level: trace, debug, info, warn, error, fatal, off\n"
        << "  -logfile=<file>           Log filename (default: debug.log)\n"
        << "\n";
}

// ---------------------------------------------------------------------------
// print_version
// ---------------------------------------------------------------------------

void print_version() {
    std::cout
        << get_client_name() << "\n"
        << "Copyright (c) 2024-2026 The FTC Developers\n"
        << "Distributed under the MIT software license.\n"
        << "\n"
        << "Protocol version: 1\n"
        << "Compiler: "
#if defined(__clang__)
        << "Clang " << __clang_major__ << "." << __clang_minor__
#elif defined(_MSC_VER)
        << "MSVC " << _MSC_VER
#elif defined(__GNUC__)
        << "GCC " << __GNUC__ << "." << __GNUC_MINOR__
#else
        << "Unknown"
#endif
        << "\n"
        << "C++ standard: " << __cplusplus << "\n"
        << "Build date: " << __DATE__ << " " << __TIME__ << "\n";
}

} // namespace node
