#ifndef FTC_UTIL_CONFIG_H
#define FTC_UTIL_CONFIG_H

#include "ftc/version.h"
#include "util/logging.h"

#include <string>
#include <cstdint>
#include <vector>

namespace ftc {
namespace util {

struct Config {
    // Data directory
    std::string data_dir;

    // Network
    uint16_t p2p_port = FTC_PORT_P2P;
    uint16_t api_port = FTC_PORT_API;
    uint16_t stratum_port = FTC_PORT_STRATUM;
    bool stratum_enabled = true;  // Enable stratum for GPU miners

    // Initial peers (--addnode=IP:PORT)
    std::vector<std::string> addnodes;

    // Logging
    log::Level log_level = log::Level::NOTICE;
    std::string log_file;

    // Network type
    bool testnet = false;

    // Mining (if enabled)
    bool mining_enabled = false;
    std::string mining_address;

    // Chain storage
    uint32_t utxo_cache_mb = 450;        // UTXO cache size in MB
    uint32_t mempool_max_mb = 300;       // Max mempool size in MB
    uint64_t min_relay_fee = 1000;       // Minimum relay fee (satoshis/KB)

    // P2P limits
    int max_inbound = 125;               // Max inbound connections
    int max_outbound = 8;                // Max outbound connections
    int target_outbound = 8;             // Target outbound connections

    // API
    bool api_cors = true;                // Enable CORS for remote miners

    // Maintenance
    bool reindex = false;                // Rebuild UTXO set from blocks

    // Parse command line arguments
    static Config parse(int argc, char** argv);

    // Get default data directory
    static std::string getDefaultDataDir();

    // Print help
    static void printHelp();

    // Print version
    static void printVersion();
};

} // namespace util
} // namespace ftc

#endif // FTC_UTIL_CONFIG_H
