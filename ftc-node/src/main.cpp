/**
 * FTC Node - Flow Token Chain
 *
 * Real P2P cryptocurrency - IPv6 only network.
 * Peer discovery via peers.dat + P2P addr exchange.
 *
 * Author: Kristian Pilatovich
 * Genesis: "Kristian Pilatovich 20091227 - First Real P2P"
 */

#include "node.h"
#include "util/config.h"
#include "util/logging.h"
#include "ftc/version.h"

#ifndef _WIN32
#include <signal.h>
#endif

int main(int argc, char** argv) {
#ifndef _WIN32
    // Ignore SIGPIPE - prevents crash when sending to closed socket
    signal(SIGPIPE, SIG_IGN);
#endif

    // Parse command line
    ftc::util::Config config = ftc::util::Config::parse(argc, argv);

    // Initialize logging
    ftc::log::init(config.log_level, config.log_file);

    // Startup banner
    LOG_NOTICE("FTC Node 1.0.0 starting...");
    LOG_NOTICE("Genesis: \"Kristian Pilatovich 20091227 - First Real P2P\"");

    // Create and start node
    ftc::Node node(config);

    if (!node.start()) {
        ftc::log::err("Failed to start node");
        return 1;
    }

    LOG_NOTICE("Node started - P2P port: {}, API port: {}", config.p2p_port, config.api_port);

    // Wait for shutdown signal (SIGINT/SIGTERM)
    node.waitForShutdown();

    return 0;
}
