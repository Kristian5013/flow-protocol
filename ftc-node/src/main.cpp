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

int main(int argc, char** argv) {
    // Parse command line
    ftc::util::Config config = ftc::util::Config::parse(argc, argv);

    // Initialize logging
    ftc::log::init(config.log_level, config.log_file);

    // Create and start node
    ftc::Node node(config);

    if (!node.start()) {
        ftc::log::err("Failed to start node");
        return 1;
    }

    // Wait for shutdown signal (SIGINT/SIGTERM)
    node.waitForShutdown();

    return 0;
}
