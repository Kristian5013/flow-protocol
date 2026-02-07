// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// ftcd -- FTC full node daemon.

#include "node/node.h"
#include "node/context.h"

#include <cstdlib>
#include <iostream>

int main(int argc, char* argv[]) {
    // Parse command-line arguments.
    node::NodeConfig config = node::parse_args(argc, argv);

    // Construct the node (no subsystems yet).
    node::Node ftc_node(config);

    // Initialize all subsystems.
    auto init_result = ftc_node.init();
    if (!init_result.ok()) {
        std::cerr << "Error: " << init_result.error().message() << std::endl;
        return EXIT_FAILURE;
    }

    // Run until shutdown signal (Ctrl+C / SIGTERM).
    ftc_node.run();

    // Graceful shutdown.
    ftc_node.shutdown();

    return EXIT_SUCCESS;
}
