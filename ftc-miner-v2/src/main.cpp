/**
 * FTC Miner v2.0
 *
 * Kristian Pilatovich 20091227 - First Real P2P
 *
 * GPU-only Keccak-256 miner with:
 * - Beautiful TUI interface
 * - AI Auto-tune optimization
 * - OpenCL GPU support
 */

#include "tui/ui.h"
#include "mining/gpu_miner.h"
#include "mining/gpu_monitor.h"
#include "mining/work.h"
#include "net/api_client.h"
#include "net/node_manager.h"
#include "net/https_client.h"
#include "config/config.h"
#include "autotune/tuner.h"
#include "autotune/adaptive_tuner.h"

#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <csignal>
#include <atomic>

// Global shutdown flag
static std::atomic<bool> g_shutdown{false};

void signalHandler(int signal) {
    g_shutdown = true;
}

void printUsage() {
    std::cout << R"(
FTC Miner v2.0.0 - GPU-only Keccak-256 OpenCL Miner

Usage: ftc-miner -a <address> [options]

Required:
  -a, --address ADDR   Mining wallet address (ftc1q...)

Node Connection:
  -o, --node URL       Node address (default: [::1]:17319 - localhost IPv6)
                       e.g., [::1]:17319 or 192.168.1.100:17319

GPU Mining:
  -I, --intensity N    GPU intensity 8-31 (default: auto)
  -w, --worksize N     GPU worksize (default: 256)
  --autotune           Enable AI auto-tune

Display:
  --no-tui             Disable TUI, use simple output
  -v, --verbose        Verbose output
  -q, --quiet          Quiet mode

Limits:
  --max-temp N         Max GPU temperature (default: 85)

Mode:
  --benchmark          Benchmark mode (no node required)

Other:
  -c, --config FILE    Load config from file
  -h, --help           Show this help

Examples:
  ftc-miner -a ftc1qwfk0r2r9f6352ad9m4nph5mh9xhrf9yukv6pap
  ftc-miner -a ftc1q... -I 22 --autotune
  ftc-miner -o 127.0.0.1:17319 -a ftc1q...
  ftc-miner --benchmark

)" << std::endl;
}

int main(int argc, char** argv) {
    // Parse config
    config::MinerConfig cfg = config::MinerConfig::parse(argc, argv);

    // Install signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    // Validate required arguments (unless benchmark mode)
    if (!cfg.benchmark_mode) {
        if (cfg.wallet_address.empty()) {
            std::cerr << "Error: Mining address required (-a <ftc1q...>)\n\n";
            printUsage();
            return 1;
        }

        // Validate wallet address format
        if (cfg.wallet_address.substr(0, 4) != "ftc1") {
            std::cerr << "Error: Invalid wallet address format (must start with ftc1)\n";
            return 1;
        }

        // Node discovery is now handled by NodeManager
        // Auto-discovery via HTTPS is still supported for backwards compatibility
        if (cfg.pool_url.substr(0, 8) == "https://") {
            std::cout << "Auto-discovering node via " << cfg.pool_url << "...\n";

            std::string api_endpoint = cfg.pool_url;
            if (api_endpoint.back() != '/') {
                api_endpoint += "/api/node";
            } else {
                api_endpoint += "api/node";
            }

            std::string discovered = net::HttpsClient::discoverNode(api_endpoint);
            if (!discovered.empty()) {
                cfg.pool_url = discovered;
                std::cout << "Discovered node: " << cfg.pool_url << "\n";
            }
        }
    } else {
        // Benchmark mode defaults
        cfg.pool_url = "[::1]:17319";
        if (cfg.wallet_address.empty()) {
            cfg.wallet_address = "ftc1qbenchmark000000000000000000000000000";
        }
        std::cout << "\n[Benchmark Mode] Running without real node connection\n\n";
    }

    // Initialize NodeManager
    net::NodeManager node_manager;

    // Parse node address (default: localhost IPv6)
    std::string host = "::1";
    uint16_t port = 17319;

    if (!cfg.pool_url.empty() && cfg.pool_url != "http://localhost:17319") {
        std::string url = cfg.pool_url;
        if (url.find("://") != std::string::npos) {
            url = url.substr(url.find("://") + 3);
        }

        // Parse IPv6 or IPv4 address
        if (!url.empty() && url[0] == '[') {
            size_t bracket_end = url.find(']');
            if (bracket_end != std::string::npos) {
                host = url.substr(1, bracket_end - 1);
                if (bracket_end + 1 < url.size() && url[bracket_end + 1] == ':') {
                    port = static_cast<uint16_t>(std::stoi(url.substr(bracket_end + 2)));
                }
            }
        } else if (!url.empty()) {
            size_t colon = url.rfind(':');
            if (colon != std::string::npos) {
                host = url.substr(0, colon);
                port = static_cast<uint16_t>(std::stoi(url.substr(colon + 1)));
            } else {
                host = url;
            }
        }
    }

    node_manager.addNode(host, port);
    std::cout << "Node:   [" << host << "]:" << port << "\n";
    std::cout << "Wallet: " << cfg.wallet_address << "\n\n";

    // Initialize TUI
    tui::MinerUI ui;
    if (cfg.tui_enabled) {
        if (!ui.init()) {
            std::cerr << "Failed to initialize TUI, falling back to simple mode\n";
            cfg.tui_enabled = false;
        } else {
            // Disable debug output when TUI is active (prevents screen corruption)
            node_manager.setDebugOutput(false);
        }
    }

    // Initialize GPU miner
    mining::GPUMiner gpu_miner;
    mining::WorkManager work_manager;
    mining::GPUMonitorManager gpu_monitor;
    autotune::AdaptiveTuner adaptive_tuner;

    // Initialize GPU monitoring
    gpu_monitor.init();

    // Detect GPUs
    if (!gpu_miner.detectDevices()) {
        std::string err = "No OpenCL GPU devices found!";
        if (cfg.tui_enabled) {
            ui.addLogMessage(err, tui::Color::Red);
            ui.render();
            std::this_thread::sleep_for(std::chrono::seconds(3));
            ui.cleanup();
        } else {
            std::cerr << "Error: " << err << "\n";
        }
        return 1;
    }

    // Setup NodeManager callbacks for TUI logging
    node_manager.setLogCallback([&ui, &cfg](const std::string& msg, bool is_error) {
        if (cfg.tui_enabled) {
            ui.addLogMessage("[Node] " + msg, is_error ? tui::Color::Red : tui::Color::Cyan);
        } else if (!cfg.benchmark_mode) {
            std::cout << "[Node] " << msg << "\n";
        }
    });

    node_manager.setOnNodeChanged([&ui, &cfg](const std::string& host, uint16_t port) {
        if (cfg.tui_enabled) {
            ui.addLogMessage("Switched to node: " + host + ":" + std::to_string(port), tui::Color::Yellow);
        } else {
            std::cout << "[Node] Switched to: " << host << ":" << port << "\n";
        }
    });

    // Initialize stats (before callback setup)
    tui::MiningStats stats;
    stats.start_time = std::chrono::steady_clock::now();

    // Configure miner
    gpu_miner.setWorkManager(&work_manager);

    gpu_miner.setSolutionCallback([&](const mining::Solution& sol) {
        // Check if this meets block target (actual block) or just share target
        bool is_block = mining::Keccak256::meetsTarget(sol.hash, sol.work.target);

        if (is_block) {
            // Actual block found!
            if (cfg.tui_enabled) {
                ui.addLogMessage("*** BLOCK FOUND! *** Height: " + std::to_string(sol.height) +
                               " Nonce: " + std::to_string(sol.nonce), tui::Color::Yellow);
            } else {
                std::cout << "\n*** BLOCK FOUND! ***\n";
                std::cout << "Height: " << sol.height << "\n";
                std::cout << "Nonce: " << sol.nonce << "\n";
                std::cout << "Hash: " << mining::Keccak256::toHex(sol.hash) << "\n\n";
            }
        }
        // Shares are logged by submission thread ("Share accepted")
    });

    // GPU device list
    auto& gpus = gpu_miner.getDevices();

    // Add initial log messages
    if (cfg.tui_enabled) {
        ui.addLogMessage("FTC Miner v2.0.0 (GPU-only) starting...", tui::Color::Cyan);
        ui.addLogMessage("Pool: " + cfg.pool_url, tui::Color::White);
        ui.addLogMessage("Address: " + cfg.wallet_address, tui::Color::White);
        ui.addLogMessage("Found " + std::to_string(gpus.size()) + " GPU(s):", tui::Color::Green);
        for (const auto& gpu : gpus) {
            ui.addLogMessage("  [" + std::to_string(gpu.id) + "] " + gpu.name +
                           " (" + std::to_string(gpu.compute_units) + " CUs, " +
                           std::to_string(gpu.global_mem / (1024*1024)) + " MB)", tui::Color::White);
        }
    } else {
        std::cout << "============================================\n";
        std::cout << "       FTC Miner v2.0.0 (GPU-only)\n";
        std::cout << "       Keccak-256 OpenCL Miner\n";
        std::cout << "============================================\n\n";
        std::cout << "Address:  " << cfg.wallet_address << "\n";
        std::cout << "GPUs:     " << gpus.size() << " device(s)\n";
        for (const auto& gpu : gpus) {
            std::cout << "  [" << gpu.id << "] " << gpu.name << " (" << gpu.compute_units << " CUs)\n";
        }
        std::cout << "\n";
    }

    // Set intensity if specified
    if (cfg.intensity > 0) {
        for (auto& gpu : gpus) {
            gpu_miner.setIntensity(gpu.id, cfg.intensity);
        }
    }

    // Connect to best available node
    if (cfg.tui_enabled) {
        ui.addLogMessage("Connecting to nodes...", tui::Color::Cyan);
    }

    if (!cfg.benchmark_mode) {
        node_manager.refreshNodes();

        auto* api_client = node_manager.getClient();
        if (!api_client) {
            std::string err = "Failed to connect to any node!";
            if (cfg.tui_enabled) {
                ui.addLogMessage(err, tui::Color::Red);
                ui.render();
                std::this_thread::sleep_for(std::chrono::seconds(3));
                ui.cleanup();
            } else {
                std::cerr << "Error: " << err << "\n";
            }
            return 1;
        }

        stats.connected = true;
        stats.block_height = static_cast<int32_t>(api_client->getBlockHeight());

        // Calculate human-readable difficulty from bits
        uint32_t bits = api_client->getDifficulty();
        if (bits > 0) {
            uint32_t exponent = (bits >> 24) & 0xFF;
            uint32_t mantissa = bits & 0x00FFFFFF;
            if (mantissa > 0) {
                stats.difficulty = static_cast<double>(0x00FFFF) / static_cast<double>(mantissa);
                int exp_diff = 0x1d - static_cast<int>(exponent);
                for (int i = 0; i < exp_diff; i++) stats.difficulty *= 256.0;
                for (int i = 0; i > exp_diff; i--) stats.difficulty /= 256.0;
            }
        }

        // Get initial network stats
        auto initial_net_stats = api_client->getNetworkStats();
        stats.node_count = initial_net_stats.node_count;
        stats.active_miners = initial_net_stats.active_miners;

        // Get initial P2Pool stats
        stats.p2pool_enabled = initial_net_stats.p2pool_enabled;
        stats.p2pool_running = initial_net_stats.p2pool_running;
        stats.sharechain_height = initial_net_stats.sharechain_height;
        stats.pool_total_shares = initial_net_stats.total_shares;
        stats.pool_total_blocks = initial_net_stats.total_blocks;
        stats.shares_per_minute = initial_net_stats.shares_per_minute;
        stats.p2pool_peers = initial_net_stats.p2pool_peers;

        if (cfg.tui_enabled) {
            std::string p2pool_status = initial_net_stats.p2pool_running ? "P2Pool Active" : "P2Pool Inactive";
            ui.addLogMessage("Connected! Height: " + std::to_string(stats.block_height) +
                            " | Nodes: " + std::to_string(stats.node_count) +
                            " | " + p2pool_status, tui::Color::Green);
        }
    } else {
        stats.connected = true;
    }

    // Get initial work
    net::APIClient* api_client = node_manager.getClient();
    auto work_opt = cfg.benchmark_mode ? std::nullopt :
                    (api_client ? api_client->getMiningTemplate(cfg.wallet_address) : std::nullopt);
    if (work_opt) {
        work_manager.setWork(*work_opt);
        if (cfg.tui_enabled) {
            ui.addLogMessage("Received work for height " + std::to_string(work_opt->height), tui::Color::Green);
            std::string target_hex;
            for (int i = 0; i < 8; i++) {
                char buf[3];
                snprintf(buf, 3, "%02x", work_opt->target[i]);
                target_hex += buf;
            }
            ui.addLogMessage("Target: " + target_hex + "...", tui::Color::Yellow);
        }
    } else if (!cfg.benchmark_mode) {
        if (cfg.tui_enabled) {
            ui.addLogMessage("ERROR: Failed to get work!", tui::Color::Red);
        }
    }

    // Auto-tune setup
    if (cfg.autotune_enabled) {
        if (cfg.tui_enabled) {
            ui.addLogMessage("Enabling AI Auto-tune (real-time adaptive)...", tui::Color::Yellow);
            stats.autotune_active = true;
        }

        // Initial intensity based on memory
        for (auto& gpu : gpus) {
            int intensity = 20;
            if (gpu.global_mem >= 12ULL * 1024 * 1024 * 1024) {
                intensity = 26;
            } else if (gpu.global_mem >= 8ULL * 1024 * 1024 * 1024) {
                intensity = 25;
            } else if (gpu.global_mem >= 4ULL * 1024 * 1024 * 1024) {
                intensity = 23;
            } else if (gpu.global_mem >= 2ULL * 1024 * 1024 * 1024) {
                intensity = 21;
            }
            gpu_miner.setIntensity(gpu.id, intensity);

            if (cfg.tui_enabled) {
                ui.addLogMessage("GPU " + std::to_string(gpu.id) + ": initial intensity=" + std::to_string(intensity), tui::Color::White);
            }
        }

        // Configure adaptive tuner
        adaptive_tuner.setGPUMonitor(&gpu_monitor);
        adaptive_tuner.setDeviceCount(static_cast<int>(gpus.size()));

        for (auto& gpu : gpus) {
            adaptive_tuner.setInitialIntensity(gpu.id, gpu.intensity > 0 ? gpu.intensity : 20);
            adaptive_tuner.setMaxTemperature(gpu.id, cfg.max_temp);
            adaptive_tuner.setTargetUtilization(gpu.id, 90, 98);
        }

        adaptive_tuner.setIntensityCallback([&gpu_miner](int device_id, int new_intensity) {
            gpu_miner.setIntensity(device_id, new_intensity);
        });

        adaptive_tuner.setStatusCallback([&ui, &cfg](int device_id, const std::string& status) {
            if (cfg.tui_enabled) {
                ui.addLogMessage("[AutoTune] " + status, tui::Color::Yellow);
            }
        });

        if (cfg.tui_enabled) {
            ui.addLogMessage("Auto-tune enabled: will adapt to reach 90-98% GPU utilization", tui::Color::Green);
        }
    }

    // Start mining
    if (cfg.tui_enabled) {
        ui.addLogMessage("Starting GPU mining on " + std::to_string(gpus.size()) + " device(s)...", tui::Color::Cyan);
    } else {
        std::cout << "Starting GPU mining...\n\n";
    }

    gpu_miner.start();

    // Start adaptive tuner if enabled
    if (cfg.autotune_enabled) {
        adaptive_tuner.start();
        if (cfg.tui_enabled) {
            ui.addLogMessage("Adaptive auto-tune started (monitoring every 500ms)", tui::Color::Green);
        }
    }

    // Device stats for TUI
    std::vector<tui::DeviceStats> devices;
    for (const auto& gpu : gpus) {
        tui::DeviceStats ds;
        ds.id = gpu.id;
        ds.name = gpu.name;
        ds.type = "GPU";
        ds.enabled = gpu.enabled;
        ds.threads = static_cast<int>(gpu.compute_units);
        devices.push_back(ds);
    }

    // Hashrate averager for proper 1m/5m/15m moving averages
    tui::HashrateAverager hashrate_averager;
    auto last_hashrate_sample = std::chrono::steady_clock::now();

    // Network thread for async operations
    std::atomic<bool> network_running{true};
    std::mutex network_mutex;
    std::atomic<int> network_height{stats.block_height};
    std::atomic<int> network_nodes{static_cast<int>(stats.node_count)};
    std::atomic<int> network_miners{static_cast<int>(stats.active_miners)};

    // P2Pool stats (shared with network thread) - initialize from initial stats
    std::atomic<bool> network_p2pool_running{stats.p2pool_running};
    std::atomic<uint64_t> network_sharechain_height{stats.sharechain_height};
    std::atomic<uint64_t> network_pool_shares{stats.pool_total_shares};
    std::atomic<uint64_t> network_pool_blocks{stats.pool_total_blocks};
    std::atomic<double> network_shares_per_minute{stats.shares_per_minute};
    std::atomic<uint32_t> network_p2pool_peers{stats.p2pool_peers};

    std::thread network_thread([&]() {
        auto last_network_stats = std::chrono::steady_clock::now();
        auto last_node_health = std::chrono::steady_clock::now();
        auto last_work_check = std::chrono::steady_clock::now();
        constexpr int NETWORK_STATS_MS = 5000;
        constexpr int NODE_HEALTH_MS = 10000;  // Check node health every 10s
        constexpr int WORK_CHECK_MS = 500;     // Check for new blocks every 500ms
        int consecutive_failures = 0;

        while (network_running && !g_shutdown) {
            auto now = std::chrono::steady_clock::now();

            // EVENT-DRIVEN: Wait for solutions instead of fixed polling
            // This is ADAPTIVE - wakes up IMMEDIATELY when GPU finds a solution
            // Timeout only triggers periodic maintenance tasks
            bool has_solutions = work_manager.waitForSolutions(std::chrono::milliseconds(100));

            if (cfg.benchmark_mode) {
                continue;
            }

            // Process ONE solution at a time - check staleness JUST before submitting
            if (has_solutions) {
                auto* client = node_manager.getClient();
                if (!client) {
                    consecutive_failures++;
                    if (consecutive_failures >= 3) {
                        node_manager.refreshNodes();
                        consecutive_failures = 0;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                    continue;
                }

                // Get ONE solution at a time
                auto sol_opt = work_manager.getOneSolution();
                if (!sol_opt) continue;
                auto& sol = *sol_opt;

                // Check staleness NOW (not when it was queued)
                mining::Work current_work = work_manager.getWork();
                bool is_stale = (sol.height != current_work.height);

                // Get total solutions found by all GPUs (for accurate hashrate reporting)
                uint64_t total_solutions = 0;
                for (const auto& gpu : gpus) {
                    total_solutions += gpu.accepted;
                }

                // Submit ALL shares to node (even stale) for accurate hashrate tracking
                auto result = client->submitBlock(sol, sol.work, total_solutions);
                if (result.accepted) {
                    stats.shares_accepted++;
                    node_manager.recordSuccess(0);

                    if (result.is_block) {
                        stats.blocks_found++;
                        if (cfg.tui_enabled) {
                            ui.addLogMessage("BLOCK FOUND! h=" + std::to_string(sol.height), tui::Color::Green);
                        }

                        // Fetch new work immediately
                        auto fresh_work = client->getMiningTemplate(cfg.wallet_address);
                        if (fresh_work) {
                            work_manager.setWork(*fresh_work);
                            network_height = fresh_work->height;
                            if (cfg.tui_enabled) {
                                ui.addLogMessage("New work: h=" + std::to_string(fresh_work->height), tui::Color::Cyan);
                            }
                            // DON'T clear pending solutions - let them be submitted as stale
                            // The node will count them for hashrate calculation
                        }
                    } else {
                        if (cfg.tui_enabled) {
                            ui.addLogMessage("Share accepted h=" + std::to_string(sol.height), tui::Color::Green);
                        }
                    }
                } else {
                    // Not accepted - check if stale or rejected
                    if (is_stale) {
                        stats.shares_stale++;
                        // Don't log stale - too spammy
                    } else {
                        stats.shares_rejected++;
                        node_manager.recordFailure();
                        if (cfg.tui_enabled) {
                            ui.addLogMessage("Share REJECTED h=" + std::to_string(sol.height), tui::Color::Red);
                        }
                    }
                }
            }

            // Update network stats periodically
            auto network_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last_network_stats).count();
            if (network_elapsed >= NETWORK_STATS_MS && !cfg.benchmark_mode) {
                last_network_stats = now;
                auto* client = node_manager.getClient();
                if (client) {
                    auto net_stats = client->getNetworkStats();
                    network_nodes = net_stats.node_count;
                    network_miners = net_stats.active_miners;
                    if (net_stats.height > 0) {
                        network_height = net_stats.height;
                    }

                    // Update network hashrate
                    stats.network_hashrate = net_stats.network_hashrate;

                    // Update P2Pool stats
                    network_p2pool_running = net_stats.p2pool_running;
                    network_sharechain_height = net_stats.sharechain_height;
                    network_pool_shares = net_stats.total_shares;
                    network_pool_blocks = net_stats.total_blocks;
                    network_shares_per_minute = net_stats.shares_per_minute;
                    network_p2pool_peers = net_stats.p2pool_peers;

                    // Update difficulty periodically
                    uint32_t new_bits = client->getDifficulty();
                    if (new_bits > 0) {
                        uint32_t exponent = (new_bits >> 24) & 0xFF;
                        uint32_t mantissa = new_bits & 0x00FFFFFF;
                        if (mantissa > 0) {
                            double diff = static_cast<double>(0x00FFFF) / static_cast<double>(mantissa);
                            int exp_diff = 0x1d - static_cast<int>(exponent);
                            for (int i = 0; i < exp_diff; i++) diff *= 256.0;
                            for (int i = 0; i > exp_diff; i--) diff /= 256.0;
                            stats.difficulty = diff;
                        }
                    }
                }
            }

            // Periodic work check - detect blocks from other miners
            now = std::chrono::steady_clock::now();
            auto work_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last_work_check).count();
            if (work_elapsed >= WORK_CHECK_MS) {
                last_work_check = now;
                auto* client = node_manager.getClient();
                if (client) {
                    mining::Work current_work = work_manager.getWork();
                    auto new_work = client->getMiningTemplate(cfg.wallet_address);
                    if (new_work && new_work->height != current_work.height) {
                        work_manager.setWork(*new_work);
                        network_height = new_work->height;
                        // DON'T clear pending solutions - let them be submitted as stale
                        // The node will count them for hashrate calculation

                        if (cfg.tui_enabled) {
                            ui.addLogMessage("New block h=" + std::to_string(new_work->height), tui::Color::Cyan);
                        }
                    }
                }
            }

            // Periodic node health check - refresh all nodes
            auto health_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last_node_health).count();
            if (health_elapsed >= NODE_HEALTH_MS) {
                last_node_health = now;
                // Check if there's a better node available
                size_t available_before = node_manager.getAvailableCount();
                node_manager.refreshNodes();
                size_t available_after = node_manager.getAvailableCount();

                if (available_after > available_before && cfg.tui_enabled) {
                    ui.addLogMessage("Node health: " + std::to_string(available_after) + "/" +
                                    std::to_string(node_manager.getNodeCount()) + " available", tui::Color::Cyan);
                }
            }

            // No fixed sleep - waitForSolutions() handles timing adaptively
        }
    });

    // Timing for main loop (TUI only)
    auto last_stats_print = std::chrono::steady_clock::now();
    auto last_gpu_metrics = std::chrono::steady_clock::now();
    constexpr int GPU_METRICS_MS = 1000;

    // Main loop - TUI only, no network blocking
    while (!g_shutdown) {
        auto now = std::chrono::steady_clock::now();

        // Update stats from GPUs (non-blocking)
        stats.total_hashrate = gpu_miner.getTotalHashrate();
        stats.block_height = network_height;
        stats.node_count = network_nodes;
        stats.active_miners = network_miners;

        // Update P2Pool stats from network thread
        stats.p2pool_running = network_p2pool_running;
        stats.sharechain_height = network_sharechain_height;
        stats.pool_total_shares = network_pool_shares;
        stats.pool_total_blocks = network_pool_blocks;
        stats.shares_per_minute = network_shares_per_minute;
        stats.p2pool_peers = network_p2pool_peers;

        // Sample hashrate every second for proper moving averages
        auto sample_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_hashrate_sample).count();
        if (sample_elapsed >= 1000) {
            last_hashrate_sample = now;
            hashrate_averager.addSample(stats.total_hashrate);
        }

        // Use proper moving averages
        stats.avg_hashrate_1m = hashrate_averager.getAverage1m();
        stats.avg_hashrate_5m = hashrate_averager.getAverage5m();
        stats.avg_hashrate_15m = hashrate_averager.getAverage15m();
        stats.peak_hashrate = hashrate_averager.getPeak();

        // Update device stats - hashrate is fast
        for (size_t i = 0; i < devices.size() && i < gpus.size(); ++i) {
            devices[i].hashrate = gpus[i].hashrate;
            devices[i].accepted = gpus[i].accepted;
            devices[i].rejected = gpus[i].rejected;

            if (cfg.autotune_enabled) {
                devices[i].intensity = adaptive_tuner.getCurrentIntensity(static_cast<int>(i));
            }
        }

        // Update GPU metrics (temp/power) only once per second
        auto gpu_metrics_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_gpu_metrics).count();
        if (gpu_metrics_elapsed >= GPU_METRICS_MS) {
            last_gpu_metrics = now;
            int nvidia_idx = 0;
            for (size_t i = 0; i < devices.size() && i < gpus.size(); ++i) {
                mining::GPUMetrics metrics;
                if (gpus[i].vendor.find("NVIDIA") != std::string::npos) {
                    metrics = gpu_monitor.getMetricsByVendor("NVIDIA", nvidia_idx);
                    nvidia_idx++;
                } else if (gpus[i].vendor.find("AMD") != std::string::npos ||
                           gpus[i].vendor.find("Advanced Micro") != std::string::npos) {
                    metrics = gpu_monitor.getMetricsByVendor("AMD", 0);
                } else {
                    metrics = gpu_monitor.getMetricsByVendor("Intel", 0);
                }

                if (metrics.temperature > 0) {
                    devices[i].temperature = metrics.temperature;
                }
                if (metrics.fan_speed > 0) {
                    devices[i].fan_percent = metrics.fan_speed;
                }
                if (metrics.power_usage > 0) {
                    devices[i].power = metrics.power_usage;
                }
            }
        }

        // Render TUI (non-blocking)
        if (cfg.tui_enabled) {
            ui.setStats(stats);
            ui.setDevices(devices);
            ui.render();

            if (!ui.handleInput()) {
                g_shutdown = true;
            }
        } else {
            auto stats_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - last_stats_print).count();

            if (stats_elapsed >= 10) {
                last_stats_print = now;
                std::cout << "[Stats] Hashrate: " << tui::formatHashrate(stats.total_hashrate)
                          << " | Net: " << tui::formatHashrate(stats.network_hashrate)
                          << " | Blocks: " << stats.blocks_found
                          << " | Height: " << stats.block_height
                          << " | Nodes: " << stats.node_count << "\n";
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Stop network thread
    network_running = false;
    if (network_thread.joinable()) {
        network_thread.join();
    }

    // Cleanup
    if (cfg.tui_enabled) {
        ui.addLogMessage("Shutting down...", tui::Color::Yellow);
        ui.render();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    if (cfg.autotune_enabled) {
        adaptive_tuner.stop();
    }

    gpu_miner.stop();
    gpu_monitor.shutdown();

    if (cfg.tui_enabled) {
        ui.cleanup();
    }

    std::cout << "\nMiner stopped. Total hashes: " << gpu_miner.getTotalHashes()
              << ", Blocks found: " << stats.blocks_found << "\n";

    return 0;
}
