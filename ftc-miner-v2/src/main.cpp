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

Usage: ftc-miner -o <node> -a <address> [options]

Required:
  -o, --pool URL       Node address (e.g., 127.0.0.1:17319 or [::1]:17319)
  -a, --address ADDR   Mining wallet address (ftc1q...)

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
  ftc-miner -o 127.0.0.1:17319 -a ftc1qwfk0r2r9f6352ad9m4nph5mh9xhrf9yukv6pap
  ftc-miner -o [::1]:17319 -a ftc1q... -I 22 --autotune
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

        // Auto-discovery: if pool_url starts with https://, discover a node
        if (cfg.pool_url.substr(0, 8) == "https://") {
            std::cout << "Auto-discovering node via " << cfg.pool_url << "...\n";

            std::string api_endpoint = cfg.pool_url;
            if (api_endpoint.back() != '/') {
                api_endpoint += "/api/node";
            } else {
                api_endpoint += "api/node";
            }

            std::string discovered = net::HttpsClient::discoverNode(api_endpoint);
            if (discovered.empty()) {
                std::cerr << "Error: Failed to discover node. Please specify -o <host:port>\n";
                return 1;
            }

            cfg.pool_url = discovered;
            std::cout << "Discovered node: " << cfg.pool_url << "\n";
        }

        // Validate that we have a node URL now
        if (cfg.pool_url.empty() || cfg.pool_url == "[::1]:17319") {
            std::cerr << "Error: Node address required (-o <host:port>)\n\n";
            printUsage();
            return 1;
        }
    } else {
        // Benchmark mode defaults
        cfg.pool_url = "[::1]:17319";
        if (cfg.wallet_address.empty()) {
            cfg.wallet_address = "ftc1qbenchmark000000000000000000000000000";
        }
        std::cout << "\n[Benchmark Mode] Running without real node connection\n\n";
    }

    std::cout << "Node:   " << cfg.pool_url << "\n";
    std::cout << "Wallet: " << cfg.wallet_address << "\n\n";

    // Initialize TUI
    tui::MinerUI ui;
    if (cfg.tui_enabled) {
        if (!ui.init()) {
            std::cerr << "Failed to initialize TUI, falling back to simple mode\n";
            cfg.tui_enabled = false;
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

    // Parse pool URL (IPv6 format: [addr]:port)
    std::string host = "::1";
    uint16_t port = 17319;

    std::string url = cfg.pool_url;
    if (url.find("://") != std::string::npos) {
        url = url.substr(url.find("://") + 3);
    }

    // IPv6 format: [addr]:port
    if (!url.empty() && url[0] == '[') {
        size_t bracket_end = url.find(']');
        if (bracket_end != std::string::npos) {
            host = url.substr(1, bracket_end - 1);
            if (bracket_end + 1 < url.size() && url[bracket_end + 1] == ':') {
                port = static_cast<uint16_t>(std::stoi(url.substr(bracket_end + 2)));
            }
        }
    } else if (!url.empty()) {
        // IPv4 format: host:port
        size_t colon = url.rfind(':');
        if (colon != std::string::npos) {
            host = url.substr(0, colon);
            port = static_cast<uint16_t>(std::stoi(url.substr(colon + 1)));
        } else {
            host = url;
        }
    }

    // Create API client
    auto api_client = std::make_unique<net::APIClient>(host, port);

    // Initialize stats (before callback setup)
    tui::MiningStats stats;
    stats.pool_url = cfg.pool_url;
    stats.start_time = std::chrono::steady_clock::now();

    // Configure miner
    gpu_miner.setWorkManager(&work_manager);

    gpu_miner.setSolutionCallback([&](const mining::Solution& sol) {
        // Just log - submission is handled by main loop via work_manager
        if (cfg.tui_enabled) {
            ui.addLogMessage("*** BLOCK FOUND! *** Height: " + std::to_string(sol.height) +
                           " Nonce: " + std::to_string(sol.nonce), tui::Color::Yellow);
        } else {
            std::cout << "\n*** BLOCK FOUND! ***\n";
            std::cout << "Height: " << sol.height << "\n";
            std::cout << "Nonce: " << sol.nonce << "\n";
            std::cout << "Hash: " << mining::Keccak256::toHex(sol.hash) << "\n\n";
        }
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
        std::cout << "Pool:     " << cfg.pool_url << "\n";
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

    // Connect to node
    if (cfg.tui_enabled) {
        ui.addLogMessage("Connecting to node...", tui::Color::Cyan);
    }

    if (!cfg.benchmark_mode && !api_client->connect()) {
        std::string err = "Failed to connect: " + api_client->getLastError();
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

    if (!cfg.benchmark_mode) {
        stats.block_height = static_cast<int32_t>(api_client->getBlockHeight());
        stats.difficulty = api_client->getDifficulty();

        // Get initial network stats
        auto initial_net_stats = api_client->getNetworkStats();
        stats.peer_count = initial_net_stats.peer_count;
        stats.active_miners = initial_net_stats.active_miners;

        if (cfg.tui_enabled) {
            ui.addLogMessage("Connected! Height: " + std::to_string(stats.block_height) +
                            " | Peers: " + std::to_string(stats.peer_count) +
                            " | Miners: " + std::to_string(stats.active_miners), tui::Color::Green);
        }
    }

    // Get initial work
    auto work_opt = cfg.benchmark_mode ? std::nullopt : api_client->getMiningTemplate(cfg.wallet_address);
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

    // Network thread for async operations
    std::atomic<bool> network_running{true};
    std::mutex network_mutex;
    std::atomic<int> network_height{0};
    std::atomic<int> network_peers{0};
    std::atomic<int> network_miners{0};

    std::thread network_thread([&]() {
        auto last_work_poll = std::chrono::steady_clock::now();
        auto last_network_stats = std::chrono::steady_clock::now();
        constexpr int WORK_POLL_MS = 500;
        constexpr int NETWORK_STATS_MS = 5000;

        while (network_running && !g_shutdown) {
            auto now = std::chrono::steady_clock::now();

            // Poll for new work
            auto work_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last_work_poll).count();

            if (work_elapsed >= WORK_POLL_MS && !cfg.benchmark_mode) {
                last_work_poll = now;

                auto new_work = api_client->getMiningTemplate(cfg.wallet_address);
                auto current = work_manager.getWork();

                // Only update work when height changes (not force refresh!)
                // Force refresh breaks solutions: nonce was computed for old merkle_root
                if (new_work && new_work->height != current.height) {
                    work_manager.setWork(*new_work);
                    network_height = new_work->height;

                    if (cfg.tui_enabled) {
                        ui.addLogMessage("New work: height " + std::to_string(new_work->height), tui::Color::Cyan);
                    }
                }

                // Submit any pending solutions
                auto solutions = work_manager.getPendingSolutions();
                mining::Work current_work = work_manager.getWork();
                for (const auto& sol : solutions) {
                    if (sol.height != current_work.height) {
                        continue;
                    }

                    bool accepted = api_client->submitBlock(sol, current_work);
                    if (accepted) {
                        stats.blocks_found++;
                        stats.shares_accepted++;

                        auto fresh_work = api_client->getMiningTemplate(cfg.wallet_address);
                        if (fresh_work) {
                            work_manager.setWork(*fresh_work);
                            current_work = *fresh_work;
                            network_height = fresh_work->height;
                            if (cfg.tui_enabled) {
                                ui.addLogMessage("Block found! New height: " + std::to_string(fresh_work->height), tui::Color::Green);
                            }
                        }
                        break;
                    } else {
                        stats.shares_rejected++;
                    }
                }
            }

            // Update network stats periodically
            auto network_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last_network_stats).count();
            if (network_elapsed >= NETWORK_STATS_MS && !cfg.benchmark_mode) {
                last_network_stats = now;
                auto net_stats = api_client->getNetworkStats();
                network_peers = net_stats.peer_count;
                network_miners = net_stats.active_miners;
                if (net_stats.height > 0) {
                    network_height = net_stats.height;
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(50));
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
        stats.avg_hashrate_1m = stats.total_hashrate;
        stats.avg_hashrate_5m = stats.total_hashrate;
        stats.avg_hashrate_15m = stats.total_hashrate;
        stats.block_height = network_height;
        stats.peer_count = network_peers;
        stats.active_miners = network_miners;

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
                          << " | Blocks: " << stats.blocks_found
                          << " | Height: " << stats.block_height
                          << " | Peers: " << stats.peer_count
                          << " | Miners: " << stats.active_miners << "\n";
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
