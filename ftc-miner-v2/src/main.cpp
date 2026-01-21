/**
 * FTC Miner v2.0
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
#include "net/peer_manager.h"
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

int main(int argc, char** argv) {
    // Parse config
    config::MinerConfig cfg = config::MinerConfig::parse(argc, argv);

    // Install signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    // Initialize peer manager
    net::PeerManager peer_manager;
    std::string selected_node;

    // Benchmark mode - skip node selection
    if (cfg.benchmark_mode) {
        std::cout << "\n[Benchmark Mode] Running without real node connection\n\n";
        selected_node = "127.0.0.1:17319";  // Dummy
    }
    // Interactive startup - show node selection dialog
    else if (cfg.interactive_startup) {
        selected_node = net::StartupDialog::showDialog(peer_manager);

        if (selected_node.empty()) {
            std::cout << "\nNo node selected. Exiting.\n";
            return 0;
        }

        // Check if benchmark mode was selected from dialog
        if (selected_node == "BENCHMARK") {
            cfg.benchmark_mode = true;
            selected_node = "127.0.0.1:17319";
            std::cout << "\n[Benchmark Mode] Running without real node connection\n";
        } else {
            // Parse selected node
            auto [host, port] = net::StartupDialog::parseAddress(selected_node);
            cfg.pool_url = host + ":" + std::to_string(port);
        }
    }
    // Non-interactive - use provided URL
    else {
        auto [host, port] = net::StartupDialog::parseAddress(cfg.pool_url);
        peer_manager.addPeer(host, port);

        std::cout << "Testing connection to " << host << ":" << port << "...\n";
        peer_manager.testAllPeers();

        if (!peer_manager.hasOnlinePeers()) {
            std::cerr << "Warning: Cannot connect to node " << cfg.pool_url << "\n";
            std::cerr << "Will keep trying...\n";
        }
    }

    // Get wallet address if not provided
    if (cfg.wallet_address.empty()) {
        std::cout << "\n";
        std::cout << "Enter your FTC wallet address\n";
        std::cout << "(format: ftc1q...): ";
        std::getline(std::cin, cfg.wallet_address);

        // Trim whitespace
        while (!cfg.wallet_address.empty() &&
               (cfg.wallet_address.front() == ' ' || cfg.wallet_address.front() == '\t')) {
            cfg.wallet_address.erase(0, 1);
        }
        while (!cfg.wallet_address.empty() &&
               (cfg.wallet_address.back() == ' ' || cfg.wallet_address.back() == '\t' ||
                cfg.wallet_address.back() == '\r' || cfg.wallet_address.back() == '\n')) {
            cfg.wallet_address.pop_back();
        }

        if (cfg.wallet_address.empty()) {
            std::cerr << "Error: Wallet address required\n";
            std::cout << "Press Enter to exit...";
            std::cin.get();
            return 1;
        }

        // Basic validation
        if (cfg.wallet_address.substr(0, 4) != "ftc1") {
            std::cout << "Warning: Address doesn't start with 'ftc1' - are you sure it's correct? (y/n): ";
            std::string confirm;
            std::getline(std::cin, confirm);
            if (confirm != "y" && confirm != "Y") {
                return 1;
            }
        }
    }

    std::cout << "\nWallet: " << cfg.wallet_address << "\n";

    // Initialize TUI (after interactive prompts)
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

    // Parse pool URL
    std::string host = "127.0.0.1";
    uint16_t port = 17319;

    std::string url = cfg.pool_url;
    if (url.find("://") != std::string::npos) {
        url = url.substr(url.find("://") + 3);
    }
    size_t colon = url.rfind(':');
    if (colon != std::string::npos) {
        host = url.substr(0, colon);
        port = static_cast<uint16_t>(std::stoi(url.substr(colon + 1)));
    } else {
        host = url;
    }

    net::APIClient api_client(host, port);

    // Start peer monitoring for auto-failover (if not benchmark)
    if (!cfg.benchmark_mode && peer_manager.getPeerCount() > 0) {
        peer_manager.startMonitoring(30000);  // Check every 30s
    }

    // Configure miner
    gpu_miner.setWorkManager(&work_manager);

    gpu_miner.setSolutionCallback([&](const mining::Solution& sol) {
        if (cfg.tui_enabled) {
            ui.addLogMessage("*** BLOCK FOUND! Height: " + std::to_string(sol.height) +
                           " Nonce: " + std::to_string(sol.nonce), tui::Color::Yellow);
        } else {
            std::cout << "\n*** BLOCK FOUND! ***\n";
            std::cout << "Height: " << sol.height << "\n";
            std::cout << "Nonce: " << sol.nonce << "\n";
            std::cout << "Hash: " << mining::Keccak256::toHex(sol.hash) << "\n\n";
        }
        // Note: solution is already submitted via work_manager in gpu_miner
    });

    // Initialize stats
    tui::MiningStats stats;
    stats.pool_url = cfg.pool_url;
    stats.start_time = std::chrono::steady_clock::now();

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
        std::cout << "\n";
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

    if (!api_client.connect()) {
        std::string err = "Failed to connect: " + api_client.getLastError();
        if (cfg.tui_enabled) {
            ui.addLogMessage(err, tui::Color::Red);
        } else {
            std::cerr << "Error: " << err << "\n";
        }
        if (cfg.tui_enabled) ui.cleanup();
        return 1;
    }

    stats.connected = true;
    stats.block_height = static_cast<int32_t>(api_client.getBlockHeight());
    stats.difficulty = api_client.getDifficulty();

    // Get initial network stats
    auto initial_net_stats = api_client.getNetworkStats();
    stats.peer_count = initial_net_stats.peer_count;
    stats.active_miners = initial_net_stats.active_miners;

    if (cfg.tui_enabled) {
        ui.addLogMessage("Connected! Height: " + std::to_string(stats.block_height) +
                        " | Peers: " + std::to_string(stats.peer_count) +
                        " | Miners: " + std::to_string(stats.active_miners), tui::Color::Green);
    }

    // Get initial work
    auto work_opt = api_client.getMiningTemplate(cfg.wallet_address);
    if (work_opt) {
        work_manager.setWork(*work_opt);
        if (cfg.tui_enabled) {
            ui.addLogMessage("Received work for height " + std::to_string(work_opt->height), tui::Color::Green);
            // Debug: show target
            std::string target_hex;
            for (int i = 0; i < 8; i++) {
                char buf[3];
                snprintf(buf, 3, "%02x", work_opt->target[i]);
                target_hex += buf;
            }
            ui.addLogMessage("Target: " + target_hex + "...", tui::Color::Yellow);
        }
    } else {
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

        // Initial intensity based on memory - start high for powerful GPUs
        for (auto& gpu : gpus) {
            int intensity = 20;  // Default 1M work items
            if (gpu.global_mem >= 12ULL * 1024 * 1024 * 1024) {
                intensity = 26;  // 64M for 12GB+ GPUs (RTX 4080/5080/etc)
            } else if (gpu.global_mem >= 8ULL * 1024 * 1024 * 1024) {
                intensity = 25;  // 32M for 8GB+ GPUs
            } else if (gpu.global_mem >= 4ULL * 1024 * 1024 * 1024) {
                intensity = 23;  // 8M for 4GB+ GPUs
            } else if (gpu.global_mem >= 2ULL * 1024 * 1024 * 1024) {
                intensity = 21;  // 2M for 2GB+ GPUs
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
            adaptive_tuner.setTargetUtilization(gpu.id, 90, 98);  // Target 90-98% utilization
        }

        // Callback to apply intensity changes
        adaptive_tuner.setIntensityCallback([&gpu_miner](int device_id, int new_intensity) {
            gpu_miner.setIntensity(device_id, new_intensity);
        });

        // Status callback for logging
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

    // Work polling interval
    auto last_work_poll = std::chrono::steady_clock::now();
    auto last_work_refresh = std::chrono::steady_clock::now();  // Force refresh periodically
    auto last_stats_print = std::chrono::steady_clock::now();
    auto last_network_stats = std::chrono::steady_clock::now();
    constexpr int WORK_POLL_MS = 1000;
    constexpr int WORK_REFRESH_MS = 5000;  // Force new work every 5s to get fresh timestamp (nonce space exhausts in ~2.5s at 1.8GH/s)
    constexpr int NETWORK_STATS_MS = 5000;  // Update network stats every 5s

    // Main loop
    while (!g_shutdown) {
        auto now = std::chrono::steady_clock::now();

        // Poll for new work
        auto work_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_work_poll).count();

        if (work_elapsed >= WORK_POLL_MS) {
            last_work_poll = now;

            auto new_work = api_client.getMiningTemplate(cfg.wallet_address);
            auto current = work_manager.getWork();

            // Check if we need to force a work refresh
            auto refresh_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last_work_refresh).count();
            bool force_refresh = (refresh_elapsed >= WORK_REFRESH_MS);

            if (new_work && (new_work->height != current.height || force_refresh)) {
                work_manager.setWork(*new_work);
                stats.block_height = new_work->height;
                last_work_refresh = now;

                if (cfg.tui_enabled) {
                    ui.addLogMessage("New work: height " + std::to_string(new_work->height), tui::Color::Cyan);
                }
            }

            // Submit any pending solutions
            auto solutions = work_manager.getPendingSolutions();
            mining::Work current_work = work_manager.getWork();
            for (const auto& sol : solutions) {
                if (cfg.benchmark_mode) {
                    // In benchmark mode, all valid solutions are accepted locally
                    stats.blocks_found++;
                    stats.shares_accepted++;
                } else {
                    bool accepted = api_client.submitBlock(sol, current_work);
                    if (accepted) {
                        stats.blocks_found++;
                        stats.shares_accepted++;

                        // IMMEDIATELY get new work after successful block submission
                        // to avoid mining stale blocks
                        auto fresh_work = api_client.getMiningTemplate(cfg.wallet_address);
                        if (fresh_work) {
                            work_manager.setWork(*fresh_work);
                            current_work = *fresh_work;  // Update for next iteration
                            stats.block_height = fresh_work->height;
                            last_work_refresh = now;  // Reset refresh timer
                            if (cfg.tui_enabled) {
                                ui.addLogMessage("New work: height " + std::to_string(fresh_work->height), tui::Color::Cyan);
                            }
                        }
                    } else {
                        stats.shares_rejected++;
                    }
                }
            }
        }

        // Update network stats periodically
        auto network_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_network_stats).count();
        if (network_elapsed >= NETWORK_STATS_MS && !cfg.benchmark_mode) {
            last_network_stats = now;
            auto net_stats = api_client.getNetworkStats();
            stats.peer_count = net_stats.peer_count;
            stats.active_miners = net_stats.active_miners;
        }

        // Update stats from GPUs
        stats.total_hashrate = gpu_miner.getTotalHashrate();
        stats.avg_hashrate_1m = stats.total_hashrate;
        stats.avg_hashrate_5m = stats.total_hashrate;
        stats.avg_hashrate_15m = stats.total_hashrate;

        // Update device stats from GPU monitor
        int nvidia_idx = 0;  // Track NVIDIA device index for NVML
        for (size_t i = 0; i < devices.size() && i < gpus.size(); ++i) {
            devices[i].hashrate = gpus[i].hashrate;
            devices[i].accepted = gpus[i].accepted;
            devices[i].rejected = gpus[i].rejected;

            // Get real GPU metrics from monitor based on vendor
            mining::GPUMetrics metrics;
            if (gpus[i].vendor.find("NVIDIA") != std::string::npos) {
                // For NVIDIA, use NVML directly with the NVIDIA device index
                metrics = gpu_monitor.getMetricsByVendor("NVIDIA", nvidia_idx);
                nvidia_idx++;
            } else if (gpus[i].vendor.find("AMD") != std::string::npos ||
                       gpus[i].vendor.find("Advanced Micro") != std::string::npos) {
                metrics = gpu_monitor.getMetricsByVendor("AMD", 0);
            } else {
                // Intel or other
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

            // Get current intensity from adaptive tuner if running
            if (cfg.autotune_enabled) {
                devices[i].intensity = adaptive_tuner.getCurrentIntensity(static_cast<int>(i));
            }
        }

        if (cfg.tui_enabled) {
            // Update and render TUI
            ui.setStats(stats);
            ui.setDevices(devices);
            ui.render();

            // Handle input
            if (!ui.handleInput()) {
                g_shutdown = true;
            }
        } else {
            // Simple output mode
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

        // Small sleep to prevent busy loop
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Cleanup
    if (cfg.tui_enabled) {
        ui.addLogMessage("Shutting down...", tui::Color::Yellow);
        ui.render();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    // Stop adaptive tuner first
    if (cfg.autotune_enabled) {
        adaptive_tuner.stop();
    }

    // Stop peer monitoring
    peer_manager.stopMonitoring();
    peer_manager.savePeersFile("peers.dat");

    gpu_miner.stop();
    gpu_monitor.shutdown();

    if (cfg.tui_enabled) {
        ui.cleanup();
    }

    std::cout << "\nMiner stopped. Total hashes: " << gpu_miner.getTotalHashes()
              << ", Blocks found: " << stats.blocks_found << "\n";

    return 0;
}
