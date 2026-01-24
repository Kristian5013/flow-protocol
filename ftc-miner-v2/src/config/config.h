#ifndef FTC_MINER_CONFIG_H
#define FTC_MINER_CONFIG_H

#include <string>
#include <vector>

namespace config {

struct MinerConfig {
    // Pool/Node settings
    std::string pool_url = "http://localhost:17319";  // Local node by default
    std::string wallet_address;
    std::string worker_name = "default";
    std::string password = "x";

    // Mining settings
    int threads = 0;        // 0 = auto
    int intensity = 0;      // 0 = auto
    int worksize = 256;

    // GPU settings
    bool gpu_enabled = true;
    std::vector<int> gpu_devices;  // Empty = all

    // Auto-tune
    bool autotune_enabled = true;  // Enabled by default for optimal performance
    std::string autotune_target = "hashrate";  // hashrate, efficiency, balanced

    // Limits
    int max_temp = 85;
    int target_temp = 75;
    int max_power = 0;  // 0 = unlimited

    // Display
    bool tui_enabled = true;
    int log_level = 1;  // 0=quiet, 1=normal, 2=verbose

    // Mode
    bool benchmark_mode = false;  // Local testing without real node

    // Parse command line
    static MinerConfig parse(int argc, char** argv);

    // Load from file
    static MinerConfig loadFromFile(const std::string& path);

    // Save to file
    void saveToFile(const std::string& path) const;

    // Get shared data directory
    // Windows: %APPDATA%\FTC
    // Linux: ~/.ftc
    static std::string getDataDir();

    static void printHelp();
};

} // namespace config

#endif // FTC_MINER_CONFIG_H
