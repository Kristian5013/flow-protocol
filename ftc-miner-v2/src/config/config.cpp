#include "config.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <thread>
#include <cstdlib>

#ifdef _WIN32
    #include <windows.h>
    #include <shlobj.h>
#else
    #include <pwd.h>
    #include <unistd.h>
    #include <sys/stat.h>
#endif

namespace config {

MinerConfig MinerConfig::parse(int argc, char** argv) {
    MinerConfig config;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            printHelp();
            exit(0);
        } else if ((arg == "-o" || arg == "--pool") && i + 1 < argc) {
            config.pool_url = argv[++i];
        } else if ((arg == "-u" || arg == "--user" || arg == "-a" || arg == "--address") && i + 1 < argc) {
            config.wallet_address = argv[++i];
        } else if ((arg == "-p" || arg == "--pass") && i + 1 < argc) {
            config.password = argv[++i];
        } else if ((arg == "-t" || arg == "--threads") && i + 1 < argc) {
            config.threads = std::stoi(argv[++i]);
        } else if ((arg == "-I" || arg == "--intensity") && i + 1 < argc) {
            config.intensity = std::stoi(argv[++i]);
        } else if ((arg == "-w" || arg == "--worksize") && i + 1 < argc) {
            config.worksize = std::stoi(argv[++i]);
        } else if (arg == "--autotune") {
            config.autotune_enabled = true;
        } else if (arg == "--no-gpu") {
            config.gpu_enabled = false;
        } else if (arg == "--no-tui") {
            config.tui_enabled = false;
        } else if ((arg == "--max-temp") && i + 1 < argc) {
            config.max_temp = std::stoi(argv[++i]);
        } else if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            return loadFromFile(argv[++i]);
        } else if (arg == "-v" || arg == "--verbose") {
            config.log_level = 2;
        } else if (arg == "-q" || arg == "--quiet") {
            config.log_level = 0;
        } else if (arg == "--benchmark") {
            config.benchmark_mode = true;
        }
    }

    // Auto-detect threads if not specified
    if (config.threads <= 0) {
        config.threads = std::thread::hardware_concurrency();
        if (config.threads == 0) config.threads = 4;
    }

    return config;
}

MinerConfig MinerConfig::loadFromFile(const std::string& path) {
    MinerConfig config;

    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Warning: Could not open config file: " << path << std::endl;
        return config;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;

        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = line.substr(0, eq);
        std::string value = line.substr(eq + 1);

        // Trim whitespace
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value = value.substr(1);

        if (key == "pool") config.pool_url = value;
        else if (key == "address" || key == "user") config.wallet_address = value;
        else if (key == "password") config.password = value;
        else if (key == "threads") config.threads = std::stoi(value);
        else if (key == "intensity") config.intensity = std::stoi(value);
        else if (key == "worksize") config.worksize = std::stoi(value);
        else if (key == "autotune") config.autotune_enabled = (value == "true" || value == "1");
        else if (key == "gpu") config.gpu_enabled = (value == "true" || value == "1");
        else if (key == "tui") config.tui_enabled = (value == "true" || value == "1");
        else if (key == "max_temp") config.max_temp = std::stoi(value);
        else if (key == "target_temp") config.target_temp = std::stoi(value);
    }

    return config;
}

void MinerConfig::saveToFile(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return;

    file << "# FTC Miner Configuration\n\n";
    file << "pool = " << pool_url << "\n";
    file << "address = " << wallet_address << "\n";
    file << "password = " << password << "\n";
    file << "threads = " << threads << "\n";
    file << "intensity = " << intensity << "\n";
    file << "worksize = " << worksize << "\n";
    file << "autotune = " << (autotune_enabled ? "true" : "false") << "\n";
    file << "gpu = " << (gpu_enabled ? "true" : "false") << "\n";
    file << "tui = " << (tui_enabled ? "true" : "false") << "\n";
    file << "max_temp = " << max_temp << "\n";
    file << "target_temp = " << target_temp << "\n";
}

void MinerConfig::printHelp() {
    std::cout << R"(
FTC Miner v2.0.0 - GPU-only Keccak-256 OpenCL Miner

Usage: ftc-miner -a <address> [options]

Required:
  -a, --address ADDR   Mining wallet address (ftc1q...)

Optional:
  -o, --pool URL       Node URL (default: auto via api.flowprotocol.net)

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
  ftc-miner -a ftc1q... --autotune
  ftc-miner -o 127.0.0.1:17319 -a ftc1q...
  ftc-miner --benchmark

)" << std::endl;
}

std::string MinerConfig::getDataDir() {
#ifdef _WIN32
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        std::string data_dir = std::string(path) + "\\FTC";
        // Create directory if it doesn't exist
        CreateDirectoryA(data_dir.c_str(), NULL);
        return data_dir;
    }
    return "C:\\FTC";
#else
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (home) {
        std::string data_dir = std::string(home) + "/.ftc";
        // Create directory if it doesn't exist
        mkdir(data_dir.c_str(), 0755);
        return data_dir;
    }
    return "/tmp/.ftc";
#endif
}

} // namespace config
