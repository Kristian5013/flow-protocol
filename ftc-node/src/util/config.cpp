#include "util/config.h"

#include <iostream>
#include <cstring>
#include <cstdlib>

#ifdef _WIN32
    #include <windows.h>
    #include <shlobj.h>
#else
    #include <pwd.h>
    #include <unistd.h>
#endif

namespace ftc {
namespace util {

std::string Config::getDefaultDataDir() {
#ifdef _WIN32
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        return std::string(path) + "\\FTC";
    }
    return "C:\\FTC";
#else
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (home) {
        return std::string(home) + "/.ftc";
    }
    return "/tmp/.ftc";
#endif
}

Config Config::parse(int argc, char** argv) {
    Config config;
    config.data_dir = getDefaultDataDir();

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            printHelp();
            exit(0);
        }
        else if (arg == "-v" || arg == "--version") {
            printVersion();
            exit(0);
        }
        else if (arg == "-d" || arg == "--datadir") {
            if (i + 1 < argc) {
                config.data_dir = argv[++i];
            }
        }
        else if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) {
                config.p2p_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            }
        }
        else if (arg == "--api-port") {
            if (i + 1 < argc) {
                config.api_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            }
        }
        else if (arg == "--api-bind") {
            if (i + 1 < argc) {
                config.api_bind = argv[++i];
            }
        }
        else if (arg == "--verbose") {
            config.log_level = log::Level::NOTICE;
            config.quiet = false;
        }
        else if (arg == "--debug") {
            config.log_level = log::Level::DEBUG;
            config.quiet = false;
        }
        else if (arg == "--log") {
            if (i + 1 < argc) {
                config.log_file = argv[++i];
            }
        }
        else if (arg == "--mine") {
            config.mining_enabled = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                config.mining_address = argv[++i];
            }
        }
        else if (arg == "--reindex") {
            config.reindex = true;
        }
    }

    return config;
}

void Config::printHelp() {
    std::cout << "FTC Node " << FTC_VERSION_STRING << "\n\n";
    std::cout << "Kristian Pilatovich 20091227 - First Real P2P\n\n";
    std::cout << "Usage: ftc-node [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help              Show this help message\n";
    std::cout << "  -v, --version           Show version\n";
    std::cout << "  -d, --datadir DIR       Data directory (default: " << getDefaultDataDir() << ")\n";
    std::cout << "  -p, --port PORT         P2P port (default: " << FTC_PORT_P2P << ")\n";
    std::cout << "  --api-port PORT         API port (default: " << FTC_PORT_API << ")\n";
    std::cout << "  --api-bind ADDR         API bind address (default: :: all interfaces)\n";
    std::cout << "  --verbose               Show progress output\n";
    std::cout << "  --debug                 Enable debug logging\n";
    std::cout << "  --log FILE              Log to file\n";
    std::cout << "  --mine [ADDRESS]        Enable mining to address\n";
    std::cout << "  --reindex               Rebuild UTXO set from blocks\n";
    std::cout << "\n";
    std::cout << "Peer Discovery:\n";
    std::cout << "  BitTorrent DHT (automatic, no configuration needed)\n";
    std::cout << "  DHT port: 17321 (UDP)\n";
    std::cout << "\n";
    std::cout << "First run:\n";
    std::cout << "  Just run: ftc-node\n";
    std::cout << "  Peers are discovered automatically via DHT\n";
    std::cout << "\n";
    std::cout << "API: curl http://[::1]:17319/status\n";
    std::cout << "\n";
}

void Config::printVersion() {
    std::cout << "FTC Node " << FTC_VERSION_STRING << "\n";
    std::cout << "Build: " << __DATE__ << " " << __TIME__ << "\n";
    std::cout << "Protocol: " << FTC_PROTOCOL_VERSION << "\n";
}

} // namespace util
} // namespace ftc
