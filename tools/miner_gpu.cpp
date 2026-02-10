// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// ftc-miner-gpu — standalone GPU-accelerated FTC miner
//
// Same RPC protocol as ftc-miner (getwork/submitwork), but uses OpenCL
// to grind nonces on the GPU.  PoW: keccak256d(header_80bytes) <= target.
//
// Usage:
//   ftc-miner-gpu --address=ADDR [--rpc-host=HOST] [--gpu-device=N]
// ---------------------------------------------------------------------------

#include "core/hex.h"
#include "core/logging.h"
#include "core/stream.h"
#include "core/types.h"
#include "crypto/keccak.h"
#include "gpu/opencl_context.h"
#include "gpu/gpu_miner.h"
#include "primitives/block_header.h"
#include "rpc/request.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// Platform-specific socket includes
// ---------------------------------------------------------------------------
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    using sock_t = SOCKET;
    static constexpr sock_t BAD_SOCK = INVALID_SOCKET;
    inline void close_sock(sock_t s) { closesocket(s); }
#else
    #include <netdb.h>
    #include <sys/socket.h>
    #include <unistd.h>
    using sock_t = int;
    static constexpr sock_t BAD_SOCK = -1;
    inline void close_sock(sock_t s) { ::close(s); }
#endif

// ---------------------------------------------------------------------------
// ANSI color codes
// ---------------------------------------------------------------------------
namespace color {

static bool g_enabled = true;

inline const char* reset()   { return g_enabled ? "\033[0m"    : ""; }
inline const char* bold()    { return g_enabled ? "\033[1m"    : ""; }
inline const char* dim()     { return g_enabled ? "\033[2m"    : ""; }
inline const char* red()     { return g_enabled ? "\033[31m"   : ""; }
inline const char* green()   { return g_enabled ? "\033[32m"   : ""; }
inline const char* yellow()  { return g_enabled ? "\033[33m"   : ""; }
inline const char* blue()    { return g_enabled ? "\033[34m"   : ""; }
inline const char* magenta() { return g_enabled ? "\033[35m"   : ""; }
inline const char* cyan()    { return g_enabled ? "\033[36m"   : ""; }

void init() {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(h, &mode)) {
            mode |= 0x0004;
            if (!SetConsoleMode(h, mode)) g_enabled = false;
        } else {
            g_enabled = false;
        }
    }
#else
    if (!isatty(fileno(stdout))) g_enabled = false;
#endif
}

} // namespace color

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------
static std::string g_rpc_user;
static std::string g_rpc_pass;
static std::atomic<bool> g_stop{false};
static std::atomic<int64_t> g_chain_height{0};  // updated by poll thread
static std::atomic<bool> g_work_stale{false};    // set when height changes

#ifdef _WIN32
static BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        g_stop = true;
        std::cout << "\n" << color::yellow() << "Stopping miner..."
                  << color::reset() << std::endl;
        return TRUE;
    }
    return FALSE;
}
#else
#include <csignal>
static void signal_handler(int) { g_stop = true; }
#endif

// ---------------------------------------------------------------------------
// Block history
// ---------------------------------------------------------------------------
struct MinedBlock {
    int64_t height;
    std::string hash;
    double solve_time_s;
    std::string timestamp;
};

static std::vector<MinedBlock> g_block_history;

// ---------------------------------------------------------------------------
// Difficulty from compact nBits (same formula as the node's RPC)
// ---------------------------------------------------------------------------
static double get_difficulty(uint32_t bits) {
    int shift = (bits >> 24) & 0xFF;
    double diff = static_cast<double>(0x0000FFFF) /
                  static_cast<double>(bits & 0x00FFFFFF);
    while (shift < 29) { diff *= 256.0; ++shift; }
    while (shift > 29) { diff /= 256.0; --shift; }
    return diff;
}

// ---------------------------------------------------------------------------
// Formatting utilities
// ---------------------------------------------------------------------------
static std::string format_hashrate(double hps) {
    std::ostringstream oss;
    oss << std::fixed;
    if (hps >= 1e9) {
        oss << std::setprecision(1) << (hps / 1e9) << " GH/s";
    } else if (hps >= 1e6) {
        oss << std::setprecision(1) << (hps / 1e6) << " MH/s";
    } else if (hps >= 1000.0) {
        oss << std::setprecision(1) << (hps / 1000.0) << " kH/s";
    } else {
        oss << std::setprecision(1) << hps << " H/s";
    }
    return oss.str();
}

static std::string format_number(uint64_t n) {
    if (n >= 1000000000ULL) {
        return std::to_string(n / 1000000000ULL) + "." +
               std::to_string((n / 100000000ULL) % 10) + "B";
    }
    if (n >= 1000000ULL) {
        return std::to_string(n / 1000000ULL) + "." +
               std::to_string((n / 100000ULL) % 10) + "M";
    }
    if (n >= 1000ULL) {
        return std::to_string(n / 1000ULL) + "." +
               std::to_string((n / 100ULL) % 10) + "k";
    }
    return std::to_string(n);
}

static std::string format_duration(double seconds) {
    if (seconds < 60.0) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1) << seconds << "s";
        return oss.str();
    }
    int mins = static_cast<int>(seconds) / 60;
    int secs = static_cast<int>(seconds) % 60;
    if (mins < 60) {
        return std::to_string(mins) + "m " + std::to_string(secs) + "s";
    }
    int hours = mins / 60;
    mins = mins % 60;
    return std::to_string(hours) + "h " + std::to_string(mins) + "m";
}

static std::string current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    char buf[20];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", &tm_buf);
    return std::string(buf);
}

static std::string base64_encode(const std::string& input) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);
    int val = 0, valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

// ---------------------------------------------------------------------------
// Cookie-based auth: auto-read .cookie from default data directory
// ---------------------------------------------------------------------------
static bool try_load_cookie() {
    // Determine the default data directory (same logic as core::fs).
    std::filesystem::path datadir;
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    if (appdata && appdata[0] != '\0')
        datadir = std::filesystem::path(appdata) / "FTC";
    else {
        const char* up = std::getenv("USERPROFILE");
        datadir = up ? std::filesystem::path(up) / "AppData" / "Roaming" / "FTC"
                     : std::filesystem::path("C:\\FTC");
    }
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    datadir = home ? std::filesystem::path(home) / "Library" / "Application Support" / "FTC"
                   : std::filesystem::path("/tmp/FTC");
#else
    const char* home = std::getenv("HOME");
    datadir = home ? std::filesystem::path(home) / ".ftc"
                   : std::filesystem::path("/tmp/.ftc");
#endif

    std::filesystem::path cookie_path = datadir / ".cookie";
    std::ifstream ifs(cookie_path);
    if (!ifs.is_open()) return false;

    std::string line;
    if (!std::getline(ifs, line)) return false;

    // Format: "__cookie__:HEXVALUE"
    auto colon = line.find(':');
    if (colon == std::string::npos) return false;

    g_rpc_user = line.substr(0, colon);
    g_rpc_pass = line.substr(colon + 1);
    return true;
}

// ---------------------------------------------------------------------------
// HTTP POST client (same as ftc-miner)
// ---------------------------------------------------------------------------
static std::string http_post(const std::string& host, uint16_t port,
                             const std::string& body) {
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result) != 0)
        return {};

    sock_t sock = socket(result->ai_family, result->ai_socktype,
                         result->ai_protocol);
    if (sock == BAD_SOCK) { freeaddrinfo(result); return {}; }

    if (connect(sock, result->ai_addr,
                static_cast<int>(result->ai_addrlen)) != 0) {
        close_sock(sock);
        freeaddrinfo(result);
        return {};
    }
    freeaddrinfo(result);

#ifdef _WIN32
    DWORD recv_timeout = 60000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&recv_timeout),
               sizeof(recv_timeout));
#else
    struct timeval tv;
    tv.tv_sec = 60;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif

    std::string auth_header;
    if (!g_rpc_user.empty()) {
        auth_header = "Authorization: Basic " +
            base64_encode(g_rpc_user + ":" + g_rpc_pass) + "\r\n";
    }

    std::string request =
        "POST / HTTP/1.1\r\n"
        "Host: " + host + "\r\n" +
        auth_header +
        "Content-Type: application/json\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Connection: close\r\n\r\n" + body;

    int total_sent = 0;
    int req_len = static_cast<int>(request.size());
    while (total_sent < req_len) {
        int n = send(sock, request.c_str() + total_sent,
                     req_len - total_sent, 0);
        if (n <= 0) { close_sock(sock); return {}; }
        total_sent += n;
    }

    std::string response;
    char buf[4096];
    for (;;) {
        int n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        response.append(buf, n);
    }
    close_sock(sock);

    auto pos = response.find("\r\n\r\n");
    if (pos != std::string::npos) return response.substr(pos + 4);
    return response;
}

static std::string rpc_call(const std::string& host, uint16_t port,
                            const std::string& method,
                            const std::string& params_json) {
    std::string body = "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"" +
                       method + "\",\"params\":" + params_json + "}";
    return http_post(host, port, body);
}

// ---------------------------------------------------------------------------
// Background height poller — detects new blocks on the chain
// ---------------------------------------------------------------------------
static void height_poll_thread(const std::string& host, uint16_t port) {
    while (!g_stop) {
        std::string resp = rpc_call(host, port, "getblockcount", "[]");
        if (!resp.empty()) {
            try {
                auto json = rpc::parse_json(resp);
                if (json["result"].is_int()) {
                    int64_t h = json["result"].get_int();
                    int64_t prev = g_chain_height.exchange(h);
                    if (prev > 0 && h > prev) {
                        g_work_stale = true;
                    }
                }
            } catch (...) {}
        }
        // Poll every 500ms — fast enough to catch new blocks promptly.
        for (int i = 0; i < 5 && !g_stop; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------
static std::string get_arg(int argc, char* argv[], const std::string& name,
                           const std::string& default_val = "") {
    std::string prefix = "--" + name + "=";
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg.rfind(prefix, 0) == 0) return arg.substr(prefix.size());
    }
    return default_val;
}

static bool has_arg(int argc, char* argv[], const std::string& name) {
    std::string prefix = "--" + name;
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == prefix || arg.rfind(prefix + "=", 0) == 0) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Keccak256d test mode: validate GPU double-hash against CPU
// ---------------------------------------------------------------------------
static bool run_keccak_test(gpu::GpuMiner& miner) {
    std::cout << "  Running Keccak256d GPU validation...\n";

    // We test by mining with a very easy target (all 0xFF)
    // and checking that the nonces we find produce hashes that
    // also pass on the CPU.

    int passed = 0;
    int total = 10;

    for (int t = 0; t < total; ++t) {
        // Create a pseudo-random 80-byte header
        std::array<uint8_t, 80> header{};
        for (int i = 0; i < 80; ++i)
            header[i] = static_cast<uint8_t>((t * 137 + i * 31) & 0xFF);

        // Set nonce to 0
        header[76] = header[77] = header[78] = header[79] = 0;

        // Easy target: 00FF... (anything with first byte < 0xFF passes)
        std::array<uint8_t, 32> target{};
        std::memset(target.data(), 0xFF, 32);
        target[31] = 0x00;  // MSB = 0 means hash must have byte[31] = 0
        target[30] = 0xFF;

        miner.set_header(std::span<const uint8_t>(header.data(), 80));
        miner.set_target(std::span<const uint8_t>(target.data(), 32));

        auto results = miner.mine_batch(0, 65536);

        if (results.empty()) {
            std::cout << "    Test " << t << ": no results (unexpected)\n";
            continue;
        }

        // Verify first result on CPU
        uint32_t nonce = results[0];
        header[76] = nonce & 0xFF;
        header[77] = (nonce >> 8) & 0xFF;
        header[78] = (nonce >> 16) & 0xFF;
        header[79] = (nonce >> 24) & 0xFF;

        auto cpu_hash = crypto::keccak256d(
            std::span<const uint8_t>(header.data(), 80));

        auto cpu_target = core::uint256::from_bytes(
            std::span<const uint8_t, 32>(target.data(), 32));

        if (cpu_hash <= cpu_target) {
            ++passed;
        } else {
            std::cout << "    FAIL: test " << t << " nonce=" << nonce
                      << " hash=" << cpu_hash.to_hex() << "\n";
        }
    }

    std::cout << "  Keccak256d test: " << passed << "/" << total;
    if (passed == total) {
        std::cout << " " << color::green() << "PASSED" << color::reset();
    } else {
        std::cout << " " << color::red() << "FAILED" << color::reset();
    }
    std::cout << "\n";
    return passed == total;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
#ifdef _WIN32
    {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#endif

    color::init();

    // --gpu-list: enumerate and exit
    if (has_arg(argc, argv, "gpu-list")) {
        auto devices = gpu::OpenCLContext::list_devices();
        if (devices.empty()) {
            std::cout << "No OpenCL GPU devices found.\n";
            return 1;
        }
        std::cout << "\nAvailable GPU devices:\n\n";
        for (const auto& d : devices) {
            std::cout << "  [" << d.platform_index << ":" << d.device_index
                      << "] " << color::bold() << d.name << color::reset()
                      << "\n"
                      << "      Vendor: " << d.vendor
                      << "  Memory: " << (d.global_mem / (1024*1024)) << " MB"
                      << "  CUs: " << d.compute_units
                      << "  Driver: " << d.driver_version << "\n\n";
        }
        return 0;
    }

    if (has_arg(argc, argv, "help") || argc < 2) {
        std::cout << color::bold() << color::cyan()
                  << "FTC GPU Miner v2.0" << color::reset() << "\n\n"
                  << "Usage: ftc-miner-gpu --address=ADDR [options]\n\n"
                  << "Options:\n"
                  << "  --address=ADDR       Mining reward address (required)\n"
                  << "  --rpc-host=HOST      RPC server host (default: 127.0.0.1)\n"
                  << "  --rpc-port=PORT      RPC server port (default: 9332)\n"
                  << "  --rpc-user=USER      RPC username (default: auto from .cookie)\n"
                  << "  --rpc-pass=PASS      RPC password (default: auto from .cookie)\n"
                  << "  --gpu-platform=N     OpenCL platform index (default: 0)\n"
                  << "  --gpu-device=N       GPU device index (default: 0)\n"
                  << "  --batch-size=N       Nonces per GPU dispatch (default: 4194304)\n"
                  << "  --gpu-list           List available GPU devices and exit\n"
                  << "  --test-keccak        Validate GPU Keccak256d against CPU\n"
                  << "  --no-color           Disable colored output\n"
                  << "  --help               Show this help\n\n"
                  << "Example:\n"
                  << "  ftc-miner-gpu --address=1A73WPJ... --rpc-host=seed.flowprotocol.net\n";
        return 0;
    }

    if (has_arg(argc, argv, "no-color")) color::g_enabled = false;

    std::string address  = get_arg(argc, argv, "address");
    std::string rpc_host = get_arg(argc, argv, "rpc-host", "127.0.0.1");
    uint16_t rpc_port    = static_cast<uint16_t>(
        std::atoi(get_arg(argc, argv, "rpc-port", "9332").c_str()));
    // RPC credentials: if user explicitly provides --rpc-user/--rpc-pass, use
    // those.  Otherwise auto-read the .cookie file from the default data dir.
    bool explicit_creds = has_arg(argc, argv, "rpc-user") ||
                          has_arg(argc, argv, "rpc-pass");
    if (explicit_creds) {
        g_rpc_user = get_arg(argc, argv, "rpc-user");
        g_rpc_pass = get_arg(argc, argv, "rpc-pass");
    } else {
        if (!try_load_cookie()) {
            // No cookie file found — leave empty; server may allow no-auth.
            g_rpc_user.clear();
            g_rpc_pass.clear();
        }
    }
    int gpu_platform     = std::atoi(
        get_arg(argc, argv, "gpu-platform", "0").c_str());
    int gpu_device       = std::atoi(
        get_arg(argc, argv, "gpu-device", "0").c_str());
    uint32_t batch_size  = static_cast<uint32_t>(
        std::atoi(get_arg(argc, argv, "batch-size", "4194304").c_str()));

    // Suppress internal logging
    auto& logger = core::Logger::instance();
    logger.set_print_to_console(false);

    // ---------------------------------------------------------------
    // Initialize GPU
    // ---------------------------------------------------------------
    std::cout << "\n  " << color::bold() << color::cyan()
              << "FTC GPU Miner v2.0"
              << color::reset() << "\n\n";

    std::cout << "  Initializing OpenCL..." << std::flush;

    gpu::OpenCLContext ctx;
    if (!ctx.init(gpu_platform, gpu_device)) {
        std::cout << " " << color::red() << "FAILED" << color::reset()
                  << "\n  No suitable GPU found. Use --gpu-list to see devices.\n";
        return 1;
    }

    auto dev = ctx.device_info();
    std::cout << " " << color::green() << "OK" << color::reset() << "\n";
    std::cout << "  " << color::dim() << "GPU:    " << color::reset()
              << "  " << color::bold() << dev.name << color::reset() << "\n";
    std::cout << "  " << color::dim() << "Memory: " << color::reset()
              << "  " << (dev.global_mem / (1024*1024)) << " MB"
              << "  CUs: " << dev.compute_units << "\n";

    gpu::GpuMiner miner(ctx);
    miner.set_batch_size(batch_size);

    if (!miner.init()) {
        std::cout << "  " << color::red()
                  << "Failed to initialize GPU miner"
                  << color::reset() << "\n";
        std::string log = ctx.get_build_log();
        if (!log.empty()) {
            std::cout << "  Build log:\n" << log << "\n";
        }
        return 1;
    }

    std::cout << "  " << color::green() << "GPU miner initialized"
              << color::reset() << "\n";
    std::cout << "  " << color::dim() << "Batch:  " << color::reset()
              << "  " << format_number(batch_size) << " nonces/dispatch\n";

    // --test-keccak: validate and exit
    if (has_arg(argc, argv, "test-keccak")) {
        bool ok = run_keccak_test(miner);
        return ok ? 0 : 1;
    }

    if (address.empty()) {
        std::cerr << color::red() << "Error: --address is required"
                  << color::reset() << "\n";
        return 1;
    }

    std::cout << "  " << color::dim() << "Address:" << color::reset()
              << "  " << color::bold() << address << color::reset() << "\n";
    std::cout << "  " << color::dim() << "Node:   " << color::reset()
              << "  " << rpc_host << ":" << rpc_port << "\n";
    std::cout << "  " << color::dim() << "Auth:   " << color::reset()
              << "  " << (g_rpc_user == "__cookie__" ? "cookie (auto)"
                         : g_rpc_user.empty() ? "none"
                         : "rpcuser") << "\n";
    std::cout << "  " << color::dim() << "Press Ctrl+C to stop"
              << color::reset() << "\n\n";

    int blocks_mined = 0;
    int blocks_rejected = 0;
    auto session_start = std::chrono::steady_clock::now();
    uint64_t session_hashes = 0;
    int64_t current_mining_height = 0;
    double current_diff = 0;  // Bitcoin-style difficulty (pow_limit / target)

    // Periodic status line interval (seconds).
    static constexpr double STATUS_INTERVAL = 10.0;
    auto last_status_time = std::chrono::steady_clock::now();

    // Format difficulty as a compact string.
    auto format_diff = [](double d) -> std::string {
        std::ostringstream oss;
        oss << std::fixed;
        if (d >= 1e12)      oss << std::setprecision(1) << (d / 1e12) << "T";
        else if (d >= 1e9)  oss << std::setprecision(1) << (d / 1e9) << "G";
        else if (d >= 1e6)  oss << std::setprecision(1) << (d / 1e6) << "M";
        else if (d >= 1e3)  oss << std::setprecision(1) << (d / 1e3) << "K";
        else                oss << std::setprecision(2) << d;
        return oss.str();
    };

    // Helper: print a periodic hashrate status line (rigel/lolminer style).
    auto print_status = [&](double hash_rate, int64_t height, bool newline) {
        auto uptime = std::chrono::steady_clock::now() - session_start;
        double uptime_s = std::chrono::duration<double>(uptime).count();

        // ETA to next block: expected_hashes = difficulty * 2^32.
        double expected_hashes = current_diff * 4294967296.0;
        double eta = (hash_rate > 0 && expected_hashes > 0)
            ? expected_hashes / hash_rate : 0;

        std::ostringstream line;
        line << "\r  " << color::dim() << current_timestamp() << color::reset()
             << "  " << color::cyan() << color::bold()
             << format_hashrate(hash_rate) << color::reset()
             << "  " << color::dim() << "|" << color::reset()
             << " block " << color::bold() << height << color::reset()
             << "  " << color::dim() << "|" << color::reset()
             << " diff " << format_diff(current_diff)
             << "  " << color::dim() << "|" << color::reset()
             << " eta " << color::yellow()
             << (eta > 0 ? "~" + format_duration(eta) : "---")
             << color::reset()
             << "  " << color::dim() << "|" << color::reset()
             << " " << color::green() << blocks_mined << color::reset()
             << " found"
             << "  " << color::dim() << "|" << color::reset()
             << " up " << format_duration(uptime_s)
             << "      ";
        if (newline) {
            std::cout << line.str() << std::endl;
        } else {
            std::cout << line.str() << std::flush;
        }
    };

    // Start background height poller to detect new blocks on the network.
    std::thread poller(height_poll_thread, rpc_host, rpc_port);

    std::cout << "  " << color::dim() << current_timestamp() << color::reset()
              << "  Mining started" << std::endl;

    while (!g_stop) {
        // Reset stale flag at the start of each work cycle.
        g_work_stale = false;
        // ---------------------------------------------------------------
        // 1. Fetch work from node (silent — no output on success)
        // ---------------------------------------------------------------
        std::string resp = rpc_call(rpc_host, rpc_port, "getwork",
                                    "[\"" + address + "\"]");
        if (resp.empty()) {
            std::cout << "\r  " << color::dim() << current_timestamp()
                      << color::reset() << "  " << color::red()
                      << "RPC connection failed, retrying in 5s..."
                      << color::reset() << std::endl;
            for (int i = 0; i < 50 && !g_stop; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        rpc::JsonValue json;
        try {
            json = rpc::parse_json(resp);
        } catch (const std::exception& e) {
            std::cout << "\r  " << color::dim() << current_timestamp()
                      << color::reset() << "  " << color::red()
                      << "JSON error: " << e.what()
                      << color::reset() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        if (!json["result"].is_object()) {
            std::cout << "\r  " << color::dim() << current_timestamp()
                      << color::reset() << "  " << color::red()
                      << "RPC error: " << rpc::json_serialize(json["error"])
                      << color::reset() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        auto& result = json["result"];
        std::string header_hex = result["header"].get_string();
        std::string target_hex = result["target"].get_string();
        int64_t height = result["height"].get_int();
        int64_t work_id = result["work_id"].is_int()
            ? result["work_id"].get_int() : 0;

        // ---------------------------------------------------------------
        // 2. Deserialize header and target
        // ---------------------------------------------------------------
        auto header_opt = core::from_hex(header_hex);
        if (!header_opt || header_opt->size() < 80) {
            std::cerr << "\r  " << color::dim() << current_timestamp()
                      << color::reset() << "  " << color::red()
                      << "Invalid header hex" << color::reset() << std::endl;
            continue;
        }

        auto target = core::uint256::from_hex(target_hex);

        // Compute Bitcoin-style difficulty from nBits in the header.
        // nBits is at header bytes [72..75] (little-endian uint32).
        {
            auto& hb = *header_opt;
            uint32_t nbits =
                static_cast<uint32_t>(hb[72])       |
                (static_cast<uint32_t>(hb[73]) << 8) |
                (static_cast<uint32_t>(hb[74]) << 16) |
                (static_cast<uint32_t>(hb[75]) << 24);
            current_diff = get_difficulty(nbits);
        }

        // Log new block height only when it changes.
        if (height != current_mining_height) {
            // Clear any inline progress
            std::cout << "\r" << std::string(100, ' ') << "\r";
            std::cout << "  " << color::dim() << current_timestamp()
                      << color::reset() << "  New job: block "
                      << color::bold() << height << color::reset()
                      << "  diff " << format_diff(current_diff)
                      << std::endl;
            current_mining_height = height;
        }

        // Upload header and target to GPU
        miner.set_header(std::span<const uint8_t>(
            header_opt->data(), 80));
        miner.set_target(std::span<const uint8_t>(
            target.data(), 32));

        auto block_start = std::chrono::steady_clock::now();
        bool found = false;
        uint32_t winning_nonce = 0;
        uint64_t block_hashes = 0;

        // Read initial timestamp from header bytes [68..71] (little-endian).
        auto& hdr_bytes = *header_opt;
        uint32_t cur_timestamp =
            static_cast<uint32_t>(hdr_bytes[68])       |
            (static_cast<uint32_t>(hdr_bytes[69]) << 8) |
            (static_cast<uint32_t>(hdr_bytes[70]) << 16) |
            (static_cast<uint32_t>(hdr_bytes[71]) << 24);

        // ---------------------------------------------------------------
        // 3. GPU mining loop with timestamp rolling
        // ---------------------------------------------------------------
        g_chain_height = height;

        while (!g_stop && !found && !g_work_stale) {
            // Inner loop: grind nonces for the current timestamp
            for (uint32_t base_nonce = 0;
                 !g_stop && !found && !g_work_stale; ) {
                uint64_t remaining64 =
                    static_cast<uint64_t>(UINT32_MAX) - base_nonce + 1;
                if (remaining64 == 0) break;
                uint32_t this_batch = static_cast<uint32_t>(
                    std::min(static_cast<uint64_t>(batch_size), remaining64));
                if (this_batch == 0) break;

                auto results = miner.mine_batch(base_nonce, this_batch);
                block_hashes += this_batch;
                session_hashes += this_batch;

                if (!results.empty()) {
                    for (uint32_t nonce : results) {
                        auto hdr = hdr_bytes;
                        hdr[76] = nonce & 0xFF;
                        hdr[77] = (nonce >> 8) & 0xFF;
                        hdr[78] = (nonce >> 16) & 0xFF;
                        hdr[79] = (nonce >> 24) & 0xFF;

                        auto cpu_hash = crypto::keccak256d(
                            std::span<const uint8_t>(hdr.data(), 80));

                        if (cpu_hash <= target) {
                            found = true;
                            winning_nonce = nonce;
                            break;
                        }
                    }
                }

                uint64_t next = static_cast<uint64_t>(base_nonce) + this_batch;
                if (next > UINT32_MAX) break;
                base_nonce = static_cast<uint32_t>(next);

                // Periodic status line every STATUS_INTERVAL seconds.
                auto now = std::chrono::steady_clock::now();
                double since_status = std::chrono::duration<double>(
                    now - last_status_time).count();
                if (since_status >= STATUS_INTERVAL) {
                    double elapsed = std::chrono::duration<double>(
                        now - block_start).count();
                    double hash_rate = elapsed > 0.01
                        ? static_cast<double>(block_hashes) / elapsed : 0;
                    print_status(hash_rate, height, true);
                    last_status_time = now;
                }
            }

            if (found || g_stop || g_work_stale) break;

            // Nonce space exhausted — roll timestamp silently and retry.
            ++cur_timestamp;

            // Safety: don't set timestamp too far into the future.
            auto real_time = static_cast<uint32_t>(std::time(nullptr));
            if (cur_timestamp > real_time + 30) break;

            // Write new timestamp into header bytes (little-endian).
            hdr_bytes[68] = cur_timestamp & 0xFF;
            hdr_bytes[69] = (cur_timestamp >> 8) & 0xFF;
            hdr_bytes[70] = (cur_timestamp >> 16) & 0xFF;
            hdr_bytes[71] = (cur_timestamp >> 24) & 0xFF;

            // Re-upload modified header to GPU.
            miner.set_header(std::span<const uint8_t>(
                hdr_bytes.data(), 80));
        }

        // Clear inline progress.
        std::cout << "\r" << std::string(100, ' ') << "\r";

        auto block_elapsed = std::chrono::steady_clock::now() - block_start;
        double block_secs = std::chrono::duration<double>(
            block_elapsed).count();
        double block_rate = block_secs > 0.01
            ? static_cast<double>(block_hashes) / block_secs : 0;

        if (!found) {
            if (g_stop) break;
            // Stale work or timestamp limit — silently fetch new work.
            continue;
        }

        // ---------------------------------------------------------------
        // 4. Submit solution
        // ---------------------------------------------------------------
        std::cout << "  " << color::dim() << current_timestamp()
                  << color::reset() << "  " << color::green() << color::bold()
                  << "BLOCK FOUND" << color::reset()
                  << "  height " << color::bold() << height << color::reset()
                  << "  " << format_hashrate(block_rate)
                  << "  " << format_duration(block_secs) << std::endl;

        std::string submit_resp = rpc_call(
            rpc_host, rpc_port, "submitwork",
            "[" + std::to_string(winning_nonce) + "," +
            std::to_string(work_id) + "," +
            std::to_string(cur_timestamp) + "]");

        if (submit_resp.empty()) {
            ++blocks_rejected;
            std::cout << "  " << color::dim() << current_timestamp()
                      << color::reset() << "  " << color::red()
                      << "Submit failed — node unreachable"
                      << color::reset() << std::endl;
            continue;
        }

        rpc::JsonValue submit_json;
        try {
            submit_json = rpc::parse_json(submit_resp);
        } catch (const std::exception& e) {
            ++blocks_rejected;
            std::cout << "  " << color::dim() << current_timestamp()
                      << color::reset() << "  " << color::red()
                      << "Submit parse error: " << e.what()
                      << color::reset() << std::endl;
            continue;
        }

        if (submit_json["result"].is_string()) {
            ++blocks_mined;
            std::string block_hash = submit_json["result"].get_string();

            g_block_history.push_back({
                height, block_hash, block_secs, current_timestamp()
            });

            std::cout << "  " << color::dim() << current_timestamp()
                      << color::reset() << "  " << color::green()
                      << "Accepted" << color::reset()
                      << " #" << blocks_mined
                      << "  " << color::dim()
                      << block_hash.substr(0, 20) << "..."
                      << color::reset() << std::endl;
        } else {
            ++blocks_rejected;
            std::cout << "  " << color::dim() << current_timestamp()
                      << color::reset() << "  " << color::red()
                      << "Rejected: "
                      << rpc::json_serialize(submit_json["error"])
                      << color::reset() << std::endl;
        }
    }

    // Stop the height poller thread.
    g_stop = true;
    if (poller.joinable()) poller.join();

    // ---------------------------------------------------------------
    // Session summary
    // ---------------------------------------------------------------
    auto session_elapsed = std::chrono::steady_clock::now() - session_start;
    double session_secs = std::chrono::duration<double>(
        session_elapsed).count();
    double session_rate = session_secs > 0.01
        ? static_cast<double>(session_hashes) / session_secs : 0;

    std::cout << "\n";
    std::cout << color::bold() << color::cyan()
              << "  === Session Summary ==="
              << color::reset() << "\n";

    std::cout << "  " << color::dim() << "Uptime:  " << color::reset()
              << format_duration(session_secs) << "\n";
    std::cout << "  " << color::dim() << "Avg rate:" << color::reset()
              << " " << format_hashrate(session_rate) << "\n";
    std::cout << "  " << color::dim() << "Hashes:  " << color::reset()
              << format_number(session_hashes) << "\n";
    std::cout << "  " << color::dim() << "Found:   " << color::reset()
              << color::green() << blocks_mined << color::reset();
    if (blocks_rejected > 0) {
        std::cout << "  " << color::red() << blocks_rejected
                  << " rejected" << color::reset();
    }
    std::cout << "\n\n";

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
