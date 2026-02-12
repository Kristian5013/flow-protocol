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
// Terminal support
// ---------------------------------------------------------------------------
static bool g_ansi = false;  // true if terminal supports ANSI cursor codes

static void term_init() {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(h, &mode)) {
            mode |= 0x0004;  // ENABLE_VIRTUAL_TERMINAL_PROCESSING
            g_ansi = SetConsoleMode(h, mode);
        }
    }
#else
    g_ansi = isatty(fileno(stdout));
#endif
}

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

static std::string format_diff(double d) {
    std::ostringstream oss;
    oss << std::fixed;
    if (d >= 1e12)      oss << std::setprecision(1) << (d / 1e12) << "T";
    else if (d >= 1e9)  oss << std::setprecision(1) << (d / 1e9) << "G";
    else if (d >= 1e6)  oss << std::setprecision(1) << (d / 1e6) << "M";
    else if (d >= 1e3)  oss << std::setprecision(1) << (d / 1e3) << "K";
    else                oss << std::setprecision(2) << d;
    return oss.str();
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

static std::string current_datetime() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
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

    int passed = 0;
    int total = 10;

    for (int t = 0; t < total; ++t) {
        std::array<uint8_t, 80> header{};
        for (int i = 0; i < 80; ++i)
            header[i] = static_cast<uint8_t>((t * 137 + i * 31) & 0xFF);
        header[76] = header[77] = header[78] = header[79] = 0;

        std::array<uint8_t, 32> target{};
        std::memset(target.data(), 0xFF, 32);
        target[31] = 0x00;
        target[30] = 0xFF;

        miner.set_header(std::span<const uint8_t>(header.data(), 80));
        miner.set_target(std::span<const uint8_t>(target.data(), 32));

        auto results = miner.mine_batch(0, 65536);

        if (results.empty()) {
            std::cout << "    Test " << t << ": no results (unexpected)\n";
            continue;
        }

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

    std::cout << "  Keccak256d test: " << passed << "/" << total
              << (passed == total ? " PASSED" : " FAILED") << "\n";
    return passed == total;
}

// ---------------------------------------------------------------------------
// TUI — cgminer-style static dashboard
// ---------------------------------------------------------------------------
static std::vector<std::string> g_tui_log;
static constexpr size_t TUI_MAX_LOG = 50;

static void tui_log(const std::string& msg) {
    g_tui_log.push_back("[" + current_timestamp() + "] " + msg);
    if (g_tui_log.size() > TUI_MAX_LOG)
        g_tui_log.erase(g_tui_log.begin());
}

struct TuiState {
    // Static info (set once)
    std::string gpu_name;
    int gpu_mem_mb = 0;
    int gpu_cus = 0;
    std::string address;
    std::string node;
    std::string auth_mode;
    std::string start_time;
    uint32_t batch_size = 0;
    int power_pct = 100;

    // Dynamic info (updated during mining)
    int64_t height = 0;
    double difficulty = 0;
    int blocks_found = 0;
    int blocks_rejected = 0;

    // Hashrate tracking
    uint64_t session_hashes = 0;
    std::chrono::steady_clock::time_point session_start;
    uint64_t window_hashes = 0;
    std::chrono::steady_clock::time_point window_start;
    double window_rate = 0;

    void add_hashes(uint64_t n) {
        session_hashes += n;
        window_hashes += n;
    }

    double avg_hashrate() const {
        double s = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - session_start).count();
        return s > 0.5 ? static_cast<double>(session_hashes) / s : 0;
    }

    double current_hashrate() {
        auto now = std::chrono::steady_clock::now();
        double s = std::chrono::duration<double>(now - window_start).count();
        if (s >= 10.0) {
            window_rate = static_cast<double>(window_hashes) / s;
            window_hashes = 0;
            window_start = now;
        }
        return window_rate > 0 ? window_rate
            : (s > 0.5 ? static_cast<double>(window_hashes) / s : 0);
    }

    double uptime() const {
        return std::chrono::duration<double>(
            std::chrono::steady_clock::now() - session_start).count();
    }
};

static void tui_redraw(TuiState& st) {
    double rate = st.current_hashrate();
    double avg = st.avg_hashrate();
    double up = st.uptime();
    double expected = st.difficulty * 4294967296.0;
    double eta = (rate > 0 && expected > 0) ? expected / rate : 0;

    std::ostringstream buf;

    if (g_ansi) buf << "\033[H";  // cursor home

    // Line 1: title
    buf << "FTC Miner v2.2 - Started: [" << st.start_time << "]";
    if (g_ansi) buf << "\033[K";
    buf << "\n";

    // Line 2: blank
    if (g_ansi) buf << "\033[K";
    buf << "\n";

    // Line 3: hashrate + stats
    buf << "(10s):" << format_hashrate(rate)
        << " (avg):" << format_hashrate(avg)
        << " | Found:" << st.blocks_found
        << " R:" << st.blocks_rejected
        << " | Up:" << format_duration(up);
    if (g_ansi) buf << "\033[K";
    buf << "\n";

    // Line 4: block info
    buf << "Block:" << st.height
        << "  Diff:" << format_diff(st.difficulty)
        << "  ETA:" << (eta > 0 ? "~" + format_duration(eta) : "---");
    if (st.power_pct < 100)
        buf << "  Power:" << st.power_pct << "%";
    if (g_ansi) buf << "\033[K";
    buf << "\n";

    // Line 5: connection info
    buf << "Node:" << st.node
        << "  Auth:" << st.auth_mode
        << "  Addr:" << st.address;
    if (g_ansi) buf << "\033[K";
    buf << "\n";

    // Line 6: blank
    if (g_ansi) buf << "\033[K";
    buf << "\n";

    // Line 7: GPU status
    buf << "GPU 0: " << st.gpu_name
        << " | " << st.gpu_mem_mb << " MB  " << st.gpu_cus << " CUs"
        << " | " << format_hashrate(rate)
        << "  Batch:" << format_number(st.batch_size);
    if (g_ansi) buf << "\033[K";
    buf << "\n";

    // Line 8: separator
    buf << std::string(72, '-');
    if (g_ansi) buf << "\033[K";
    buf << "\n";

    // Lines 9+: event log
    for (const auto& line : g_tui_log) {
        buf << line;
        if (g_ansi) buf << "\033[K";
        buf << "\n";
    }

    // Clear any stale content below
    if (g_ansi) buf << "\033[J";

    std::cout << buf.str() << std::flush;
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

    term_init();

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
                      << "] " << d.name << "\n"
                      << "      Vendor: " << d.vendor
                      << "  Memory: " << (d.global_mem / (1024*1024)) << " MB"
                      << "  CUs: " << d.compute_units
                      << "  Driver: " << d.driver_version << "\n\n";
        }
        return 0;
    }

    if (has_arg(argc, argv, "help") || argc < 2) {
        std::cout << "FTC GPU Miner v2.2\n\n"
                  << "Usage: ftc-miner-gpu --address=ADDR [options]\n\n"
                  << "Options:\n"
                  << "  --address=ADDR       Mining reward address (required)\n"
                  << "  --rpc-host=HOST      RPC server host (default: 127.0.0.1)\n"
                  << "  --rpc-port=PORT      RPC server port (default: 9332)\n"
                  << "  --rpc-user=USER      RPC username (default: auto from .cookie)\n"
                  << "  --rpc-pass=PASS      RPC password (default: auto from .cookie)\n"
                  << "  --gpu-platform=N     OpenCL platform index (default: 0)\n"
                  << "  --gpu-device=N       GPU device index (default: 0)\n"
                  << "  --batch-size=N       Nonces per GPU dispatch (default: auto-tune)\n"
                  << "  --power=N            GPU power limit 1-100% (default: 100)\n"
                  << "                       Use 60-80 on laptops to prevent overheating\n"
                  << "  --gpu-list           List available GPU devices and exit\n"
                  << "  --test-keccak        Validate GPU Keccak256d against CPU\n"
                  << "  --help               Show this help\n\n"
                  << "Example:\n"
                  << "  ftc-miner-gpu --address=1A73WPJ... --rpc-host=seed.flowprotocol.net\n"
                  << "  ftc-miner-gpu --address=1A73WPJ... --power=70  (laptop mode)\n";
        return 0;
    }

    std::string address  = get_arg(argc, argv, "address");
    std::string rpc_host = get_arg(argc, argv, "rpc-host", "127.0.0.1");
    uint16_t rpc_port    = static_cast<uint16_t>(
        std::atoi(get_arg(argc, argv, "rpc-port", "9332").c_str()));
    bool explicit_creds = has_arg(argc, argv, "rpc-user") ||
                          has_arg(argc, argv, "rpc-pass");
    if (explicit_creds) {
        g_rpc_user = get_arg(argc, argv, "rpc-user");
        g_rpc_pass = get_arg(argc, argv, "rpc-pass");
    } else {
        if (!try_load_cookie()) {
            g_rpc_user.clear();
            g_rpc_pass.clear();
        }
    }
    int gpu_platform     = std::atoi(
        get_arg(argc, argv, "gpu-platform", "0").c_str());
    int gpu_device       = std::atoi(
        get_arg(argc, argv, "gpu-device", "0").c_str());
    bool manual_batch    = has_arg(argc, argv, "batch-size");
    uint32_t batch_size  = manual_batch
        ? static_cast<uint32_t>(
              std::atoi(get_arg(argc, argv, "batch-size", "0").c_str()))
        : 0;  // 0 = auto-tune
    int power_pct = std::atoi(
        get_arg(argc, argv, "power", "100").c_str());
    if (power_pct < 1) power_pct = 1;
    if (power_pct > 100) power_pct = 100;

    // Suppress internal logging
    auto& logger = core::Logger::instance();
    logger.set_print_to_console(false);

    // ---------------------------------------------------------------
    // Initialize GPU (plain text startup)
    // ---------------------------------------------------------------
    std::cout << "\n  FTC Miner v2.2\n\n";

    std::cout << "  Initializing OpenCL..." << std::flush;

    gpu::OpenCLContext ctx;
    if (!ctx.init(gpu_platform, gpu_device)) {
        std::cout << " FAILED\n  No suitable GPU found. Use --gpu-list.\n";
        return 1;
    }

    auto dev = ctx.device_info();
    std::cout << " OK\n";
    std::cout << "  GPU:      " << dev.name << "\n";
    std::cout << "  Memory:   " << (dev.global_mem / (1024*1024)) << " MB"
              << "  CUs: " << dev.compute_units << "\n";

    gpu::GpuMiner miner(ctx);

    if (!miner.init()) {
        std::cout << "  Failed to initialize GPU miner\n";
        std::string log = ctx.get_build_log();
        if (!log.empty()) std::cout << "  Build log:\n" << log << "\n";
        return 1;
    }

    std::cout << "  GPU miner initialized\n";

    // ---------------------------------------------------------------
    // Auto-tune batch size
    // ---------------------------------------------------------------
    if (batch_size == 0) {
        std::cout << "  Auto-tuning batch size..." << std::flush;

        std::array<uint8_t, 80> dummy_hdr{};
        for (int i = 0; i < 80; ++i)
            dummy_hdr[i] = static_cast<uint8_t>((i * 37) & 0xFF);
        std::array<uint8_t, 32> dummy_target{};
        miner.set_header(std::span<const uint8_t>(dummy_hdr.data(), 80));
        miner.set_target(std::span<const uint8_t>(dummy_target.data(), 32));

        static constexpr uint32_t candidates[] = {
            1u << 18, 1u << 19, 1u << 20, 1u << 21,
            1u << 22, 1u << 23, 1u << 24, 1u << 25,
        };
        static constexpr int N_CANDIDATES =
            static_cast<int>(sizeof(candidates) / sizeof(candidates[0]));

        double best_rate = 0;
        uint32_t best_size = 1u << 22;

        miner.set_batch_size(1u << 20);
        miner.mine_batch(0, 1u << 20);

        for (int i = 0; i < N_CANDIDATES; ++i) {
            uint32_t sz = candidates[i];
            miner.set_batch_size(sz);

            miner.mine_batch(0, sz);
            if (miner.last_kernel_error() != 0) continue;

            auto t0 = std::chrono::steady_clock::now();
            miner.mine_batch(sz, sz);
            auto t1 = std::chrono::steady_clock::now();

            if (miner.last_kernel_error() != 0) continue;

            double secs = std::chrono::duration<double>(t1 - t0).count();
            double rate = static_cast<double>(sz) / secs;

            if (rate > best_rate) {
                best_rate = rate;
                best_size = sz;
            }

            if (secs > 4.0) break;
        }

        batch_size = best_size;
        std::cout << " " << format_number(batch_size)
                  << " nonces/dispatch (" << format_hashrate(best_rate)
                  << ")\n";
    }

    miner.set_batch_size(batch_size);

    // --test-keccak: validate and exit
    if (has_arg(argc, argv, "test-keccak")) {
        bool ok = run_keccak_test(miner);
        return ok ? 0 : 1;
    }

    if (address.empty()) {
        std::cerr << "Error: --address is required\n";
        return 1;
    }

    // ---------------------------------------------------------------
    // Prepare TUI state
    // ---------------------------------------------------------------
    TuiState state;
    state.gpu_name = dev.name;
    state.gpu_mem_mb = static_cast<int>(dev.global_mem / (1024*1024));
    state.gpu_cus = static_cast<int>(dev.compute_units);
    state.address = address;
    state.node = rpc_host + ":" + std::to_string(rpc_port);
    state.auth_mode = (g_rpc_user == "__cookie__") ? "cookie"
                    : g_rpc_user.empty() ? "none" : "rpcuser";
    state.start_time = current_datetime();
    state.batch_size = batch_size;
    state.power_pct = power_pct;
    auto now = std::chrono::steady_clock::now();
    state.session_start = now;
    state.window_start = now;

    // Start background height poller
    std::thread poller(height_poll_thread, rpc_host, rpc_port);

    // Clear screen and enter TUI mode
    if (g_ansi) std::cout << "\033[2J\033[H" << std::flush;

    tui_log("Mining started");
    tui_redraw(state);

    // Periodic TUI refresh interval
    auto last_redraw = std::chrono::steady_clock::now();
    static constexpr double REDRAW_INTERVAL = 1.0;

    // ---------------------------------------------------------------
    // Mining loop
    // ---------------------------------------------------------------
    while (!g_stop) {
        g_work_stale = false;

        // 1. Fetch work
        std::string resp = rpc_call(rpc_host, rpc_port, "getwork",
                                    "[\"" + address + "\"]");
        if (resp.empty()) {
            tui_log("RPC connection failed, retrying in 5s...");
            tui_redraw(state);
            for (int i = 0; i < 50 && !g_stop; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        rpc::JsonValue json;
        try {
            json = rpc::parse_json(resp);
        } catch (const std::exception& e) {
            tui_log(std::string("JSON error: ") + e.what());
            tui_redraw(state);
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        if (!json["result"].is_object()) {
            tui_log("RPC error: " + rpc::json_serialize(json["error"]));
            tui_redraw(state);
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        auto& result = json["result"];
        std::string header_hex = result["header"].get_string();
        std::string target_hex = result["target"].get_string();
        int64_t height = result["height"].get_int();
        int64_t work_id = result["work_id"].is_int()
            ? result["work_id"].get_int() : 0;

        // 2. Deserialize header and target
        auto header_opt = core::from_hex(header_hex);
        if (!header_opt || header_opt->size() < 80) {
            tui_log("Invalid header hex from RPC");
            tui_redraw(state);
            continue;
        }

        auto target = core::uint256::from_hex(target_hex);

        // Compute difficulty from nBits
        {
            auto& hb = *header_opt;
            uint32_t nbits =
                static_cast<uint32_t>(hb[72])       |
                (static_cast<uint32_t>(hb[73]) << 8) |
                (static_cast<uint32_t>(hb[74]) << 16) |
                (static_cast<uint32_t>(hb[75]) << 24);
            state.difficulty = get_difficulty(nbits);
        }

        // Log new block height
        if (height != state.height) {
            state.height = height;
            tui_log("New job  block " + std::to_string(height) +
                    "  diff " + format_diff(state.difficulty));
            tui_redraw(state);
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

        // Read initial timestamp from header bytes [68..71]
        auto& hdr_bytes = *header_opt;
        uint32_t cur_timestamp =
            static_cast<uint32_t>(hdr_bytes[68])       |
            (static_cast<uint32_t>(hdr_bytes[69]) << 8) |
            (static_cast<uint32_t>(hdr_bytes[70]) << 16) |
            (static_cast<uint32_t>(hdr_bytes[71]) << 24);

        // 3. GPU mining loop with timestamp rolling
        g_chain_height = height;

        while (!g_stop && !found && !g_work_stale) {
            for (uint32_t base_nonce = 0;
                 !g_stop && !found && !g_work_stale; ) {
                uint64_t remaining64 =
                    static_cast<uint64_t>(UINT32_MAX) - base_nonce + 1;
                if (remaining64 == 0) break;
                uint32_t this_batch = static_cast<uint32_t>(
                    std::min(static_cast<uint64_t>(batch_size), remaining64));
                if (this_batch == 0) break;

                auto dispatch_t0 = std::chrono::steady_clock::now();
                auto results = miner.mine_batch(base_nonce, this_batch);
                auto dispatch_t1 = std::chrono::steady_clock::now();

                // Power throttle
                if (power_pct < 100) {
                    double dispatch_ms = std::chrono::duration<double,
                        std::milli>(dispatch_t1 - dispatch_t0).count();
                    double sleep_ms = dispatch_ms *
                        (100.0 - power_pct) / power_pct;
                    if (sleep_ms > 1.0) {
                        std::this_thread::sleep_for(
                            std::chrono::microseconds(
                                static_cast<int64_t>(sleep_ms * 1000)));
                    }
                }

                if (miner.last_kernel_error() != 0) {
                    tui_log("GPU kernel error (OpenCL code " +
                        std::to_string(miner.last_kernel_error()) +
                        "). Try --batch-size=1048576");
                    tui_redraw(state);
                    found = false;
                    g_stop = true;
                    break;
                }

                block_hashes += this_batch;
                state.add_hashes(this_batch);

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

                // Periodic TUI refresh
                auto tnow = std::chrono::steady_clock::now();
                double since_redraw = std::chrono::duration<double>(
                    tnow - last_redraw).count();
                if (since_redraw >= REDRAW_INTERVAL) {
                    tui_redraw(state);
                    last_redraw = tnow;
                }
            }

            if (found || g_stop || g_work_stale) break;

            // Nonce space exhausted — roll timestamp
            ++cur_timestamp;

            auto real_time = static_cast<uint32_t>(std::time(nullptr));
            if (cur_timestamp > real_time + 30) break;

            hdr_bytes[68] = cur_timestamp & 0xFF;
            hdr_bytes[69] = (cur_timestamp >> 8) & 0xFF;
            hdr_bytes[70] = (cur_timestamp >> 16) & 0xFF;
            hdr_bytes[71] = (cur_timestamp >> 24) & 0xFF;

            miner.set_header(std::span<const uint8_t>(
                hdr_bytes.data(), 80));
        }

        auto block_elapsed = std::chrono::steady_clock::now() - block_start;
        double block_secs = std::chrono::duration<double>(
            block_elapsed).count();

        if (!found) {
            if (g_stop) break;
            continue;
        }

        // 4. Submit solution
        tui_log("BLOCK FOUND  height " + std::to_string(height) +
                "  solve " + format_duration(block_secs));
        tui_redraw(state);

        std::string submit_resp = rpc_call(
            rpc_host, rpc_port, "submitwork",
            "[" + std::to_string(winning_nonce) + "," +
            std::to_string(work_id) + "," +
            std::to_string(cur_timestamp) + "]");

        if (submit_resp.empty()) {
            ++state.blocks_rejected;
            tui_log("Submit failed -- node unreachable");
            tui_redraw(state);
            continue;
        }

        rpc::JsonValue submit_json;
        try {
            submit_json = rpc::parse_json(submit_resp);
        } catch (const std::exception& e) {
            ++state.blocks_rejected;
            tui_log(std::string("Submit parse error: ") + e.what());
            tui_redraw(state);
            continue;
        }

        if (submit_json["result"].is_string()) {
            ++state.blocks_found;
            std::string block_hash = submit_json["result"].get_string();

            g_block_history.push_back({
                height, block_hash, block_secs, current_timestamp()
            });

            tui_log("Accepted #" + std::to_string(state.blocks_found) +
                    "  " + block_hash.substr(0, 24) + "...");
        } else {
            ++state.blocks_rejected;
            tui_log("Rejected: " +
                    rpc::json_serialize(submit_json["error"]));
        }
        tui_redraw(state);
    }

    // Stop the height poller thread
    g_stop = true;
    if (poller.joinable()) poller.join();

    // ---------------------------------------------------------------
    // Session summary (below TUI)
    // ---------------------------------------------------------------
    tui_redraw(state);  // final update

    double session_secs = state.uptime();
    double session_rate = session_secs > 0.01
        ? static_cast<double>(state.session_hashes) / session_secs : 0;

    std::cout << "\n"
              << "=== Session Summary ===\n"
              << "Uptime:   " << format_duration(session_secs) << "\n"
              << "Avg rate: " << format_hashrate(session_rate) << "\n"
              << "Hashes:   " << format_number(state.session_hashes) << "\n"
              << "Found:    " << state.blocks_found;
    if (state.blocks_rejected > 0) {
        std::cout << "  Rejected: " << state.blocks_rejected;
    }
    std::cout << "\n\n";

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
