// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// ftc-miner-gpu — standalone multi-GPU-accelerated FTC miner
//
// Same RPC protocol as ftc-miner (getwork/submitwork), but uses OpenCL
// to grind nonces on one or more GPUs.  PoW: keccak256d(header_80bytes) <= target.
//
// Usage:
//   ftc-miner-gpu --address=ADDR [--rpc-host=HOST] [--gpu-devices=all]
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
#include <memory>
#include <mutex>
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

// Multi-GPU solution sharing
static std::atomic<bool> g_solution_found{false};
static std::atomic<uint32_t> g_solution_nonce{0};
static std::atomic<uint32_t> g_solution_timestamp{0};
static std::atomic<int> g_solution_gpu{-1};
static std::atomic<int> g_active_threads{0};  // tracks running GPU threads

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
// Per-GPU worker state
// ---------------------------------------------------------------------------
struct GpuWorker {
    gpu::OpenCLContext ctx;
    std::unique_ptr<gpu::GpuMiner> miner;
    gpu::DeviceInfo info;
    uint32_t batch_size = 0;
    int gpu_index = 0;        // sequential index (0, 1, 2...)
    int device_index = 0;     // OpenCL device index
    int platform_index = 0;   // OpenCL platform index

    // Per-GPU hashrate tracking (atomics for thread safety)
    std::atomic<uint64_t> session_hashes{0};
    std::atomic<uint64_t> window_hashes{0};
    std::chrono::steady_clock::time_point window_start;
    double window_rate = 0;
    int power_pct = 100;
};

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
// Parse --gpu-devices argument: "all", "0", "0,2,3", etc.
// ---------------------------------------------------------------------------
static std::vector<int> parse_gpu_devices(const std::string& arg,
                                          int total_devices) {
    std::vector<int> result;
    if (arg.empty() || arg == "all") {
        for (int i = 0; i < total_devices; ++i) result.push_back(i);
        return result;
    }
    std::istringstream ss(arg);
    std::string token;
    while (std::getline(ss, token, ',')) {
        int idx = std::atoi(token.c_str());
        if (idx >= 0 && idx < total_devices) result.push_back(idx);
    }
    return result;
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
// TUI — cgminer-style static dashboard (multi-GPU)
// ---------------------------------------------------------------------------

// ANSI color helpers — emit codes only when g_ansi is true
#define C_RESET   (g_ansi ? "\033[0m"    : "")
#define C_BOLD    (g_ansi ? "\033[1m"    : "")
#define C_DIM     (g_ansi ? "\033[2m"    : "")
#define C_RED     (g_ansi ? "\033[31m"   : "")
#define C_GREEN   (g_ansi ? "\033[32m"   : "")
#define C_YELLOW  (g_ansi ? "\033[33m"   : "")
#define C_BLUE    (g_ansi ? "\033[34m"   : "")
#define C_CYAN    (g_ansi ? "\033[36m"   : "")
#define C_WHITE   (g_ansi ? "\033[37m"   : "")
#define C_BGREEN  (g_ansi ? "\033[1;32m" : "")
#define C_BYELLOW (g_ansi ? "\033[1;33m" : "")
#define C_BCYAN   (g_ansi ? "\033[1;36m" : "")
#define C_BWHITE  (g_ansi ? "\033[1;37m" : "")
#define C_BRED    (g_ansi ? "\033[1;31m" : "")

static std::vector<std::string> g_tui_log;
static constexpr size_t TUI_MAX_LOG = 50;

static void tui_log(const std::string& msg) {
    g_tui_log.push_back("[" + current_timestamp() + "] " + msg);
    if (g_tui_log.size() > TUI_MAX_LOG)
        g_tui_log.erase(g_tui_log.begin());
}

struct TuiState {
    // Static info
    std::string address;
    std::string node;
    std::string auth_mode;
    std::string start_time;
    int power_pct = 100;

    // Dynamic info
    int64_t height = 0;
    double difficulty = 0;
    int blocks_found = 0;
    int blocks_rejected = 0;

    // Workers
    std::vector<GpuWorker*> workers;

    // Session timing
    std::chrono::steady_clock::time_point session_start;

    uint64_t total_session_hashes() const {
        uint64_t total = 0;
        for (auto* w : workers)
            total += w->session_hashes.load(std::memory_order_relaxed);
        return total;
    }

    double avg_hashrate() const {
        double s = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - session_start).count();
        return s > 0.5 ? static_cast<double>(total_session_hashes()) / s : 0;
    }

    double total_current_hashrate() const {
        double total = 0;
        for (auto* w : workers) {
            // Use the cached window_rate
            total += w->window_rate;
        }
        return total;
    }

    void update_window_rates() {
        auto now = std::chrono::steady_clock::now();
        for (auto* w : workers) {
            double s = std::chrono::duration<double>(
                now - w->window_start).count();
            if (s >= 10.0) {
                uint64_t wh = w->window_hashes.exchange(0,
                    std::memory_order_relaxed);
                w->window_rate = static_cast<double>(wh) / s;
                w->window_start = now;
            } else if (w->window_rate == 0 && s > 0.5) {
                // Initial estimate before first window
                w->window_rate = static_cast<double>(
                    w->window_hashes.load(std::memory_order_relaxed)) / s;
            }
        }
    }

    double uptime() const {
        return std::chrono::duration<double>(
            std::chrono::steady_clock::now() - session_start).count();
    }
};

static void tui_redraw(TuiState& st) {
    st.update_window_rates();
    double rate = st.total_current_hashrate();
    double avg = st.avg_hashrate();
    double up = st.uptime();
    double expected = st.difficulty * 4294967296.0;
    double eta = (rate > 0 && expected > 0) ? expected / rate : 0;

    std::ostringstream buf;

    if (g_ansi) buf << "\033[H";  // cursor home

    // Line 1: title bar
    buf << C_BCYAN << "FTC Miner v2.3" << C_RESET
        << C_DIM << " - Started: [" << st.start_time << "]" << C_RESET;
    if (g_ansi) buf << "\033[K";
    buf << "\n";

    // Line 2: blank
    if (g_ansi) buf << "\033[K";
    buf << "\n";

    // Line 3: hashrate + stats
    buf << C_WHITE << "(10s):" << C_BGREEN << format_hashrate(rate) << C_RESET
        << C_WHITE << " (avg):" << C_GREEN << format_hashrate(avg) << C_RESET
        << C_DIM << " | " << C_RESET
        << C_WHITE << "Found:" << C_BGREEN << st.blocks_found << C_RESET
        << " " << C_WHITE << "R:" << C_RESET;
    if (st.blocks_rejected > 0)
        buf << C_BRED << st.blocks_rejected << C_RESET;
    else
        buf << C_DIM << "0" << C_RESET;
    buf << C_DIM << " | " << C_RESET
        << C_WHITE << "Up:" << C_CYAN << format_duration(up) << C_RESET;
    if (g_ansi) buf << "\033[K";
    buf << "\n";

    // Line 4: block info
    buf << C_WHITE << "Block:" << C_BWHITE << st.height << C_RESET
        << "  " << C_WHITE << "Diff:" << C_YELLOW << format_diff(st.difficulty) << C_RESET
        << "  " << C_WHITE << "ETA:" << C_BYELLOW
        << (eta > 0 ? "~" + format_duration(eta) : "---") << C_RESET;
    if (st.power_pct < 100)
        buf << "  " << C_WHITE << "Power:" << C_YELLOW << st.power_pct << "%" << C_RESET;
    if (g_ansi) buf << "\033[K";
    buf << "\n";

    // Line 5: connection info
    buf << C_DIM << "Node:" << st.node
        << "  Auth:" << st.auth_mode
        << "  Addr:" << st.address << C_RESET;
    if (g_ansi) buf << "\033[K";
    buf << "\n";

    // Line 6: blank
    if (g_ansi) buf << "\033[K";
    buf << "\n";

    // Lines 7+: per-GPU status
    for (auto* w : st.workers) {
        buf << C_BWHITE << "GPU " << w->gpu_index << C_RESET
            << C_DIM << ": " << C_RESET
            << C_CYAN << w->info.name << C_RESET
            << C_DIM << " | " << C_RESET
            << C_WHITE << (w->info.global_mem / (1024*1024)) << " MB  "
            << w->info.compute_units << " CUs" << C_RESET
            << C_DIM << " | " << C_RESET
            << C_BGREEN << format_hashrate(w->window_rate) << C_RESET
            << "  " << C_DIM << "Batch:" << format_number(w->batch_size) << C_RESET;
        if (g_ansi) buf << "\033[K";
        buf << "\n";
    }

    // Total line (multi-GPU only)
    if (st.workers.size() > 1) {
        buf << C_BWHITE << "Total: " << st.workers.size() << " GPUs" << C_RESET
            << C_DIM << " | " << C_RESET
            << C_BGREEN << format_hashrate(rate) << C_RESET;
        if (g_ansi) buf << "\033[K";
        buf << "\n";
    }

    // Separator
    buf << C_DIM << std::string(72, '-') << C_RESET;
    if (g_ansi) buf << "\033[K";
    buf << "\n";

    // Event log
    for (const auto& line : g_tui_log) {
        // Colorize important log events
        if (line.find("BLOCK FOUND") != std::string::npos ||
            line.find("Accepted") != std::string::npos) {
            buf << C_BGREEN << line << C_RESET;
        } else if (line.find("Rejected") != std::string::npos ||
                   line.find("failed") != std::string::npos ||
                   line.find("error") != std::string::npos ||
                   line.find("Error") != std::string::npos) {
            buf << C_BRED << line << C_RESET;
        } else if (line.find("New job") != std::string::npos) {
            buf << C_DIM << line << C_RESET;
        } else {
            buf << C_WHITE << line << C_RESET;
        }
        if (g_ansi) buf << "\033[K";
        buf << "\n";
    }

    // Clear any stale content below
    if (g_ansi) buf << "\033[J";

    std::cout << buf.str() << std::flush;
}

// ---------------------------------------------------------------------------
// GPU mining thread function
// ---------------------------------------------------------------------------
static void gpu_mine_thread(GpuWorker& worker,
                            const std::vector<uint8_t>& header_bytes,
                            const core::uint256& target,
                            uint32_t nonce_start,
                            uint32_t nonce_count,
                            uint32_t timestamp) {
    // RAII guard to decrement active thread count on exit
    struct ThreadGuard {
        ~ThreadGuard() { g_active_threads.fetch_sub(1, std::memory_order_release); }
    } guard;

    auto& miner = *worker.miner;

    // Each thread gets its own copy of the header for timestamp rolling
    auto hdr = header_bytes;

    // Set header and target on this GPU
    miner.set_header(std::span<const uint8_t>(hdr.data(), 80));
    miner.set_target(std::span<const uint8_t>(target.data(), 32));

    uint32_t cur_timestamp = timestamp;
    uint32_t batch = worker.batch_size;

    while (!g_stop && !g_solution_found && !g_work_stale) {
        // Mine through the nonce range for this GPU
        for (uint64_t offset = 0;
             !g_stop && !g_solution_found && !g_work_stale; ) {

            uint64_t abs_nonce = static_cast<uint64_t>(nonce_start) + offset;
            if (abs_nonce > UINT32_MAX) break;

            uint64_t remaining = static_cast<uint64_t>(nonce_count) - offset;
            if (remaining == 0) break;

            uint32_t this_batch = static_cast<uint32_t>(
                std::min(static_cast<uint64_t>(batch), remaining));
            if (this_batch == 0) break;

            auto dispatch_t0 = std::chrono::steady_clock::now();
            auto results = miner.mine_batch(
                static_cast<uint32_t>(abs_nonce), this_batch);
            auto dispatch_t1 = std::chrono::steady_clock::now();

            // Power throttle
            if (worker.power_pct < 100) {
                double dispatch_ms = std::chrono::duration<double,
                    std::milli>(dispatch_t1 - dispatch_t0).count();
                double sleep_ms = dispatch_ms *
                    (100.0 - worker.power_pct) / worker.power_pct;
                if (sleep_ms > 1.0) {
                    std::this_thread::sleep_for(
                        std::chrono::microseconds(
                            static_cast<int64_t>(sleep_ms * 1000)));
                }
            }

            if (miner.last_kernel_error() != 0) {
                // GPU error — stop this thread
                g_stop = true;
                break;
            }

            // Update hash counters
            worker.session_hashes.fetch_add(this_batch,
                std::memory_order_relaxed);
            worker.window_hashes.fetch_add(this_batch,
                std::memory_order_relaxed);

            // Check results
            if (!results.empty()) {
                for (uint32_t nonce : results) {
                    // CPU-verify the result
                    auto verify_hdr = hdr;
                    verify_hdr[76] = nonce & 0xFF;
                    verify_hdr[77] = (nonce >> 8) & 0xFF;
                    verify_hdr[78] = (nonce >> 16) & 0xFF;
                    verify_hdr[79] = (nonce >> 24) & 0xFF;

                    auto cpu_hash = crypto::keccak256d(
                        std::span<const uint8_t>(verify_hdr.data(), 80));

                    if (cpu_hash <= target) {
                        // Found a valid solution!
                        bool expected = false;
                        if (g_solution_found.compare_exchange_strong(
                                expected, true)) {
                            g_solution_nonce = nonce;
                            g_solution_timestamp = cur_timestamp;
                            g_solution_gpu = worker.gpu_index;
                        }
                        return;
                    }
                }
            }

            offset += this_batch;
        }

        // Nonce range exhausted for this GPU — roll timestamp
        ++cur_timestamp;
        auto real_time = static_cast<uint32_t>(std::time(nullptr));
        if (cur_timestamp > real_time + 30) break;

        hdr[68] = cur_timestamp & 0xFF;
        hdr[69] = (cur_timestamp >> 8) & 0xFF;
        hdr[70] = (cur_timestamp >> 16) & 0xFF;
        hdr[71] = (cur_timestamp >> 24) & 0xFF;

        miner.set_header(std::span<const uint8_t>(hdr.data(), 80));
    }
}

// ---------------------------------------------------------------------------
// Auto-tune batch size for a single GPU
// ---------------------------------------------------------------------------
static uint32_t auto_tune_gpu(gpu::GpuMiner& miner) {
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

    // Warm up
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
        double rate_val = static_cast<double>(sz) / secs;

        if (rate_val > best_rate) {
            best_rate = rate_val;
            best_size = sz;
        }

        if (secs > 4.0) break;
    }

    miner.set_batch_size(best_size);
    return best_size;
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
        for (size_t i = 0; i < devices.size(); ++i) {
            auto& d = devices[i];
            std::cout << "  [" << i << "] " << d.name
                      << "  (platform:" << d.platform_index
                      << " device:" << d.device_index << ")\n"
                      << "      Vendor: " << d.vendor
                      << "  Memory: " << (d.global_mem / (1024*1024)) << " MB"
                      << "  CUs: " << d.compute_units
                      << "  Driver: " << d.driver_version << "\n\n";
        }
        return 0;
    }

    if (has_arg(argc, argv, "help") || argc < 2) {
        std::cout << "FTC GPU Miner v2.3 (multi-GPU)\n\n"
                  << "Usage: ftc-miner-gpu --address=ADDR [options]\n\n"
                  << "Options:\n"
                  << "  --address=ADDR       Mining reward address (required)\n"
                  << "  --rpc-host=HOST      RPC server host (default: 127.0.0.1)\n"
                  << "  --rpc-port=PORT      RPC server port (default: 9332)\n"
                  << "  --rpc-user=USER      RPC username (default: auto from .cookie)\n"
                  << "  --rpc-pass=PASS      RPC password (default: auto from .cookie)\n"
                  << "  --gpu-devices=LIST   GPU devices: 'all' or comma-separated indices\n"
                  << "                       (default: all). Use --gpu-list for indices.\n"
                  << "  --gpu-device=N       Use single GPU N (backward compat)\n"
                  << "  --batch-size=N       Nonces per GPU dispatch (default: auto-tune)\n"
                  << "  --power=N            GPU power limit 1-100% (default: 100)\n"
                  << "                       Use 60-80 on laptops to prevent overheating\n"
                  << "  --gpu-list           List available GPU devices and exit\n"
                  << "  --test-keccak        Validate GPU Keccak256d against CPU\n"
                  << "  --help               Show this help\n\n"
                  << "Examples:\n"
                  << "  ftc-miner-gpu --address=1A73WPJ...  (use all GPUs)\n"
                  << "  ftc-miner-gpu --address=1A73WPJ... --gpu-devices=0,2,3\n"
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
    // Enumerate and select GPUs
    // ---------------------------------------------------------------
    std::cout << "\n  FTC Miner v2.3 (multi-GPU)\n\n";

    auto all_devices = gpu::OpenCLContext::list_devices();
    if (all_devices.empty()) {
        std::cout << "  No OpenCL GPU devices found.\n";
        return 1;
    }

    // Determine which GPUs to use
    std::vector<int> selected_indices;
    if (has_arg(argc, argv, "gpu-devices")) {
        selected_indices = parse_gpu_devices(
            get_arg(argc, argv, "gpu-devices", "all"),
            static_cast<int>(all_devices.size()));
    } else if (has_arg(argc, argv, "gpu-device")) {
        // Backward compat: --gpu-device=N selects single GPU
        int idx = std::atoi(get_arg(argc, argv, "gpu-device", "0").c_str());
        if (idx >= 0 && idx < static_cast<int>(all_devices.size()))
            selected_indices.push_back(idx);
    } else {
        // Default: all GPUs
        for (int i = 0; i < static_cast<int>(all_devices.size()); ++i)
            selected_indices.push_back(i);
    }

    if (selected_indices.empty()) {
        std::cout << "  No valid GPU indices selected. Use --gpu-list.\n";
        return 1;
    }

    // ---------------------------------------------------------------
    // Initialize GPU workers
    // ---------------------------------------------------------------
    std::vector<std::unique_ptr<GpuWorker>> workers;

    for (int sel_idx : selected_indices) {
        auto& dev_info = all_devices[sel_idx];
        auto worker = std::make_unique<GpuWorker>();
        worker->gpu_index = static_cast<int>(workers.size());
        worker->device_index = dev_info.device_index;
        worker->platform_index = dev_info.platform_index;
        worker->power_pct = power_pct;

        std::cout << "  Initializing GPU " << worker->gpu_index
                  << " [" << sel_idx << "]..." << std::flush;

        if (!worker->ctx.init(dev_info.platform_index, dev_info.device_index)) {
            std::cout << " FAILED (OpenCL init)\n";
            continue;
        }

        worker->info = worker->ctx.device_info();
        worker->miner = std::make_unique<gpu::GpuMiner>(worker->ctx);

        if (!worker->miner->init()) {
            std::cout << " FAILED (miner init)\n";
            std::string log = worker->ctx.get_build_log();
            if (!log.empty()) std::cout << "  Build log:\n" << log << "\n";
            continue;
        }

        std::cout << " OK  " << worker->info.name
                  << "  " << (worker->info.global_mem / (1024*1024)) << " MB"
                  << "  " << worker->info.compute_units << " CUs\n";

        // Auto-tune or set manual batch size
        if (batch_size == 0) {
            std::cout << "  Auto-tuning GPU " << worker->gpu_index
                      << "..." << std::flush;
            worker->batch_size = auto_tune_gpu(*worker->miner);
            std::cout << " " << format_number(worker->batch_size)
                      << " nonces/dispatch\n";
        } else {
            worker->batch_size = batch_size;
            worker->miner->set_batch_size(batch_size);
        }

        workers.push_back(std::move(worker));
    }

    if (workers.empty()) {
        std::cout << "  No GPUs initialized successfully.\n";
        return 1;
    }

    std::cout << "  " << workers.size() << " GPU(s) ready\n";

    // --test-keccak: validate first GPU and exit
    if (has_arg(argc, argv, "test-keccak")) {
        bool ok = run_keccak_test(*workers[0]->miner);
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
    state.address = address;
    state.node = rpc_host + ":" + std::to_string(rpc_port);
    state.auth_mode = (g_rpc_user == "__cookie__") ? "cookie"
                    : g_rpc_user.empty() ? "none" : "rpcuser";
    state.start_time = current_datetime();
    state.power_pct = power_pct;
    auto now = std::chrono::steady_clock::now();
    state.session_start = now;

    for (auto& w : workers) {
        w->window_start = now;
        state.workers.push_back(w.get());
    }

    // Start background height poller
    std::thread poller(height_poll_thread, rpc_host, rpc_port);

    // Clear screen and enter TUI mode
    if (g_ansi) std::cout << "\033[2J\033[H" << std::flush;

    tui_log("Mining started with " + std::to_string(workers.size()) + " GPU(s)");
    tui_redraw(state);

    // Periodic TUI refresh interval
    auto last_redraw = std::chrono::steady_clock::now();
    static constexpr double REDRAW_INTERVAL = 1.0;

    int num_gpus = static_cast<int>(workers.size());

    // ---------------------------------------------------------------
    // Mining loop
    // ---------------------------------------------------------------
    while (!g_stop) {
        g_work_stale = false;
        g_solution_found = false;
        g_solution_nonce = 0;
        g_solution_timestamp = 0;
        g_solution_gpu = -1;

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

        // Read initial timestamp from header bytes [68..71]
        auto& hdr_bytes = *header_opt;
        uint32_t cur_timestamp =
            static_cast<uint32_t>(hdr_bytes[68])       |
            (static_cast<uint32_t>(hdr_bytes[69]) << 8) |
            (static_cast<uint32_t>(hdr_bytes[70]) << 16) |
            (static_cast<uint32_t>(hdr_bytes[71]) << 24);

        // 3. Partition nonce space and launch GPU threads
        g_chain_height = height;
        auto block_start = std::chrono::steady_clock::now();

        // Each GPU gets UINT32_MAX / num_gpus nonces
        // Use uint64_t to avoid overflow
        uint64_t total_nonces = static_cast<uint64_t>(UINT32_MAX) + 1;
        uint64_t stride = total_nonces / num_gpus;

        std::vector<std::thread> gpu_threads;
        gpu_threads.reserve(num_gpus);
        g_active_threads = num_gpus;

        for (int i = 0; i < num_gpus; ++i) {
            uint32_t nonce_start = static_cast<uint32_t>(
                static_cast<uint64_t>(i) * stride);
            uint32_t nonce_count = (i == num_gpus - 1)
                ? static_cast<uint32_t>(total_nonces - i * stride)
                : static_cast<uint32_t>(stride);

            gpu_threads.emplace_back(gpu_mine_thread,
                std::ref(*workers[i]),
                std::cref(*header_opt),
                std::cref(target),
                nonce_start,
                nonce_count,
                cur_timestamp);
        }

        // 4. Wait for threads, refreshing TUI periodically
        while (!g_stop) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

            // Check termination conditions
            if (g_solution_found || g_work_stale || g_stop) break;

            // All threads finished (nonce space exhausted)
            if (g_active_threads.load(std::memory_order_acquire) == 0) break;

            // TUI refresh
            auto tnow = std::chrono::steady_clock::now();
            double since_redraw = std::chrono::duration<double>(
                tnow - last_redraw).count();
            if (since_redraw >= REDRAW_INTERVAL) {
                tui_redraw(state);
                last_redraw = tnow;
            }
        }

        // Join all threads
        for (auto& t : gpu_threads) {
            if (t.joinable()) t.join();
        }

        auto block_elapsed = std::chrono::steady_clock::now() - block_start;
        double block_secs = std::chrono::duration<double>(
            block_elapsed).count();

        if (!g_solution_found) {
            if (g_stop) break;
            continue;
        }

        // 5. Submit solution
        uint32_t winning_nonce = g_solution_nonce.load();
        uint32_t winning_timestamp = g_solution_timestamp.load();
        int winning_gpu = g_solution_gpu.load();

        tui_log("BLOCK FOUND by GPU " + std::to_string(winning_gpu) +
                "  height " + std::to_string(height) +
                "  solve " + format_duration(block_secs));
        tui_redraw(state);

        std::string submit_resp = rpc_call(
            rpc_host, rpc_port, "submitwork",
            "[" + std::to_string(winning_nonce) + "," +
            std::to_string(work_id) + "," +
            std::to_string(winning_timestamp) + "]");

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
    uint64_t total_hashes = state.total_session_hashes();
    double session_rate = session_secs > 0.01
        ? static_cast<double>(total_hashes) / session_secs : 0;

    std::cout << "\n"
              << "=== Session Summary ===\n"
              << "GPUs:     " << workers.size() << "\n"
              << "Uptime:   " << format_duration(session_secs) << "\n"
              << "Avg rate: " << format_hashrate(session_rate) << "\n"
              << "Hashes:   " << format_number(total_hashes) << "\n"
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
