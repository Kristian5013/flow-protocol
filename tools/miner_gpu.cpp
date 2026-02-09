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
#include <cstring>
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
                  << "  --rpc-user=USER      RPC username (default: ftcuser)\n"
                  << "  --rpc-pass=PASS      RPC password (default: ftcpass)\n"
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
    g_rpc_user           = get_arg(argc, argv, "rpc-user", "ftcuser");
    g_rpc_pass           = get_arg(argc, argv, "rpc-pass", "ftcpass");
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
    std::cout << "\n";
    std::cout << color::bold() << color::cyan()
              << "  +===================================+\n"
              << "  |       FTC GPU Miner v2.0          |\n"
              << "  +===================================+"
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
    std::cout << "  " << color::dim() << "Press Ctrl+C to stop"
              << color::reset() << "\n\n";

    int blocks_mined = 0;
    auto session_start = std::chrono::steady_clock::now();
    uint64_t session_hashes = 0;

    while (!g_stop) {
        // ---------------------------------------------------------------
        // 1. Fetch work from node
        // ---------------------------------------------------------------
        std::cout << "  " << color::dim() << "[" << current_timestamp() << "]"
                  << color::reset() << " Fetching work..." << std::flush;

        std::string resp = rpc_call(rpc_host, rpc_port, "getwork",
                                    "[\"" + address + "\"]");
        if (resp.empty()) {
            std::cout << "\r  " << color::dim() << "[" << current_timestamp()
                      << "]" << color::reset() << " " << color::red()
                      << "Failed to connect. Retrying in 5s..."
                      << color::reset() << std::endl;
            for (int i = 0; i < 50 && !g_stop; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        rpc::JsonValue json;
        try {
            json = rpc::parse_json(resp);
        } catch (const std::exception& e) {
            std::cout << "\r  " << color::dim() << "[" << current_timestamp()
                      << "]" << color::reset() << " " << color::red()
                      << "JSON error: " << e.what()
                      << color::reset() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        if (!json["result"].is_object()) {
            std::cout << "\r  " << color::dim() << "[" << current_timestamp()
                      << "]" << color::reset() << " " << color::red()
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
            std::cerr << "\r  " << color::red()
                      << "Invalid header hex" << color::reset() << std::endl;
            continue;
        }

        auto target = core::uint256::from_hex(target_hex);

        std::cout << "\r  " << color::dim() << "[" << current_timestamp()
                  << "]" << color::reset() << " " << color::bold()
                  << "Mining block " << height << color::reset()
                  << "  " << color::dim() << "target: "
                  << target_hex.substr(0, 16) << "..."
                  << color::reset() << std::endl;

        // Upload header and target to GPU
        miner.set_header(std::span<const uint8_t>(
            header_opt->data(), 80));
        miner.set_target(std::span<const uint8_t>(
            target.data(), 32));

        auto block_start = std::chrono::steady_clock::now();
        bool found = false;
        uint32_t winning_nonce = 0;
        uint64_t block_hashes = 0;

        // ---------------------------------------------------------------
        // 3. GPU mining loop: dispatch batches of nonces
        // ---------------------------------------------------------------
        for (uint32_t base_nonce = 0; !g_stop && !found; ) {
            // Compute actual batch size using 64-bit to avoid overflow.
            // remaining64 = number of nonces left (including base_nonce).
            uint64_t remaining64 =
                static_cast<uint64_t>(UINT32_MAX) - base_nonce + 1;
            if (remaining64 == 0) break;  // Full nonce space exhausted
            uint32_t this_batch = static_cast<uint32_t>(
                std::min(static_cast<uint64_t>(batch_size), remaining64));
            if (this_batch == 0) break;

            auto results = miner.mine_batch(base_nonce, this_batch);
            block_hashes += this_batch;

            if (!results.empty()) {
                // CPU verification: double-check the GPU result
                for (uint32_t nonce : results) {
                    // Reconstruct header with this nonce
                    auto hdr = *header_opt;
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

            // Advance base nonce (64-bit to detect overflow)
            uint64_t next = static_cast<uint64_t>(base_nonce) + this_batch;
            if (next > UINT32_MAX) break;
            base_nonce = static_cast<uint32_t>(next);

            // Update progress
            auto now = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(
                now - block_start).count();
            double hash_rate = elapsed > 0.01
                ? static_cast<double>(block_hashes) / elapsed : 0;

            std::ostringstream line;
            line << "\r  " << color::dim() << "  " << color::reset()
                 << color::cyan() << format_hashrate(hash_rate)
                 << color::reset()
                 << "  " << color::dim() << format_number(block_hashes)
                 << " hashes"
                 << "  " << format_duration(elapsed)
                 << color::reset() << "      ";
            std::cout << line.str() << std::flush;
        }

        // Clear progress line
        std::cout << "\r" << std::string(80, ' ') << "\r";

        session_hashes += block_hashes;

        auto block_elapsed = std::chrono::steady_clock::now() - block_start;
        double block_secs = std::chrono::duration<double>(
            block_elapsed).count();
        double block_rate = block_secs > 0.01
            ? static_cast<double>(block_hashes) / block_secs : 0;

        if (!found) {
            if (g_stop) break;
            std::cout << "  " << color::dim() << "[" << current_timestamp()
                      << "]" << color::reset() << " " << color::yellow()
                      << "Nonce space exhausted, fetching new work..."
                      << color::reset() << std::endl;
            continue;
        }

        std::cout << "  " << color::dim() << "[" << current_timestamp()
                  << "]" << color::reset() << " " << color::green()
                  << color::bold() << "Solution found!"
                  << color::reset()
                  << "  nonce=" << winning_nonce
                  << "  " << color::dim() << format_duration(block_secs)
                  << color::reset()
                  << "  " << format_hashrate(block_rate)
                  << "  " << format_number(block_hashes) << " hashes"
                  << std::endl;

        // ---------------------------------------------------------------
        // 4. Submit solution
        // ---------------------------------------------------------------
        std::cout << "  " << color::dim() << "[" << current_timestamp()
                  << "]" << color::reset() << " Submitting block..."
                  << std::flush;

        std::string submit_resp = rpc_call(
            rpc_host, rpc_port, "submitwork",
            "[" + std::to_string(winning_nonce) + "," +
            std::to_string(work_id) + "]");

        if (submit_resp.empty()) {
            std::cout << "\r  " << color::dim() << "[" << current_timestamp()
                      << "]" << color::reset() << " " << color::red()
                      << "Failed to submit. Node unreachable."
                      << color::reset() << std::endl;
            continue;
        }

        rpc::JsonValue submit_json;
        try {
            submit_json = rpc::parse_json(submit_resp);
        } catch (const std::exception& e) {
            std::cout << "\r  " << color::dim() << "[" << current_timestamp()
                      << "]" << color::reset() << " " << color::red()
                      << "Parse error: " << e.what()
                      << color::reset() << std::endl;
            continue;
        }

        if (submit_json["result"].is_string()) {
            ++blocks_mined;
            std::string block_hash = submit_json["result"].get_string();

            g_block_history.push_back({
                height, block_hash, block_secs, current_timestamp()
            });

            std::cout << "\r  " << color::dim() << "[" << current_timestamp()
                      << "]" << color::reset() << " " << color::green()
                      << color::bold() << "Block accepted!"
                      << color::reset()
                      << "  height=" << color::bold() << height
                      << color::reset()
                      << "  hash=" << color::dim()
                      << block_hash.substr(0, 16) << "..."
                      << color::reset() << std::endl << std::endl;
        } else {
            std::cout << "\r  " << color::dim() << "[" << current_timestamp()
                      << "]" << color::reset() << " " << color::red()
                      << color::bold() << "Block rejected: "
                      << rpc::json_serialize(submit_json["error"])
                      << color::reset() << std::endl;
        }
    }

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
              << "  +===================================+\n"
              << "  |         Session Summary            |\n"
              << "  +===================================+"
              << color::reset() << "\n\n";

    std::cout << "  " << color::dim() << "Blocks mined:" << color::reset()
              << "  " << color::bold() << color::green() << blocks_mined
              << color::reset() << "\n";
    std::cout << "  " << color::dim() << "Hashes:     " << color::reset()
              << "  " << format_number(session_hashes) << "\n";
    std::cout << "  " << color::dim() << "Session time:" << color::reset()
              << "  " << format_duration(session_secs) << "\n";
    std::cout << "  " << color::dim() << "Avg rate:   " << color::reset()
              << "  " << format_hashrate(session_rate) << "\n";

    std::cout << "\n";

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
