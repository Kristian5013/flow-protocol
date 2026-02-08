// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// ftc-miner — standalone FTC miner
//
// Runs locally on any PC. Connects to a remote FTC node via JSON-RPC to
// fetch work (block header + target), solves Equihash using local CPU,
// and submits the winning nonce back to the node.
//
// Usage:
//   ftc-miner --rpc-host=HOST --rpc-port=PORT --address=ADDR [--threads=N]
// ---------------------------------------------------------------------------

#include "core/hex.h"
#include "core/logging.h"
#include "core/stream.h"
#include "core/types.h"
#include "miner/solver.h"
#include "primitives/block_header.h"
#include "rpc/request.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
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
inline const char* white()   { return g_enabled ? "\033[37m"   : ""; }

void init() {
#ifdef _WIN32
    // Enable virtual terminal processing on Windows 10+
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(h, &mode)) {
            mode |= 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
            if (!SetConsoleMode(h, mode)) {
                g_enabled = false;
            }
        } else {
            g_enabled = false;
        }
    }
#else
    // Disable colors if stdout is not a terminal
    if (!isatty(fileno(stdout))) {
        g_enabled = false;
    }
#endif
}

} // namespace color

// ---------------------------------------------------------------------------
// Global RPC credentials and Base64 for HTTP Basic Auth
// ---------------------------------------------------------------------------
static std::string g_rpc_user;
static std::string g_rpc_pass;

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
    while (out.size() % 4)
        out.push_back('=');
    return out;
}

// ---------------------------------------------------------------------------
// Global cancel flag for Ctrl+C
// ---------------------------------------------------------------------------
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
static void signal_handler(int) {
    g_stop = true;
}
#endif

// ---------------------------------------------------------------------------
// Block history entry
// ---------------------------------------------------------------------------
struct MinedBlock {
    int64_t height;
    std::string hash;
    double solve_time_s;
    double hashrate;
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
        oss << std::setprecision(2) << (hps / 1e9) << " GH/s";
    } else if (hps >= 1e6) {
        oss << std::setprecision(2) << (hps / 1e6) << " MH/s";
    } else if (hps >= 1e3) {
        oss << std::setprecision(2) << (hps / 1e3) << " kH/s";
    } else {
        oss << std::setprecision(1) << hps << " H/s";
    }
    return oss.str();
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

static std::string format_number(uint64_t n) {
    std::string s = std::to_string(n);
    std::string result;
    int count = 0;
    for (int i = static_cast<int>(s.size()) - 1; i >= 0; --i) {
        if (count > 0 && count % 3 == 0) result = "," + result;
        result = s[i] + result;
        ++count;
    }
    return result;
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

static std::string nonce_progress_bar(uint64_t hashes, int width = 20) {
    // Show % of 32-bit nonce space explored
    double pct = static_cast<double>(hashes) / 4294967296.0 * 100.0;
    if (pct > 100.0) pct = 100.0;
    int filled = static_cast<int>(pct / 100.0 * width);
    if (filled > width) filled = width;

    std::string bar;
    bar += color::cyan();
    bar += "[";
    for (int i = 0; i < width; ++i) {
        if (i < filled) bar += "#";
        else bar += ".";
    }
    bar += "]";
    bar += color::reset();

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << pct << "%";
    bar += " " + oss.str();
    return bar;
}

// ---------------------------------------------------------------------------
// Print block history table
// ---------------------------------------------------------------------------
static void print_block_table() {
    if (g_block_history.empty()) return;

    std::cout << "\n" << color::bold() << color::cyan()
              << "  Block History" << color::reset() << "\n";
    std::cout << color::dim()
              << "  +-------+--------+-----------+------------------+-----------+"
              << color::reset() << "\n";
    std::cout << color::dim() << "  |" << color::reset()
              << color::bold() << "  #    " << color::reset()
              << color::dim() << "|" << color::reset()
              << color::bold() << " Height " << color::reset()
              << color::dim() << "|" << color::reset()
              << color::bold() << "  Time     " << color::reset()
              << color::dim() << "|" << color::reset()
              << color::bold() << " Hash             " << color::reset()
              << color::dim() << "|" << color::reset()
              << color::bold() << " Hashrate  " << color::reset()
              << color::dim() << "|" << color::reset() << "\n";
    std::cout << color::dim()
              << "  +-------+--------+-----------+------------------+-----------+"
              << color::reset() << "\n";

    for (size_t i = 0; i < g_block_history.size(); ++i) {
        const auto& b = g_block_history[i];
        std::ostringstream row;
        row << color::dim() << "  |" << color::reset()
            << color::green() << "  " << std::setw(4) << (i + 1) << " "
            << color::reset()
            << color::dim() << "|" << color::reset()
            << " " << std::setw(6) << b.height << " "
            << color::dim() << "|" << color::reset()
            << " " << std::setw(9) << b.timestamp << " "
            << color::dim() << "|" << color::reset()
            << " " << b.hash.substr(0, 16) << " "
            << color::dim() << "|" << color::reset()
            << " " << std::setw(9) << format_hashrate(b.hashrate) << " "
            << color::dim() << "|" << color::reset();
        std::cout << row.str() << "\n";
    }

    std::cout << color::dim()
              << "  +-------+--------+-----------+------------------+-----------+"
              << color::reset() << "\n";
}

// ---------------------------------------------------------------------------
// Minimal HTTP POST client
// ---------------------------------------------------------------------------
static std::string http_post(const std::string& host, uint16_t port,
                             const std::string& body) {
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result) != 0) {
        return {};
    }

    sock_t sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == BAD_SOCK) {
        freeaddrinfo(result);
        return {};
    }

    if (connect(sock, result->ai_addr, static_cast<int>(result->ai_addrlen)) != 0) {
        close_sock(sock);
        freeaddrinfo(result);
        return {};
    }
    freeaddrinfo(result);

    // Build HTTP request
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
        "Connection: close\r\n"
        "\r\n" + body;

    // Send
    int total_sent = 0;
    int req_len = static_cast<int>(request.size());
    while (total_sent < req_len) {
        int n = send(sock, request.c_str() + total_sent, req_len - total_sent, 0);
        if (n <= 0) { close_sock(sock); return {}; }
        total_sent += n;
    }

    // Receive
    std::string response;
    char buf[4096];
    for (;;) {
        int n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        response.append(buf, n);
    }
    close_sock(sock);

    // Extract body (skip HTTP headers)
    auto pos = response.find("\r\n\r\n");
    if (pos != std::string::npos) {
        return response.substr(pos + 4);
    }
    return response;
}

// ---------------------------------------------------------------------------
// JSON-RPC helper
// ---------------------------------------------------------------------------
static std::string rpc_call(const std::string& host, uint16_t port,
                            const std::string& method,
                            const std::string& params_json) {
    std::string body = "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"" +
                       method + "\",\"params\":" + params_json + "}";
    return http_post(host, port, body);
}

// ---------------------------------------------------------------------------
// Command-line argument parsing
// ---------------------------------------------------------------------------
static std::string get_arg(int argc, char* argv[], const std::string& name,
                           const std::string& default_val = "") {
    std::string prefix = "--" + name + "=";
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg.rfind(prefix, 0) == 0) {
            return arg.substr(prefix.size());
        }
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
// Main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    // Setup signal handlers
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

    // Initialize colors
    color::init();

    if (has_arg(argc, argv, "help") || argc < 2) {
        std::cout << color::bold() << color::cyan()
                  << "FTC Miner v1.1" << color::reset() << "\n\n"
                  << "Usage: ftc-miner --address=ADDR [options]\n\n"
                  << "Options:\n"
                  << "  --address=ADDR     Mining reward address (required)\n"
                  << "  --rpc-host=HOST    RPC server host (default: 127.0.0.1)\n"
                  << "  --rpc-port=PORT    RPC server port (default: 9332)\n"
                  << "  --rpc-user=USER    RPC username (default: ftcuser)\n"
                  << "  --rpc-pass=PASS    RPC password (default: ftcpass)\n"
                  << "  --threads=N        Mining threads (default: 1)\n"
                  << "  --no-color         Disable colored output\n"
                  << "  --help             Show this help\n\n"
                  << "Example:\n"
                  << "  ftc-miner --address=1A73WPJ... --rpc-host=seed.flowprotocol.net --threads=4\n";
        return 0;
    }

    if (has_arg(argc, argv, "no-color")) {
        color::g_enabled = false;
    }

    std::string address  = get_arg(argc, argv, "address");
    std::string rpc_host = get_arg(argc, argv, "rpc-host", "127.0.0.1");
    uint16_t rpc_port    = static_cast<uint16_t>(
        std::atoi(get_arg(argc, argv, "rpc-port", "9332").c_str()));
    g_rpc_user           = get_arg(argc, argv, "rpc-user", "ftcuser");
    g_rpc_pass           = get_arg(argc, argv, "rpc-pass", "ftcpass");
    int num_threads      = std::atoi(get_arg(argc, argv, "threads", "1").c_str());

    if (address.empty()) {
        std::cerr << color::red() << "Error: --address is required"
                  << color::reset() << "\n";
        return 1;
    }
    if (num_threads < 1) num_threads = 1;
    if (num_threads > 64) num_threads = 64;

    // Suppress solver's internal LOG_INFO from printing to console.
    auto& logger = core::Logger::instance();
    logger.set_print_to_console(false);

    // Banner
    std::cout << "\n";
    std::cout << color::bold() << color::cyan()
              << "  +===================================+\n"
              << "  |         FTC Miner v1.1            |\n"
              << "  +===================================+"
              << color::reset() << "\n\n";

    std::cout << "  " << color::dim() << "Address:" << color::reset()
              << "  " << color::bold() << address << color::reset() << "\n";
    std::cout << "  " << color::dim() << "Node:   " << color::reset()
              << "  " << rpc_host << ":" << rpc_port << "\n";
    std::cout << "  " << color::dim() << "Threads:" << color::reset()
              << "  " << num_threads << "\n";
    std::cout << "  " << color::dim() << "Press Ctrl+C to stop" << color::reset()
              << "\n\n";

    int blocks_mined = 0;
    auto session_start = std::chrono::steady_clock::now();
    uint64_t session_total_hashes = 0;

    while (!g_stop) {
        // ---------------------------------------------------------------
        // 1. Fetch work from node
        // ---------------------------------------------------------------
        std::cout << "  " << color::dim() << "[" << current_timestamp() << "]"
                  << color::reset() << " Fetching work..." << std::flush;

        std::string resp = rpc_call(rpc_host, rpc_port, "getwork",
                                    "[\"" + address + "\"]");
        if (resp.empty()) {
            std::cout << "\r  " << color::dim() << "[" << current_timestamp() << "]"
                      << color::reset() << " " << color::red()
                      << "Failed to connect to " << rpc_host << ":" << rpc_port
                      << ". Retrying in 5s..." << color::reset() << std::endl;
            for (int i = 0; i < 50 && !g_stop; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        rpc::JsonValue json;
        try {
            json = rpc::parse_json(resp);
        } catch (const std::exception& e) {
            std::cout << "\r  " << color::dim() << "[" << current_timestamp() << "]"
                      << color::reset() << " " << color::red()
                      << "JSON parse error: " << e.what()
                      << color::reset() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        if (!json["result"].is_object()) {
            std::cout << "\r  " << color::dim() << "[" << current_timestamp() << "]"
                      << color::reset() << " " << color::red()
                      << "RPC error: " << rpc::json_serialize(json["error"])
                      << color::reset() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        auto& result = json["result"];
        std::string header_hex = result["header"].get_string();
        std::string target_hex = result["target"].get_string();
        int64_t height = result["height"].get_int();
        int64_t work_id = result["work_id"].is_int() ? result["work_id"].get_int() : 0;

        // ---------------------------------------------------------------
        // 2. Deserialize header and target
        // ---------------------------------------------------------------
        auto header_opt = core::from_hex(header_hex);
        if (!header_opt) {
            std::cerr << "\r  " << color::red() << "Invalid header hex from node"
                      << color::reset() << std::endl;
            continue;
        }
        auto header_bytes = std::move(*header_opt);

        core::DataStream stream(std::move(header_bytes));
        auto header = primitives::BlockHeader::deserialize(stream);
        auto target = core::uint256::from_hex(target_hex);

        std::cout << "\r  " << color::dim() << "[" << current_timestamp() << "]"
                  << color::reset() << " " << color::bold()
                  << "Mining block " << height << color::reset()
                  << "  " << color::dim() << "target: " << target_hex.substr(0, 16) << "..."
                  << color::reset() << std::endl;

        auto block_start = std::chrono::steady_clock::now();
        std::atomic<uint64_t> hash_counter{0};

        // ---------------------------------------------------------------
        // 3. Start monitoring thread (live hashrate + progress)
        // ---------------------------------------------------------------
        std::atomic<bool> mining_done{false};
        std::thread monitor_thread([&]() {
            uint64_t prev_hashes = 0;
            auto prev_time = std::chrono::steady_clock::now();

            while (!mining_done.load(std::memory_order_relaxed) &&
                   !g_stop.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(750));

                auto now = std::chrono::steady_clock::now();
                uint64_t cur_hashes = hash_counter.load(std::memory_order_relaxed);
                double dt = std::chrono::duration<double>(now - prev_time).count();
                double elapsed = std::chrono::duration<double>(now - block_start).count();

                double instant_rate = 0;
                if (dt > 0.01) {
                    instant_rate = static_cast<double>(cur_hashes - prev_hashes) / dt;
                }
                double avg_rate = 0;
                if (elapsed > 0.01) {
                    avg_rate = static_cast<double>(cur_hashes) / elapsed;
                }

                prev_hashes = cur_hashes;
                prev_time = now;

                // Build progress line
                std::ostringstream line;
                line << "  " << color::dim() << "  " << color::reset()
                     << color::cyan() << format_hashrate(instant_rate) << color::reset()
                     << color::dim() << " instant" << color::reset()
                     << "  "
                     << color::cyan() << format_hashrate(avg_rate) << color::reset()
                     << color::dim() << " avg" << color::reset()
                     << "  "
                     << color::dim() << format_number(cur_hashes) << " hashes" << color::reset()
                     << "  "
                     << color::dim() << format_duration(elapsed) << color::reset()
                     << "  "
                     << nonce_progress_bar(cur_hashes, 15)
                     << "      ";  // extra spaces to overwrite previous line

                std::cout << "\r" << line.str() << std::flush;
            }
        });

        // ---------------------------------------------------------------
        // 4. Solve (locally, using CPU)
        // ---------------------------------------------------------------
        std::optional<miner::SolverResult> winning;

        if (num_threads <= 1) {
            miner::EquihashSolver solver;
            winning = solver.solve(header, target, g_stop, &hash_counter);
        } else {
            std::mutex result_mutex;
            std::atomic<bool> found{false};
            std::vector<std::thread> threads;

            uint32_t range = UINT32_MAX / static_cast<uint32_t>(num_threads);

            for (int t = 0; t < num_threads; ++t) {
                threads.emplace_back([&, t]() {
                    miner::EquihashSolver solver;
                    auto h = header;
                    h.nonce = static_cast<uint32_t>(t) * range;

                    auto res = solver.solve(h, target, found, &hash_counter);
                    if (res) {
                        std::lock_guard<std::mutex> lock(result_mutex);
                        if (!found.exchange(true)) {
                            winning = std::move(res);
                        }
                    }
                });
            }

            while (!found && !g_stop) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            if (g_stop) found = true;

            for (auto& t : threads) t.join();
        }

        // Stop monitor thread
        mining_done = true;
        monitor_thread.join();

        // Clear the progress line
        std::cout << "\r" << std::string(100, ' ') << "\r";

        uint64_t block_hashes = hash_counter.load();
        session_total_hashes += block_hashes;

        auto block_elapsed = std::chrono::steady_clock::now() - block_start;
        double block_secs = std::chrono::duration<double>(block_elapsed).count();
        double block_rate = block_secs > 0.01 ? static_cast<double>(block_hashes) / block_secs : 0;

        if (!winning) {
            if (g_stop) break;
            std::cout << "  " << color::dim() << "[" << current_timestamp() << "]"
                      << color::reset() << " " << color::yellow()
                      << "No solution found, fetching new work..."
                      << color::reset() << std::endl;
            continue;
        }

        std::cout << "  " << color::dim() << "[" << current_timestamp() << "]"
                  << color::reset() << " " << color::green() << color::bold()
                  << "Solution found!" << color::reset()
                  << "  nonce=" << winning->nonce
                  << "  " << color::dim() << format_duration(block_secs) << color::reset()
                  << "  " << format_hashrate(block_rate)
                  << "  " << format_number(block_hashes) << " hashes"
                  << std::endl;

        // ---------------------------------------------------------------
        // 5. Submit solution to node
        // ---------------------------------------------------------------
        std::cout << "  " << color::dim() << "[" << current_timestamp() << "]"
                  << color::reset() << " Submitting block..." << std::flush;

        std::string submit_resp = rpc_call(
            rpc_host, rpc_port, "submitwork",
            "[" + std::to_string(winning->nonce) + "," +
            std::to_string(work_id) + "]");

        if (submit_resp.empty()) {
            std::cout << "\r  " << color::dim() << "[" << current_timestamp() << "]"
                      << color::reset() << " " << color::red()
                      << "Failed to submit. Node unreachable."
                      << color::reset() << std::endl;
            continue;
        }

        rpc::JsonValue submit_json;
        try {
            submit_json = rpc::parse_json(submit_resp);
        } catch (const std::exception& e) {
            std::cout << "\r  " << color::dim() << "[" << current_timestamp() << "]"
                      << color::reset() << " " << color::red()
                      << "Submit response parse error: " << e.what()
                      << color::reset() << std::endl;
            continue;
        }

        if (submit_json["result"].is_string()) {
            ++blocks_mined;
            std::string block_hash = submit_json["result"].get_string();

            g_block_history.push_back({
                height,
                block_hash,
                block_secs,
                block_rate,
                current_timestamp()
            });

            std::cout << "\r  " << color::dim() << "[" << current_timestamp() << "]"
                      << color::reset() << " " << color::green() << color::bold()
                      << "Block accepted!" << color::reset()
                      << "  height=" << color::bold() << height << color::reset()
                      << "  hash=" << color::dim() << block_hash.substr(0, 16) << "..."
                      << color::reset() << std::endl;

            std::cout << std::endl;
        } else {
            std::cout << "\r  " << color::dim() << "[" << current_timestamp() << "]"
                      << color::reset() << " " << color::red() << color::bold()
                      << "Block rejected: "
                      << rpc::json_serialize(submit_json["error"])
                      << color::reset() << std::endl;
        }
    }

    // ---------------------------------------------------------------
    // Session summary
    // ---------------------------------------------------------------
    auto session_elapsed = std::chrono::steady_clock::now() - session_start;
    double session_secs = std::chrono::duration<double>(session_elapsed).count();
    double session_rate = session_secs > 0.01
        ? static_cast<double>(session_total_hashes) / session_secs : 0;

    std::cout << "\n";
    std::cout << color::bold() << color::cyan()
              << "  +===================================+\n"
              << "  |         Session Summary            |\n"
              << "  +===================================+"
              << color::reset() << "\n\n";

    std::cout << "  " << color::dim() << "Blocks mined:" << color::reset()
              << "  " << color::bold() << color::green() << blocks_mined
              << color::reset() << "\n";
    std::cout << "  " << color::dim() << "Total hashes:" << color::reset()
              << "  " << format_number(session_total_hashes) << "\n";
    std::cout << "  " << color::dim() << "Session time:" << color::reset()
              << "  " << format_duration(session_secs) << "\n";
    std::cout << "  " << color::dim() << "Avg hashrate:" << color::reset()
              << "  " << format_hashrate(session_rate) << "\n";

    if (!g_block_history.empty()) {
        // Average time per block
        double total_solve = 0;
        for (const auto& b : g_block_history) total_solve += b.solve_time_s;
        double avg_time = total_solve / static_cast<double>(g_block_history.size());
        std::cout << "  " << color::dim() << "Avg block time:" << color::reset()
                  << " " << format_duration(avg_time) << "\n";

        print_block_table();
    }

    std::cout << "\n";

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
