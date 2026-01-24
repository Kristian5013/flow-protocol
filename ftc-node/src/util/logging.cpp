#include "util/logging.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <mutex>
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#endif

namespace ftc {
namespace log {

static Level g_min_level = Level::NOTICE;
static std::ofstream g_log_file;
static std::mutex g_log_mutex;
static size_t g_unflushed_count = 0;
static constexpr size_t FLUSH_THRESHOLD = 100;  // Flush after 100 log entries

Level getLevel() {
    return g_min_level;
}

bool isEnabled(Level level) {
    return level >= g_min_level;
}

void init(Level min_level, const std::string& log_file) {
    g_min_level = min_level;

#ifdef _WIN32
    // Ensure we have a console and proper handles
    if (GetStdHandle(STD_OUTPUT_HANDLE) == INVALID_HANDLE_VALUE ||
        GetStdHandle(STD_OUTPUT_HANDLE) == nullptr) {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
    }
#endif

    // Disable stdout buffering for immediate output
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);

    if (!log_file.empty()) {
        g_log_file.open(log_file, std::ios::app);
    }
}

void setLevel(Level level) {
    g_min_level = level;
}

static const char* levelToString(Level level) {
    switch (level) {
        case Level::DEBUG:  return "debug";
        case Level::INFO:   return "info";
        case Level::NOTICE: return "notice";
        case Level::WARN:   return "warn";
        case Level::ERR:    return "err";
        default:            return "unknown";
    }
}

void log(Level level, const std::string& msg) {
    if (level < g_min_level) return;

    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::lock_guard<std::mutex> lock(g_log_mutex);

    // Format: "Jan 20 12:30:00.123 [notice] message"
    std::tm tm_buf;
#ifdef _WIN32
    localtime_s(&tm_buf, &time_t);
#else
    localtime_r(&time_t, &tm_buf);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%b %d %H:%M:%S")
        << "." << std::setfill('0') << std::setw(3) << ms.count()
        << " [" << levelToString(level) << "] " << msg;

    std::string line = oss.str();
    line += "\n";

    // Output to console - use printf which works reliably
    printf("%s", line.c_str());
    fflush(stdout);

    if (g_log_file.is_open()) {
        g_log_file << line << std::endl;

        // Optimize flush: immediate for WARN/ERR, batched for others
        if (level >= Level::WARN) {
            g_log_file.flush();
            g_unflushed_count = 0;
        } else {
            g_unflushed_count++;
            if (g_unflushed_count >= FLUSH_THRESHOLD) {
                g_log_file.flush();
                g_unflushed_count = 0;
            }
        }
    }
}

void debug(const std::string& msg) {
    log(Level::DEBUG, msg);
}

void info(const std::string& msg) {
    log(Level::INFO, msg);
}

void notice(const std::string& msg) {
    log(Level::NOTICE, msg);
}

void warn(const std::string& msg) {
    log(Level::WARN, msg);
}

void err(const std::string& msg) {
    log(Level::ERR, msg);
}

void bootstrap(int percent, const std::string& tag, const std::string& summary) {
    std::ostringstream oss;
    oss << "Bootstrapped " << percent << "% (" << tag << "): " << summary;
    notice(oss.str());
}

// Format bytes to human readable (1.2 MB, 45.3 KB, etc.)
static std::string formatBytes(uint64_t bytes) {
    char buf[32];
    if (bytes >= 1000000000ULL) {
        snprintf(buf, sizeof(buf), "%.1f GB", bytes / 1000000000.0);
    } else if (bytes >= 1000000ULL) {
        snprintf(buf, sizeof(buf), "%.1f MB", bytes / 1000000.0);
    } else if (bytes >= 1000ULL) {
        snprintf(buf, sizeof(buf), "%.1f KB", bytes / 1000.0);
    } else {
        snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)bytes);
    }
    return buf;
}

// Format bandwidth (bytes/sec to readable)
static std::string formatBandwidth(double bps) {
    char buf[32];
    if (bps >= 1000000.0) {
        snprintf(buf, sizeof(buf), "%.1f MB/s", bps / 1000000.0);
    } else if (bps >= 1000.0) {
        snprintf(buf, sizeof(buf), "%.1f KB/s", bps / 1000.0);
    } else {
        snprintf(buf, sizeof(buf), "%.0f B/s", bps);
    }
    return buf;
}

// Format uptime (1d 2h 30m or 2h 30m 15s)
static std::string formatUptime(uint64_t sec) {
    char buf[64];
    uint64_t days = sec / 86400;
    uint64_t hours = (sec % 86400) / 3600;
    uint64_t mins = (sec % 3600) / 60;
    uint64_t secs = sec % 60;

    if (days > 0) {
        snprintf(buf, sizeof(buf), "%llud %lluh %llum",
                 (unsigned long long)days, (unsigned long long)hours, (unsigned long long)mins);
    } else if (hours > 0) {
        snprintf(buf, sizeof(buf), "%lluh %llum %llus",
                 (unsigned long long)hours, (unsigned long long)mins, (unsigned long long)secs);
    } else if (mins > 0) {
        snprintf(buf, sizeof(buf), "%llum %llus", (unsigned long long)mins, (unsigned long long)secs);
    } else {
        snprintf(buf, sizeof(buf), "%llus", (unsigned long long)secs);
    }
    return buf;
}

// Format large numbers (1.2M, 45.3K, etc.)
static std::string formatCount(uint64_t count) {
    char buf[32];
    if (count >= 1000000000ULL) {
        snprintf(buf, sizeof(buf), "%.1fB", count / 1000000000.0);
    } else if (count >= 1000000ULL) {
        snprintf(buf, sizeof(buf), "%.1fM", count / 1000000.0);
    } else if (count >= 1000ULL) {
        snprintf(buf, sizeof(buf), "%.1fK", count / 1000.0);
    } else {
        snprintf(buf, sizeof(buf), "%llu", (unsigned long long)count);
    }
    return buf;
}

void heartbeat(
    uint64_t uptime_sec,
    int32_t height,
    uint64_t peers,
    uint64_t known_addrs,
    uint64_t mempool_txs,
    uint64_t mempool_bytes,
    double sync_progress,
    uint64_t blocks_received,
    uint64_t txs_received,
    double bandwidth_in,
    double bandwidth_out
) {
    std::ostringstream oss;

    // Format: Heartbeat: height=12345 peers=8/127 sync=100% mempool=42tx/1.2MB in=45.3KB/s out=12.1KB/s up=2h30m
    oss << "Heartbeat: "
        << "height=" << height
        << " peers=" << peers << "/" << formatCount(known_addrs)
        << " sync=" << static_cast<int>(sync_progress * 100) << "%"
        << " mempool=" << mempool_txs << "tx/" << formatBytes(mempool_bytes)
        << " blk=" << formatCount(blocks_received)
        << " tx=" << formatCount(txs_received)
        << " in=" << formatBandwidth(bandwidth_in)
        << " out=" << formatBandwidth(bandwidth_out)
        << " up=" << formatUptime(uptime_sec);

    notice(oss.str());
}

void heartbeat_simple(int32_t height, uint64_t peers, double sync_progress) {
    std::ostringstream oss;

    if (sync_progress < 1.0) {
        oss << "Syncing: height=" << height
            << " progress=" << static_cast<int>(sync_progress * 100) << "%"
            << " peers=" << peers;
    } else {
        oss << "Heartbeat: height=" << height << " peers=" << peers << " synced=yes";
    }

    notice(oss.str());
}

void shutdown() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_file.is_open()) {
        g_log_file.flush();
        g_log_file.close();
    }
}

} // namespace log
} // namespace ftc
