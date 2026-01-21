#include "util/logging.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <mutex>
#include <ctime>

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

    std::cout << line << std::endl;

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

void shutdown() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_file.is_open()) {
        g_log_file.flush();
        g_log_file.close();
    }
}

} // namespace log
} // namespace ftc
