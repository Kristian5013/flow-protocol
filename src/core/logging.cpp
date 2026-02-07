// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/logging.h"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <iostream>

namespace core {

// ---------------------------------------------------------------------------
// log_level_string
// ---------------------------------------------------------------------------
std::string_view log_level_string(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        case LogLevel::OFF:   return "OFF";
    }
    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// log_category_string
// ---------------------------------------------------------------------------
std::string_view log_category_string(LogCategory cat) noexcept {
    // Return the name for the lowest set bit. When multiple bits are set
    // we report only the first one; callers typically pass a single
    // category per log statement.
    uint32_t bits = static_cast<uint32_t>(cat);
    if (bits == 0) return "NONE";

    // Isolate lowest set bit.
    uint32_t lowest = bits & (~bits + 1u);

    switch (static_cast<LogCategory>(lowest)) {
        case LogCategory::NET:        return "NET";
        case LogCategory::MEMPOOL:    return "MEMPOOL";
        case LogCategory::VALIDATION: return "VALIDATION";
        case LogCategory::MINING:     return "MINING";
        case LogCategory::RPC:        return "RPC";
        case LogCategory::WALLET:     return "WALLET";
        case LogCategory::CHAIN:      return "CHAIN";
        case LogCategory::SCRIPT:     return "SCRIPT";
        case LogCategory::LOCK:       return "LOCK";
        case LogCategory::P2P:        return "P2P";
        case LogCategory::BENCH:      return "BENCH";
        default:                      break;
    }

    // If ALL or an unrecognised combination, return "ALL".
    if (bits == static_cast<uint32_t>(LogCategory::ALL)) return "ALL";

    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// Logger -- singleton access
// ---------------------------------------------------------------------------
Logger& Logger::instance() {
    static Logger the_logger;
    return the_logger;
}

// ---------------------------------------------------------------------------
// Logger -- construction / destruction
// ---------------------------------------------------------------------------
Logger::Logger() {
    buffer_.reserve(BUFFER_FLUSH_THRESHOLD * 2);
}

Logger::~Logger() {
    flush();
}

// ---------------------------------------------------------------------------
// Logger -- configuration
// ---------------------------------------------------------------------------
void Logger::set_level(LogLevel lvl) {
    level_.store(static_cast<int>(lvl), std::memory_order_release);
}

void Logger::enable_category(LogCategory cat) {
    enabled_categories_.fetch_or(static_cast<uint32_t>(cat),
                                 std::memory_order_release);
}

void Logger::disable_category(LogCategory cat) {
    enabled_categories_.fetch_and(~static_cast<uint32_t>(cat),
                                  std::memory_order_release);
}

LogLevel Logger::level() const noexcept {
    return static_cast<LogLevel>(
        level_.load(std::memory_order_acquire));
}

LogCategory Logger::enabled_categories() const noexcept {
    return static_cast<LogCategory>(
        enabled_categories_.load(std::memory_order_acquire));
}

bool Logger::will_log(LogLevel lvl, LogCategory cat) const noexcept {
    // Fast path: check level first (single atomic load).
    if (static_cast<int>(lvl) <
        level_.load(std::memory_order_acquire)) {
        return false;
    }
    // NONE category (0) always passes the category filter.
    // Otherwise, check that at least one bit in cat is enabled.
    uint32_t cat_bits = static_cast<uint32_t>(cat);
    if (cat_bits != 0) {
        uint32_t mask = enabled_categories_.load(std::memory_order_acquire);
        if ((mask & cat_bits) == 0) {
            return false;
        }
    }
    // At least one sink must be active.
    return print_to_console_.load(std::memory_order_acquire) ||
           print_to_file_.load(std::memory_order_acquire);
}

void Logger::set_print_to_console(bool enable) {
    print_to_console_.store(enable, std::memory_order_release);
}

void Logger::set_print_to_file(bool enable) {
    print_to_file_.store(enable, std::memory_order_release);
}

void Logger::set_log_file(const std::filesystem::path& path) {
    std::lock_guard<std::mutex> lock(write_mutex_);

    // Flush anything still buffered to the old file.
    if (file_stream_.is_open()) {
        if (!buffer_.empty()) {
            file_stream_.write(buffer_.data(),
                               static_cast<std::streamsize>(
                                   buffer_.size()));
            // Buffer is flushed below after we possibly reopen.
        }
        file_stream_.close();
    }

    buffer_.clear();
    log_file_path_ = path;

    if (!path.empty()) {
        file_stream_.open(path,
                          std::ios::out | std::ios::app | std::ios::ate);
        if (!file_stream_.is_open()) {
            // If we cannot open the file, disable file logging so we
            // don't silently swallow messages.
            print_to_file_.store(false, std::memory_order_release);
            std::cerr << "Logger: failed to open log file: "
                      << path << "\n";
        }
    }
}

void Logger::flush() {
    std::lock_guard<std::mutex> lock(write_mutex_);

    if (!buffer_.empty()) {
        if (print_to_file_.load(std::memory_order_relaxed) &&
            file_stream_.is_open()) {
            file_stream_.write(buffer_.data(),
                               static_cast<std::streamsize>(
                                   buffer_.size()));
            file_stream_.flush();
        }
        buffer_.clear();
    } else {
        if (file_stream_.is_open()) {
            file_stream_.flush();
        }
    }

    std::cerr.flush();
}

// ---------------------------------------------------------------------------
// Logger -- writing
// ---------------------------------------------------------------------------
void Logger::write(LogLevel lvl, LogCategory cat,
                   std::string_view message) {
    // Build the formatted line:
    //   [2026-02-03 12:00:00.123] [INFO] [NET] message here\n
    std::string line;
    line.reserve(64 + message.size());

    line += '[';
    line += format_timestamp();
    line += "] [";
    line += log_level_string(lvl);
    line += "] [";
    line += log_category_string(cat);
    line += "] ";
    line += message;
    line += '\n';

    std::lock_guard<std::mutex> lock(write_mutex_);
    write_line_locked(line);

    // Auto-flush on WARN and above so important messages are not lost.
    if (static_cast<int>(lvl) >=
        static_cast<int>(LogLevel::WARN)) {
        if (file_stream_.is_open()) {
            if (!buffer_.empty()) {
                file_stream_.write(
                    buffer_.data(),
                    static_cast<std::streamsize>(buffer_.size()));
                buffer_.clear();
            }
            file_stream_.flush();
        }
        std::cerr.flush();
    }
}

void Logger::write_line_locked(std::string_view line) {
    // Console sink: write immediately to stderr.
    if (print_to_console_.load(std::memory_order_relaxed)) {
        std::cerr.write(line.data(),
                        static_cast<std::streamsize>(line.size()));
    }

    // File sink: buffer writes to reduce syscall overhead.
    if (print_to_file_.load(std::memory_order_relaxed) &&
        file_stream_.is_open()) {
        buffer_ += line;

        if (buffer_.size() >= BUFFER_FLUSH_THRESHOLD) {
            file_stream_.write(
                buffer_.data(),
                static_cast<std::streamsize>(buffer_.size()));
            buffer_.clear();
        }
    }
}

// ---------------------------------------------------------------------------
// Logger -- timestamp formatting
// ---------------------------------------------------------------------------
std::string Logger::format_timestamp() {
    using Clock = std::chrono::system_clock;

    auto now = Clock::now();
    auto epoch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now.time_since_epoch())
                        .count();
    int millis = static_cast<int>(epoch_ms % 1000);

    std::time_t time_val = Clock::to_time_t(now);
    std::tm tm_buf{};

#if defined(_WIN32) || defined(_WIN64)
    gmtime_s(&tm_buf, &time_val);
#else
    gmtime_r(&time_val, &tm_buf);
#endif

    // "YYYY-MM-DD HH:MM:SS.mmm"  (23 chars)
    char buf[32];
    int n = std::snprintf(
        buf, sizeof(buf),
        "%04d-%02d-%02d %02d:%02d:%02d.%03d",
        tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
        tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, millis);

    return std::string(buf, static_cast<std::size_t>(n));
}

} // namespace core
