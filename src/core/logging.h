#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FTC_CORE_LOGGING_H
#define FTC_CORE_LOGGING_H

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace core {

// ---------------------------------------------------------------------------
// LogLevel: severity levels for log messages
// ---------------------------------------------------------------------------
enum class LogLevel : int {
    TRACE   = 0,
    DEBUG   = 1,
    INFO    = 2,
    WARN    = 3,
    ERR     = 4,  // "ERROR" conflicts with Windows <windows.h> macro
    FATAL   = 5,
    OFF     = 6,
};

// ---------------------------------------------------------------------------
// LogCategory: bitmask categories for filtering log output
// ---------------------------------------------------------------------------
enum class LogCategory : uint32_t {
    NONE       = 0,
    NET        = 1u << 0,
    MEMPOOL    = 1u << 1,
    VALIDATION = 1u << 2,
    MINING     = 1u << 3,
    RPC        = 1u << 4,
    WALLET     = 1u << 5,
    CHAIN      = 1u << 6,
    SCRIPT     = 1u << 7,
    LOCK       = 1u << 8,
    P2P        = 1u << 9,
    BENCH      = 1u << 10,
    ALL        = 0xFFFFFFFF,
};

// Bitwise operators for LogCategory so it can be used as a bitmask.
inline constexpr LogCategory operator|(LogCategory a, LogCategory b) noexcept {
    return static_cast<LogCategory>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr LogCategory operator&(LogCategory a, LogCategory b) noexcept {
    return static_cast<LogCategory>(
        static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline constexpr LogCategory operator~(LogCategory a) noexcept {
    return static_cast<LogCategory>(~static_cast<uint32_t>(a));
}

inline constexpr LogCategory& operator|=(LogCategory& a,
                                          LogCategory b) noexcept {
    a = a | b;
    return a;
}

inline constexpr LogCategory& operator&=(LogCategory& a,
                                          LogCategory b) noexcept {
    a = a & b;
    return a;
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Returns the short string name for a log level (e.g. "INFO", "WARN").
[[nodiscard]] std::string_view log_level_string(LogLevel level) noexcept;

/// Returns the short string name for a single log category bit.
/// If multiple bits are set, returns the name of the lowest set bit.
/// Returns "NONE" when the value is zero.
[[nodiscard]] std::string_view log_category_string(
    LogCategory cat) noexcept;

// ---------------------------------------------------------------------------
// Logger: thread-safe singleton logger
// ---------------------------------------------------------------------------
class Logger {
public:
    /// Returns the process-wide singleton instance.
    static Logger& instance();

    // -- configuration (all thread-safe) ------------------------------------

    /// Sets the minimum severity level. Messages below this are discarded.
    void set_level(LogLevel level);

    /// Enables logging for the given category (bitwise OR).
    void enable_category(LogCategory cat);

    /// Disables logging for the given category.
    void disable_category(LogCategory cat);

    /// Returns the current effective log level.
    [[nodiscard]] LogLevel level() const noexcept;

    /// Returns the current enabled category bitmask.
    [[nodiscard]] LogCategory enabled_categories() const noexcept;

    /// Fast lockless check: returns true if a message at the given
    /// level and category would actually be written.
    [[nodiscard]] bool will_log(LogLevel level,
                                LogCategory cat) const noexcept;

    /// Enables or disables writing to stderr / console.
    void set_print_to_console(bool enable);

    /// Enables or disables writing to the log file.
    void set_print_to_file(bool enable);

    /// Opens (or replaces) the output log file. The file is opened in
    /// append mode. An empty path closes the current file.
    void set_log_file(const std::filesystem::path& path);

    /// Flushes all buffered output to console and file sinks.
    void flush();

    // -- logging entry point ------------------------------------------------

    /// Writes a fully formatted log line. The caller is responsible for
    /// performing the will_log() check beforehand to avoid unnecessary
    /// formatting work.
    void write(LogLevel level, LogCategory cat,
               std::string_view message);

    // Non-copyable, non-movable.
    Logger(const Logger&)            = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&)                 = delete;
    Logger& operator=(Logger&&)      = delete;

private:
    Logger();
    ~Logger();

    /// Formats a timestamp string:  "2026-02-03 12:00:00.123"
    static std::string format_timestamp();

    /// Formats and writes one complete log line to all active sinks.
    /// Must be called with write_mutex_ held.
    void write_line_locked(std::string_view line);

    // -- atomic state for lockless will_log() checks -----------------------
    std::atomic<int>      level_{static_cast<int>(LogLevel::INFO)};
    std::atomic<uint32_t> enabled_categories_{
        static_cast<uint32_t>(LogCategory::ALL)};
    std::atomic<bool>     print_to_console_{true};
    std::atomic<bool>     print_to_file_{false};

    // -- guarded state for I/O ---------------------------------------------
    mutable std::mutex    write_mutex_;
    std::ofstream         file_stream_;
    std::filesystem::path log_file_path_;

    // -- internal write buffer (reduces small write syscalls) ---------------
    std::string           buffer_;

    static constexpr std::size_t BUFFER_FLUSH_THRESHOLD = 8192;
};

} // namespace core

// ---------------------------------------------------------------------------
// Convenience macros
// ---------------------------------------------------------------------------
// Each macro performs a lockless will_log() check before doing any string
// formatting, so disabled paths have near-zero overhead.
//
// Usage:
//   LOG_INFO(core::LogCategory::NET, "connected to peer " + peer_addr);
//   LOG_WARN(core::LogCategory::MEMPOOL, "tx pool is full");
//
// The message argument can be any expression convertible to std::string.
// ---------------------------------------------------------------------------

#define LOG_TRACE(cat, msg)                                               \
    do {                                                                  \
        if (core::Logger::instance().will_log(                            \
                core::LogLevel::TRACE, (cat))) {                          \
            core::Logger::instance().write(                               \
                core::LogLevel::TRACE, (cat),                             \
                std::string(msg));                                        \
        }                                                                 \
    } while (0)

#define LOG_DEBUG(cat, msg)                                               \
    do {                                                                  \
        if (core::Logger::instance().will_log(                            \
                core::LogLevel::DEBUG, (cat))) {                          \
            core::Logger::instance().write(                               \
                core::LogLevel::DEBUG, (cat),                             \
                std::string(msg));                                        \
        }                                                                 \
    } while (0)

#define LOG_INFO(cat, msg)                                                \
    do {                                                                  \
        if (core::Logger::instance().will_log(                            \
                core::LogLevel::INFO, (cat))) {                           \
            core::Logger::instance().write(                               \
                core::LogLevel::INFO, (cat),                              \
                std::string(msg));                                        \
        }                                                                 \
    } while (0)

#define LOG_WARN(cat, msg)                                                \
    do {                                                                  \
        if (core::Logger::instance().will_log(                            \
                core::LogLevel::WARN, (cat))) {                           \
            core::Logger::instance().write(                               \
                core::LogLevel::WARN, (cat),                              \
                std::string(msg));                                        \
        }                                                                 \
    } while (0)

#define LOG_ERROR(cat, msg)                                               \
    do {                                                                  \
        if (core::Logger::instance().will_log(                            \
                core::LogLevel::ERR, (cat))) {                          \
            core::Logger::instance().write(                               \
                core::LogLevel::ERR, (cat),                             \
                std::string(msg));                                        \
        }                                                                 \
    } while (0)

#define LOG_FATAL(cat, msg)                                               \
    do {                                                                  \
        if (core::Logger::instance().will_log(                            \
                core::LogLevel::FATAL, (cat))) {                          \
            core::Logger::instance().write(                               \
                core::LogLevel::FATAL, (cat),                             \
                std::string(msg));                                        \
        }                                                                 \
    } while (0)

#endif // FTC_CORE_LOGGING_H
