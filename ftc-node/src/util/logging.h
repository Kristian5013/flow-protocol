#ifndef FTC_UTIL_LOGGING_H
#define FTC_UTIL_LOGGING_H

#include <string>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <type_traits>

namespace ftc {
namespace log {

// Log levels (Tor-style)
enum class Level {
    DEBUG = 0,
    INFO = 1,
    NOTICE = 2,
    WARN = 3,
    ERR = 4
};

// Initialize logging
void init(Level min_level = Level::NOTICE, const std::string& log_file = "");

// Shutdown logging (flush and close)
void shutdown();

// Set minimum log level
void setLevel(Level level);

// Get current minimum level (for early-exit optimization)
Level getLevel();

// Check if level is enabled - MUST be fast for hot path filtering
bool isEnabled(Level level);

// Log functions
void debug(const std::string& msg);
void info(const std::string& msg);
void notice(const std::string& msg);
void warn(const std::string& msg);
void err(const std::string& msg);

// Generic log
void log(Level level, const std::string& msg);

// Bootstrap progress (Tor-style)
void bootstrap(int percent, const std::string& tag, const std::string& summary);

// Generic toString - fallback for char arrays and other types
template<typename T>
inline std::string toString(const T& val) {
    // For char arrays, treat as C-string
    if constexpr (std::is_array_v<T> && std::is_same_v<std::remove_extent_t<T>, char>) {
        return std::string(val);
    } else if constexpr (std::is_same_v<T, const char*> || std::is_same_v<T, char*>) {
        return val ? std::string(val) : "(null)";
    } else {
        return std::to_string(val);
    }
}

// Specializations for common types
template<> inline std::string toString(const std::string& val) { return val; }
template<> inline std::string toString(const char* const& val) { return val ? val : "(null)"; }
template<> inline std::string toString(const int& val) { return std::to_string(val); }
template<> inline std::string toString(const long& val) { return std::to_string(val); }
template<> inline std::string toString(const long long& val) { return std::to_string(val); }
template<> inline std::string toString(const unsigned int& val) { return std::to_string(val); }
template<> inline std::string toString(const unsigned long& val) { return std::to_string(val); }
template<> inline std::string toString(const unsigned long long& val) { return std::to_string(val); }
template<> inline std::string toString(const double& val) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%.1f", val);
    return buf;
}
template<> inline std::string toString(const bool& val) { return val ? "true" : "false"; }
template<> inline std::string toString(const uint16_t& val) { return std::to_string(val); }
template<> inline std::string toString(const unsigned char& val) { return std::to_string(static_cast<unsigned int>(val)); }
template<> inline std::string toString(const signed char& val) { return std::to_string(static_cast<int>(val)); }

// Base case - no args
inline std::string format(const char* fmt) {
    return std::string(fmt);
}

// Recursive template for {} placeholder formatting
template<typename T, typename... Args>
std::string format(const char* fmt, const T& first, const Args&... rest) {
    std::string result;
    const char* p = fmt;

    while (*p) {
        if (*p == '{') {
            // Find matching close brace
            const char* close = p + 1;
            while (*close && *close != '}') close++;
            if (*close == '}') {
                // Found placeholder (handles {}, {:.1f}, etc.)
                result += toString(first);
                p = close + 1;
                // Recurse for remaining placeholders
                result += format(p, rest...);
                return result;
            }
        }
        result += *p++;
    }

    return result;
}

// Convenience macros with early-exit optimization
// Check level BEFORE expensive string formatting to avoid overhead in hot paths
#define LOG_DEBUG(...) do { if (ftc::log::isEnabled(ftc::log::Level::DEBUG)) ftc::log::debug(ftc::log::format(__VA_ARGS__)); } while(0)
#define LOG_INFO(...) do { if (ftc::log::isEnabled(ftc::log::Level::INFO)) ftc::log::info(ftc::log::format(__VA_ARGS__)); } while(0)
#define LOG_NOTICE(...) ftc::log::notice(ftc::log::format(__VA_ARGS__))
#define LOG_WARN(...) ftc::log::warn(ftc::log::format(__VA_ARGS__))
#define LOG_ERR(...) ftc::log::err(ftc::log::format(__VA_ARGS__))
#define LOG_ERROR(...) ftc::log::err(ftc::log::format(__VA_ARGS__))

// Bootstrap macro (supports format string in summary)
#define LOG_BOOTSTRAP(pct, tag, ...) ftc::log::bootstrap(pct, tag, ftc::log::format(__VA_ARGS__))

} // namespace log
} // namespace ftc

#endif // FTC_UTIL_LOGGING_H
