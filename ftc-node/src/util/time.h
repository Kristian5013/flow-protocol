#ifndef FTC_UTIL_TIME_H
#define FTC_UTIL_TIME_H

#include <cstdint>
#include <chrono>
#include <string>

namespace ftc {
namespace util {

// Get current Unix timestamp (seconds)
uint64_t unixTime();

// Get current Unix timestamp (milliseconds)
uint64_t unixTimeMs();

// Get high-resolution monotonic time (for measuring durations)
uint64_t monotonicMs();

// Sleep for milliseconds
void sleepMs(uint32_t ms);

// Format timestamp for display
std::string formatTime(uint64_t timestamp);

// Parse timestamp from string
uint64_t parseTime(const std::string& str);

} // namespace util
} // namespace ftc

#endif // FTC_UTIL_TIME_H
