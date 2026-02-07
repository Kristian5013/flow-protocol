#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace core {

/// Returns current Unix timestamp in seconds since epoch.
int64_t get_time();

/// Returns current time in milliseconds since epoch.
int64_t get_time_millis();

/// Returns current time in microseconds since epoch.
int64_t get_time_micros();

/// Formats a Unix timestamp (seconds) as ISO 8601: "2026-02-03T00:00:00Z".
std::string format_iso8601(int64_t timestamp);

/// Parses an ISO 8601 string ("YYYY-MM-DDTHH:MM:SSZ") into a Unix timestamp.
/// Returns std::nullopt on failure.
std::optional<int64_t> parse_iso8601(std::string_view str);

/// Returns get_time() adjusted by the accumulated peer time offset.
int64_t get_adjusted_time();

/// Adds a time offset sample from a peer to the running offset accumulator.
void add_time_offset(int64_t offset);

// ---------------------------------------------------------------------------
// MockableClock - a clock that can be overridden for deterministic testing.
// ---------------------------------------------------------------------------

inline std::atomic<int64_t> mock_time{0};

class MockableClock {
public:
    /// Returns the mock time if set (non-zero), otherwise real wall-clock time.
    static int64_t now();

    /// Sets the mock time. Pass 0 to disable mocking and revert to real time.
    static void set_mock_time(int64_t t);

    /// Returns the current mock time value (0 means not mocking).
    static int64_t get_mock_time();
};

// ---------------------------------------------------------------------------
// StopWatch - a simple high-resolution timer.
// ---------------------------------------------------------------------------

class StopWatch {
public:
    /// Constructs and immediately starts the stopwatch.
    StopWatch();

    /// Returns elapsed time in milliseconds since construction or last reset.
    int64_t elapsed_ms() const;

    /// Returns elapsed time in microseconds since construction or last reset.
    int64_t elapsed_us() const;

    /// Resets the stopwatch to the current point in time.
    void reset();

private:
    std::chrono::steady_clock::time_point start_;
};

} // namespace core
