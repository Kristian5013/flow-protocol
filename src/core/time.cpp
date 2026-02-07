#include "time.h"

#include <array>
#include <charconv>
#include <cstring>
#include <ctime>
#include <mutex>
#include <numeric>
#include <vector>

namespace core {

// ---------------------------------------------------------------------------
// Free functions - wall-clock time
// ---------------------------------------------------------------------------

int64_t get_time()
{
    using namespace std::chrono;
    return duration_cast<seconds>(
        system_clock::now().time_since_epoch()
    ).count();
}

int64_t get_time_millis()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()
    ).count();
}

int64_t get_time_micros()
{
    using namespace std::chrono;
    return duration_cast<microseconds>(
        system_clock::now().time_since_epoch()
    ).count();
}

// ---------------------------------------------------------------------------
// ISO 8601 formatting / parsing
// ---------------------------------------------------------------------------

std::string format_iso8601(int64_t timestamp)
{
    std::time_t tt = static_cast<std::time_t>(timestamp);
    std::tm utc{};

#ifdef _WIN32
    gmtime_s(&utc, &tt);
#else
    gmtime_r(&tt, &utc);
#endif

    // "YYYY-MM-DDTHH:MM:SSZ" is exactly 20 characters + null.
    std::array<char, 32> buf{};
    std::strftime(buf.data(), buf.size(), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return std::string(buf.data());
}

/// Helper: parse exactly `n` digits from `str` starting at `pos`.
/// Advances `pos` past the digits on success.
static bool parse_digits(std::string_view str, size_t& pos, int n, int& out)
{
    if (pos + static_cast<size_t>(n) > str.size()) {
        return false;
    }
    std::string_view segment = str.substr(pos, static_cast<size_t>(n));
    auto result = std::from_chars(segment.data(), segment.data() + n, out);
    if (result.ec != std::errc{} || result.ptr != segment.data() + n) {
        return false;
    }
    pos += static_cast<size_t>(n);
    return true;
}

/// Helper: expect a specific character at `pos` and advance past it.
static bool expect_char(std::string_view str, size_t& pos, char ch)
{
    if (pos >= str.size() || str[pos] != ch) {
        return false;
    }
    ++pos;
    return true;
}

std::optional<int64_t> parse_iso8601(std::string_view str)
{
    // Expected format: "YYYY-MM-DDTHH:MM:SSZ" (20 chars).
    if (str.size() < 20) {
        return std::nullopt;
    }

    size_t pos = 0;
    int year = 0, month = 0, day = 0;
    int hour = 0, minute = 0, second = 0;

    if (!parse_digits(str, pos, 4, year))   return std::nullopt;
    if (!expect_char(str, pos, '-'))         return std::nullopt;
    if (!parse_digits(str, pos, 2, month))  return std::nullopt;
    if (!expect_char(str, pos, '-'))         return std::nullopt;
    if (!parse_digits(str, pos, 2, day))    return std::nullopt;
    if (!expect_char(str, pos, 'T'))         return std::nullopt;
    if (!parse_digits(str, pos, 2, hour))   return std::nullopt;
    if (!expect_char(str, pos, ':'))         return std::nullopt;
    if (!parse_digits(str, pos, 2, minute)) return std::nullopt;
    if (!expect_char(str, pos, ':'))         return std::nullopt;
    if (!parse_digits(str, pos, 2, second)) return std::nullopt;
    if (!expect_char(str, pos, 'Z'))         return std::nullopt;

    // Basic range validation.
    if (month < 1 || month > 12)   return std::nullopt;
    if (day < 1 || day > 31)       return std::nullopt;
    if (hour < 0 || hour > 23)     return std::nullopt;
    if (minute < 0 || minute > 59) return std::nullopt;
    if (second < 0 || second > 60) return std::nullopt; // allow leap second

    std::tm utc{};
    utc.tm_year  = year - 1900;
    utc.tm_mon   = month - 1;
    utc.tm_mday  = day;
    utc.tm_hour  = hour;
    utc.tm_min   = minute;
    utc.tm_sec   = second;
    utc.tm_isdst = 0;

    // Convert to time_t in UTC.  Neither timegm nor _mkgmtime are in the
    // C++ standard, but they are available on all target platforms.
#ifdef _WIN32
    std::time_t tt = _mkgmtime(&utc);
#else
    std::time_t tt = timegm(&utc);
#endif

    if (tt == static_cast<std::time_t>(-1)) {
        return std::nullopt;
    }

    return static_cast<int64_t>(tt);
}

// ---------------------------------------------------------------------------
// Peer time offset
// ---------------------------------------------------------------------------

/// We keep a small rolling window of offset samples and expose the median.
/// Protected by a mutex because multiple peers may report concurrently.

static constexpr size_t MAX_OFFSET_SAMPLES = 200;

struct OffsetState {
    std::mutex              mutex;
    std::vector<int64_t>    samples;
    int64_t                 cached_median{0};
};

static OffsetState& offset_state()
{
    static OffsetState state;
    return state;
}

static int64_t compute_median(std::vector<int64_t> v)
{
    if (v.empty()) {
        return 0;
    }
    auto mid = v.begin() + static_cast<std::ptrdiff_t>(v.size() / 2);
    std::nth_element(v.begin(), mid, v.end());
    return *mid;
}

void add_time_offset(int64_t offset)
{
    auto& state = offset_state();
    std::lock_guard<std::mutex> lock(state.mutex);

    if (state.samples.size() >= MAX_OFFSET_SAMPLES) {
        // Drop the oldest sample (FIFO).
        state.samples.erase(state.samples.begin());
    }
    state.samples.push_back(offset);

    // Recompute median.
    state.cached_median = compute_median(state.samples);
}

int64_t get_adjusted_time()
{
    auto& state = offset_state();
    int64_t median;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        median = state.cached_median;
    }
    return get_time() + median;
}

// ---------------------------------------------------------------------------
// MockableClock
// ---------------------------------------------------------------------------

int64_t MockableClock::now()
{
    int64_t mt = mock_time.load(std::memory_order_relaxed);
    if (mt != 0) {
        return mt;
    }
    return get_time();
}

void MockableClock::set_mock_time(int64_t t)
{
    mock_time.store(t, std::memory_order_relaxed);
}

int64_t MockableClock::get_mock_time()
{
    return mock_time.load(std::memory_order_relaxed);
}

// ---------------------------------------------------------------------------
// StopWatch
// ---------------------------------------------------------------------------

StopWatch::StopWatch()
    : start_(std::chrono::steady_clock::now())
{
}

int64_t StopWatch::elapsed_ms() const
{
    using namespace std::chrono;
    auto now = steady_clock::now();
    return duration_cast<milliseconds>(now - start_).count();
}

int64_t StopWatch::elapsed_us() const
{
    using namespace std::chrono;
    auto now = steady_clock::now();
    return duration_cast<microseconds>(now - start_).count();
}

void StopWatch::reset()
{
    start_ = std::chrono::steady_clock::now();
}

} // namespace core
