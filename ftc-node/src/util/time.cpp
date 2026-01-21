#include "util/time.h"
#include <thread>
#include <sstream>
#include <iomanip>
#include <ctime>

namespace ftc {
namespace util {

uint64_t unixTime() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

uint64_t unixTimeMs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

uint64_t monotonicMs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count()
    );
}

void sleepMs(uint32_t ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

std::string formatTime(uint64_t timestamp) {
    std::time_t t = static_cast<std::time_t>(timestamp);

    std::tm tm_buf;
#ifdef _WIN32
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S UTC");
    return oss.str();
}

uint64_t parseTime(const std::string& str) {
    std::tm tm = {};
    std::istringstream iss(str);
    iss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");

    if (iss.fail()) {
        return 0;
    }

#ifdef _WIN32
    return static_cast<uint64_t>(_mkgmtime(&tm));
#else
    return static_cast<uint64_t>(timegm(&tm));
#endif
}

} // namespace util
} // namespace ftc
