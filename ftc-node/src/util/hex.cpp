#include "util/hex.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace ftc {
namespace util {

std::string toHex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::string toHex(const std::vector<uint8_t>& data) {
    return toHex(data.data(), data.size());
}

std::optional<std::vector<uint8_t>> fromHex(const std::string& hex) {
    std::string clean = hex;

    // Remove 0x prefix if present
    if (clean.size() >= 2 && clean[0] == '0' && (clean[1] == 'x' || clean[1] == 'X')) {
        clean = clean.substr(2);
    }

    // Must be even length
    if (clean.size() % 2 != 0) {
        return std::nullopt;
    }

    std::vector<uint8_t> result;
    result.reserve(clean.size() / 2);

    for (size_t i = 0; i < clean.size(); i += 2) {
        char c1 = clean[i];
        char c2 = clean[i + 1];

        int v1, v2;

        if (c1 >= '0' && c1 <= '9') v1 = c1 - '0';
        else if (c1 >= 'a' && c1 <= 'f') v1 = c1 - 'a' + 10;
        else if (c1 >= 'A' && c1 <= 'F') v1 = c1 - 'A' + 10;
        else return std::nullopt;

        if (c2 >= '0' && c2 <= '9') v2 = c2 - '0';
        else if (c2 >= 'a' && c2 <= 'f') v2 = c2 - 'a' + 10;
        else if (c2 >= 'A' && c2 <= 'F') v2 = c2 - 'A' + 10;
        else return std::nullopt;

        result.push_back(static_cast<uint8_t>((v1 << 4) | v2));
    }

    return result;
}

std::vector<uint8_t> fromHexStrict(const std::string& hex) {
    auto result = fromHex(hex);
    if (!result) {
        throw std::invalid_argument("Invalid hex string: " + hex);
    }
    return *result;
}

std::string reverseHex(const std::string& hex) {
    auto bytes = fromHex(hex);
    if (!bytes) return "";

    std::vector<uint8_t> reversed(bytes->rbegin(), bytes->rend());
    return toHex(reversed);
}

} // namespace util
} // namespace ftc
