#ifndef FTC_UTIL_HEX_H
#define FTC_UTIL_HEX_H

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace ftc {
namespace util {

// Convert bytes to hex string
std::string toHex(const uint8_t* data, size_t len);
std::string toHex(const std::vector<uint8_t>& data);

// Convert hex string to bytes
std::optional<std::vector<uint8_t>> fromHex(const std::string& hex);

// Parse hex, throwing on error
std::vector<uint8_t> fromHexStrict(const std::string& hex);

// Reverse byte order (for display of hashes)
std::string reverseHex(const std::string& hex);

} // namespace util
} // namespace ftc

#endif // FTC_UTIL_HEX_H
