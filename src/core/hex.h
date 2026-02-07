#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace core {

// Encode a byte span to a lowercase hexadecimal string.
std::string to_hex(std::span<const uint8_t> data);

// Encode a byte span to an uppercase hexadecimal string.
std::string to_hex_upper(std::span<const uint8_t> data);

// Decode a hexadecimal string to bytes. Returns nullopt if the input is
// invalid (odd length or non-hex characters).
std::optional<std::vector<uint8_t>> from_hex(std::string_view hex);

// Check whether a string is a valid hexadecimal encoding (even length,
// every character in [0-9a-fA-F]).
bool is_hex(std::string_view str);

// Reverse the byte order of a hex string. Useful for endian conversions.
// If the input has odd length the last nibble is dropped so that the result
// always represents whole bytes.
std::string reverse_hex(std::string_view hex);

}  // namespace core
