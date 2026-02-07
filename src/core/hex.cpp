#include "hex.h"

#include <algorithm>
#include <array>
#include <cstring>

namespace core {

// ---------------------------------------------------------------------------
// Lookup tables
// ---------------------------------------------------------------------------

// Each byte value maps to two ASCII hex characters (lowercase).
static constexpr std::array<char, 512> make_lower_table() {
    constexpr char digits[] = "0123456789abcdef";
    std::array<char, 512> table{};
    for (int i = 0; i < 256; ++i) {
        table[static_cast<size_t>(i) * 2]     = digits[(i >> 4) & 0xF];
        table[static_cast<size_t>(i) * 2 + 1] = digits[i & 0xF];
    }
    return table;
}

// Same as above but uppercase.
static constexpr std::array<char, 512> make_upper_table() {
    constexpr char digits[] = "0123456789ABCDEF";
    std::array<char, 512> table{};
    for (int i = 0; i < 256; ++i) {
        table[static_cast<size_t>(i) * 2]     = digits[(i >> 4) & 0xF];
        table[static_cast<size_t>(i) * 2 + 1] = digits[i & 0xF];
    }
    return table;
}

// Decode table: maps ASCII value -> nibble value, 0xFF means invalid.
static constexpr std::array<uint8_t, 256> make_decode_table() {
    std::array<uint8_t, 256> table{};
    for (auto& v : table) v = 0xFF;
    for (int i = 0; i <= 9; ++i) {
        table[static_cast<size_t>('0') + i] = static_cast<uint8_t>(i);
    }
    for (int i = 0; i < 6; ++i) {
        table[static_cast<size_t>('a') + i] = static_cast<uint8_t>(10 + i);
        table[static_cast<size_t>('A') + i] = static_cast<uint8_t>(10 + i);
    }
    return table;
}

static constexpr auto LOWER_TABLE  = make_lower_table();
static constexpr auto UPPER_TABLE  = make_upper_table();
static constexpr auto DECODE_TABLE = make_decode_table();

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

std::string to_hex(std::span<const uint8_t> data) {
    std::string result;
    result.resize(data.size() * 2);
    char* out = result.data();
    for (uint8_t byte : data) {
        const size_t idx = static_cast<size_t>(byte) * 2;
        *out++ = LOWER_TABLE[idx];
        *out++ = LOWER_TABLE[idx + 1];
    }
    return result;
}

std::string to_hex_upper(std::span<const uint8_t> data) {
    std::string result;
    result.resize(data.size() * 2);
    char* out = result.data();
    for (uint8_t byte : data) {
        const size_t idx = static_cast<size_t>(byte) * 2;
        *out++ = UPPER_TABLE[idx];
        *out++ = UPPER_TABLE[idx + 1];
    }
    return result;
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

std::optional<std::vector<uint8_t>> from_hex(std::string_view hex) {
    if (hex.size() % 2 != 0) {
        return std::nullopt;
    }

    const size_t byte_count = hex.size() / 2;
    std::vector<uint8_t> result;
    result.reserve(byte_count);

    for (size_t i = 0; i < hex.size(); i += 2) {
        const uint8_t hi = DECODE_TABLE[static_cast<uint8_t>(hex[i])];
        const uint8_t lo = DECODE_TABLE[static_cast<uint8_t>(hex[i + 1])];
        if (hi == 0xFF || lo == 0xFF) {
            return std::nullopt;
        }
        result.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }

    return result;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

bool is_hex(std::string_view str) {
    if (str.size() % 2 != 0) {
        return false;
    }
    for (char ch : str) {
        if (DECODE_TABLE[static_cast<uint8_t>(ch)] == 0xFF) {
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Byte-order reversal
// ---------------------------------------------------------------------------

std::string reverse_hex(std::string_view hex) {
    // Work only with whole bytes; drop a trailing odd nibble.
    const size_t usable = hex.size() & ~size_t{1};
    if (usable == 0) {
        return {};
    }

    std::string result;
    result.resize(usable);

    // Walk source from the last byte-pair toward the first.
    size_t out_pos = 0;
    for (size_t i = usable; i >= 2; i -= 2) {
        result[out_pos]     = hex[i - 2];
        result[out_pos + 1] = hex[i - 1];
        out_pos += 2;
    }

    return result;
}

}  // namespace core
