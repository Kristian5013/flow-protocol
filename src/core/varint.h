#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace core {

// ---------------------------------------------------------------------------
// Base-128 variable-length integer encoding (protobuf / LEB128-style)
// ---------------------------------------------------------------------------
// Each byte carries 7 bits of payload in bits [0..6].  Bit 7 (0x80) is the
// continuation flag: when set, more bytes follow.  The encoding is
// little-endian (least-significant group first).
//
// Examples:
//   0          -> 0x00
//   127        -> 0x7F
//   128        -> 0x80 0x01
//   300        -> 0xAC 0x02
//   16384      -> 0x80 0x80 0x01
// ---------------------------------------------------------------------------

// -- Constants --------------------------------------------------------------

/// Maximum number of bytes a varint can occupy (ceil(64/7) = 10).
inline constexpr size_t MAX_VARINT_BYTES = 10;

// -- Stream-based I/O (templates) -------------------------------------------

/// Encode \p n as a base-128 varint and write it to \p s.
template <typename Stream>
void write_varint(Stream& s, uint64_t n) {
    uint8_t buf[MAX_VARINT_BYTES];
    size_t len = 0;
    while (n > 0x7F) {
        buf[len++] = static_cast<uint8_t>(n & 0x7F) | 0x80;
        n >>= 7;
    }
    buf[len++] = static_cast<uint8_t>(n);
    s.write(std::span<const uint8_t>(buf, len));
}

/// Read a base-128 varint from \p s.
/// Throws on malformed input (more than MAX_VARINT_BYTES) or truncated
/// stream (the underlying stream's read() will throw).
template <typename Stream>
uint64_t read_varint(Stream& s) {
    uint64_t result = 0;
    unsigned shift = 0;

    for (size_t i = 0; i < MAX_VARINT_BYTES; ++i) {
        uint8_t byte{};
        s.read(std::span<uint8_t>(&byte, 1));

        result |= static_cast<uint64_t>(byte & 0x7F) << shift;

        if ((byte & 0x80) == 0) {
            return result;
        }
        shift += 7;
    }
    throw std::runtime_error("read_varint(): varint exceeds maximum size");
}

// -- Standalone helpers (non-stream) ----------------------------------------

/// Compute the encoded size of \p n in bytes without actually writing.
inline size_t varint_size(uint64_t n) noexcept {
    size_t len = 1;
    while (n > 0x7F) {
        ++len;
        n >>= 7;
    }
    return len;
}

/// Encode \p n as a base-128 varint into a self-contained byte vector.
inline std::vector<uint8_t> encode_varint(uint64_t n) {
    std::vector<uint8_t> out;
    out.reserve(varint_size(n));
    while (n > 0x7F) {
        out.push_back(static_cast<uint8_t>(n & 0x7F) | 0x80);
        n >>= 7;
    }
    out.push_back(static_cast<uint8_t>(n));
    return out;
}

/// Decode a base-128 varint from a byte span.
/// Returns a pair of (decoded value, number of bytes consumed).
/// Throws if the span is too short or the encoding exceeds 10 bytes.
inline std::pair<uint64_t, size_t>
decode_varint(std::span<const uint8_t> data) {
    uint64_t result = 0;
    unsigned shift = 0;

    for (size_t i = 0; i < data.size() && i < MAX_VARINT_BYTES; ++i) {
        uint8_t byte = data[i];
        result |= static_cast<uint64_t>(byte & 0x7F) << shift;

        if ((byte & 0x80) == 0) {
            return {result, i + 1};
        }
        shift += 7;
    }

    if (data.size() == 0) {
        throw std::runtime_error(
            "decode_varint(): empty input");
    }
    if (data.size() < MAX_VARINT_BYTES) {
        throw std::runtime_error(
            "decode_varint(): truncated varint");
    }
    throw std::runtime_error(
        "decode_varint(): varint exceeds maximum size");
}

}  // namespace core
