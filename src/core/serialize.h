#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/stream.h"
#include "core/types.h"
#include "core/varint.h"

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace core {

// ===================================================================
// Serialization concepts
// ===================================================================

/// A type is Serializable if it exposes a `serialize(Stream&)` method.
template <typename T>
concept Serializable = requires(T t, DataStream& s) {
    { t.serialize(s) };
};

/// A type is Deserializable if it exposes a static `deserialize(Stream&)`
/// factory that returns an instance of itself.
template <typename T>
concept Deserializable = requires(DataStream& s) {
    { T::deserialize(s) } -> std::same_as<T>;
};

// ===================================================================
// Safety limits
// ===================================================================

/// Maximum byte length for a deserialized string (1 MiB).
inline constexpr size_t MAX_STRING_LENGTH = 1u << 20;

/// Maximum element count for a deserialized vector (1 Mi elements).
inline constexpr size_t MAX_VECTOR_SIZE = 1u << 20;

/// Maximum value accepted by ser_read_compact_size (2^32 - 1).
/// Bitcoin Core uses the same bound on 32-bit-safe consensus paths.
inline constexpr uint64_t MAX_COMPACT_SIZE = 0xFFFFFFFFULL;

// ===================================================================
// CompactSize encoding (Bitcoin-compatible)
// ===================================================================
//
// Encoding scheme:
//   0   .. 252         -> 1 byte   (value itself)
//   253 .. 0xFFFF      -> 0xFD + 2 bytes LE
//   0x10000 .. 0xFFFF'FFFF  -> 0xFE + 4 bytes LE
//   0x1'0000'0000 ..   -> 0xFF + 8 bytes LE
// ===================================================================

/// Write a CompactSize-encoded unsigned integer.
template <typename Stream>
void ser_write_compact_size(Stream& s, uint64_t n) {
    if (n < 253) {
        uint8_t v = static_cast<uint8_t>(n);
        s.write(std::span<const uint8_t>(&v, 1));
    } else if (n <= 0xFFFF) {
        uint8_t hdr = 0xFD;
        s.write(std::span<const uint8_t>(&hdr, 1));
        uint8_t buf[2];
        buf[0] = static_cast<uint8_t>(n & 0xFF);
        buf[1] = static_cast<uint8_t>((n >> 8) & 0xFF);
        s.write(std::span<const uint8_t>(buf, 2));
    } else if (n <= 0xFFFFFFFFULL) {
        uint8_t hdr = 0xFE;
        s.write(std::span<const uint8_t>(&hdr, 1));
        uint8_t buf[4];
        buf[0] = static_cast<uint8_t>(n & 0xFF);
        buf[1] = static_cast<uint8_t>((n >> 8) & 0xFF);
        buf[2] = static_cast<uint8_t>((n >> 16) & 0xFF);
        buf[3] = static_cast<uint8_t>((n >> 24) & 0xFF);
        s.write(std::span<const uint8_t>(buf, 4));
    } else {
        uint8_t hdr = 0xFF;
        s.write(std::span<const uint8_t>(&hdr, 1));
        uint8_t buf[8];
        for (int i = 0; i < 8; ++i) {
            buf[i] = static_cast<uint8_t>((n >> (8 * i)) & 0xFF);
        }
        s.write(std::span<const uint8_t>(buf, 8));
    }
}

/// Read a CompactSize-encoded unsigned integer.
/// Throws on non-canonical encoding or values exceeding MAX_COMPACT_SIZE
/// (unless the caller explicitly needs 64-bit compact sizes).
template <typename Stream>
uint64_t ser_read_compact_size(Stream& s) {
    uint8_t hdr{};
    s.read(std::span<uint8_t>(&hdr, 1));

    uint64_t n;
    if (hdr < 253) {
        n = hdr;
    } else if (hdr == 0xFD) {
        uint8_t buf[2];
        s.read(std::span<uint8_t>(buf, 2));
        n = static_cast<uint64_t>(buf[0])
          | (static_cast<uint64_t>(buf[1]) << 8);
        if (n < 253) {
            throw std::runtime_error(
                "ser_read_compact_size(): non-canonical encoding");
        }
    } else if (hdr == 0xFE) {
        uint8_t buf[4];
        s.read(std::span<uint8_t>(buf, 4));
        n = static_cast<uint64_t>(buf[0])
          | (static_cast<uint64_t>(buf[1]) << 8)
          | (static_cast<uint64_t>(buf[2]) << 16)
          | (static_cast<uint64_t>(buf[3]) << 24);
        if (n < 0x10000ULL) {
            throw std::runtime_error(
                "ser_read_compact_size(): non-canonical encoding");
        }
    } else {  // 0xFF
        uint8_t buf[8];
        s.read(std::span<uint8_t>(buf, 8));
        n = 0;
        for (int i = 0; i < 8; ++i) {
            n |= static_cast<uint64_t>(buf[i]) << (8 * i);
        }
        if (n < 0x100000000ULL) {
            throw std::runtime_error(
                "ser_read_compact_size(): non-canonical encoding");
        }
    }

    if (n > MAX_COMPACT_SIZE) {
        throw std::runtime_error(
            "ser_read_compact_size(): size exceeds MAX_COMPACT_SIZE");
    }
    return n;
}

// ===================================================================
// Primitive serializers -- little-endian wire format
// ===================================================================

template <typename Stream>
inline void ser_write_u8(Stream& s, uint8_t v) {
    s.write(std::span<const uint8_t>(&v, 1));
}

template <typename Stream>
inline void ser_write_u16(Stream& s, uint16_t v) {
    uint8_t buf[2];
    buf[0] = static_cast<uint8_t>(v & 0xFF);
    buf[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    s.write(std::span<const uint8_t>(buf, 2));
}

template <typename Stream>
inline void ser_write_u32(Stream& s, uint32_t v) {
    uint8_t buf[4];
    buf[0] = static_cast<uint8_t>(v & 0xFF);
    buf[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    buf[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    buf[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
    s.write(std::span<const uint8_t>(buf, 4));
}

template <typename Stream>
inline void ser_write_u64(Stream& s, uint64_t v) {
    uint8_t buf[8];
    for (int i = 0; i < 8; ++i) {
        buf[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
    }
    s.write(std::span<const uint8_t>(buf, 8));
}

template <typename Stream>
inline void ser_write_i32(Stream& s, int32_t v) {
    ser_write_u32(s, static_cast<uint32_t>(v));
}

template <typename Stream>
inline void ser_write_i64(Stream& s, int64_t v) {
    ser_write_u64(s, static_cast<uint64_t>(v));
}

template <typename Stream>
inline void ser_write_bytes(Stream& s, std::span<const uint8_t> data) {
    s.write(data);
}

// ===================================================================
// Primitive deserializers -- little-endian wire format
// ===================================================================

template <typename Stream>
inline uint8_t ser_read_u8(Stream& s) {
    uint8_t v{};
    s.read(std::span<uint8_t>(&v, 1));
    return v;
}

template <typename Stream>
inline uint16_t ser_read_u16(Stream& s) {
    uint8_t buf[2];
    s.read(std::span<uint8_t>(buf, 2));
    return static_cast<uint16_t>(buf[0])
         | (static_cast<uint16_t>(buf[1]) << 8);
}

template <typename Stream>
inline uint32_t ser_read_u32(Stream& s) {
    uint8_t buf[4];
    s.read(std::span<uint8_t>(buf, 4));
    return static_cast<uint32_t>(buf[0])
         | (static_cast<uint32_t>(buf[1]) << 8)
         | (static_cast<uint32_t>(buf[2]) << 16)
         | (static_cast<uint32_t>(buf[3]) << 24);
}

template <typename Stream>
inline uint64_t ser_read_u64(Stream& s) {
    uint8_t buf[8];
    s.read(std::span<uint8_t>(buf, 8));
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(buf[i]) << (8 * i);
    }
    return v;
}

template <typename Stream>
inline int32_t ser_read_i32(Stream& s) {
    return static_cast<int32_t>(ser_read_u32(s));
}

template <typename Stream>
inline int64_t ser_read_i64(Stream& s) {
    return static_cast<int64_t>(ser_read_u64(s));
}

template <typename Stream>
inline void ser_read_bytes(Stream& s, std::span<uint8_t> buf) {
    s.read(buf);
}

// ===================================================================
// Bool serialization (single byte: 0x00 or 0x01)
// ===================================================================

template <typename Stream>
inline void ser_write_bool(Stream& s, bool v) {
    ser_write_u8(s, v ? 1 : 0);
}

template <typename Stream>
inline bool ser_read_bool(Stream& s) {
    uint8_t v = ser_read_u8(s);
    if (v > 1) {
        throw std::runtime_error(
            "ser_read_bool(): invalid boolean value");
    }
    return v != 0;
}

// ===================================================================
// Compound serializers -- strings
// ===================================================================

/// Write a string: CompactSize length prefix followed by raw bytes.
template <typename Stream>
void ser_write_string(Stream& s, std::string_view str) {
    ser_write_compact_size(s, str.size());
    if (!str.empty()) {
        s.write(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(str.data()), str.size()));
    }
}

/// Read a string: CompactSize length prefix followed by raw bytes.
/// Throws if the decoded length exceeds MAX_STRING_LENGTH.
template <typename Stream>
std::string ser_read_string(Stream& s) {
    uint64_t len = ser_read_compact_size(s);
    if (len > MAX_STRING_LENGTH) {
        throw std::runtime_error(
            "ser_read_string(): string exceeds MAX_STRING_LENGTH");
    }
    std::string result(static_cast<size_t>(len), '\0');
    if (len > 0) {
        s.read(std::span<uint8_t>(
            reinterpret_cast<uint8_t*>(result.data()),
            static_cast<size_t>(len)));
    }
    return result;
}

// ===================================================================
// Compound serializers -- byte vectors
// ===================================================================

/// Write a byte vector: CompactSize length prefix followed by raw bytes.
template <typename Stream>
void ser_write_vector(Stream& s, const std::vector<uint8_t>& v) {
    ser_write_compact_size(s, v.size());
    if (!v.empty()) {
        s.write(std::span<const uint8_t>(v));
    }
}

/// Read a byte vector: CompactSize length prefix followed by raw bytes.
/// Throws if the decoded length exceeds MAX_VECTOR_SIZE.
template <typename Stream>
std::vector<uint8_t> ser_read_vector(Stream& s) {
    uint64_t len = ser_read_compact_size(s);
    if (len > MAX_VECTOR_SIZE) {
        throw std::runtime_error(
            "ser_read_vector(): vector exceeds MAX_VECTOR_SIZE");
    }
    std::vector<uint8_t> result(static_cast<size_t>(len));
    if (len > 0) {
        s.read(std::span<uint8_t>(result));
    }
    return result;
}

// ===================================================================
// Compound serializers -- vectors of Serializable / Deserializable T
// ===================================================================

/// Write a vector of Serializable elements.
template <typename Stream, Serializable T>
void ser_write_obj_vector(Stream& s, const std::vector<T>& v) {
    ser_write_compact_size(s, v.size());
    for (const auto& elem : v) {
        elem.serialize(s);
    }
}

/// Read a vector of Deserializable elements.
template <typename Stream, Deserializable T>
std::vector<T> ser_read_obj_vector(Stream& s) {
    uint64_t count = ser_read_compact_size(s);
    if (count > MAX_VECTOR_SIZE) {
        throw std::runtime_error(
            "ser_read_obj_vector(): count exceeds MAX_VECTOR_SIZE");
    }
    std::vector<T> result;
    result.reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
        result.push_back(T::deserialize(s));
    }
    return result;
}

// ===================================================================
// Fixed-size array serialization
// ===================================================================

/// Write a std::array<uint8_t, N> as raw bytes (no length prefix).
template <typename Stream, size_t N>
inline void ser_write_array(Stream& s,
                            const std::array<uint8_t, N>& arr) {
    s.write(std::span<const uint8_t>(arr));
}

/// Read a std::array<uint8_t, N> as raw bytes (no length prefix).
template <typename Stream, size_t N>
inline std::array<uint8_t, N> ser_read_array(Stream& s) {
    std::array<uint8_t, N> arr{};
    s.read(std::span<uint8_t>(arr));
    return arr;
}

// ===================================================================
// Blob<N> / uint256 / uint160 serialization
// ===================================================================
// Blobs are serialized as raw little-endian bytes (no length prefix),
// matching their internal storage order.

template <typename Stream, size_t N>
inline void ser_write_blob(Stream& s, const core::Blob<N>& blob) {
    s.write(std::span<const uint8_t>(blob.data(), N));
}

template <typename Stream, size_t N>
inline core::Blob<N> ser_read_blob(Stream& s) {
    std::array<uint8_t, N> bytes{};
    s.read(std::span<uint8_t>(bytes));
    return core::Blob<N>::from_bytes(
        std::span<const uint8_t, N>(bytes));
}

/// Convenience: serialize a uint256 (32 bytes, no length prefix).
template <typename Stream>
inline void ser_write_uint256(Stream& s, const core::uint256& v) {
    s.write(std::span<const uint8_t>(v.data(), 32));
}

/// Convenience: deserialize a uint256 (32 bytes, no length prefix).
template <typename Stream>
inline core::uint256 ser_read_uint256(Stream& s) {
    std::array<uint8_t, 32> bytes{};
    s.read(std::span<uint8_t>(bytes));
    return core::uint256::from_bytes(
        std::span<const uint8_t, 32>(bytes));
}

/// Convenience: serialize a uint160 (20 bytes, no length prefix).
template <typename Stream>
inline void ser_write_uint160(Stream& s, const core::uint160& v) {
    s.write(std::span<const uint8_t>(v.data(), 20));
}

/// Convenience: deserialize a uint160 (20 bytes, no length prefix).
template <typename Stream>
inline core::uint160 ser_read_uint160(Stream& s) {
    std::array<uint8_t, 20> bytes{};
    s.read(std::span<uint8_t>(bytes));
    return core::uint160::from_bytes(
        std::span<const uint8_t, 20>(bytes));
}

// ===================================================================
// Generic serialize / deserialize dispatchers
// ===================================================================
// These allow writing `core::serialize(stream, obj)` for any
// Serializable type, providing a uniform calling convention.

template <typename Stream, Serializable T>
inline void serialize(Stream& s, const T& obj) {
    obj.serialize(s);
}

template <typename Stream, Deserializable T>
inline T deserialize(Stream& s) {
    return T::deserialize(s);
}

// ===================================================================
// Helper: compute serialized size of a Serializable object
// ===================================================================

/// Serialize \p obj into a temporary DataStream and return the byte count.
template <Serializable T>
inline size_t serialized_size(const T& obj) {
    DataStream tmp;
    obj.serialize(tmp);
    return tmp.size();
}

}  // namespace core
