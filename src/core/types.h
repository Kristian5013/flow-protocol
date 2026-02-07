#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>

namespace core {

// ---------------------------------------------------------------------------
// Blob<N> -- fixed-size byte array (little-endian internal storage)
// ---------------------------------------------------------------------------
// Base template for uint256 (N=32) and uint160 (N=20).
// Bytes are stored in LITTLE-ENDIAN order internally (least-significant byte
// at index 0).  Hex display uses BIG-ENDIAN order (most-significant byte
// first), matching the conventional blockchain representation.
// ---------------------------------------------------------------------------
template <std::size_t N>
class Blob {
public:
    static constexpr std::size_t SIZE = N;

    // -- Construction -------------------------------------------------------

    /// Default: zero-initialized.
    constexpr Blob() noexcept : bytes_{} {}

    /// Construct from a raw little-endian byte span.
    static Blob from_bytes(std::span<const uint8_t, N> bytes) noexcept;

    /// Construct from a raw big-endian byte span (reverses into LE storage).
    static Blob from_bytes_be(std::span<const uint8_t, N> bytes) noexcept;

    /// Parse a hex string in big-endian display order (2*N hex chars).
    /// Accepts optional "0x" / "0X" prefix.  Throws std::invalid_argument
    /// on malformed input.
    static Blob from_hex(std::string_view hex);

    // -- Serialization ------------------------------------------------------

    /// Return the big-endian hex string (2*N lower-case hex chars, no prefix).
    [[nodiscard]] std::string to_hex() const;

    // -- Raw access ---------------------------------------------------------

    [[nodiscard]] const uint8_t* data() const noexcept { return bytes_.data(); }
    [[nodiscard]]       uint8_t* data()       noexcept { return bytes_.data(); }

    [[nodiscard]] const std::array<uint8_t, N>& bytes() const noexcept {
        return bytes_;
    }

    [[nodiscard]] constexpr std::size_t size() const noexcept { return N; }

    // -- Queries ------------------------------------------------------------

    [[nodiscard]] bool is_zero() const noexcept;

    // -- Comparison (numeric, as big unsigned integers) ----------------------

    [[nodiscard]] std::strong_ordering operator<=>(const Blob& other) const noexcept;
    [[nodiscard]] bool operator==(const Blob& other) const noexcept;

    // -- Bitwise operations -------------------------------------------------

    [[nodiscard]] Blob operator~() const noexcept;

    Blob& operator>>=(int shift) noexcept;
    Blob& operator<<=(int shift) noexcept;

    [[nodiscard]] Blob operator>>(int shift) const noexcept {
        Blob result = *this;
        result >>= shift;
        return result;
    }

    [[nodiscard]] Blob operator<<(int shift) const noexcept {
        Blob result = *this;
        result <<= shift;
        return result;
    }

protected:
    std::array<uint8_t, N> bytes_;
};

// ---------------------------------------------------------------------------
// uint256 -- 256-bit unsigned integer (32 bytes)
// ---------------------------------------------------------------------------
class uint256 : public Blob<32> {
public:
    using Blob<32>::Blob;

    // Re-expose static factories returning uint256 (not Blob<32>).
    static uint256 from_hex(std::string_view hex);
    static uint256 from_bytes(std::span<const uint8_t, 32> bytes) noexcept;
    static uint256 from_bytes_be(std::span<const uint8_t, 32> bytes) noexcept;

    // -- Scalar arithmetic (used for difficulty target calculations) ---------

    uint256& operator*=(uint64_t n) noexcept;
    uint256& operator/=(uint64_t n) noexcept;

    [[nodiscard]] uint256 operator*(uint64_t n) const noexcept {
        uint256 result = *this;
        result *= n;
        return result;
    }

    [[nodiscard]] uint256 operator/(uint64_t n) const noexcept {
        uint256 result = *this;
        result /= n;
        return result;
    }
};

// ---------------------------------------------------------------------------
// uint160 -- 160-bit unsigned integer (20 bytes, for addresses / Hash160)
// ---------------------------------------------------------------------------
class uint160 : public Blob<20> {
public:
    using Blob<20>::Blob;

    // Re-expose static factories returning uint160.
    static uint160 from_hex(std::string_view hex);
    static uint160 from_bytes(std::span<const uint8_t, 20> bytes) noexcept;
    static uint160 from_bytes_be(std::span<const uint8_t, 20> bytes) noexcept;
};

}  // namespace core

// ---------------------------------------------------------------------------
// std::hash specializations
// ---------------------------------------------------------------------------
template <>
struct std::hash<core::uint256> {
    std::size_t operator()(const core::uint256& v) const noexcept;
};

template <>
struct std::hash<core::uint160> {
    std::size_t operator()(const core::uint160& v) const noexcept;
};
