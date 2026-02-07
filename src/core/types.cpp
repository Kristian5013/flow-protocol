#include "core/types.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace core {

// ===========================================================================
// Internal hex helpers
// ===========================================================================

namespace {

constexpr char HEX_DIGITS[] = "0123456789abcdef";

/// Convert a single hex character to its 4-bit value.
/// Returns -1 on invalid input.
constexpr int hex_digit_value(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}  // namespace

// ===========================================================================
// Blob<N> -- template method definitions
// ===========================================================================

// Because Blob is a class template, most members must be visible at the point
// of instantiation.  We provide explicit instantiations at the bottom of this
// file for N=32 and N=20, which means we can keep the definitions here in the
// .cpp rather than in the header.

template <std::size_t N>
Blob<N> Blob<N>::from_bytes(std::span<const uint8_t, N> bytes) noexcept {
    Blob<N> result;
    std::copy(bytes.begin(), bytes.end(), result.bytes_.begin());
    return result;
}

template <std::size_t N>
Blob<N> Blob<N>::from_bytes_be(std::span<const uint8_t, N> bytes) noexcept {
    Blob<N> result;
    // Reverse: big-endian input -> little-endian internal storage.
    std::reverse_copy(bytes.begin(), bytes.end(), result.bytes_.begin());
    return result;
}

template <std::size_t N>
Blob<N> Blob<N>::from_hex(std::string_view hex) {
    // Strip optional "0x" / "0X" prefix.
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex.remove_prefix(2);
    }

    constexpr std::size_t EXPECTED_HEX_LEN = N * 2;

    // Allow shorter strings -- left-pad with zeros conceptually.
    if (hex.size() > EXPECTED_HEX_LEN) {
        throw std::invalid_argument(
            "Blob::from_hex: input too long (expected at most " +
            std::to_string(EXPECTED_HEX_LEN) + " hex chars)");
    }

    // Parse hex in big-endian display order into a big-endian byte buffer,
    // then reverse into little-endian storage.
    std::array<uint8_t, N> be_bytes{};

    // The hex string represents the number with the most-significant nibble
    // first.  If the string is shorter than 2*N chars we right-align the
    // value within be_bytes (i.e. leading bytes remain zero).
    const std::size_t pad = EXPECTED_HEX_LEN - hex.size();
    // pad is the number of missing hex chars (leading zeros).

    for (std::size_t i = 0; i < hex.size(); ++i) {
        int v = hex_digit_value(hex[i]);
        if (v < 0) {
            throw std::invalid_argument(
                "Blob::from_hex: invalid hex character");
        }
        // The position in the full 2*N hex string is (pad + i).
        std::size_t full_pos = pad + i;
        std::size_t byte_idx = full_pos / 2;
        if (full_pos % 2 == 0) {
            be_bytes[byte_idx] = static_cast<uint8_t>(v << 4);
        } else {
            be_bytes[byte_idx] |= static_cast<uint8_t>(v);
        }
    }

    // Convert big-endian -> little-endian.
    Blob<N> result;
    std::reverse_copy(be_bytes.begin(), be_bytes.end(),
                      result.bytes_.begin());
    return result;
}

template <std::size_t N>
std::string Blob<N>::to_hex() const {
    // Output in big-endian display order: most-significant byte first.
    std::string out;
    out.reserve(N * 2);
    for (std::size_t i = N; i > 0; --i) {
        uint8_t byte = bytes_[i - 1];
        out.push_back(HEX_DIGITS[byte >> 4]);
        out.push_back(HEX_DIGITS[byte & 0x0F]);
    }
    return out;
}

template <std::size_t N>
bool Blob<N>::is_zero() const noexcept {
    for (auto b : bytes_) {
        if (b != 0) return false;
    }
    return true;
}

template <std::size_t N>
std::strong_ordering Blob<N>::operator<=>(const Blob& other) const noexcept {
    // Compare as big unsigned integers.  Because internal storage is
    // little-endian, we compare from the MOST-significant byte (index N-1)
    // down to index 0.
    for (std::size_t i = N; i > 0; --i) {
        if (bytes_[i - 1] != other.bytes_[i - 1]) {
            return bytes_[i - 1] < other.bytes_[i - 1]
                       ? std::strong_ordering::less
                       : std::strong_ordering::greater;
        }
    }
    return std::strong_ordering::equal;
}

template <std::size_t N>
bool Blob<N>::operator==(const Blob& other) const noexcept {
    return bytes_ == other.bytes_;
}

template <std::size_t N>
Blob<N> Blob<N>::operator~() const noexcept {
    Blob<N> result;
    for (std::size_t i = 0; i < N; ++i) {
        result.bytes_[i] = static_cast<uint8_t>(~bytes_[i]);
    }
    return result;
}

template <std::size_t N>
Blob<N>& Blob<N>::operator>>=(int shift) noexcept {
    if (shift <= 0) return *this;
    if (shift >= static_cast<int>(N * 8)) {
        bytes_.fill(0);
        return *this;
    }

    const int byte_shift = shift / 8;
    const int bit_shift  = shift % 8;

    if (bit_shift == 0) {
        // Pure byte-level shift: move bytes toward index 0 (less significant).
        for (std::size_t i = 0; i < N; ++i) {
            std::size_t src = i + static_cast<std::size_t>(byte_shift);
            bytes_[i] = (src < N) ? bytes_[src] : 0;
        }
    } else {
        // Combined byte + bit shift.  In little-endian, a right-shift of the
        // numerical value moves bits toward lower byte indices.
        for (std::size_t i = 0; i < N; ++i) {
            std::size_t lo_src = i + static_cast<std::size_t>(byte_shift);
            std::size_t hi_src = lo_src + 1;
            uint8_t lo = (lo_src < N) ? bytes_[lo_src] : 0;
            uint8_t hi = (hi_src < N) ? bytes_[hi_src] : 0;
            bytes_[i] = static_cast<uint8_t>(
                (lo >> bit_shift) | (hi << (8 - bit_shift)));
        }
    }
    return *this;
}

template <std::size_t N>
Blob<N>& Blob<N>::operator<<=(int shift) noexcept {
    if (shift <= 0) return *this;
    if (shift >= static_cast<int>(N * 8)) {
        bytes_.fill(0);
        return *this;
    }

    const int byte_shift = shift / 8;
    const int bit_shift  = shift % 8;

    if (bit_shift == 0) {
        // Pure byte-level shift: move bytes toward higher indices.
        for (std::size_t i = N; i > 0; --i) {
            std::size_t idx = i - 1;
            if (idx >= static_cast<std::size_t>(byte_shift)) {
                bytes_[idx] = bytes_[idx -
                    static_cast<std::size_t>(byte_shift)];
            } else {
                bytes_[idx] = 0;
            }
        }
    } else {
        // Combined byte + bit shift.  In little-endian, a left-shift moves
        // bits toward higher byte indices.
        for (std::size_t i = N; i > 0; --i) {
            std::size_t idx = i - 1;
            int lo_src =
                static_cast<int>(idx) - byte_shift - 1;
            int hi_src =
                static_cast<int>(idx) - byte_shift;
            uint8_t lo = (lo_src >= 0)
                ? bytes_[static_cast<std::size_t>(lo_src)] : 0;
            uint8_t hi = (hi_src >= 0)
                ? bytes_[static_cast<std::size_t>(hi_src)] : 0;
            bytes_[idx] = static_cast<uint8_t>(
                (hi << bit_shift) | (lo >> (8 - bit_shift)));
        }
    }
    return *this;
}

// ---------------------------------------------------------------------------
// Explicit template instantiations for N=32 and N=20
// ---------------------------------------------------------------------------
template class Blob<32>;
template class Blob<20>;

// ===========================================================================
// uint256 -- factory methods & arithmetic
// ===========================================================================

uint256 uint256::from_hex(std::string_view hex) {
    uint256 result;
    static_cast<Blob<32>&>(result) = Blob<32>::from_hex(hex);
    return result;
}

uint256 uint256::from_bytes(
    std::span<const uint8_t, 32> bytes) noexcept {
    uint256 result;
    static_cast<Blob<32>&>(result) = Blob<32>::from_bytes(bytes);
    return result;
}

uint256 uint256::from_bytes_be(
    std::span<const uint8_t, 32> bytes) noexcept {
    uint256 result;
    static_cast<Blob<32>&>(result) = Blob<32>::from_bytes_be(bytes);
    return result;
}

uint256& uint256::operator*=(uint64_t n) noexcept {
    // Multiply the 256-bit little-endian value by a 64-bit scalar.
    // Process 8 bytes (uint64_t) at a time for efficiency while correctly
    // propagating carries across the full width.
    //
    // We treat bytes_ as an array of four uint64_t limbs in little-endian
    // order.  This works because the internal byte array is itself stored
    // in little-endian byte order on little-endian machines, and we use
    // memcpy to avoid aliasing issues (the compiler will optimize this).

    // Use a byte-level approach for portability (no endian assumption
    // beyond our own LE storage convention).
    // We accumulate using 128-bit intermediates via uint64_t pairs.

    uint64_t carry = 0;

    // Process one byte at a time -- simple, correct, and the compiler
    // will vectorize/unroll as needed.
    for (std::size_t i = 0; i < 32; ++i) {
        uint64_t product =
            static_cast<uint64_t>(bytes_[i]) * n + carry;
        bytes_[i] = static_cast<uint8_t>(product & 0xFF);
        carry = product >> 8;
    }
    // Overflow beyond 256 bits is silently discarded.
    return *this;
}

uint256& uint256::operator/=(uint64_t n) noexcept {
    if (n == 0) {
        // Division by zero: saturate to max (all 0xFF).
        bytes_.fill(0xFF);
        return *this;
    }

    // Long division from the most-significant byte downward.
    uint64_t remainder = 0;
    for (std::size_t i = 32; i > 0; --i) {
        uint64_t current =
            (remainder << 8) | static_cast<uint64_t>(bytes_[i - 1]);
        bytes_[i - 1] = static_cast<uint8_t>(current / n);
        remainder = current % n;
    }
    return *this;
}

// ===========================================================================
// uint160 -- factory methods
// ===========================================================================

uint160 uint160::from_hex(std::string_view hex) {
    uint160 result;
    static_cast<Blob<20>&>(result) = Blob<20>::from_hex(hex);
    return result;
}

uint160 uint160::from_bytes(
    std::span<const uint8_t, 20> bytes) noexcept {
    uint160 result;
    static_cast<Blob<20>&>(result) = Blob<20>::from_bytes(bytes);
    return result;
}

uint160 uint160::from_bytes_be(
    std::span<const uint8_t, 20> bytes) noexcept {
    uint160 result;
    static_cast<Blob<20>&>(result) = Blob<20>::from_bytes_be(bytes);
    return result;
}

}  // namespace core

// ===========================================================================
// std::hash specializations
// ===========================================================================

std::size_t std::hash<core::uint256>::operator()(
    const core::uint256& v) const noexcept {
    // FNV-1a over the raw bytes -- fast and gives decent distribution for
    // hash-table use.  Not cryptographic, but that is not the goal here.
    const auto& b = v.bytes();
    std::size_t h = 14695981039346656037ULL;  // FNV offset basis (64-bit)
    for (auto byte : b) {
        h ^= static_cast<std::size_t>(byte);
        h *= 1099511628211ULL;  // FNV prime (64-bit)
    }
    return h;
}

std::size_t std::hash<core::uint160>::operator()(
    const core::uint160& v) const noexcept {
    const auto& b = v.bytes();
    std::size_t h = 14695981039346656037ULL;
    for (auto byte : b) {
        h ^= static_cast<std::size_t>(byte);
        h *= 1099511628211ULL;
    }
    return h;
}
