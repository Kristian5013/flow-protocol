#pragma once

#include <cstdint>
#include <cmath>
#include <limits>
#include <type_traits>

#include "core/error.h"
#include "core/serialize.h"

namespace primitives {

/// Represents a monetary amount in base units (satoshi-equivalent).
/// One FTC coin equals 100,000,000 base units.
class Amount {
    int64_t value_ = 0;

public:
    /// Number of base units per coin.
    static constexpr int64_t COIN = 100'000'000;

    /// Maximum total supply in base units (21 million coins).
    static constexpr int64_t MAX_MONEY = 21'000'000 * COIN;

    /// Default-construct a zero amount.
    constexpr Amount() = default;

    /// Construct from a raw base-unit value. No validation is performed;
    /// prefer from_value() when the source is untrusted.
    constexpr explicit Amount(int64_t v) : value_(v) {}

    /// Construct an Amount after validating that v is within [0, MAX_MONEY].
    static core::Result<Amount> from_value(int64_t v);

    /// Convert a floating-point FTC value to an Amount, rounding to the
    /// nearest base unit. Returns an error if the result is out of range
    /// or the input is not finite.
    static core::Result<Amount> from_ftc(double ftc);

    /// Return the raw base-unit value.
    [[nodiscard]] int64_t value() const { return value_; }

    /// Convert to a floating-point FTC value.
    [[nodiscard]] double to_ftc() const;

    /// Checked addition. Returns an error on overflow or if the result
    /// falls outside the valid money range.
    [[nodiscard]] core::Result<Amount> operator+(Amount other) const;

    /// Checked subtraction. Returns an error on underflow or if the result
    /// falls outside the valid money range.
    [[nodiscard]] core::Result<Amount> operator-(Amount other) const;

    /// In-place addition. Undefined behaviour if the result overflows;
    /// callers must ensure both operands and the result are in range.
    Amount& operator+=(Amount other);

    /// In-place subtraction. Undefined behaviour if the result underflows;
    /// callers must ensure both operands and the result are in range.
    Amount& operator-=(Amount other);

    bool operator==(Amount o) const { return value_ == o.value_; }
    auto operator<=>(Amount o) const { return value_ <=> o.value_; }

    /// Returns true when the value is within the valid range [0, MAX_MONEY].
    [[nodiscard]] bool is_valid() const {
        return value_ >= 0 && value_ <= MAX_MONEY;
    }

    /// Serialize the amount as a signed 64-bit little-endian integer.
    template<typename Stream>
    void serialize(Stream& s) const {
        core::ser_write_i64(s, value_);
    }

    /// Deserialize an amount from a signed 64-bit little-endian integer.
    template<typename Stream>
    static Amount deserialize(Stream& s) {
        int64_t v = core::ser_read_i64(s);
        return Amount(v);
    }
};

/// A convenient constant representing a zero amount.
inline constexpr Amount ZERO_AMOUNT{0};

} // namespace primitives
