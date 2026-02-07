#include "primitives/amount.h"

#include <cmath>
#include <limits>

namespace primitives {

core::Result<Amount> Amount::from_value(int64_t v) {
    if (v < 0 || v > MAX_MONEY) {
        return core::make_error(
            core::ErrorCode::VALIDATION_ERROR,
            "Amount out of valid range [0, " +
                std::to_string(MAX_MONEY) + "]: " + std::to_string(v));
    }
    return Amount(v);
}

core::Result<Amount> Amount::from_ftc(double ftc) {
    if (!std::isfinite(ftc)) {
        return core::make_error(
            core::ErrorCode::VALIDATION_ERROR,
            "FTC amount is not finite");
    }
    if (ftc < 0.0) {
        return core::make_error(
            core::ErrorCode::VALIDATION_ERROR,
            "FTC amount must be non-negative");
    }

    // Multiply first, then round to nearest base unit.
    double raw = ftc * static_cast<double>(COIN);

    // Guard against values that would overflow int64_t after rounding.
    if (raw > static_cast<double>(std::numeric_limits<int64_t>::max())) {
        return core::make_error(
            core::ErrorCode::VALIDATION_ERROR,
            "FTC amount overflows base-unit representation");
    }

    int64_t value = static_cast<int64_t>(std::llround(raw));
    if (value < 0 || value > MAX_MONEY) {
        return core::make_error(
            core::ErrorCode::VALIDATION_ERROR,
            "FTC amount out of valid range after conversion");
    }

    return Amount(value);
}

double Amount::to_ftc() const {
    return static_cast<double>(value_) / static_cast<double>(COIN);
}

core::Result<Amount> Amount::operator+(Amount other) const {
    // Check for signed overflow before performing the addition.
    if (other.value_ > 0 &&
        value_ > std::numeric_limits<int64_t>::max() - other.value_) {
        return core::make_error(
            core::ErrorCode::VALIDATION_ERROR,
            "Amount addition overflows int64_t");
    }
    if (other.value_ < 0 &&
        value_ < std::numeric_limits<int64_t>::min() - other.value_) {
        return core::make_error(
            core::ErrorCode::VALIDATION_ERROR,
            "Amount addition underflows int64_t");
    }

    int64_t result = value_ + other.value_;
    if (result < 0 || result > MAX_MONEY) {
        return core::make_error(
            core::ErrorCode::VALIDATION_ERROR,
            "Amount addition result out of valid money range");
    }
    return Amount(result);
}

core::Result<Amount> Amount::operator-(Amount other) const {
    // Check for signed overflow / underflow before performing subtraction.
    if (other.value_ < 0 &&
        value_ > std::numeric_limits<int64_t>::max() + other.value_) {
        return core::make_error(
            core::ErrorCode::VALIDATION_ERROR,
            "Amount subtraction overflows int64_t");
    }
    if (other.value_ > 0 &&
        value_ < std::numeric_limits<int64_t>::min() + other.value_) {
        return core::make_error(
            core::ErrorCode::VALIDATION_ERROR,
            "Amount subtraction underflows int64_t");
    }

    int64_t result = value_ - other.value_;
    if (result < 0 || result > MAX_MONEY) {
        return core::make_error(
            core::ErrorCode::VALIDATION_ERROR,
            "Amount subtraction result out of valid money range");
    }
    return Amount(result);
}

Amount& Amount::operator+=(Amount other) {
    value_ += other.value_;
    return *this;
}

Amount& Amount::operator-=(Amount other) {
    value_ -= other.value_;
    return *this;
}

} // namespace primitives
