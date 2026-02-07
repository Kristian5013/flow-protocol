#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license.

#include <cstdint>
#include <source_location>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

namespace core {

// ErrorCode: categorized error codes for the FTC stack
enum class ErrorCode : uint16_t {
    NONE              = 0,
    // Parsing / serialization (100-199)
    PARSE_ERROR       = 100, PARSE_OVERFLOW  = 101,
    PARSE_UNDERFLOW   = 102, PARSE_BAD_FORMAT = 103,
    // Validation (200-299)
    VALIDATION_ERROR  = 200, VALIDATION_RANGE  = 201,
    VALIDATION_SCRIPT = 202, VALIDATION_SIG    = 203,
    // Network (300-399)
    NETWORK_ERROR     = 300, NETWORK_TIMEOUT = 301,
    NETWORK_REFUSED   = 302, NETWORK_CLOSED  = 303,
    // Cryptography (400-499)
    CRYPTO_ERROR      = 400, CRYPTO_HASH_FAIL = 401,
    CRYPTO_SIG_FAIL   = 402, CRYPTO_KEY_FAIL  = 403,
    // Storage (500-599)
    STORAGE_ERROR     = 500, STORAGE_NOT_FOUND = 501,
    STORAGE_CORRUPT   = 502, STORAGE_FULL      = 503,
    // Wallet (600-699)
    WALLET_ERROR      = 600, WALLET_LOCKED   = 601,
    WALLET_NO_FUNDS   = 602, WALLET_KEY_MISS = 603,
    // RPC (700-799)
    RPC_ERROR         = 700, RPC_INVALID_REQ = 701,
    RPC_METHOD_MISS   = 702, RPC_FORBIDDEN   = 703,
    // Internal (900-999)
    INTERNAL_ERROR    = 900, NOT_IMPLEMENTED = 901,
    OUT_OF_MEMORY     = 902,
};

[[nodiscard]] std::string_view error_code_name(ErrorCode code) noexcept;

// Error: rich error value carrying code, message, and origin location
class Error {
public:
    Error() noexcept : code_(ErrorCode::NONE) {}

    explicit Error(
        ErrorCode code,
        std::string message = {},
        std::source_location loc = std::source_location::current()) noexcept
        : code_(code), message_(std::move(message)), location_(loc) {}

    [[nodiscard]] ErrorCode          code()    const noexcept { return code_; }
    [[nodiscard]] const std::string& message() const noexcept { return message_; }
    [[nodiscard]] const std::source_location& location() const noexcept {
        return location_;
    }
    [[nodiscard]] bool is_ok() const noexcept { return code_ == ErrorCode::NONE; }
    [[nodiscard]] explicit operator bool() const noexcept { return !is_ok(); }
    [[nodiscard]] std::string format() const;

    bool operator==(const Error& o) const noexcept { return code_ == o.code_; }
    bool operator!=(const Error& o) const noexcept { return code_ != o.code_; }

private:
    ErrorCode            code_;
    std::string          message_;
    std::source_location location_;
};

// Result<T, E>: a sum type holding either a value T or an error E
template <typename T, typename E = Error>
class Result {
    static_assert(!std::is_same_v<T, E>,
                  "Result value and error types must differ");
public:
    Result(const T& val) : storage_(val) {}             // NOLINT implicit
    Result(T&& val) : storage_(std::move(val)) {}       // NOLINT implicit
    Result(const E& err) : storage_(err) {}             // NOLINT implicit
    Result(E&& err) : storage_(std::move(err)) {}       // NOLINT implicit

    Result(const Result&)            = default;
    Result(Result&&) noexcept        = default;
    Result& operator=(const Result&) = default;
    Result& operator=(Result&&) noexcept = default;
    ~Result()                        = default;

    [[nodiscard]] bool has_value() const noexcept {
        return std::holds_alternative<T>(storage_);
    }
    [[nodiscard]] bool ok() const noexcept { return has_value(); }
    [[nodiscard]] explicit operator bool() const noexcept { return ok(); }

    [[nodiscard]] T& value() & {
        if (!ok()) throw std::runtime_error("Result::value() on error");
        return std::get<T>(storage_);
    }
    [[nodiscard]] const T& value() const& {
        if (!ok()) throw std::runtime_error("Result::value() on error");
        return std::get<T>(storage_);
    }
    [[nodiscard]] T&& value() && {
        if (!ok()) throw std::runtime_error("Result::value() on error");
        return std::get<T>(std::move(storage_));
    }
    [[nodiscard]] E& error() & {
        if (ok()) throw std::runtime_error("Result::error() on value");
        return std::get<E>(storage_);
    }
    [[nodiscard]] const E& error() const& {
        if (ok()) throw std::runtime_error("Result::error() on value");
        return std::get<E>(storage_);
    }
    [[nodiscard]] E&& error() && {
        if (ok()) throw std::runtime_error("Result::error() on value");
        return std::get<E>(std::move(storage_));
    }

    [[nodiscard]] T value_or(T default_val) const {
        return ok() ? std::get<T>(storage_) : std::move(default_val);
    }

    // map: Result<T,E> -> (T -> U) -> Result<U,E>
    template <typename F>
    [[nodiscard]] auto map(F&& func) const&
        -> Result<std::invoke_result_t<F, const T&>, E> {
        using U = std::invoke_result_t<F, const T&>;
        if (ok()) return Result<U, E>{func(std::get<T>(storage_))};
        return Result<U, E>{std::get<E>(storage_)};
    }
    template <typename F>
    [[nodiscard]] auto map(F&& func) &&
        -> Result<std::invoke_result_t<F, T&&>, E> {
        using U = std::invoke_result_t<F, T&&>;
        if (ok()) return Result<U, E>{func(std::get<T>(std::move(storage_)))};
        return Result<U, E>{std::get<E>(std::move(storage_))};
    }

    // and_then: Result<T,E> -> (T -> Result<U,E>) -> Result<U,E>
    template <typename F>
    [[nodiscard]] auto and_then(F&& func) const&
        -> std::invoke_result_t<F, const T&> {
        using R = std::invoke_result_t<F, const T&>;
        if (ok()) return func(std::get<T>(storage_));
        return R{std::get<E>(storage_)};
    }
    template <typename F>
    [[nodiscard]] auto and_then(F&& func) &&
        -> std::invoke_result_t<F, T&&> {
        using R = std::invoke_result_t<F, T&&>;
        if (ok()) return func(std::get<T>(std::move(storage_)));
        return R{std::get<E>(std::move(storage_))};
    }

private:
    std::variant<T, E> storage_;
};

// Void-specialization: Result<void, E> for side-effect-only operations
template <typename E>
class Result<void, E> {
public:
    Result() noexcept : storage_(Void{}) {}
    Result(const E& err) : storage_(err) {}             // NOLINT implicit
    Result(E&& err) : storage_(std::move(err)) {}       // NOLINT implicit

    Result(const Result&)            = default;
    Result(Result&&) noexcept        = default;
    Result& operator=(const Result&) = default;
    Result& operator=(Result&&) noexcept = default;
    ~Result()                        = default;

    [[nodiscard]] bool has_value() const noexcept {
        return std::holds_alternative<Void>(storage_);
    }
    [[nodiscard]] bool ok() const noexcept { return has_value(); }
    [[nodiscard]] explicit operator bool() const noexcept { return ok(); }

    void value() const {
        if (!ok()) throw std::runtime_error("Result::value() on error");
    }
    [[nodiscard]] E& error() & {
        if (ok()) throw std::runtime_error("Result::error() on value");
        return std::get<E>(storage_);
    }
    [[nodiscard]] const E& error() const& {
        if (ok()) throw std::runtime_error("Result::error() on value");
        return std::get<E>(storage_);
    }

    template <typename F>
    [[nodiscard]] auto and_then(F&& func) const&
        -> std::invoke_result_t<F> {
        if (ok()) return func();
        return std::invoke_result_t<F>{std::get<E>(storage_)};
    }

private:
    struct Void {};
    std::variant<Void, E> storage_;
};

// Factory helpers
[[nodiscard]] inline Error make_error(
    ErrorCode code,
    std::string message = {},
    std::source_location loc = std::source_location::current()) noexcept {
    return Error(code, std::move(message), loc);
}

template <typename T>
[[nodiscard]] inline Result<T> make_result(T&& val) {
    return Result<T>{std::forward<T>(val)};
}

[[nodiscard]] inline Result<void> make_ok() noexcept {
    return Result<void>{};
}

// FTC_TRY: propagate errors (GCC/Clang statement-expression)
// Usage:  auto val = FTC_TRY(some_result_expr);
#define FTC_TRY(expr)                                                     \
    ({                                                                    \
        auto&& _ftc_res = (expr);                                         \
        if (!_ftc_res.ok()) return std::move(_ftc_res).error();           \
        std::move(_ftc_res).value();                                      \
    })

// FTC_TRY_ASSIGN: MSVC-compatible alternative (no statement-expressions)
// Usage:  FTC_TRY_ASSIGN(val, some_result_expr);
#define FTC_TRY_ASSIGN(var, expr)                                         \
    auto _ftc_tmp_##var = (expr);                                         \
    if (!_ftc_tmp_##var.ok())                                             \
        return std::move(_ftc_tmp_##var).error();                         \
    auto var = std::move(_ftc_tmp_##var).value()

// FTC_TRY_VOID: propagate errors from Result<void> expressions
#define FTC_TRY_VOID(expr)                                                \
    do {                                                                  \
        auto _ftc_tmp = (expr);                                           \
        if (!_ftc_tmp.ok()) return std::move(_ftc_tmp).error();           \
    } while (false)

} // namespace core
