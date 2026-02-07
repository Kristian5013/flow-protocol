#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FTC_RPC_REQUEST_H
#define FTC_RPC_REQUEST_H

#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace rpc {

// ---------------------------------------------------------------------------
// JsonValue -- lightweight JSON value (no external dependencies)
// ---------------------------------------------------------------------------
// A variant of: null, bool, int64_t, double, string, array, object.
// Provides constructors, type queries, and accessors for each alternative.
// ---------------------------------------------------------------------------

struct NullValue {
    bool operator==(const NullValue&) const { return true; }
};

class JsonValue {
public:
    using Array  = std::vector<JsonValue>;
    using Object = std::map<std::string, JsonValue>;

private:
    using Storage = std::variant<NullValue, bool, int64_t, double,
                                 std::string, Array, Object>;
    Storage storage_;

public:
    // -- Constructors -------------------------------------------------------

    JsonValue()                        : storage_(NullValue{}) {}
    JsonValue(std::nullptr_t)          : storage_(NullValue{}) {}  // NOLINT
    JsonValue(bool v)                  : storage_(v) {}            // NOLINT
    JsonValue(int v)                   : storage_(static_cast<int64_t>(v)) {} // NOLINT
    JsonValue(int64_t v)               : storage_(v) {}            // NOLINT
    JsonValue(uint64_t v)              : storage_(static_cast<int64_t>(v)) {} // NOLINT
    JsonValue(double v)                : storage_(v) {}            // NOLINT
    JsonValue(const char* v)           : storage_(std::string(v)) {} // NOLINT
    JsonValue(std::string v)           : storage_(std::move(v)) {} // NOLINT
    JsonValue(std::string_view v)      : storage_(std::string(v)) {} // NOLINT
    JsonValue(Array v)                 : storage_(std::move(v)) {} // NOLINT
    JsonValue(Object v)                : storage_(std::move(v)) {} // NOLINT

    // -- Type queries -------------------------------------------------------

    [[nodiscard]] bool is_null()   const { return std::holds_alternative<NullValue>(storage_); }
    [[nodiscard]] bool is_bool()   const { return std::holds_alternative<bool>(storage_); }
    [[nodiscard]] bool is_int()    const { return std::holds_alternative<int64_t>(storage_); }
    [[nodiscard]] bool is_double() const { return std::holds_alternative<double>(storage_); }
    [[nodiscard]] bool is_string() const { return std::holds_alternative<std::string>(storage_); }
    [[nodiscard]] bool is_array()  const { return std::holds_alternative<Array>(storage_); }
    [[nodiscard]] bool is_object() const { return std::holds_alternative<Object>(storage_); }

    [[nodiscard]] bool is_number() const { return is_int() || is_double(); }

    // -- Accessors (throw on type mismatch) ---------------------------------

    [[nodiscard]] bool get_bool() const {
        if (auto* p = std::get_if<bool>(&storage_)) return *p;
        throw std::runtime_error("JsonValue: not a bool");
    }
    [[nodiscard]] int64_t get_int() const {
        if (auto* p = std::get_if<int64_t>(&storage_)) return *p;
        if (auto* p = std::get_if<double>(&storage_)) return static_cast<int64_t>(*p);
        throw std::runtime_error("JsonValue: not an integer");
    }
    [[nodiscard]] double get_double() const {
        if (auto* p = std::get_if<double>(&storage_)) return *p;
        if (auto* p = std::get_if<int64_t>(&storage_)) return static_cast<double>(*p);
        throw std::runtime_error("JsonValue: not a number");
    }
    [[nodiscard]] const std::string& get_string() const {
        if (auto* p = std::get_if<std::string>(&storage_)) return *p;
        throw std::runtime_error("JsonValue: not a string");
    }
    [[nodiscard]] std::string& get_string() {
        if (auto* p = std::get_if<std::string>(&storage_)) return *p;
        throw std::runtime_error("JsonValue: not a string");
    }
    [[nodiscard]] const Array& get_array() const {
        if (auto* p = std::get_if<Array>(&storage_)) return *p;
        throw std::runtime_error("JsonValue: not an array");
    }
    [[nodiscard]] Array& get_array() {
        if (auto* p = std::get_if<Array>(&storage_)) return *p;
        throw std::runtime_error("JsonValue: not an array");
    }
    [[nodiscard]] const Object& get_object() const {
        if (auto* p = std::get_if<Object>(&storage_)) return *p;
        throw std::runtime_error("JsonValue: not an object");
    }
    [[nodiscard]] Object& get_object() {
        if (auto* p = std::get_if<Object>(&storage_)) return *p;
        throw std::runtime_error("JsonValue: not an object");
    }

    // -- Object element access (creates entry if not present) ---------------

    JsonValue& operator[](const std::string& key) {
        if (is_null()) storage_ = Object{};
        return std::get<Object>(storage_)[key];
    }

    const JsonValue& operator[](const std::string& key) const {
        static const JsonValue null_val;
        if (!is_object()) return null_val;
        auto& obj = std::get<Object>(storage_);
        auto it = obj.find(key);
        return (it != obj.end()) ? it->second : null_val;
    }

    // -- Array element access -----------------------------------------------

    JsonValue& operator[](size_t index) {
        return std::get<Array>(storage_).at(index);
    }

    const JsonValue& operator[](size_t index) const {
        return std::get<Array>(storage_).at(index);
    }

    // -- Array push ---------------------------------------------------------

    void push_back(JsonValue val) {
        if (is_null()) storage_ = Array{};
        std::get<Array>(storage_).push_back(std::move(val));
    }

    // -- Object helpers -----------------------------------------------------

    [[nodiscard]] bool has_key(const std::string& key) const {
        if (!is_object()) return false;
        return std::get<Object>(storage_).count(key) > 0;
    }

    [[nodiscard]] size_t size() const {
        if (is_array())  return std::get<Array>(storage_).size();
        if (is_object()) return std::get<Object>(storage_).size();
        if (is_string()) return std::get<std::string>(storage_).size();
        return 0;
    }

    // -- Comparison ---------------------------------------------------------

    bool operator==(const JsonValue& other) const { return storage_ == other.storage_; }
    bool operator!=(const JsonValue& other) const { return storage_ != other.storage_; }
};

// ---------------------------------------------------------------------------
// JSON parsing and serialization
// ---------------------------------------------------------------------------

/// Parse a JSON string into a JsonValue.
/// Throws std::runtime_error on malformed input.
JsonValue parse_json(std::string_view input);

/// Serialize a JsonValue to a JSON string.
std::string json_serialize(const JsonValue& val);

/// Serialize with indentation for human-readable output.
std::string json_serialize_pretty(const JsonValue& val, int indent = 2);

// ---------------------------------------------------------------------------
// RpcError -- standard JSON-RPC 2.0 error codes + FTC custom codes
// ---------------------------------------------------------------------------

enum class RpcError : int {
    // Standard JSON-RPC 2.0 errors
    PARSE_ERROR      = -32700,
    INVALID_REQUEST  = -32600,
    METHOD_NOT_FOUND = -32601,
    INVALID_PARAMS   = -32602,
    INTERNAL_ERROR   = -32603,

    // FTC custom errors (Bitcoin-compatible ranges)
    MISC_ERROR              = -1,
    FORBIDDEN_BY_SAFE_MODE  = -2,
    TYPE_ERROR              = -3,
    INVALID_ADDRESS         = -5,
    OUT_OF_MEMORY           = -7,
    INVALID_PARAMETER       = -8,
    DATABASE_ERROR          = -20,
    DESERIALIZATION_ERROR   = -22,
    VERIFY_ERROR            = -25,
    VERIFY_REJECTED         = -26,
    VERIFY_ALREADY_IN_CHAIN = -27,
    IN_WARMUP               = -28,

    // Wallet errors
    WALLET_ERROR             = -4,
    WALLET_INSUFFICIENT_FUNDS = -6,
    WALLET_INVALID_LABEL     = -11,
    WALLET_KEYPOOL_RAN_OUT   = -12,
    WALLET_UNLOCK_NEEDED     = -13,
    WALLET_PASSPHRASE_INCORRECT = -14,
    WALLET_NOT_FOUND         = -18,
    WALLET_NOT_SPECIFIED     = -19,
};

// ---------------------------------------------------------------------------
// RpcRequest / RpcResponse
// ---------------------------------------------------------------------------

struct RpcRequest {
    std::string method;
    JsonValue   params;      // array or object
    int64_t     id = 0;

    /// Parse a JSON-RPC 2.0 request from a JsonValue object.
    /// Validates required fields and sets defaults.
    static RpcRequest from_json(const JsonValue& val);
};

struct RpcResponse {
    JsonValue result;
    JsonValue error;   // null on success, object on error
    int64_t   id = 0;

    /// Convert to a JSON-RPC 2.0 response object.
    [[nodiscard]] JsonValue to_json() const;

    /// Serialize to a JSON string.
    [[nodiscard]] std::string serialize() const;
};

/// Create a successful response.
RpcResponse make_result(JsonValue result, int64_t id);

/// Create an error response.
RpcResponse make_error(RpcError code, const std::string& message, int64_t id = 0);

/// Create an error response with additional data.
RpcResponse make_error(RpcError code, const std::string& message,
                       const JsonValue& data, int64_t id = 0);

} // namespace rpc

#endif // FTC_RPC_REQUEST_H
