// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/request.h"

#include <algorithm>
#include <cassert>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace rpc {

// ===========================================================================
// JSON Parser
// ===========================================================================

namespace {

class JsonParser {
public:
    explicit JsonParser(std::string_view input) : input_(input), pos_(0) {}

    JsonValue parse() {
        skip_whitespace();
        auto val = parse_value();
        skip_whitespace();
        if (pos_ < input_.size()) {
            throw std::runtime_error("JSON: trailing content after value");
        }
        return val;
    }

private:
    std::string_view input_;
    size_t pos_;

    [[nodiscard]] char peek() const {
        if (pos_ >= input_.size()) {
            throw std::runtime_error("JSON: unexpected end of input");
        }
        return input_[pos_];
    }

    char advance() {
        if (pos_ >= input_.size()) {
            throw std::runtime_error("JSON: unexpected end of input");
        }
        return input_[pos_++];
    }

    void skip_whitespace() {
        while (pos_ < input_.size()) {
            char c = input_[pos_];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                ++pos_;
            } else {
                break;
            }
        }
    }

    void expect(char c) {
        skip_whitespace();
        char got = advance();
        if (got != c) {
            throw std::runtime_error(
                std::string("JSON: expected '") + c + "' but got '" + got + "'");
        }
    }

    bool try_consume(char c) {
        skip_whitespace();
        if (pos_ < input_.size() && input_[pos_] == c) {
            ++pos_;
            return true;
        }
        return false;
    }

    JsonValue parse_value() {
        skip_whitespace();
        if (pos_ >= input_.size()) {
            throw std::runtime_error("JSON: unexpected end of input");
        }

        char c = peek();
        switch (c) {
            case '"': return parse_string_value();
            case '{': return parse_object();
            case '[': return parse_array();
            case 't': case 'f': return parse_bool();
            case 'n': return parse_null();
            default:
                if (c == '-' || (c >= '0' && c <= '9')) {
                    return parse_number();
                }
                throw std::runtime_error(
                    std::string("JSON: unexpected character '") + c + "'");
        }
    }

    JsonValue parse_null() {
        if (input_.substr(pos_, 4) == "null") {
            pos_ += 4;
            return JsonValue(nullptr);
        }
        throw std::runtime_error("JSON: invalid literal");
    }

    JsonValue parse_bool() {
        if (input_.substr(pos_, 4) == "true") {
            pos_ += 4;
            return JsonValue(true);
        }
        if (input_.substr(pos_, 5) == "false") {
            pos_ += 5;
            return JsonValue(false);
        }
        throw std::runtime_error("JSON: invalid literal");
    }

    JsonValue parse_number() {
        size_t start = pos_;
        bool is_float = false;

        if (pos_ < input_.size() && input_[pos_] == '-') ++pos_;

        if (pos_ < input_.size() && input_[pos_] == '0') {
            ++pos_;
        } else if (pos_ < input_.size() && input_[pos_] >= '1' && input_[pos_] <= '9') {
            while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9') {
                ++pos_;
            }
        } else {
            throw std::runtime_error("JSON: invalid number");
        }

        if (pos_ < input_.size() && input_[pos_] == '.') {
            is_float = true;
            ++pos_;
            if (pos_ >= input_.size() || input_[pos_] < '0' || input_[pos_] > '9') {
                throw std::runtime_error("JSON: invalid number after decimal point");
            }
            while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9') {
                ++pos_;
            }
        }

        if (pos_ < input_.size() && (input_[pos_] == 'e' || input_[pos_] == 'E')) {
            is_float = true;
            ++pos_;
            if (pos_ < input_.size() && (input_[pos_] == '+' || input_[pos_] == '-')) {
                ++pos_;
            }
            if (pos_ >= input_.size() || input_[pos_] < '0' || input_[pos_] > '9') {
                throw std::runtime_error("JSON: invalid number exponent");
            }
            while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9') {
                ++pos_;
            }
        }

        std::string_view num_str = input_.substr(start, pos_ - start);

        if (is_float) {
            double d = 0.0;
            auto [ptr, ec] = std::from_chars(num_str.data(), num_str.data() + num_str.size(), d);
            if (ec != std::errc{}) {
                throw std::runtime_error("JSON: failed to parse float");
            }
            return JsonValue(d);
        } else {
            int64_t i = 0;
            auto [ptr, ec] = std::from_chars(num_str.data(), num_str.data() + num_str.size(), i);
            if (ec != std::errc{}) {
                // Number too large for int64, try double
                double d = 0.0;
                auto [ptr2, ec2] = std::from_chars(num_str.data(), num_str.data() + num_str.size(), d);
                if (ec2 != std::errc{}) {
                    throw std::runtime_error("JSON: failed to parse number");
                }
                return JsonValue(d);
            }
            return JsonValue(i);
        }
    }

    std::string parse_string() {
        expect('"');
        std::string result;
        result.reserve(32);

        while (true) {
            if (pos_ >= input_.size()) {
                throw std::runtime_error("JSON: unterminated string");
            }
            char c = advance();
            if (c == '"') {
                return result;
            }
            if (c == '\\') {
                if (pos_ >= input_.size()) {
                    throw std::runtime_error("JSON: unterminated escape");
                }
                char esc = advance();
                switch (esc) {
                    case '"':  result += '"'; break;
                    case '\\': result += '\\'; break;
                    case '/':  result += '/'; break;
                    case 'b':  result += '\b'; break;
                    case 'f':  result += '\f'; break;
                    case 'n':  result += '\n'; break;
                    case 'r':  result += '\r'; break;
                    case 't':  result += '\t'; break;
                    case 'u':  {
                        // Parse 4-hex-digit unicode escape
                        if (pos_ + 4 > input_.size()) {
                            throw std::runtime_error("JSON: short unicode escape");
                        }
                        uint32_t cp = 0;
                        for (int i = 0; i < 4; ++i) {
                            char h = advance();
                            cp <<= 4;
                            if (h >= '0' && h <= '9') cp |= (h - '0');
                            else if (h >= 'a' && h <= 'f') cp |= (h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') cp |= (h - 'A' + 10);
                            else throw std::runtime_error("JSON: invalid unicode escape");
                        }
                        // Handle surrogate pairs
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            if (pos_ + 6 > input_.size() ||
                                input_[pos_] != '\\' || input_[pos_ + 1] != 'u') {
                                throw std::runtime_error("JSON: missing low surrogate");
                            }
                            pos_ += 2; // skip \u
                            uint32_t lo = 0;
                            for (int i = 0; i < 4; ++i) {
                                char h = advance();
                                lo <<= 4;
                                if (h >= '0' && h <= '9') lo |= (h - '0');
                                else if (h >= 'a' && h <= 'f') lo |= (h - 'a' + 10);
                                else if (h >= 'A' && h <= 'F') lo |= (h - 'A' + 10);
                                else throw std::runtime_error("JSON: invalid unicode escape");
                            }
                            if (lo < 0xDC00 || lo > 0xDFFF) {
                                throw std::runtime_error("JSON: invalid low surrogate");
                            }
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        }
                        // UTF-8 encode the code point
                        if (cp < 0x80) {
                            result += static_cast<char>(cp);
                        } else if (cp < 0x800) {
                            result += static_cast<char>(0xC0 | (cp >> 6));
                            result += static_cast<char>(0x80 | (cp & 0x3F));
                        } else if (cp < 0x10000) {
                            result += static_cast<char>(0xE0 | (cp >> 12));
                            result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                            result += static_cast<char>(0x80 | (cp & 0x3F));
                        } else {
                            result += static_cast<char>(0xF0 | (cp >> 18));
                            result += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
                            result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                            result += static_cast<char>(0x80 | (cp & 0x3F));
                        }
                        break;
                    }
                    default:
                        throw std::runtime_error(
                            std::string("JSON: invalid escape '\\") + esc + "'");
                }
            } else {
                result += c;
            }
        }
    }

    JsonValue parse_string_value() {
        return JsonValue(parse_string());
    }

    JsonValue parse_array() {
        expect('[');
        JsonValue::Array arr;

        if (try_consume(']')) {
            return JsonValue(std::move(arr));
        }

        while (true) {
            arr.push_back(parse_value());
            skip_whitespace();
            if (try_consume(']')) break;
            expect(',');
        }
        return JsonValue(std::move(arr));
    }

    JsonValue parse_object() {
        expect('{');
        JsonValue::Object obj;

        if (try_consume('}')) {
            return JsonValue(std::move(obj));
        }

        while (true) {
            skip_whitespace();
            std::string key = parse_string();
            expect(':');
            obj[std::move(key)] = parse_value();
            skip_whitespace();
            if (try_consume('}')) break;
            expect(',');
        }
        return JsonValue(std::move(obj));
    }
};

// ---------------------------------------------------------------------------
// JSON Serializer helpers
// ---------------------------------------------------------------------------

void escape_string(std::string& out, const std::string& s) {
    out += '"';
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x",
                                  static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    out += '"';
}

void serialize_impl(std::string& out, const JsonValue& val) {
    if (val.is_null()) {
        out += "null";
    } else if (val.is_bool()) {
        out += val.get_bool() ? "true" : "false";
    } else if (val.is_int()) {
        out += std::to_string(val.get_int());
    } else if (val.is_double()) {
        double d = val.get_double();
        if (std::isnan(d) || std::isinf(d)) {
            out += "null"; // JSON does not support NaN/Inf
        } else {
            // Use sufficient precision
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%.17g", d);
            out += buf;
            // Ensure it looks like a float (has . or e)
            if (out.find_last_of(".eE") == std::string::npos) {
                // This won't happen with %g normally, but just in case
            }
        }
    } else if (val.is_string()) {
        escape_string(out, val.get_string());
    } else if (val.is_array()) {
        out += '[';
        const auto& arr = val.get_array();
        for (size_t i = 0; i < arr.size(); ++i) {
            if (i > 0) out += ',';
            serialize_impl(out, arr[i]);
        }
        out += ']';
    } else if (val.is_object()) {
        out += '{';
        const auto& obj = val.get_object();
        bool first = true;
        for (const auto& [key, v] : obj) {
            if (!first) out += ',';
            first = false;
            escape_string(out, key);
            out += ':';
            serialize_impl(out, v);
        }
        out += '}';
    }
}

void serialize_pretty_impl(std::string& out, const JsonValue& val,
                           int indent, int depth) {
    std::string pad(static_cast<size_t>(indent * depth), ' ');
    std::string pad_inner(static_cast<size_t>(indent * (depth + 1)), ' ');

    if (val.is_null()) {
        out += "null";
    } else if (val.is_bool()) {
        out += val.get_bool() ? "true" : "false";
    } else if (val.is_int()) {
        out += std::to_string(val.get_int());
    } else if (val.is_double()) {
        double d = val.get_double();
        if (std::isnan(d) || std::isinf(d)) {
            out += "null";
        } else {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%.17g", d);
            out += buf;
        }
    } else if (val.is_string()) {
        escape_string(out, val.get_string());
    } else if (val.is_array()) {
        const auto& arr = val.get_array();
        if (arr.empty()) {
            out += "[]";
            return;
        }
        out += "[\n";
        for (size_t i = 0; i < arr.size(); ++i) {
            out += pad_inner;
            serialize_pretty_impl(out, arr[i], indent, depth + 1);
            if (i + 1 < arr.size()) out += ',';
            out += '\n';
        }
        out += pad;
        out += ']';
    } else if (val.is_object()) {
        const auto& obj = val.get_object();
        if (obj.empty()) {
            out += "{}";
            return;
        }
        out += "{\n";
        size_t count = 0;
        for (const auto& [key, v] : obj) {
            out += pad_inner;
            escape_string(out, key);
            out += ": ";
            serialize_pretty_impl(out, v, indent, depth + 1);
            if (++count < obj.size()) out += ',';
            out += '\n';
        }
        out += pad;
        out += '}';
    }
}

} // anonymous namespace

// ===========================================================================
// Public JSON API
// ===========================================================================

JsonValue parse_json(std::string_view input) {
    if (input.empty()) {
        throw std::runtime_error("JSON: empty input");
    }
    JsonParser parser(input);
    return parser.parse();
}

std::string json_serialize(const JsonValue& val) {
    std::string out;
    out.reserve(256);
    serialize_impl(out, val);
    return out;
}

std::string json_serialize_pretty(const JsonValue& val, int indent) {
    std::string out;
    out.reserve(512);
    serialize_pretty_impl(out, val, indent, 0);
    out += '\n';
    return out;
}

// ===========================================================================
// RpcRequest
// ===========================================================================

RpcRequest RpcRequest::from_json(const JsonValue& val) {
    if (!val.is_object()) {
        throw std::runtime_error("RPC request must be a JSON object");
    }

    RpcRequest req;

    // method (required)
    const auto& method_val = val["method"];
    if (!method_val.is_string()) {
        throw std::runtime_error("RPC request missing 'method' string");
    }
    req.method = method_val.get_string();

    // params (optional, defaults to empty array)
    const auto& params_val = val["params"];
    if (params_val.is_null()) {
        req.params = JsonValue(JsonValue::Array{});
    } else if (params_val.is_array() || params_val.is_object()) {
        req.params = params_val;
    } else {
        throw std::runtime_error("RPC 'params' must be an array or object");
    }

    // id (optional, defaults to 0)
    const auto& id_val = val["id"];
    if (id_val.is_int()) {
        req.id = id_val.get_int();
    } else if (id_val.is_string()) {
        // Some clients send string IDs; accept but convert
        try {
            req.id = std::stoll(id_val.get_string());
        } catch (...) {
            req.id = 0;
        }
    } else if (id_val.is_null()) {
        req.id = 0;
    }

    return req;
}

// ===========================================================================
// RpcResponse
// ===========================================================================

JsonValue RpcResponse::to_json() const {
    JsonValue obj(JsonValue::Object{});
    obj["jsonrpc"] = JsonValue("2.0");
    obj["result"]  = result;
    obj["error"]   = error;
    obj["id"]      = JsonValue(id);
    return obj;
}

std::string RpcResponse::serialize() const {
    return json_serialize(to_json());
}

RpcResponse make_result(JsonValue result, int64_t id) {
    RpcResponse resp;
    resp.result = std::move(result);
    resp.error  = JsonValue(nullptr);
    resp.id     = id;
    return resp;
}

RpcResponse make_error(RpcError code, const std::string& message, int64_t id) {
    RpcResponse resp;
    resp.result = JsonValue(nullptr);

    JsonValue err_obj(JsonValue::Object{});
    err_obj["code"]    = JsonValue(static_cast<int64_t>(static_cast<int>(code)));
    err_obj["message"] = JsonValue(message);
    resp.error = std::move(err_obj);
    resp.id    = id;
    return resp;
}

RpcResponse make_error(RpcError code, const std::string& message,
                       const JsonValue& data, int64_t id) {
    RpcResponse resp;
    resp.result = JsonValue(nullptr);

    JsonValue err_obj(JsonValue::Object{});
    err_obj["code"]    = JsonValue(static_cast<int64_t>(static_cast<int>(code)));
    err_obj["message"] = JsonValue(message);
    err_obj["data"]    = data;
    resp.error = std::move(err_obj);
    resp.id    = id;
    return resp;
}

} // namespace rpc
