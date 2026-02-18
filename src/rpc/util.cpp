// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/util.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>

namespace rpc {

// ===========================================================================
// Parameter extraction
// ===========================================================================

namespace {

const JsonValue& get_param_at(const JsonValue& params, size_t index) {
    if (!params.is_array()) {
        throw std::runtime_error("params must be an array");
    }
    const auto& arr = params.get_array();
    if (index >= arr.size()) {
        throw std::runtime_error(
            "Missing required parameter at index " + std::to_string(index));
    }
    return arr[index];
}

bool has_param(const JsonValue& params, size_t index) {
    if (!params.is_array()) return false;
    const auto& arr = params.get_array();
    return index < arr.size() && !arr[index].is_null();
}

// Global help text registry
std::mutex g_help_mutex;
std::map<std::string, std::string> g_help_texts;

} // anonymous namespace

std::string param_string(const JsonValue& params, size_t index) {
    const auto& val = get_param_at(params, index);
    if (!val.is_string()) {
        throw std::runtime_error(
            "Expected string for parameter " + std::to_string(index));
    }
    return val.get_string();
}

std::string param_string(const JsonValue& params, size_t index,
                         const std::string& default_val) {
    if (!has_param(params, index)) return default_val;
    const auto& arr = params.get_array();
    const auto& val = arr[index];
    if (val.is_null()) return default_val;
    if (!val.is_string()) {
        throw std::runtime_error(
            "Expected string for parameter " + std::to_string(index));
    }
    return val.get_string();
}

int64_t param_int(const JsonValue& params, size_t index) {
    const auto& val = get_param_at(params, index);
    if (!val.is_int() && !val.is_double()) {
        throw std::runtime_error(
            "Expected integer for parameter " + std::to_string(index));
    }
    return val.get_int();
}

int64_t param_int(const JsonValue& params, size_t index, int64_t default_val) {
    if (!has_param(params, index)) return default_val;
    const auto& arr = params.get_array();
    const auto& val = arr[index];
    if (val.is_null()) return default_val;
    if (!val.is_int() && !val.is_double()) {
        throw std::runtime_error(
            "Expected integer for parameter " + std::to_string(index));
    }
    return val.get_int();
}

bool param_bool(const JsonValue& params, size_t index) {
    const auto& val = get_param_at(params, index);
    if (!val.is_bool()) {
        throw std::runtime_error(
            "Expected boolean for parameter " + std::to_string(index));
    }
    return val.get_bool();
}

bool param_bool(const JsonValue& params, size_t index, bool default_val) {
    if (!has_param(params, index)) return default_val;
    const auto& arr = params.get_array();
    const auto& val = arr[index];
    if (val.is_null()) return default_val;
    if (!val.is_bool()) {
        throw std::runtime_error(
            "Expected boolean for parameter " + std::to_string(index));
    }
    return val.get_bool();
}

double param_double(const JsonValue& params, size_t index) {
    const auto& val = get_param_at(params, index);
    if (!val.is_number()) {
        throw std::runtime_error(
            "Expected number for parameter " + std::to_string(index));
    }
    return val.get_double();
}

double param_double(const JsonValue& params, size_t index, double default_val) {
    if (!has_param(params, index)) return default_val;
    const auto& arr = params.get_array();
    const auto& val = arr[index];
    if (val.is_null()) return default_val;
    if (!val.is_number()) {
        throw std::runtime_error(
            "Expected number for parameter " + std::to_string(index));
    }
    return val.get_double();
}

std::vector<uint8_t> param_hex(const JsonValue& params, size_t index) {
    std::string hex_str = param_string(params, index);
    return hex_decode(hex_str);
}

std::vector<uint8_t> param_hex_opt(const JsonValue& params, size_t index) {
    if (!has_param(params, index)) return {};
    return param_hex(params, index);
}

const JsonValue& param_value(const JsonValue& params, size_t index) {
    return get_param_at(params, index);
}

bool param_exists(const JsonValue& params, size_t index) {
    return has_param(params, index);
}

size_t param_count(const JsonValue& params) {
    if (!params.is_array()) return 0;
    return params.get_array().size();
}

// ===========================================================================
// Amount parsing/formatting
// ===========================================================================

static constexpr int64_t COIN = 100'000'000;
static constexpr int64_t MAX_MONEY = 21'000'000LL * COIN;

int64_t parse_amount(const JsonValue& val) {
    int64_t satoshis = 0;

    if (val.is_int()) {
        // Treat as satoshis directly if it is clearly a large integer,
        // or as FTC if it seems small. However, the convention in Bitcoin
        // RPC is that amounts are always in BTC (FTC), so we follow that.
        double ftc = static_cast<double>(val.get_int());
        satoshis = static_cast<int64_t>(std::round(ftc * COIN));
    } else if (val.is_double()) {
        double ftc = val.get_double();
        if (!std::isfinite(ftc)) {
            throw std::runtime_error("Invalid amount: not finite");
        }
        satoshis = static_cast<int64_t>(std::round(ftc * COIN));
    } else if (val.is_string()) {
        // Parse string representation of amount
        const std::string& s = val.get_string();
        double ftc = 0.0;
        auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), ftc);
        if (ec != std::errc{} || ptr != s.data() + s.size()) {
            throw std::runtime_error("Invalid amount string: " + s);
        }
        satoshis = static_cast<int64_t>(std::round(ftc * COIN));
    } else {
        throw std::runtime_error("Amount must be a number or string");
    }

    if (satoshis < 0) {
        throw std::runtime_error("Amount out of range: negative");
    }
    if (satoshis > MAX_MONEY) {
        throw std::runtime_error("Amount out of range: exceeds MAX_MONEY");
    }
    return satoshis;
}

std::string format_amount(int64_t satoshis) {
    bool negative = satoshis < 0;
    int64_t abs_val = negative ? -satoshis : satoshis;

    int64_t whole = abs_val / COIN;
    int64_t frac  = abs_val % COIN;

    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s%lld.%08lld",
                  negative ? "-" : "",
                  static_cast<long long>(whole),
                  static_cast<long long>(frac));
    return std::string(buf);
}

// ===========================================================================
// Hex encoding/decoding
// ===========================================================================

static constexpr char HEX_CHARS[] = "0123456789abcdef";

std::string hex_encode(const std::vector<uint8_t>& data) {
    return hex_encode(data.data(), data.size());
}

std::string hex_encode(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result += HEX_CHARS[data[i] >> 4];
        result += HEX_CHARS[data[i] & 0x0F];
    }
    return result;
}

std::vector<uint8_t> hex_decode(std::string_view hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("Invalid hex string: odd length");
    }

    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        auto hex_digit = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };

        int hi = hex_digit(hex[i]);
        int lo = hex_digit(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            throw std::runtime_error("Invalid hex character");
        }
        result.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return result;
}

bool is_valid_hex(std::string_view hex, size_t expected_bytes) {
    if (hex.size() % 2 != 0) return false;
    if (expected_bytes > 0 && hex.size() != expected_bytes * 2) return false;
    for (char c : hex) {
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

std::string parse_hash_hex(const JsonValue& val) {
    if (!val.is_string()) {
        throw std::runtime_error("Expected hex string for hash");
    }
    const std::string& hex = val.get_string();
    if (!is_valid_hex(hex, 32)) {
        throw std::runtime_error("Invalid hash: must be 64 hex characters");
    }
    return hex;
}

// ===========================================================================
// Help text system
// ===========================================================================

std::string help_text(const std::string& method_name) {
    std::lock_guard lock(g_help_mutex);
    auto it = g_help_texts.find(method_name);
    if (it != g_help_texts.end()) return it->second;
    return "";
}

std::vector<std::string> get_all_method_names() {
    std::lock_guard lock(g_help_mutex);
    std::vector<std::string> names;
    names.reserve(g_help_texts.size());
    for (const auto& [name, _] : g_help_texts) {
        names.push_back(name);
    }
    std::sort(names.begin(), names.end());
    return names;
}

void register_help(const std::string& method, const std::string& text) {
    std::lock_guard lock(g_help_mutex);
    g_help_texts[method] = text;
}

// ===========================================================================
// HTTP Basic Auth / Base64
// ===========================================================================

static constexpr char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(std::string_view input) {
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i < input.size()) {
        uint32_t octet_a = static_cast<uint8_t>(input[i++]);
        uint32_t octet_b = (i < input.size()) ? static_cast<uint8_t>(input[i++]) : 0;
        uint32_t octet_c = (i < input.size()) ? static_cast<uint8_t>(input[i++]) : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        // Encode triple to 4 base64 characters:
        out += B64_TABLE[(triple >> 18) & 0x3F];
        out += B64_TABLE[(triple >> 12) & 0x3F];
        out += B64_TABLE[(triple >> 6) & 0x3F];
        out += B64_TABLE[triple & 0x3F];
    }

    // Fix padding
    size_t mod = input.size() % 3;
    if (mod > 0) {
        out[out.size() - 1] = '=';
        if (mod == 1) {
            out[out.size() - 2] = '=';
        }
    }

    return out;
}

std::string base64_decode(std::string_view input) {
    // Build decode table
    static constexpr auto make_decode_table = []() {
        std::array<int, 256> t{};
        t.fill(-1);
        for (int i = 0; i < 64; ++i) {
            t[static_cast<unsigned char>(B64_TABLE[i])] = i;
        }
        return t;
    };
    static constexpr auto DECODE_TABLE = make_decode_table();

    std::string out;
    out.reserve(input.size() * 3 / 4);

    uint32_t accum = 0;
    int bits = 0;

    for (char c : input) {
        if (c == '=') break;
        if (c == '\r' || c == '\n' || c == ' ') continue;

        int val = DECODE_TABLE[static_cast<unsigned char>(c)];
        if (val < 0) {
            throw std::runtime_error("Invalid base64 character");
        }

        accum = (accum << 6) | static_cast<uint32_t>(val);
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            out += static_cast<char>((accum >> bits) & 0xFF);
        }
    }

    return out;
}

bool verify_auth(std::string_view auth_header,
                 const std::string& rpc_user,
                 const std::string& rpc_password) {
    // Expected format: "Basic <base64(user:pass)>"
    constexpr std::string_view prefix = "Basic ";
    if (auth_header.size() <= prefix.size()) return false;
    if (auth_header.substr(0, prefix.size()) != prefix) return false;

    std::string_view b64 = auth_header.substr(prefix.size());
    std::string decoded;
    try {
        decoded = base64_decode(b64);
    } catch (...) {
        return false;
    }

    std::string expected = rpc_user + ":" + rpc_password;
    return decoded == expected;
}

} // namespace rpc
