#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FTC_RPC_UTIL_H
#define FTC_RPC_UTIL_H

#include "rpc/request.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rpc {

// ---------------------------------------------------------------------------
// Parameter extraction helpers
// ---------------------------------------------------------------------------
// These functions safely extract typed parameters from the JSON-RPC params
// array.  They throw on type mismatch and return nullopt if the index is
// out of range (for optional parameters).
// ---------------------------------------------------------------------------

/// Extract a required string parameter at the given index.
/// Throws RpcError::INVALID_PARAMS on type mismatch.
std::string param_string(const JsonValue& params, size_t index);

/// Extract an optional string parameter. Returns default_val if missing.
std::string param_string(const JsonValue& params, size_t index,
                         const std::string& default_val);

/// Extract a required integer parameter at the given index.
int64_t param_int(const JsonValue& params, size_t index);

/// Extract an optional integer parameter. Returns default_val if missing.
int64_t param_int(const JsonValue& params, size_t index, int64_t default_val);

/// Extract a required boolean parameter.
bool param_bool(const JsonValue& params, size_t index);

/// Extract an optional boolean parameter. Returns default_val if missing.
bool param_bool(const JsonValue& params, size_t index, bool default_val);

/// Extract a required double parameter.
double param_double(const JsonValue& params, size_t index);

/// Extract an optional double parameter.
double param_double(const JsonValue& params, size_t index, double default_val);

/// Extract a hex string parameter and decode to bytes.
/// Throws INVALID_PARAMS if not a valid hex string.
std::vector<uint8_t> param_hex(const JsonValue& params, size_t index);

/// Extract an optional hex string parameter (empty vector if missing).
std::vector<uint8_t> param_hex_opt(const JsonValue& params, size_t index);

/// Extract a required JsonValue parameter (array or object) at the given index.
const JsonValue& param_value(const JsonValue& params, size_t index);

/// Check if a parameter exists at the given index.
bool param_exists(const JsonValue& params, size_t index);

/// Get the number of parameters.
size_t param_count(const JsonValue& params);

// ---------------------------------------------------------------------------
// Amount parsing/formatting
// ---------------------------------------------------------------------------

/// Parse a JSON value representing a coin amount into satoshis (base units).
/// Accepts both integer satoshi values and floating-point FTC values.
/// Floating-point values are interpreted as FTC (1 FTC = 100,000,000 satoshis).
/// Returns the amount in satoshis.
/// Throws on invalid amounts, negative values, or values exceeding MAX_MONEY.
int64_t parse_amount(const JsonValue& val);

/// Format a satoshi value as a string with 8 decimal places (FTC).
/// E.g., 100000000 -> "1.00000000"
std::string format_amount(int64_t satoshis);

// ---------------------------------------------------------------------------
// Hex encoding/decoding helpers for RPC
// ---------------------------------------------------------------------------

/// Encode bytes to lowercase hex string.
std::string hex_encode(const std::vector<uint8_t>& data);
std::string hex_encode(const uint8_t* data, size_t len);

/// Decode hex string to bytes. Throws INVALID_PARAMS on invalid hex.
std::vector<uint8_t> hex_decode(std::string_view hex);

/// Validate that a string is valid hex with the given byte length.
bool is_valid_hex(std::string_view hex, size_t expected_bytes = 0);

/// Parse a hex string as a 256-bit hash (64 hex chars).
/// Throws on invalid format.
std::string parse_hash_hex(const JsonValue& val);

// ---------------------------------------------------------------------------
// Help text system
// ---------------------------------------------------------------------------

/// Return the help text for a single RPC method.
/// Returns an empty string if the method is unknown.
std::string help_text(const std::string& method_name);

/// Return a list of all registered RPC method names.
std::vector<std::string> get_all_method_names();

/// Register help text for a method. Called during command registration.
void register_help(const std::string& method, const std::string& text);

// ---------------------------------------------------------------------------
// HTTP Basic Auth helpers
// ---------------------------------------------------------------------------

/// Encode username:password as Base64 for HTTP Basic auth.
std::string base64_encode(std::string_view input);

/// Decode a Base64-encoded string.
std::string base64_decode(std::string_view input);

/// Verify HTTP Basic auth header value against expected user:pass.
bool verify_auth(std::string_view auth_header,
                 const std::string& rpc_user,
                 const std::string& rpc_password);

} // namespace rpc

#endif // FTC_RPC_UTIL_H
