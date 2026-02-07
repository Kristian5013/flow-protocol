#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace core {

// Base58 alphabet (no 0, O, I, l to avoid visual ambiguity).
inline constexpr char BASE58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// ---------------------------------------------------------------------------
// Pure Base58 encoding / decoding
// ---------------------------------------------------------------------------

/// Encode raw bytes as a Base58 string.
/// Leading zero bytes map to leading '1' characters.
std::string base58_encode(std::span<const uint8_t> data);

/// Decode a Base58 string back to raw bytes.
/// Returns std::nullopt if any character is outside the Base58 alphabet.
std::optional<std::vector<uint8_t>> base58_decode(std::string_view str);

// ---------------------------------------------------------------------------
// Base58Check (with double Keccak-256 checksum via OpenSSL SHA3-256)
// ---------------------------------------------------------------------------

/// Encode raw bytes with a 4-byte double-Keccak-256 checksum appended,
/// then Base58-encode the result.
std::string base58check_encode(std::span<const uint8_t> data);

/// Decode a Base58Check string: verify the 4-byte checksum and return
/// the payload without the checksum.  Returns std::nullopt on invalid
/// encoding or checksum mismatch.
std::optional<std::vector<uint8_t>> base58check_decode(
    std::string_view str);

// ---------------------------------------------------------------------------
// Version-prefixed Base58Check (addresses, WIF keys, etc.)
// ---------------------------------------------------------------------------

/// Prepend a single version byte to the payload, then Base58Check-encode.
std::string encode_with_version(
    uint8_t version,
    std::span<const uint8_t> payload);

/// Decode a version-prefixed Base58Check string.  Returns a pair of
/// (version_byte, payload) on success, or std::nullopt on failure.
std::optional<std::pair<uint8_t, std::vector<uint8_t>>>
decode_with_version(std::string_view str);

}  // namespace core
