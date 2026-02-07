#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Bech32 / Bech32m encoding as defined in BIP173 and BIP350.

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace core {

// ---------------------------------------------------------------------------
// Encoding variants
// ---------------------------------------------------------------------------

/// Bech32 encoding type: original (BIP173), modified (BIP350), or invalid.
enum class Bech32Encoding {
    BECH32,     // BIP173 -- witness version 0
    BECH32M,    // BIP350 -- witness version 1+
    INVALID,    // decode failure / unknown
};

// ---------------------------------------------------------------------------
// Decode result
// ---------------------------------------------------------------------------

/// Holds the result of decoding a Bech32/Bech32m string.
struct Bech32DecodeResult {
    Bech32Encoding          encoding = Bech32Encoding::INVALID;
    std::string             hrp;           // human-readable part
    std::vector<uint8_t>    data;          // 5-bit values (excluding checksum)
};

// ---------------------------------------------------------------------------
// Core Bech32 encode / decode
// ---------------------------------------------------------------------------

/// Encode a Bech32 / Bech32m string from an HRP and 5-bit data values.
/// Returns: HRP + '1' + data characters + 6-character checksum.
/// The caller is responsible for ensuring every element of `values` is
/// in the range [0, 31].
std::string bech32_encode(
    std::string_view hrp,
    std::span<const uint8_t> values,
    Bech32Encoding encoding);

/// Decode a Bech32 / Bech32m string.
/// On failure, result.encoding == Bech32Encoding::INVALID.
Bech32DecodeResult bech32_decode(std::string_view str);

// ---------------------------------------------------------------------------
// Bit conversion
// ---------------------------------------------------------------------------

/// Convert between arbitrary bit groupings (e.g., 8-bit bytes to 5-bit
/// values or vice versa).
///
/// @param data     Input values, each in [0, 2^from_bits).
/// @param from_bits  Bit width of each input element (typically 8 or 5).
/// @param to_bits    Bit width of each output element (typically 5 or 8).
/// @param pad        If true, zero-pad the final group when converting to
///                   a wider representation.
/// @return Converted values.  Returns an empty vector on error (e.g.,
///         non-zero padding bits when pad==false, or values out of range).
std::vector<uint8_t> convert_bits(
    std::span<const uint8_t> data,
    int from_bits,
    int to_bits,
    bool pad);

// ---------------------------------------------------------------------------
// SegWit address helpers
// ---------------------------------------------------------------------------

/// Encode a SegWit address from a witness version and program.
/// Uses BECH32 for version 0, BECH32M for version 1+.
///
/// @param hrp               Human-readable part (e.g. "ftc", "tftc").
/// @param witness_version   Witness version (0-16).
/// @param program           Witness program bytes (typically 20 or 32).
/// @return The Bech32-encoded address, or an empty string on error.
std::string encode_segwit(
    std::string_view hrp,
    uint8_t witness_version,
    std::span<const uint8_t> program);

/// Decode a SegWit address.
///
/// @param hrp   Expected human-readable part.
/// @param addr  The Bech32-encoded address string.
/// @return A pair of (witness_version, program) on success, or
///         std::nullopt on failure (bad encoding, wrong HRP, invalid
///         witness version or program length).
std::optional<std::pair<uint8_t, std::vector<uint8_t>>>
decode_segwit(std::string_view hrp, std::string_view addr);

}  // namespace core
