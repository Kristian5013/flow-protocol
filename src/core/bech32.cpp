// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Bech32 / Bech32m implementation per BIP173 and BIP350.

#include "bech32.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <limits>

namespace core {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
namespace {

// Bech32 character set (BIP173).
constexpr char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Reverse lookup: ASCII value -> 5-bit value, or -1 if invalid.
constexpr std::array<int8_t, 128> make_charset_rev() {
    std::array<int8_t, 128> table{};
    for (auto& v : table) v = -1;
    for (int i = 0; i < 32; ++i) {
        table[static_cast<uint8_t>(BECH32_CHARSET[i])] =
            static_cast<int8_t>(i);
    }
    return table;
}

constexpr auto CHARSET_REV = make_charset_rev();

// Final XOR constant for Bech32 (BIP173).
constexpr uint32_t BECH32_CONST = 1;

// Final XOR constant for Bech32m (BIP350).
constexpr uint32_t BECH32M_CONST = 0x2bc830a3;

// ---------------------------------------------------------------------------
// Polymod -- GF(2^5) BCH checksum as defined in BIP173
// ---------------------------------------------------------------------------
// The generator polynomial coefficients encode the BCH code properties.
// ---------------------------------------------------------------------------
uint32_t polymod(const std::vector<uint8_t>& values) {
    uint32_t chk = 1;
    for (uint8_t v : values) {
        uint8_t top = static_cast<uint8_t>(chk >> 25);
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        if (top & 0x01) chk ^= 0x3b6a57b2;
        if (top & 0x02) chk ^= 0x26508e6d;
        if (top & 0x04) chk ^= 0x1ea119fa;
        if (top & 0x08) chk ^= 0x3d4233dd;
        if (top & 0x10) chk ^= 0x2a1462b3;
    }
    return chk;
}

// ---------------------------------------------------------------------------
// hrp_expand -- expand the HRP for checksum computation
// ---------------------------------------------------------------------------
// Returns: [high bits of each char] ++ [0] ++ [low 5 bits of each char]
// ---------------------------------------------------------------------------
std::vector<uint8_t> hrp_expand(std::string_view hrp) {
    std::vector<uint8_t> result;
    result.reserve(hrp.size() * 2 + 1);

    for (char c : hrp) {
        result.push_back(static_cast<uint8_t>(c) >> 5);
    }
    result.push_back(0);
    for (char c : hrp) {
        result.push_back(static_cast<uint8_t>(c) & 0x1f);
    }

    return result;
}

// ---------------------------------------------------------------------------
// verify_checksum -- verify and identify the encoding
// ---------------------------------------------------------------------------
Bech32Encoding verify_checksum(
    std::string_view hrp,
    const std::vector<uint8_t>& values)
{
    auto exp = hrp_expand(hrp);
    exp.insert(exp.end(), values.begin(), values.end());

    uint32_t check = polymod(exp);
    if (check == BECH32_CONST)  return Bech32Encoding::BECH32;
    if (check == BECH32M_CONST) return Bech32Encoding::BECH32M;
    return Bech32Encoding::INVALID;
}

// ---------------------------------------------------------------------------
// create_checksum -- compute the 6-value checksum
// ---------------------------------------------------------------------------
std::vector<uint8_t> create_checksum(
    std::string_view hrp,
    std::span<const uint8_t> values,
    Bech32Encoding enc)
{
    auto exp = hrp_expand(hrp);
    exp.insert(exp.end(), values.begin(), values.end());

    // Append 6 zero bytes for the checksum positions.
    exp.resize(exp.size() + 6, 0);

    uint32_t target = (enc == Bech32Encoding::BECH32M)
                          ? BECH32M_CONST
                          : BECH32_CONST;

    uint32_t mod = polymod(exp) ^ target;

    std::vector<uint8_t> result(6);
    for (int i = 0; i < 6; ++i) {
        result[i] = static_cast<uint8_t>((mod >> (5 * (5 - i))) & 0x1f);
    }

    return result;
}

}  // namespace

// ---------------------------------------------------------------------------
// bech32_encode
// ---------------------------------------------------------------------------
std::string bech32_encode(
    std::string_view hrp,
    std::span<const uint8_t> values,
    Bech32Encoding encoding)
{
    // Validate HRP: must be 1-83 characters, all printable ASCII in
    // range [33, 126].
    if (hrp.empty() || hrp.size() > 83) {
        return {};
    }
    for (char c : hrp) {
        if (c < 33 || c > 126) {
            return {};
        }
    }

    // Validate data values: each must be in [0, 31].
    for (uint8_t v : values) {
        if (v > 31) {
            return {};
        }
    }

    // Total length check: HRP + '1' + data + 6-char checksum <= 90.
    if (hrp.size() + 1 + values.size() + 6 > 90) {
        return {};
    }

    auto checksum = create_checksum(hrp, values, encoding);

    std::string result;
    result.reserve(hrp.size() + 1 + values.size() + 6);

    // HRP in lowercase.
    for (char c : hrp) {
        result.push_back(static_cast<char>(std::tolower(
            static_cast<unsigned char>(c))));
    }

    result.push_back('1');  // Separator.

    // Data characters.
    for (uint8_t v : values) {
        result.push_back(BECH32_CHARSET[v]);
    }

    // Checksum characters.
    for (uint8_t v : checksum) {
        result.push_back(BECH32_CHARSET[v]);
    }

    return result;
}

// ---------------------------------------------------------------------------
// bech32_decode
// ---------------------------------------------------------------------------
Bech32DecodeResult bech32_decode(std::string_view str) {
    Bech32DecodeResult fail;  // encoding == INVALID

    // Length checks.
    if (str.size() > 90 || str.empty()) {
        return fail;
    }

    // Must not have mixed case.
    bool has_lower = false;
    bool has_upper = false;
    for (char c : str) {
        auto uc = static_cast<unsigned char>(c);
        if (uc < 33 || uc > 126) {
            return fail;
        }
        if (c >= 'a' && c <= 'z') has_lower = true;
        if (c >= 'A' && c <= 'Z') has_upper = true;
    }
    if (has_lower && has_upper) {
        return fail;
    }

    // Find the last '1' -- this is the separator between HRP and data.
    auto sep_pos = str.rfind('1');
    if (sep_pos == std::string_view::npos) {
        return fail;
    }

    // HRP must be at least 1 character; data part must be at least 6
    // characters (the checksum).
    if (sep_pos < 1 || (str.size() - sep_pos - 1) < 6) {
        return fail;
    }

    // Extract HRP (lowercase it).
    std::string hrp;
    hrp.reserve(sep_pos);
    for (size_t i = 0; i < sep_pos; ++i) {
        hrp.push_back(static_cast<char>(std::tolower(
            static_cast<unsigned char>(str[i]))));
    }

    // Decode data part (including checksum) from charset.
    std::vector<uint8_t> data;
    data.reserve(str.size() - sep_pos - 1);
    for (size_t i = sep_pos + 1; i < str.size(); ++i) {
        char c = static_cast<char>(std::tolower(
            static_cast<unsigned char>(str[i])));
        int8_t val = CHARSET_REV[static_cast<uint8_t>(c)];
        if (val < 0) {
            return fail;
        }
        data.push_back(static_cast<uint8_t>(val));
    }

    // Verify checksum (which also identifies the encoding variant).
    Bech32Encoding enc = verify_checksum(hrp, data);
    if (enc == Bech32Encoding::INVALID) {
        return fail;
    }

    // Strip the 6-byte checksum from the data.
    data.resize(data.size() - 6);

    return Bech32DecodeResult{enc, std::move(hrp), std::move(data)};
}

// ---------------------------------------------------------------------------
// convert_bits
// ---------------------------------------------------------------------------
std::vector<uint8_t> convert_bits(
    std::span<const uint8_t> data,
    int from_bits,
    int to_bits,
    bool pad)
{
    std::vector<uint8_t> result;

    int acc = 0;       // accumulator holding unconsumed bits
    int bits = 0;      // number of bits currently in acc
    const int max_v = (1 << to_bits) - 1;
    const int max_acc = (1 << (from_bits + to_bits - 1)) - 1;

    for (uint8_t value : data) {
        if ((value >> from_bits) != 0) {
            return {};  // Value out of range.
        }
        acc = ((acc << from_bits) | value) & max_acc;
        bits += from_bits;
        while (bits >= to_bits) {
            bits -= to_bits;
            result.push_back(static_cast<uint8_t>((acc >> bits) & max_v));
        }
    }

    if (pad) {
        if (bits > 0) {
            result.push_back(
                static_cast<uint8_t>((acc << (to_bits - bits)) & max_v));
        }
    } else {
        // When not padding, any remaining bits must be zero.
        if (bits >= from_bits) {
            return {};  // Too many leftover bits.
        }
        if (((acc << (to_bits - bits)) & max_v) != 0) {
            return {};  // Non-zero padding bits.
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// encode_segwit
// ---------------------------------------------------------------------------
std::string encode_segwit(
    std::string_view hrp,
    uint8_t witness_version,
    std::span<const uint8_t> program)
{
    // Witness version must be 0-16.
    if (witness_version > 16) {
        return {};
    }

    // Program length validation per BIP141:
    //   version 0: must be 20 (P2WPKH) or 32 (P2WSH)
    //   version 1-16: must be 2-40 bytes
    if (witness_version == 0) {
        if (program.size() != 20 && program.size() != 32) {
            return {};
        }
    } else {
        if (program.size() < 2 || program.size() > 40) {
            return {};
        }
    }

    // Convert 8-bit program bytes to 5-bit values.
    auto conv = convert_bits(program, 8, 5, true);
    if (conv.empty() && !program.empty()) {
        return {};
    }

    // Prepend witness version as the first 5-bit value.
    std::vector<uint8_t> values;
    values.reserve(1 + conv.size());
    values.push_back(witness_version);
    values.insert(values.end(), conv.begin(), conv.end());

    // Use BECH32 for version 0, BECH32M for version 1+.
    Bech32Encoding enc = (witness_version == 0)
                             ? Bech32Encoding::BECH32
                             : Bech32Encoding::BECH32M;

    return bech32_encode(hrp, values, enc);
}

// ---------------------------------------------------------------------------
// decode_segwit
// ---------------------------------------------------------------------------
std::optional<std::pair<uint8_t, std::vector<uint8_t>>>
decode_segwit(std::string_view hrp, std::string_view addr)
{
    auto result = bech32_decode(addr);
    if (result.encoding == Bech32Encoding::INVALID) {
        return std::nullopt;
    }

    // Verify HRP matches (case-insensitive comparison -- both are already
    // lowercased by bech32_decode, so we lowercase the expected HRP too).
    std::string expected_hrp;
    expected_hrp.reserve(hrp.size());
    for (char c : hrp) {
        expected_hrp.push_back(static_cast<char>(std::tolower(
            static_cast<unsigned char>(c))));
    }
    if (result.hrp != expected_hrp) {
        return std::nullopt;
    }

    // Must have at least the witness version byte in the 5-bit data.
    if (result.data.empty()) {
        return std::nullopt;
    }

    uint8_t witness_version = result.data[0];
    if (witness_version > 16) {
        return std::nullopt;
    }

    // Verify encoding variant matches witness version.
    if (witness_version == 0 &&
        result.encoding != Bech32Encoding::BECH32) {
        return std::nullopt;
    }
    if (witness_version != 0 &&
        result.encoding != Bech32Encoding::BECH32M) {
        return std::nullopt;
    }

    // Convert 5-bit data (excluding version) back to 8-bit bytes.
    auto program = convert_bits(
        std::span<const uint8_t>(
            result.data.data() + 1, result.data.size() - 1),
        5, 8, false);

    if (program.empty() && result.data.size() > 1) {
        return std::nullopt;  // Conversion failure.
    }

    // Program length validation per BIP141.
    if (witness_version == 0) {
        if (program.size() != 20 && program.size() != 32) {
            return std::nullopt;
        }
    } else {
        if (program.size() < 2 || program.size() > 40) {
            return std::nullopt;
        }
    }

    return std::pair{witness_version, std::move(program)};
}

}  // namespace core
