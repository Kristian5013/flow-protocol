// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"

#include <algorithm>
#include <array>
#include <cstring>

#include <openssl/evp.h>

namespace core {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
namespace {

// Reverse lookup: ASCII value -> Base58 digit index (0-57), or -1 if invalid.
constexpr std::array<int8_t, 256> make_base58_map() {
    std::array<int8_t, 256> table{};
    for (auto& v : table) v = -1;
    for (int i = 0; i < 58; ++i) {
        table[static_cast<uint8_t>(BASE58_ALPHABET[i])] =
            static_cast<int8_t>(i);
    }
    return table;
}

constexpr auto BASE58_MAP = make_base58_map();

// Compute double Keccak-256 (SHA3-256) of data and write the first 4 bytes
// of the result into checksum_out.  Uses OpenSSL EVP directly.
//
// NOTE: FTC uses Keccak-256 for its checksum, which is operationally
// identical to SHA3-256 as exposed by OpenSSL's EVP_sha3_256().
void compute_checksum(
    std::span<const uint8_t> data,
    uint8_t (&checksum_out)[4])
{
    std::array<uint8_t, 32> hash1{};
    std::array<uint8_t, 32> hash2{};
    unsigned int out_len = 0;

    // First pass: SHA3-256(data)
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, hash1.data(), &out_len);

    // Second pass: SHA3-256(hash1)
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
    EVP_DigestUpdate(ctx, hash1.data(), hash1.size());
    EVP_DigestFinal_ex(ctx, hash2.data(), &out_len);

    EVP_MD_CTX_free(ctx);

    std::memcpy(checksum_out, hash2.data(), 4);
}

}  // namespace

// ---------------------------------------------------------------------------
// base58_encode
// ---------------------------------------------------------------------------
// Algorithm: treat the input byte array as a big-endian unsigned integer
// and repeatedly divide by 58, collecting remainders.  Leading zero bytes
// in the input map to leading '1' characters in the output.
// ---------------------------------------------------------------------------
std::string base58_encode(std::span<const uint8_t> data) {
    // Count leading zero bytes.
    size_t leading_zeros = 0;
    while (leading_zeros < data.size() && data[leading_zeros] == 0) {
        ++leading_zeros;
    }

    // Allocate enough space.  log(256) / log(58) ~ 1.366, so we use
    // size * 138 / 100 + 1 as a safe upper bound.
    const size_t buf_size = data.size() * 138 / 100 + 1;
    std::vector<uint8_t> digits(buf_size, 0);

    // Process each input byte: for each byte, multiply the existing
    // base-58 number by 256 and add the new byte, propagating carries.
    for (size_t i = leading_zeros; i < data.size(); ++i) {
        int carry = static_cast<int>(data[i]);
        // Iterate in reverse over digits to propagate the carry.
        for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
            carry += 256 * static_cast<int>(*it);
            *it = static_cast<uint8_t>(carry % 58);
            carry /= 58;
        }
        // carry should be zero here for correctly sized buffer.
    }

    // Skip leading zeros in the digit buffer (they are high-order zeros
    // from the oversized allocation).
    auto it = digits.begin();
    while (it != digits.end() && *it == 0) {
        ++it;
    }

    // Build the result string: leading '1's + encoded digits.
    std::string result;
    result.reserve(leading_zeros + static_cast<size_t>(digits.end() - it));
    result.assign(leading_zeros, '1');
    for (; it != digits.end(); ++it) {
        result.push_back(BASE58_ALPHABET[*it]);
    }

    return result;
}

// ---------------------------------------------------------------------------
// base58_decode
// ---------------------------------------------------------------------------
// Reverse of base58_encode.  Each character maps to a digit 0-57.  We
// maintain the result as a big-endian byte array, multiplying by 58 and
// adding each digit.  Leading '1' characters map to leading zero bytes.
// ---------------------------------------------------------------------------
std::optional<std::vector<uint8_t>> base58_decode(std::string_view str) {
    if (str.empty()) {
        return std::vector<uint8_t>{};
    }

    // Count leading '1' characters (these represent leading zero bytes).
    size_t leading_ones = 0;
    while (leading_ones < str.size() && str[leading_ones] == '1') {
        ++leading_ones;
    }

    // Allocate enough space for the decoded bytes.
    // log(58) / log(256) ~ 0.733, so str.size() * 733 / 1000 + 1 is safe.
    const size_t buf_size = str.size() * 733 / 1000 + 1;
    std::vector<uint8_t> bytes(buf_size, 0);

    for (size_t i = leading_ones; i < str.size(); ++i) {
        int digit = BASE58_MAP[static_cast<uint8_t>(str[i])];
        if (digit < 0) {
            return std::nullopt;  // Invalid character.
        }

        int carry = digit;
        for (auto it = bytes.rbegin(); it != bytes.rend(); ++it) {
            carry += 58 * static_cast<int>(*it);
            *it = static_cast<uint8_t>(carry % 256);
            carry /= 256;
        }

        if (carry != 0) {
            return std::nullopt;  // Number too large for buffer (shouldn't happen).
        }
    }

    // Skip leading zeros in the byte buffer.
    auto it = bytes.begin();
    while (it != bytes.end() && *it == 0) {
        ++it;
    }

    // Assemble result: leading zero bytes + decoded value.
    std::vector<uint8_t> result;
    result.reserve(leading_ones + static_cast<size_t>(bytes.end() - it));
    result.assign(leading_ones, 0x00);
    result.insert(result.end(), it, bytes.end());

    return result;
}

// ---------------------------------------------------------------------------
// base58check_encode
// ---------------------------------------------------------------------------
std::string base58check_encode(std::span<const uint8_t> data) {
    // Build buffer: original data + 4-byte checksum.
    std::vector<uint8_t> buf(data.begin(), data.end());
    buf.resize(data.size() + 4);

    uint8_t checksum[4];
    compute_checksum(data, checksum);
    std::memcpy(buf.data() + data.size(), checksum, 4);

    return base58_encode(buf);
}

// ---------------------------------------------------------------------------
// base58check_decode
// ---------------------------------------------------------------------------
std::optional<std::vector<uint8_t>> base58check_decode(
    std::string_view str)
{
    auto decoded = base58_decode(str);
    if (!decoded) {
        return std::nullopt;
    }

    // Need at least 4 bytes for the checksum.
    if (decoded->size() < 4) {
        return std::nullopt;
    }

    const size_t payload_len = decoded->size() - 4;
    const uint8_t* payload_ptr = decoded->data();
    const uint8_t* checksum_ptr = decoded->data() + payload_len;

    // Recompute checksum over the payload portion.
    uint8_t expected[4];
    compute_checksum(
        std::span<const uint8_t>(payload_ptr, payload_len), expected);

    if (std::memcmp(checksum_ptr, expected, 4) != 0) {
        return std::nullopt;  // Checksum mismatch.
    }

    // Return the payload without the checksum.
    return std::vector<uint8_t>(payload_ptr, payload_ptr + payload_len);
}

// ---------------------------------------------------------------------------
// encode_with_version
// ---------------------------------------------------------------------------
std::string encode_with_version(
    uint8_t version,
    std::span<const uint8_t> payload)
{
    std::vector<uint8_t> versioned;
    versioned.reserve(1 + payload.size());
    versioned.push_back(version);
    versioned.insert(versioned.end(), payload.begin(), payload.end());

    return base58check_encode(versioned);
}

// ---------------------------------------------------------------------------
// decode_with_version
// ---------------------------------------------------------------------------
std::optional<std::pair<uint8_t, std::vector<uint8_t>>>
decode_with_version(std::string_view str)
{
    auto decoded = base58check_decode(str);
    if (!decoded) {
        return std::nullopt;
    }

    // Need at least the version byte.
    if (decoded->empty()) {
        return std::nullopt;
    }

    uint8_t version = (*decoded)[0];
    std::vector<uint8_t> payload(
        decoded->begin() + 1, decoded->end());

    return std::pair{version, std::move(payload)};
}

}  // namespace core
