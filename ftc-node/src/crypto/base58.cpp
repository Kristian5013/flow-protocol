#include "crypto/base58.h"
#include "crypto/keccak256.h"
#include <algorithm>
#include <cstring>

namespace ftc {
namespace crypto {

static const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string base58Encode(const std::vector<uint8_t>& data) {
    // Count leading zeros
    size_t zeros = 0;
    while (zeros < data.size() && data[zeros] == 0) {
        zeros++;
    }

    // Allocate enough space
    std::vector<uint8_t> b58((data.size() - zeros) * 138 / 100 + 1);
    size_t length = 0;

    for (size_t i = zeros; i < data.size(); i++) {
        int carry = data[i];
        for (size_t j = 0; j < length || carry; j++) {
            if (j == length) length++;
            carry += 256 * b58[j];
            b58[j] = carry % 58;
            carry /= 58;
        }
    }

    std::string result(zeros, '1');
    for (size_t i = length; i > 0; i--) {
        result += BASE58_ALPHABET[b58[i - 1]];
    }

    return result;
}

std::optional<std::vector<uint8_t>> base58Decode(const std::string& str) {
    // Count leading '1's
    size_t zeros = 0;
    while (zeros < str.size() && str[zeros] == '1') {
        zeros++;
    }

    std::vector<uint8_t> b256((str.size() - zeros) * 733 / 1000 + 1);
    size_t length = 0;

    for (size_t i = zeros; i < str.size(); i++) {
        const char* p = std::strchr(BASE58_ALPHABET, str[i]);
        if (!p) return std::nullopt;

        int carry = static_cast<int>(p - BASE58_ALPHABET);
        for (size_t j = 0; j < length || carry; j++) {
            if (j == length) length++;
            carry += 58 * b256[j];
            b256[j] = carry % 256;
            carry /= 256;
        }
    }

    std::vector<uint8_t> result(zeros, 0);
    for (size_t i = length; i > 0; i--) {
        result.push_back(b256[i - 1]);
    }

    return result;
}

std::string base58CheckEncode(const std::vector<uint8_t>& data) {
    // Add 4-byte checksum
    auto hash1 = Keccak256::hash(data);
    auto hash2 = Keccak256::hash(hash1.data(), hash1.size());

    std::vector<uint8_t> with_checksum = data;
    with_checksum.insert(with_checksum.end(), hash2.begin(), hash2.begin() + 4);

    return base58Encode(with_checksum);
}

std::optional<std::vector<uint8_t>> base58CheckDecode(const std::string& str) {
    auto decoded = base58Decode(str);
    if (!decoded || decoded->size() < 4) return std::nullopt;

    // Verify checksum
    std::vector<uint8_t> data(decoded->begin(), decoded->end() - 4);
    auto hash1 = Keccak256::hash(data);
    auto hash2 = Keccak256::hash(hash1.data(), hash1.size());

    for (int i = 0; i < 4; i++) {
        if ((*decoded)[decoded->size() - 4 + i] != hash2[i]) {
            return std::nullopt;
        }
    }

    return data;
}

} // namespace crypto
} // namespace ftc
