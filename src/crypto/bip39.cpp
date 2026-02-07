#include "crypto/bip39.h"
#include "crypto/bip39_wordlist.h"
#include "crypto/keccak.h"
#include "core/random.h"

#include <openssl/evp.h>
#include <algorithm>
#include <cstring>
#include <sstream>
#include <string>

namespace crypto {

namespace {

// Find word index in sorted wordlist using binary search.
int find_word_index(std::string_view word) {
    int lo = 0;
    int hi = static_cast<int>(detail::BIP39_WORDLIST_SIZE) - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        int cmp = word.compare(detail::BIP39_WORDLIST[mid]);
        if (cmp == 0) return mid;
        if (cmp < 0) hi = mid - 1;
        else lo = mid + 1;
    }
    return -1;
}

// Extract bit at position from byte array (MSB first).
bool get_bit(const uint8_t* data, size_t bit_pos) {
    return (data[bit_pos / 8] >> (7 - (bit_pos % 8))) & 1;
}

// Set bit at position in byte array (MSB first).
void set_bit(uint8_t* data, size_t bit_pos, bool val) {
    if (val) {
        data[bit_pos / 8] |= (1 << (7 - (bit_pos % 8)));
    } else {
        data[bit_pos / 8] &= ~(1 << (7 - (bit_pos % 8)));
    }
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// generate_mnemonic
// ---------------------------------------------------------------------------
std::vector<std::string> generate_mnemonic(size_t word_count) {
    // Valid counts: 12,15,18,21,24 -> entropy bits: 128,160,192,224,256
    size_t entropy_bits;
    switch (word_count) {
        case 12: entropy_bits = 128; break;
        case 15: entropy_bits = 160; break;
        case 18: entropy_bits = 192; break;
        case 21: entropy_bits = 224; break;
        case 24: entropy_bits = 256; break;
        default: return {};  // invalid word count
    }

    size_t entropy_bytes = entropy_bits / 8;
    std::vector<uint8_t> entropy(entropy_bytes);
    core::get_random_bytes(entropy);

    auto result = entropy_to_mnemonic(entropy);
    if (!result.ok()) return {};
    return std::move(result).value();
}

// ---------------------------------------------------------------------------
// entropy_to_mnemonic
// ---------------------------------------------------------------------------
core::Result<std::vector<std::string>> entropy_to_mnemonic(
    std::span<const uint8_t> entropy)
{
    size_t ent_bytes = entropy.size();
    if (ent_bytes != 16 && ent_bytes != 20 && ent_bytes != 24 &&
        ent_bytes != 28 && ent_bytes != 32) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "Invalid entropy size for BIP39");
    }

    size_t ent_bits = ent_bytes * 8;
    size_t cs_bits = ent_bits / 32;  // checksum bits
    size_t total_bits = ent_bits + cs_bits;
    size_t word_count = total_bits / 11;

    // Compute checksum: first cs_bits of keccak256(entropy)
    core::uint256 hash = keccak256(entropy);

    // Build combined bitstream: entropy || checksum
    std::vector<uint8_t> bits((total_bits + 7) / 8, 0);
    std::memcpy(bits.data(), entropy.data(), ent_bytes);

    // Append checksum bits
    for (size_t i = 0; i < cs_bits; ++i) {
        bool b = get_bit(hash.data(), i);
        set_bit(bits.data(), ent_bits + i, b);
    }

    // Extract 11-bit groups and map to words
    std::vector<std::string> words;
    words.reserve(word_count);
    for (size_t i = 0; i < word_count; ++i) {
        uint32_t idx = 0;
        for (size_t j = 0; j < 11; ++j) {
            if (get_bit(bits.data(), i * 11 + j)) {
                idx |= (1u << (10 - j));
            }
        }
        if (idx >= detail::BIP39_WORDLIST_SIZE) {
            return core::Error(core::ErrorCode::CRYPTO_ERROR,
                "BIP39 word index out of range");
        }
        words.emplace_back(detail::BIP39_WORDLIST[idx]);
    }

    return words;
}

// ---------------------------------------------------------------------------
// mnemonic_to_entropy
// ---------------------------------------------------------------------------
core::Result<std::vector<uint8_t>> mnemonic_to_entropy(
    const std::vector<std::string>& words)
{
    size_t word_count = words.size();
    if (word_count != 12 && word_count != 15 && word_count != 18 &&
        word_count != 21 && word_count != 24) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "Invalid mnemonic word count");
    }

    // Map words to 11-bit indices
    size_t total_bits = word_count * 11;
    std::vector<uint8_t> bits((total_bits + 7) / 8, 0);

    for (size_t i = 0; i < word_count; ++i) {
        int idx = find_word_index(words[i]);
        if (idx < 0) {
            return core::Error(core::ErrorCode::CRYPTO_ERROR,
                "Unknown BIP39 word: " + words[i]);
        }
        for (size_t j = 0; j < 11; ++j) {
            if ((idx >> (10 - j)) & 1) {
                set_bit(bits.data(), i * 11 + j, true);
            }
        }
    }

    // Split into entropy and checksum
    size_t cs_bits = word_count * 11 / 33;  // total_bits / (32+1)
    size_t ent_bits = total_bits - cs_bits;
    size_t ent_bytes = ent_bits / 8;

    std::vector<uint8_t> entropy(ent_bytes);
    std::memcpy(entropy.data(), bits.data(), ent_bytes);

    // Verify checksum
    core::uint256 hash = keccak256(entropy);
    for (size_t i = 0; i < cs_bits; ++i) {
        bool expected = get_bit(hash.data(), i);
        bool actual = get_bit(bits.data(), ent_bits + i);
        if (expected != actual) {
            return core::Error(core::ErrorCode::CRYPTO_ERROR,
                "BIP39 checksum mismatch");
        }
    }

    return entropy;
}

// ---------------------------------------------------------------------------
// validate_mnemonic
// ---------------------------------------------------------------------------
bool validate_mnemonic(const std::vector<std::string>& words) {
    return mnemonic_to_entropy(words).ok();
}

// ---------------------------------------------------------------------------
// mnemonic_to_seed
// ---------------------------------------------------------------------------
core::Result<std::vector<uint8_t>> mnemonic_to_seed(
    const std::vector<std::string>& words,
    std::string_view passphrase)
{
    if (!validate_mnemonic(words)) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "Invalid mnemonic");
    }

    // Join words with spaces
    std::string mnemonic;
    for (size_t i = 0; i < words.size(); ++i) {
        if (i > 0) mnemonic += ' ';
        mnemonic += words[i];
    }

    // Salt = "mnemonic" + passphrase
    std::string salt = "mnemonic";
    salt.append(passphrase.data(), passphrase.size());

    // PBKDF2-HMAC-SHA512, 2048 iterations, 64-byte output
    std::vector<uint8_t> seed(64);
    int rc = PKCS5_PBKDF2_HMAC(
        mnemonic.c_str(),
        static_cast<int>(mnemonic.size()),
        reinterpret_cast<const unsigned char*>(salt.c_str()),
        static_cast<int>(salt.size()),
        2048,
        EVP_sha512(),
        64,
        seed.data());

    if (rc != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "PBKDF2 failed in BIP39 seed derivation");
    }

    return seed;
}

} // namespace crypto
