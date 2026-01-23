#ifndef FTC_CRYPTO_KECCAK256_H
#define FTC_CRYPTO_KECCAK256_H

#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <vector>

namespace ftc {
namespace crypto {

// Keccak-256 hash output size
constexpr size_t KECCAK256_HASH_SIZE = 32;

// Hash256 type - 32 bytes
using Hash256 = std::array<uint8_t, KECCAK256_HASH_SIZE>;

// Zero hash constant
extern const Hash256 ZERO_HASH;

/**
 * Keccak-256 hash function (NOT SHA3-256!)
 *
 * Keccak-256 uses the original Keccak padding (0x01),
 * while SHA3-256 uses domain separation padding (0x06).
 *
 * This is the same algorithm used by Ethereum.
 */
class Keccak256 {
public:
    Keccak256();

    // Reset to initial state
    void reset();

    // Update with data
    void update(const uint8_t* data, size_t len);
    void update(const std::vector<uint8_t>& data);
    void update(const std::string& data);

    // Finalize and get hash
    Hash256 finalize();

    // One-shot hash functions
    static Hash256 hash(const uint8_t* data, size_t len);
    static Hash256 hash(const std::vector<uint8_t>& data);
    static Hash256 hash(const std::string& data);

    // Hash to hex string
    static std::string hashHex(const uint8_t* data, size_t len);
    static std::string hashHex(const std::vector<uint8_t>& data);
    static std::string hashHex(const std::string& data);

    // Double hash (for block header)
    static Hash256 doubleHash(const uint8_t* data, size_t len);

    // Hash256 utilities
    static std::string toHex(const Hash256& hash);
    static Hash256 fromHex(const std::string& hex);
    static bool isZero(const Hash256& hash);
    static int compare(const Hash256& a, const Hash256& b);

private:
    // Keccak state: 5x5 matrix of 64-bit words = 1600 bits
    uint64_t state_[25];

    // Buffer for incomplete blocks
    uint8_t buffer_[136];  // rate = 1088 bits = 136 bytes for Keccak-256
    size_t buffer_len_;

    // Internal functions
    void absorb(const uint8_t* data, size_t len);
    void keccakF();
    void pad();
};

// Convenience function
inline Hash256 keccak256(const uint8_t* data, size_t len) {
    return Keccak256::hash(data, len);
}

inline Hash256 keccak256(const std::vector<uint8_t>& data) {
    return Keccak256::hash(data);
}

inline Hash256 keccak256(const std::string& data) {
    return Keccak256::hash(data);
}

// Free function for converting Hash256 to hex string
inline std::string toHex(const Hash256& hash) {
    return Keccak256::toHex(hash);
}

// Free function for converting arbitrary byte vector to hex string
inline std::string toHex(const std::vector<uint8_t>& bytes) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        result.push_back(hex_chars[b >> 4]);
        result.push_back(hex_chars[b & 0x0f]);
    }
    return result;
}

// Free function for converting arbitrary byte array to hex string
inline std::string toHex(const uint8_t* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result.push_back(hex_chars[data[i] >> 4]);
        result.push_back(hex_chars[data[i] & 0x0f]);
    }
    return result;
}

} // namespace crypto
} // namespace ftc

#endif // FTC_CRYPTO_KECCAK256_H
