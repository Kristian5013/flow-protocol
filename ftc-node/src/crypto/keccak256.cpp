#include "crypto/keccak256.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace ftc {
namespace crypto {

// Zero hash
const Hash256 ZERO_HASH = {0};

// Keccak-256 constants
namespace {

// Round constants for Keccak-f[1600]
constexpr uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

// Rotation offsets
constexpr int ROTATIONS[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

// Pi permutation indices
constexpr int PI[25] = {
     0, 6, 12, 18, 24,
     3, 9, 10, 16, 22,
     1, 7, 13, 19, 20,
     4, 5, 11, 17, 23,
     2, 8, 14, 15, 21
};

// Rotate left
inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

} // anonymous namespace

Keccak256::Keccak256() {
    reset();
}

void Keccak256::reset() {
    std::memset(state_, 0, sizeof(state_));
    std::memset(buffer_, 0, sizeof(buffer_));
    buffer_len_ = 0;
}

void Keccak256::keccakF() {
    // Keccak-f[1600] permutation - 24 rounds
    uint64_t C[5], D[5], temp[25];

    for (int round = 0; round < 24; round++) {
        // Theta step
        for (int x = 0; x < 5; x++) {
            C[x] = state_[x] ^ state_[x + 5] ^ state_[x + 10] ^
                   state_[x + 15] ^ state_[x + 20];
        }

        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }

        for (int i = 0; i < 25; i++) {
            state_[i] ^= D[i % 5];
        }

        // Rho and Pi steps combined
        for (int i = 0; i < 25; i++) {
            temp[PI[i]] = rotl64(state_[i], ROTATIONS[i]);
        }

        // Chi step
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                int i = y * 5 + x;
                state_[i] = temp[i] ^ ((~temp[y * 5 + (x + 1) % 5]) &
                                        temp[y * 5 + (x + 2) % 5]);
            }
        }

        // Iota step
        state_[0] ^= RC[round];
    }
}

void Keccak256::absorb(const uint8_t* data, size_t len) {
    // Rate for Keccak-256: 1088 bits = 136 bytes
    constexpr size_t RATE = 136;

    size_t offset = 0;

    // Process any buffered data first
    if (buffer_len_ > 0) {
        size_t to_copy = std::min(len, RATE - buffer_len_);
        std::memcpy(buffer_ + buffer_len_, data, to_copy);
        buffer_len_ += to_copy;
        offset += to_copy;

        if (buffer_len_ == RATE) {
            // XOR buffer into state
            for (size_t i = 0; i < RATE / 8; i++) {
                uint64_t word;
                std::memcpy(&word, buffer_ + i * 8, 8);
                state_[i] ^= word;
            }
            keccakF();
            buffer_len_ = 0;
        }
    }

    // Process full blocks
    while (offset + RATE <= len) {
        for (size_t i = 0; i < RATE / 8; i++) {
            uint64_t word;
            std::memcpy(&word, data + offset + i * 8, 8);
            state_[i] ^= word;
        }
        keccakF();
        offset += RATE;
    }

    // Buffer remaining data
    if (offset < len) {
        std::memcpy(buffer_, data + offset, len - offset);
        buffer_len_ = len - offset;
    }
}

void Keccak256::pad() {
    // Keccak padding: append 0x01, then zeros, then 0x80
    // Note: This is Keccak padding, NOT SHA3 padding (which uses 0x06)
    constexpr size_t RATE = 136;

    buffer_[buffer_len_++] = 0x01;

    if (buffer_len_ == RATE) {
        for (size_t i = 0; i < RATE / 8; i++) {
            uint64_t word;
            std::memcpy(&word, buffer_ + i * 8, 8);
            state_[i] ^= word;
        }
        keccakF();
        buffer_len_ = 0;
        std::memset(buffer_, 0, RATE);
    }

    std::memset(buffer_ + buffer_len_, 0, RATE - buffer_len_);
    buffer_[RATE - 1] |= 0x80;

    for (size_t i = 0; i < RATE / 8; i++) {
        uint64_t word;
        std::memcpy(&word, buffer_ + i * 8, 8);
        state_[i] ^= word;
    }
    keccakF();
}

void Keccak256::update(const uint8_t* data, size_t len) {
    absorb(data, len);
}

void Keccak256::update(const std::vector<uint8_t>& data) {
    absorb(data.data(), data.size());
}

void Keccak256::update(const std::string& data) {
    absorb(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

Hash256 Keccak256::finalize() {
    pad();

    Hash256 result;
    // Extract 256 bits (32 bytes) from state
    std::memcpy(result.data(), state_, 32);

    reset();
    return result;
}

// Static one-shot functions
Hash256 Keccak256::hash(const uint8_t* data, size_t len) {
    Keccak256 hasher;
    hasher.update(data, len);
    return hasher.finalize();
}

Hash256 Keccak256::hash(const std::vector<uint8_t>& data) {
    return hash(data.data(), data.size());
}

Hash256 Keccak256::hash(const std::string& data) {
    return hash(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::string Keccak256::hashHex(const uint8_t* data, size_t len) {
    return toHex(hash(data, len));
}

std::string Keccak256::hashHex(const std::vector<uint8_t>& data) {
    return toHex(hash(data));
}

std::string Keccak256::hashHex(const std::string& data) {
    return toHex(hash(data));
}

Hash256 Keccak256::doubleHash(const uint8_t* data, size_t len) {
    Hash256 first = hash(data, len);
    return hash(first.data(), first.size());
}

std::string Keccak256::toHex(const Hash256& hash) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < hash.size(); i++) {
        ss << std::setw(2) << static_cast<int>(hash[i]);
    }
    return ss.str();
}

Hash256 Keccak256::fromHex(const std::string& hex) {
    Hash256 result;

    std::string clean = hex;
    if (clean.substr(0, 2) == "0x" || clean.substr(0, 2) == "0X") {
        clean = clean.substr(2);
    }

    if (clean.size() != 64) {
        throw std::invalid_argument("Invalid hash hex length");
    }

    for (size_t i = 0; i < 32; i++) {
        std::string byte_str = clean.substr(i * 2, 2);
        result[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }

    return result;
}

bool Keccak256::isZero(const Hash256& hash) {
    for (const auto& byte : hash) {
        if (byte != 0) return false;
    }
    return true;
}

int Keccak256::compare(const Hash256& a, const Hash256& b) {
    // Compare as big-endian numbers (for difficulty comparison)
    for (size_t i = 0; i < a.size(); i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

} // namespace crypto
} // namespace ftc
