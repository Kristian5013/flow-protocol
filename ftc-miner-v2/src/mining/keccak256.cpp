#include "keccak256.h"
#include <cstring>
#include <sstream>
#include <iomanip>

namespace mining {

// Keccak-256 constants - same as node
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

// Rotation offsets - SAME as node
constexpr int ROTATIONS[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

// Pi permutation indices - SAME as node
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

// Keccak-f[1600] permutation - EXACT COPY from node
void Keccak256::keccakF1600(uint64_t state[25]) {
    uint64_t C[5], D[5], temp[25];

    for (int round = 0; round < 24; round++) {
        // Theta step
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^
                   state[x + 15] ^ state[x + 20];
        }

        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }

        for (int i = 0; i < 25; i++) {
            state[i] ^= D[i % 5];
        }

        // Rho and Pi steps combined - SAME as node
        for (int i = 0; i < 25; i++) {
            temp[PI[i]] = rotl64(state[i], ROTATIONS[i]);
        }

        // Chi step
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                int i = y * 5 + x;
                state[i] = temp[i] ^ ((~temp[y * 5 + (x + 1) % 5]) &
                                        temp[y * 5 + (x + 2) % 5]);
            }
        }

        // Iota step
        state[0] ^= RC[round];
    }
}

Hash256 Keccak256::hash(const uint8_t* data, size_t length) {
    uint64_t state[25] = {0};
    const size_t RATE = 136;  // Rate for Keccak-256 (1088 bits = 136 bytes)

    size_t offset = 0;

    // Process full blocks
    while (offset + RATE <= length) {
        for (size_t i = 0; i < RATE / 8; i++) {
            uint64_t word;
            std::memcpy(&word, data + offset + i * 8, 8);
            state[i] ^= word;
        }
        keccakF1600(state);
        offset += RATE;
    }

    // Pad and absorb final block
    uint8_t padded[RATE] = {0};
    size_t remaining = length - offset;
    std::memcpy(padded, data + offset, remaining);

    // Keccak padding: 0x01 at end of data, 0x80 at end of rate
    padded[remaining] = 0x01;
    padded[RATE - 1] |= 0x80;

    for (size_t i = 0; i < RATE / 8; i++) {
        uint64_t word;
        std::memcpy(&word, padded + i * 8, 8);
        state[i] ^= word;
    }
    keccakF1600(state);

    // Squeeze - extract 32 bytes from state
    Hash256 result;
    std::memcpy(result.data(), state, 32);

    return result;
}

Hash256 Keccak256::hash(const std::vector<uint8_t>& data) {
    return hash(data.data(), data.size());
}

Hash256 Keccak256::hashHeader(const uint8_t* header76, uint32_t nonce) {
    uint8_t data[80];
    std::memcpy(data, header76, 76);

    // Append nonce (little-endian)
    data[76] = nonce & 0xFF;
    data[77] = (nonce >> 8) & 0xFF;
    data[78] = (nonce >> 16) & 0xFF;
    data[79] = (nonce >> 24) & 0xFF;

    return hash(data, 80);
}

Hash256 Keccak256::bitsToTarget(uint32_t bits) {
    Hash256 target = {0};

    uint32_t exponent = (bits >> 24) & 0xFF;
    uint32_t mantissa = bits & 0x00FFFFFF;

    // Target is stored in BIG-ENDIAN format (byte 0 = MSB, byte 31 = LSB)
    // Same format as node for compatibility
    if (exponent <= 3) {
        mantissa >>= 8 * (3 - exponent);
        target[31] = mantissa & 0xFF;
        target[30] = (mantissa >> 8) & 0xFF;
        target[29] = (mantissa >> 16) & 0xFF;
    } else {
        int offset = 32 - exponent;  // Position from MSB
        if (offset >= 0 && offset < 32) {
            target[offset] = (mantissa >> 16) & 0xFF;
            if (offset + 1 < 32) target[offset + 1] = (mantissa >> 8) & 0xFF;
            if (offset + 2 < 32) target[offset + 2] = mantissa & 0xFF;
        }
    }

    return target;
}

bool Keccak256::meetsTarget(const Hash256& hash, const Hash256& target) {
    // Compare BIG-ENDIAN (most significant byte is at index 0)
    // Same as node's crypto::Keccak256::compare
    for (int i = 0; i < 32; ++i) {
        if (hash[i] < target[i]) return true;
        if (hash[i] > target[i]) return false;
    }
    return true;
}

std::string Keccak256::toHex(const Hash256& hash) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 32; ++i) {
        ss << std::setw(2) << static_cast<int>(hash[i]);
    }
    return ss.str();
}

Hash256 Keccak256::fromHex(const std::string& hex) {
    Hash256 result = {0};
    for (size_t i = 0; i < 32 && i * 2 + 1 < hex.size(); ++i) {
        result[i] = static_cast<uint8_t>(std::stoi(hex.substr(i * 2, 2), nullptr, 16));
    }
    return result;
}

} // namespace mining
