#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "core/types.h"
#include "core/error.h"

namespace crypto {

struct ChaCha20Encrypted {
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, 12> nonce;
    std::array<uint8_t, 16> tag;
};

// ChaCha20-Poly1305 AEAD encrypt
core::Result<ChaCha20Encrypted> chacha20_poly1305_encrypt(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad = {});

// ChaCha20-Poly1305 AEAD decrypt
core::Result<std::vector<uint8_t>> chacha20_poly1305_decrypt(
    std::span<const uint8_t, 32> key,
    const ChaCha20Encrypted& encrypted,
    std::span<const uint8_t> aad = {});

// Raw ChaCha20 stream cipher (for V2 P2P transport)
class ChaCha20 {
public:
    explicit ChaCha20(std::span<const uint8_t, 32> key,
                      uint64_t counter = 0);

    void set_counter(uint64_t counter);
    void set_iv(uint64_t iv);

    void encrypt(std::span<const uint8_t> input,
                 std::span<uint8_t> output);
    void decrypt(std::span<const uint8_t> input,
                 std::span<uint8_t> output);

    // Generate keystream (XOR with zeros)
    void keystream(std::span<uint8_t> output);

private:
    std::array<uint8_t, 32> key_;
    uint64_t counter_ = 0;
    uint64_t iv_ = 0;
};

} // namespace crypto
