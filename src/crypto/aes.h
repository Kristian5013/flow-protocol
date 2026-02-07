#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "core/types.h"
#include "core/error.h"

namespace crypto {

struct AESEncrypted {
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, 12> iv;   // 96-bit nonce
    std::array<uint8_t, 16> tag;  // 128-bit auth tag
};

// Encrypt with AES-256-GCM
core::Result<AESEncrypted> aes256_gcm_encrypt(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad = {});

// Decrypt with AES-256-GCM
core::Result<std::vector<uint8_t>> aes256_gcm_decrypt(
    std::span<const uint8_t, 32> key,
    const AESEncrypted& encrypted,
    std::span<const uint8_t> aad = {});

// AES-256-CBC encrypt (for legacy wallet compatibility)
core::Result<std::vector<uint8_t>> aes256_cbc_encrypt(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 16> iv,
    std::span<const uint8_t> plaintext);

// AES-256-CBC decrypt (for legacy wallet compatibility)
core::Result<std::vector<uint8_t>> aes256_cbc_decrypt(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 16> iv,
    std::span<const uint8_t> ciphertext);

} // namespace crypto
