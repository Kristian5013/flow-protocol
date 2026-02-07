#include "crypto/chacha20.h"

#include <cstring>
#include <memory>
#include <stdexcept>

#include <openssl/evp.h>

#include "core/random.h"

namespace crypto {

namespace {

// RAII wrapper for EVP_CIPHER_CTX
struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
};
using CipherCtxPtr =
    std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

CipherCtxPtr make_cipher_ctx() {
    return CipherCtxPtr(EVP_CIPHER_CTX_new());
}

// Build the 16-byte IV for raw ChaCha20 from counter and IV.
// OpenSSL's EVP_chacha20 expects a 16-byte IV structured as:
//   bytes [0..3]  = 32-bit counter (little-endian)
//   bytes [4..11] = 64-bit IV / nonce (little-endian)
// We split our 64-bit counter: low 32 bits as the block counter,
// and store the 64-bit iv_ in the nonce portion.
void build_chacha20_iv(uint64_t counter, uint64_t iv,
                       uint8_t out[16]) {
    std::memset(out, 0, 16);

    // Block counter in first 4 bytes (little-endian)
    auto ctr32 = static_cast<uint32_t>(counter);
    out[0] = static_cast<uint8_t>(ctr32);
    out[1] = static_cast<uint8_t>(ctr32 >> 8);
    out[2] = static_cast<uint8_t>(ctr32 >> 16);
    out[3] = static_cast<uint8_t>(ctr32 >> 24);

    // 64-bit IV / nonce in bytes [4..11] (little-endian)
    out[4]  = static_cast<uint8_t>(iv);
    out[5]  = static_cast<uint8_t>(iv >> 8);
    out[6]  = static_cast<uint8_t>(iv >> 16);
    out[7]  = static_cast<uint8_t>(iv >> 24);
    out[8]  = static_cast<uint8_t>(iv >> 32);
    out[9]  = static_cast<uint8_t>(iv >> 40);
    out[10] = static_cast<uint8_t>(iv >> 48);
    out[11] = static_cast<uint8_t>(iv >> 56);
}

} // namespace

// -----------------------------------------------------------
// ChaCha20-Poly1305 AEAD
// -----------------------------------------------------------

core::Result<ChaCha20Encrypted> chacha20_poly1305_encrypt(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad) {

    ChaCha20Encrypted result;

    // Generate random 96-bit nonce
    core::get_random_bytes(
        {result.nonce.data(), result.nonce.size()});

    auto ctx = make_cipher_ctx();
    if (!ctx) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "failed to create cipher context");
    }

    if (EVP_EncryptInit_ex(
            ctx.get(), EVP_chacha20_poly1305(),
            nullptr, nullptr, nullptr) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_EncryptInit_ex failed for "
            "ChaCha20-Poly1305");
    }

    // Set nonce length to 12 bytes (default, but explicit)
    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
            static_cast<int>(result.nonce.size()),
            nullptr) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "failed to set nonce length");
    }

    // Initialize key and nonce
    if (EVP_EncryptInit_ex(
            ctx.get(), nullptr, nullptr,
            key.data(), result.nonce.data()) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_EncryptInit_ex key/nonce failed");
    }

    // Process AAD if provided
    if (!aad.empty()) {
        int aad_len = 0;
        if (EVP_EncryptUpdate(
                ctx.get(), nullptr, &aad_len,
                aad.data(),
                static_cast<int>(aad.size())) != 1) {
            return core::Error(core::ErrorCode::CRYPTO_ERROR,
                "EVP_EncryptUpdate AAD failed");
        }
    }

    // Encrypt plaintext
    result.ciphertext.resize(plaintext.size());
    int out_len = 0;
    if (EVP_EncryptUpdate(
            ctx.get(), result.ciphertext.data(), &out_len,
            plaintext.data(),
            static_cast<int>(plaintext.size())) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_EncryptUpdate plaintext failed");
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(
            ctx.get(),
            result.ciphertext.data() + out_len,
            &final_len) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_EncryptFinal_ex failed");
    }
    result.ciphertext.resize(
        static_cast<size_t>(out_len + final_len));

    // Retrieve Poly1305 authentication tag
    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(), EVP_CTRL_AEAD_GET_TAG,
            static_cast<int>(result.tag.size()),
            result.tag.data()) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "failed to get Poly1305 tag");
    }

    return std::move(result);
}

core::Result<std::vector<uint8_t>> chacha20_poly1305_decrypt(
    std::span<const uint8_t, 32> key,
    const ChaCha20Encrypted& encrypted,
    std::span<const uint8_t> aad) {

    auto ctx = make_cipher_ctx();
    if (!ctx) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "failed to create cipher context");
    }

    if (EVP_DecryptInit_ex(
            ctx.get(), EVP_chacha20_poly1305(),
            nullptr, nullptr, nullptr) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_DecryptInit_ex failed for "
            "ChaCha20-Poly1305");
    }

    // Set nonce length
    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
            static_cast<int>(encrypted.nonce.size()),
            nullptr) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "failed to set nonce length");
    }

    // Initialize key and nonce
    if (EVP_DecryptInit_ex(
            ctx.get(), nullptr, nullptr,
            key.data(), encrypted.nonce.data()) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_DecryptInit_ex key/nonce failed");
    }

    // Process AAD if provided
    if (!aad.empty()) {
        int aad_len = 0;
        if (EVP_DecryptUpdate(
                ctx.get(), nullptr, &aad_len,
                aad.data(),
                static_cast<int>(aad.size())) != 1) {
            return core::Error(core::ErrorCode::CRYPTO_ERROR,
                "EVP_DecryptUpdate AAD failed");
        }
    }

    // Decrypt ciphertext
    std::vector<uint8_t> plaintext(
        encrypted.ciphertext.size());
    int out_len = 0;
    if (EVP_DecryptUpdate(
            ctx.get(), plaintext.data(), &out_len,
            encrypted.ciphertext.data(),
            static_cast<int>(
                encrypted.ciphertext.size())) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_DecryptUpdate ciphertext failed");
    }

    // Set expected authentication tag before finalization
    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(), EVP_CTRL_AEAD_SET_TAG,
            static_cast<int>(encrypted.tag.size()),
            const_cast<uint8_t*>(
                encrypted.tag.data())) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "failed to set expected Poly1305 tag");
    }

    // Finalize -- this verifies the tag
    int final_len = 0;
    if (EVP_DecryptFinal_ex(
            ctx.get(), plaintext.data() + out_len,
            &final_len) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "ChaCha20-Poly1305 authentication failed");
    }
    plaintext.resize(
        static_cast<size_t>(out_len + final_len));

    return std::move(plaintext);
}

// -----------------------------------------------------------
// Raw ChaCha20 stream cipher
// -----------------------------------------------------------

ChaCha20::ChaCha20(std::span<const uint8_t, 32> key,
                   uint64_t counter)
    : counter_(counter) {
    std::memcpy(key_.data(), key.data(), 32);
}

void ChaCha20::set_counter(uint64_t counter) {
    counter_ = counter;
}

void ChaCha20::set_iv(uint64_t iv) {
    iv_ = iv;
}

void ChaCha20::encrypt(std::span<const uint8_t> input,
                       std::span<uint8_t> output) {
    if (input.size() != output.size()) {
        throw std::invalid_argument(
            "ChaCha20::encrypt: input and output sizes "
            "must match");
    }
    if (input.empty()) {
        return;
    }

    auto ctx = make_cipher_ctx();
    if (!ctx) {
        throw std::runtime_error(
            "failed to create cipher context");
    }

    // Build the 16-byte IV for OpenSSL's EVP_chacha20
    uint8_t full_iv[16];
    build_chacha20_iv(counter_, iv_, full_iv);

    if (EVP_EncryptInit_ex(
            ctx.get(), EVP_chacha20(),
            nullptr, key_.data(), full_iv) != 1) {
        throw std::runtime_error(
            "EVP_EncryptInit_ex failed for ChaCha20");
    }

    int out_len = 0;
    if (EVP_EncryptUpdate(
            ctx.get(), output.data(), &out_len,
            input.data(),
            static_cast<int>(input.size())) != 1) {
        throw std::runtime_error(
            "EVP_EncryptUpdate failed for ChaCha20");
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(
            ctx.get(), output.data() + out_len,
            &final_len) != 1) {
        throw std::runtime_error(
            "EVP_EncryptFinal_ex failed for ChaCha20");
    }

    // Advance the block counter by the number of 64-byte
    // blocks consumed
    size_t bytes_processed =
        static_cast<size_t>(out_len + final_len);
    counter_ += (bytes_processed + 63) / 64;
}

void ChaCha20::decrypt(std::span<const uint8_t> input,
                       std::span<uint8_t> output) {
    // ChaCha20 is a symmetric stream cipher; encryption
    // and decryption are the same XOR operation.
    encrypt(input, output);
}

void ChaCha20::keystream(std::span<uint8_t> output) {
    // Generate keystream by encrypting zeros
    std::vector<uint8_t> zeros(output.size(), 0);
    encrypt(
        std::span<const uint8_t>(zeros.data(), zeros.size()),
        output);
}

} // namespace crypto
