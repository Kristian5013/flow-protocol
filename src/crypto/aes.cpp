#include "crypto/aes.h"

#include <cstring>
#include <memory>

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

// Apply PKCS#7 padding to plaintext for CBC mode
std::vector<uint8_t> pkcs7_pad(std::span<const uint8_t> data,
                               size_t block_size) {
    size_t padding_len = block_size - (data.size() % block_size);
    std::vector<uint8_t> padded(data.size() + padding_len);
    std::memcpy(padded.data(), data.data(), data.size());
    std::memset(
        padded.data() + data.size(),
        static_cast<uint8_t>(padding_len),
        padding_len);
    return padded;
}

// Remove PKCS#7 padding; returns empty on invalid padding
core::Result<std::vector<uint8_t>> pkcs7_unpad(
    std::span<const uint8_t> data, size_t block_size) {
    if (data.empty() || data.size() % block_size != 0) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "invalid ciphertext length for CBC");
    }

    uint8_t padding_len = data.back();
    if (padding_len == 0 || padding_len > block_size) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "invalid PKCS#7 padding value");
    }

    // Verify all padding bytes are correct
    // (constant-time comparison to avoid timing attacks)
    uint8_t check = 0;
    for (size_t i = data.size() - padding_len;
         i < data.size(); ++i) {
        check |= (data[i] ^ padding_len);
    }
    if (check != 0) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "invalid PKCS#7 padding");
    }

    size_t unpadded_len = data.size() - padding_len;
    return std::vector<uint8_t>(data.begin(), data.begin() + unpadded_len);
}

} // namespace

// -----------------------------------------------------------
// AES-256-GCM
// -----------------------------------------------------------

core::Result<AESEncrypted> aes256_gcm_encrypt(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad) {

    AESEncrypted result;

    // Generate random 96-bit IV
    core::get_random_bytes({result.iv.data(), result.iv.size()});

    auto ctx = make_cipher_ctx();
    if (!ctx) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "failed to create cipher context");
    }

    if (EVP_EncryptInit_ex(
            ctx.get(), EVP_aes_256_gcm(),
            nullptr, nullptr, nullptr) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_EncryptInit_ex failed for GCM");
    }

    // Set IV length to 12 bytes
    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
            static_cast<int>(result.iv.size()),
            nullptr) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "failed to set GCM IV length");
    }

    // Initialize key and IV
    if (EVP_EncryptInit_ex(
            ctx.get(), nullptr, nullptr,
            key.data(), result.iv.data()) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_EncryptInit_ex key/IV failed");
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

    // Retrieve GCM authentication tag
    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(), EVP_CTRL_GCM_GET_TAG,
            static_cast<int>(result.tag.size()),
            result.tag.data()) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "failed to get GCM tag");
    }

    return result;
}

core::Result<std::vector<uint8_t>> aes256_gcm_decrypt(
    std::span<const uint8_t, 32> key,
    const AESEncrypted& encrypted,
    std::span<const uint8_t> aad) {

    auto ctx = make_cipher_ctx();
    if (!ctx) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "failed to create cipher context");
    }

    if (EVP_DecryptInit_ex(
            ctx.get(), EVP_aes_256_gcm(),
            nullptr, nullptr, nullptr) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_DecryptInit_ex failed for GCM");
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
            static_cast<int>(encrypted.iv.size()),
            nullptr) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "failed to set GCM IV length");
    }

    // Initialize key and IV
    if (EVP_DecryptInit_ex(
            ctx.get(), nullptr, nullptr,
            key.data(), encrypted.iv.data()) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_DecryptInit_ex key/IV failed");
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
    std::vector<uint8_t> plaintext(encrypted.ciphertext.size());
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
            ctx.get(), EVP_CTRL_GCM_SET_TAG,
            static_cast<int>(encrypted.tag.size()),
            const_cast<uint8_t*>(
                encrypted.tag.data())) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "failed to set GCM expected tag");
    }

    // Finalize -- this verifies the tag
    int final_len = 0;
    if (EVP_DecryptFinal_ex(
            ctx.get(), plaintext.data() + out_len,
            &final_len) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "GCM authentication failed");
    }
    plaintext.resize(
        static_cast<size_t>(out_len + final_len));

    return plaintext;
}

// -----------------------------------------------------------
// AES-256-CBC (legacy wallet compatibility)
// -----------------------------------------------------------

core::Result<std::vector<uint8_t>> aes256_cbc_encrypt(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 16> iv,
    std::span<const uint8_t> plaintext) {

    auto ctx = make_cipher_ctx();
    if (!ctx) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "failed to create cipher context");
    }

    // We handle PKCS#7 padding ourselves for full control
    if (EVP_EncryptInit_ex(
            ctx.get(), EVP_aes_256_cbc(),
            nullptr, key.data(), iv.data()) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_EncryptInit_ex failed for CBC");
    }

    // Disable OpenSSL's internal padding; we do PKCS#7 manually
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);

    constexpr size_t BLOCK_SIZE = 16;
    auto padded = pkcs7_pad(plaintext, BLOCK_SIZE);

    std::vector<uint8_t> ciphertext(padded.size());
    int out_len = 0;
    if (EVP_EncryptUpdate(
            ctx.get(), ciphertext.data(), &out_len,
            padded.data(),
            static_cast<int>(padded.size())) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_EncryptUpdate failed for CBC");
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(
            ctx.get(), ciphertext.data() + out_len,
            &final_len) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_EncryptFinal_ex failed for CBC");
    }
    ciphertext.resize(
        static_cast<size_t>(out_len + final_len));

    return ciphertext;
}

core::Result<std::vector<uint8_t>> aes256_cbc_decrypt(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 16> iv,
    std::span<const uint8_t> ciphertext) {

    constexpr size_t BLOCK_SIZE = 16;
    if (ciphertext.empty() ||
        ciphertext.size() % BLOCK_SIZE != 0) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "ciphertext length must be a multiple of 16");
    }

    auto ctx = make_cipher_ctx();
    if (!ctx) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "failed to create cipher context");
    }

    if (EVP_DecryptInit_ex(
            ctx.get(), EVP_aes_256_cbc(),
            nullptr, key.data(), iv.data()) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_DecryptInit_ex failed for CBC");
    }

    // Disable OpenSSL's internal padding; we unpad manually
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);

    std::vector<uint8_t> decrypted(ciphertext.size());
    int out_len = 0;
    if (EVP_DecryptUpdate(
            ctx.get(), decrypted.data(), &out_len,
            ciphertext.data(),
            static_cast<int>(ciphertext.size())) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_DecryptUpdate failed for CBC");
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(
            ctx.get(), decrypted.data() + out_len,
            &final_len) != 1) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
            "EVP_DecryptFinal_ex failed for CBC");
    }
    decrypted.resize(
        static_cast<size_t>(out_len + final_len));

    // Remove and validate PKCS#7 padding
    return pkcs7_unpad(decrypted, BLOCK_SIZE);
}

} // namespace crypto
