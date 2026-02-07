// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/encrypt.h"
#include "core/logging.h"
#include "core/random.h"
#include "crypto/aes.h"
#include "wallet/keys.h"
#include "wallet/walletdb.h"

#include <openssl/evp.h>
#include <openssl/err.h>

#include <algorithm>
#include <cstring>

namespace wallet {

// Known plaintext used as a test vector for passphrase verification.
static constexpr uint8_t TEST_PLAINTEXT[32] = {
    0x46, 0x54, 0x43, 0x20, 0x57, 0x41, 0x4C, 0x4C,  // "FTC WALL"
    0x45, 0x54, 0x20, 0x54, 0x45, 0x53, 0x54, 0x20,  // "ET TEST "
    0x56, 0x45, 0x43, 0x54, 0x4F, 0x52, 0x20, 0x56,  // "VECTOR V"
    0x45, 0x52, 0x49, 0x46, 0x59, 0x20, 0x4F, 0x4B,  // "ERIFY OK"
};

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

core::Result<void> WalletEncrypt::init(WalletDB& db) {
    db_ = &db;
    auto result = load_metadata();
    if (!result.ok()) {
        // If there's no encryption metadata, that's fine -- wallet is not encrypted.
        encrypted_ = false;
    }
    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// Encryption lifecycle
// ---------------------------------------------------------------------------

core::Result<void> WalletEncrypt::encrypt(KeyManager& keys,
                                            std::string_view passphrase) {
    if (!db_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "WalletEncrypt not initialized");
    }

    if (encrypted_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Wallet is already encrypted");
    }

    if (passphrase.empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "Passphrase must not be empty");
    }

    // Generate a random salt.
    salt_.resize(SALT_LENGTH);
    core::get_random_bytes(std::span<uint8_t>(salt_.data(), salt_.size()));

    // Derive the master key.
    auto key_result = derive_key(passphrase, std::span<const uint8_t>(salt_));
    if (!key_result.ok()) {
        return key_result.error();
    }

    auto master_key = key_result.value();

    // Create and store the test vector.
    std::array<uint8_t, 16> test_iv{};
    core::get_random_bytes(std::span<uint8_t>(test_iv.data(), test_iv.size()));

    auto test_enc_result = crypto::aes256_cbc_encrypt(
        std::span<const uint8_t, 32>(master_key),
        std::span<const uint8_t, 16>(test_iv),
        std::span<const uint8_t>(TEST_PLAINTEXT, 32));

    if (!test_enc_result.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
                           "Failed to create test vector: " +
                           test_enc_result.error().message());
    }

    // Store IV + ciphertext as the test vector.
    test_vector_.clear();
    test_vector_.insert(test_vector_.end(), test_iv.begin(), test_iv.end());
    test_vector_.insert(test_vector_.end(),
                        test_enc_result.value().begin(),
                        test_enc_result.value().end());

    // Encrypt all keys in the key manager.
    auto enc_result = keys.encrypt_all_keys(master_key);
    if (!enc_result.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
                           "Failed to encrypt keys: " +
                           enc_result.error().message());
    }

    encrypted_ = true;

    // Persist encryption metadata.
    auto store_result = store_metadata();
    if (!store_result.ok()) {
        return store_result;
    }

    // Clear the master key from memory.
    std::memset(master_key.data(), 0, master_key.size());

    LOG_INFO(core::LogCategory::WALLET, "Wallet encrypted successfully");
    return core::Result<void>{};
}

core::Result<void> WalletEncrypt::change_passphrase(
    KeyManager& keys,
    std::string_view old_passphrase,
    std::string_view new_passphrase) {

    if (!encrypted_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Wallet is not encrypted");
    }

    if (new_passphrase.empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "New passphrase must not be empty");
    }

    // Verify old passphrase.
    auto verify_result = verify_passphrase(old_passphrase);
    if (!verify_result.ok()) {
        return verify_result.error();
    }
    if (!verify_result.value()) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Incorrect passphrase");
    }

    // Derive old master key to unlock keys.
    auto old_key_result = derive_key(old_passphrase,
        std::span<const uint8_t>(salt_));
    if (!old_key_result.ok()) {
        return old_key_result.error();
    }
    auto old_master_key = old_key_result.value();

    // Set the old encryption key so we can decrypt.
    keys.set_encryption_key(old_master_key);

    // Export all keys while decrypted.
    auto addresses = keys.get_all_addresses();
    std::vector<std::pair<std::string, crypto::ECKey>> decrypted_keys;
    for (const auto& addr : addresses) {
        auto key_result = keys.get_key(addr);
        if (!key_result.ok()) {
            keys.clear_encryption_key();
            return core::Error(core::ErrorCode::CRYPTO_ERROR,
                               "Failed to decrypt key for re-encryption: " +
                               key_result.error().message());
        }
        decrypted_keys.emplace_back(addr, std::move(key_result).value());
    }

    // Generate new salt and derive new master key.
    salt_.resize(SALT_LENGTH);
    core::get_random_bytes(std::span<uint8_t>(salt_.data(), salt_.size()));

    auto new_key_result = derive_key(new_passphrase,
        std::span<const uint8_t>(salt_));
    if (!new_key_result.ok()) {
        keys.clear_encryption_key();
        return new_key_result.error();
    }
    auto new_master_key = new_key_result.value();

    // Create new test vector.
    std::array<uint8_t, 16> test_iv{};
    core::get_random_bytes(std::span<uint8_t>(test_iv.data(), test_iv.size()));

    auto test_enc_result = crypto::aes256_cbc_encrypt(
        std::span<const uint8_t, 32>(new_master_key),
        std::span<const uint8_t, 16>(test_iv),
        std::span<const uint8_t>(TEST_PLAINTEXT, 32));

    if (!test_enc_result.ok()) {
        keys.clear_encryption_key();
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
                           "Failed to create new test vector");
    }

    test_vector_.clear();
    test_vector_.insert(test_vector_.end(), test_iv.begin(), test_iv.end());
    test_vector_.insert(test_vector_.end(),
                        test_enc_result.value().begin(),
                        test_enc_result.value().end());

    // Re-encrypt all keys with the new master key.
    auto reenc_result = keys.encrypt_all_keys(new_master_key);
    if (!reenc_result.ok()) {
        keys.clear_encryption_key();
        return reenc_result;
    }

    // Update encryption key to the new one.
    keys.set_encryption_key(new_master_key);

    // Persist updated metadata.
    auto store_result = store_metadata();
    if (!store_result.ok()) {
        return store_result;
    }

    // Clear keys from memory.
    std::memset(old_master_key.data(), 0, old_master_key.size());
    std::memset(new_master_key.data(), 0, new_master_key.size());

    LOG_INFO(core::LogCategory::WALLET, "Wallet passphrase changed successfully");
    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// Key-level encryption/decryption
// ---------------------------------------------------------------------------

core::Result<crypto::ECKey> WalletEncrypt::decrypt_key(
    std::span<const uint8_t> encrypted_key,
    std::string_view passphrase) const {

    if (salt_.empty()) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "No encryption salt available");
    }

    auto key_result = derive_key(passphrase,
        std::span<const uint8_t>(salt_));
    if (!key_result.ok()) {
        return key_result.error();
    }

    auto master_key = key_result.value();

    // Encrypted key format: IV(16) + ciphertext.
    if (encrypted_key.size() < 32) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Encrypted key data too short");
    }

    std::array<uint8_t, 16> iv{};
    std::copy(encrypted_key.begin(), encrypted_key.begin() + 16, iv.begin());

    auto ciphertext = encrypted_key.subspan(16);

    auto dec_result = crypto::aes256_cbc_decrypt(
        std::span<const uint8_t, 32>(master_key),
        std::span<const uint8_t, 16>(iv),
        ciphertext);

    std::memset(master_key.data(), 0, master_key.size());

    if (!dec_result.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
                           "Failed to decrypt key: " +
                           dec_result.error().message());
    }

    const auto& plaintext = dec_result.value();
    if (plaintext.size() < 32) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Decrypted key too short");
    }

    std::array<uint8_t, 32> secret{};
    std::copy(plaintext.begin(), plaintext.begin() + 32, secret.begin());

    auto ec_result = crypto::ECKey::from_secret(
        std::span<const uint8_t, 32>(secret));
    std::memset(secret.data(), 0, secret.size());

    if (!ec_result.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_KEY_FAIL,
                           "Decrypted secret is not a valid key");
    }

    return std::move(ec_result).value();
}

core::Result<std::vector<uint8_t>> WalletEncrypt::encrypt_key(
    const crypto::ECKey& key,
    std::string_view passphrase) const {

    if (salt_.empty()) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "No encryption salt available");
    }

    auto master_result = derive_key(passphrase,
        std::span<const uint8_t>(salt_));
    if (!master_result.ok()) {
        return master_result.error();
    }

    auto master_key = master_result.value();
    auto secret = key.secret();

    // Generate random IV.
    std::array<uint8_t, 16> iv{};
    core::get_random_bytes(std::span<uint8_t>(iv.data(), iv.size()));

    auto enc_result = crypto::aes256_cbc_encrypt(
        std::span<const uint8_t, 32>(master_key),
        std::span<const uint8_t, 16>(iv),
        std::span<const uint8_t>(secret.data(), 32));

    std::memset(master_key.data(), 0, master_key.size());

    if (!enc_result.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
                           "Failed to encrypt key: " +
                           enc_result.error().message());
    }

    // Return IV + ciphertext.
    std::vector<uint8_t> result;
    result.reserve(16 + enc_result.value().size());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(),
                  enc_result.value().begin(),
                  enc_result.value().end());

    return result;
}

// ---------------------------------------------------------------------------
// Passphrase verification
// ---------------------------------------------------------------------------

core::Result<bool> WalletEncrypt::verify_passphrase(
    std::string_view passphrase) const {

    if (!encrypted_ || test_vector_.empty() || salt_.empty()) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Wallet is not encrypted");
    }

    auto key_result = derive_key(passphrase,
        std::span<const uint8_t>(salt_));
    if (!key_result.ok()) {
        return key_result.error();
    }

    auto master_key = key_result.value();

    // Decrypt the test vector.
    if (test_vector_.size() < 32) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Test vector too short");
    }

    std::array<uint8_t, 16> iv{};
    std::copy(test_vector_.begin(), test_vector_.begin() + 16, iv.begin());

    auto ciphertext = std::span<const uint8_t>(
        test_vector_.data() + 16, test_vector_.size() - 16);

    auto dec_result = crypto::aes256_cbc_decrypt(
        std::span<const uint8_t, 32>(master_key),
        std::span<const uint8_t, 16>(iv),
        ciphertext);

    std::memset(master_key.data(), 0, master_key.size());

    if (!dec_result.ok()) {
        // Decryption failed -- wrong passphrase or corrupt data.
        return false;
    }

    const auto& plaintext = dec_result.value();
    if (plaintext.size() < 32) {
        return false;
    }

    // Compare with known plaintext.
    bool match = (std::memcmp(plaintext.data(), TEST_PLAINTEXT, 32) == 0);
    return match;
}

core::Result<std::array<uint8_t, 32>> WalletEncrypt::derive_key(
    std::string_view passphrase,
    std::span<const uint8_t> salt) const {
    return pbkdf2_derive(passphrase, salt, PBKDF2_ITERATIONS);
}

// ---------------------------------------------------------------------------
// State queries
// ---------------------------------------------------------------------------

bool WalletEncrypt::is_encrypted() const {
    return encrypted_;
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

core::Result<void> WalletEncrypt::store_metadata() {
    if (!db_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "WalletEncrypt not initialized");
    }

    // Store salt.
    auto salt_result = db_->write("meta:enc_salt",
        std::span<const uint8_t>(salt_));
    if (!salt_result.ok()) return salt_result;

    // Store test vector.
    auto tv_result = db_->write("meta:enc_test",
        std::span<const uint8_t>(test_vector_));
    if (!tv_result.ok()) return tv_result;

    // Store encrypted flag.
    std::vector<uint8_t> flag_data = {1};
    return db_->write("meta:encrypted",
        std::span<const uint8_t>(flag_data));
}

core::Result<void> WalletEncrypt::load_metadata() {
    if (!db_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "WalletEncrypt not initialized");
    }

    // Check if wallet is encrypted.
    auto flag_result = db_->read("meta:encrypted");
    if (!flag_result.ok() || flag_result.value().empty() ||
        flag_result.value()[0] != 1) {
        encrypted_ = false;
        return core::Result<void>{};
    }

    // Load salt.
    auto salt_result = db_->read("meta:enc_salt");
    if (!salt_result.ok()) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Cannot read encryption salt");
    }
    salt_ = salt_result.value();

    // Load test vector.
    auto tv_result = db_->read("meta:enc_test");
    if (!tv_result.ok()) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Cannot read encryption test vector");
    }
    test_vector_ = tv_result.value();

    encrypted_ = true;
    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// PBKDF2 key derivation
// ---------------------------------------------------------------------------

core::Result<std::array<uint8_t, 32>> WalletEncrypt::pbkdf2_derive(
    std::string_view passphrase,
    std::span<const uint8_t> salt,
    int iterations) {

    std::array<uint8_t, 32> derived_key{};

    int result = PKCS5_PBKDF2_HMAC(
        passphrase.data(),
        static_cast<int>(passphrase.size()),
        salt.data(),
        static_cast<int>(salt.size()),
        iterations,
        EVP_sha256(),
        static_cast<int>(derived_key.size()),
        derived_key.data());

    if (result != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
                           std::string("PBKDF2 derivation failed: ") +
                           err_buf);
    }

    return derived_key;
}

} // namespace wallet
