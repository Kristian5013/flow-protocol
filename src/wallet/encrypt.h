#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "crypto/secp256k1.h"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace wallet {

// Forward declarations.
class KeyManager;
class WalletDB;

// ---------------------------------------------------------------------------
// WalletEncrypt -- manages wallet passphrase encryption
// ---------------------------------------------------------------------------
// Uses PBKDF2-SHA256 with 100,000 iterations to derive a 256-bit key from
// the user's passphrase, then encrypts all private keys with AES-256-CBC.
//
// A random salt is generated and stored in the wallet database. The derived
// key is used both as the AES key and for verification (a test vector is
// encrypted and stored to verify the passphrase on unlock).
// ---------------------------------------------------------------------------

class WalletEncrypt {
public:
    /// Number of PBKDF2 iterations for key derivation.
    static constexpr int PBKDF2_ITERATIONS = 100000;

    /// Salt length in bytes.
    static constexpr size_t SALT_LENGTH = 32;

    WalletEncrypt() = default;

    /// Initialize with database reference.
    core::Result<void> init(WalletDB& db);

    // -- Encryption lifecycle -----------------------------------------------

    /// Encrypt the wallet with the given passphrase.
    /// Derives an encryption key using PBKDF2 and encrypts all keys.
    ///
    /// @param keys        The key manager holding the keys to encrypt.
    /// @param passphrase  The user-chosen passphrase.
    /// @returns Success or an error.
    core::Result<void> encrypt(KeyManager& keys,
                                std::string_view passphrase);

    /// Change the wallet passphrase.
    /// Decrypts all keys with the old passphrase, then re-encrypts with
    /// the new one.
    ///
    /// @param keys          The key manager.
    /// @param old_passphrase  The current passphrase.
    /// @param new_passphrase  The new passphrase.
    /// @returns Success or an error.
    core::Result<void> change_passphrase(KeyManager& keys,
                                          std::string_view old_passphrase,
                                          std::string_view new_passphrase);

    // -- Key-level encryption/decryption ------------------------------------

    /// Decrypt a single encrypted key using the given passphrase.
    core::Result<crypto::ECKey> decrypt_key(
        std::span<const uint8_t> encrypted_key,
        std::string_view passphrase) const;

    /// Encrypt a single key using the given passphrase.
    core::Result<std::vector<uint8_t>> encrypt_key(
        const crypto::ECKey& key,
        std::string_view passphrase) const;

    // -- Passphrase verification --------------------------------------------

    /// Verify that the given passphrase is correct by checking the stored
    /// test vector.
    core::Result<bool> verify_passphrase(
        std::string_view passphrase) const;

    /// Derive the master encryption key from a passphrase and salt.
    core::Result<std::array<uint8_t, 32>> derive_key(
        std::string_view passphrase,
        std::span<const uint8_t> salt) const;

    // -- State queries ------------------------------------------------------

    /// Returns true if the wallet has been encrypted.
    [[nodiscard]] bool is_encrypted() const;

    /// Get the stored salt (if encrypted).
    [[nodiscard]] const std::vector<uint8_t>& salt() const { return salt_; }

private:
    WalletDB* db_ = nullptr;
    std::vector<uint8_t> salt_;
    std::vector<uint8_t> test_vector_;  // encrypted verification data
    bool encrypted_ = false;

    /// Store encryption metadata (salt, test vector) in the database.
    core::Result<void> store_metadata();

    /// Load encryption metadata from the database.
    core::Result<void> load_metadata();

    /// PBKDF2-SHA256 key derivation using OpenSSL EVP.
    static core::Result<std::array<uint8_t, 32>> pbkdf2_derive(
        std::string_view passphrase,
        std::span<const uint8_t> salt,
        int iterations);
};

} // namespace wallet
