#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "core/types.h"
#include "crypto/secp256k1.h"
#include "wallet/walletdb.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace wallet {

// ---------------------------------------------------------------------------
// KeyManager -- manages private keys and address derivation
// ---------------------------------------------------------------------------
// Stores keys encrypted in the wallet database. When the wallet is locked,
// keys cannot be accessed for signing. When unlocked, they are decrypted
// using the passphrase-derived master key (AES-256-CBC).
//
// WIF encoding uses version byte 0x80 for mainnet, with a compression flag
// byte appended before base58check encoding.
// ---------------------------------------------------------------------------

class KeyManager {
public:
    /// WIF version byte for FTC mainnet.
    static constexpr uint8_t WIF_VERSION = 0x80;

    KeyManager() = default;

    /// Initialize the key manager with a wallet database reference.
    /// Loads all stored keys into memory.
    core::Result<void> init(WalletDB& db);

    // -- Key generation and import ------------------------------------------

    /// Generate a new random key and store it. Returns the address.
    core::Result<std::string> generate_key();

    /// Import a key from WIF (Wallet Import Format).
    /// Returns the address corresponding to the imported key.
    core::Result<std::string> import_key(std::string_view wif);

    /// Export a key as WIF given its address.
    core::Result<std::string> export_key(const std::string& address) const;

    // -- Key access ---------------------------------------------------------

    /// Retrieve the ECKey for a given address. The wallet must be unlocked
    /// if encryption is enabled.
    core::Result<crypto::ECKey> get_key(const std::string& address) const;

    /// Retrieve the ECKey for a given pubkey hash.
    core::Result<crypto::ECKey> get_key_by_hash(
        const core::uint160& pubkey_hash) const;

    /// Check if we have the key for a given address.
    [[nodiscard]] bool has_key(const std::string& address) const;

    /// Check if we have the key for a given pubkey hash.
    [[nodiscard]] bool has_key_for_hash(const core::uint160& pubkey_hash) const;

    /// Get all addresses managed by this key manager.
    [[nodiscard]] std::vector<std::string> get_all_addresses() const;

    /// Get the pubkey hash for a given address string.
    core::Result<core::uint160> get_pubkey_hash(
        const std::string& address) const;

    // -- Signing ------------------------------------------------------------

    /// Sign a hash with the key corresponding to the given address.
    core::Result<std::vector<uint8_t>> sign(const std::string& address,
                                             const core::uint256& hash) const;

    /// Sign a hash with the key corresponding to the given pubkey hash.
    core::Result<std::vector<uint8_t>> sign_with_hash(
        const core::uint160& pubkey_hash,
        const core::uint256& hash) const;

    // -- Encryption ---------------------------------------------------------

    /// Set the encryption key derived from the wallet passphrase.
    /// When set, all keys are encrypted/decrypted using this key.
    void set_encryption_key(const std::array<uint8_t, 32>& master_key);

    /// Clear the encryption key (lock the wallet).
    void clear_encryption_key();

    /// Returns true if an encryption key is currently set (wallet unlocked).
    [[nodiscard]] bool is_unlocked() const;

    /// Returns true if the wallet has encrypted keys.
    [[nodiscard]] bool is_encrypted() const;

    /// Encrypt all currently unencrypted keys with the given master key.
    core::Result<void> encrypt_all_keys(
        const std::array<uint8_t, 32>& master_key);

    // -- Persistence helpers ------------------------------------------------

    /// Get the number of keys in the key manager.
    [[nodiscard]] size_t key_count() const;

    /// Encode a 32-byte secret into WIF format.
    static std::string encode_wif(
        const std::array<uint8_t, 32>& secret);

    /// Decode a WIF string into a 32-byte secret.
    static core::Result<std::array<uint8_t, 32>> decode_wif(
        std::string_view wif);

private:
    mutable std::mutex mutex_;
    WalletDB* db_ = nullptr;
    bool encrypted_ = false;

    /// Currently active encryption key (empty when locked).
    std::array<uint8_t, 32> encryption_key_{};
    bool has_encryption_key_ = false;

    /// In-memory key storage.
    /// Maps address string -> 32-byte secret (cleartext when unencrypted,
    /// encrypted bytes when wallet is encrypted).
    struct KeyEntry {
        std::array<uint8_t, 32> secret;     // raw secret or encrypted data
        std::array<uint8_t, 33> pubkey;      // compressed public key
        core::uint160 pubkey_hash;           // HASH160 of compressed pubkey
        std::string address;                 // encoded address string
        bool is_encrypted = false;
    };

    std::vector<KeyEntry> keys_;

    /// Maps address -> index into keys_.
    std::unordered_map<std::string, size_t> addr_to_index_;

    /// Maps pubkey_hash -> index into keys_.
    std::unordered_map<core::uint160, size_t> hash_to_index_;

    /// Store a key entry to the database.
    core::Result<void> store_key(const KeyEntry& entry);

    /// Load all keys from the database.
    core::Result<void> load_keys();

    /// Derive the address string from a compressed public key.
    static std::string pubkey_to_address(
        const std::array<uint8_t, 33>& pubkey);

    /// Compute HASH160 of a compressed public key.
    static core::uint160 compute_pubkey_hash(
        const std::array<uint8_t, 33>& pubkey);

    /// Decrypt a key entry using the current encryption key.
    core::Result<std::array<uint8_t, 32>> decrypt_secret(
        const KeyEntry& entry) const;
};

} // namespace wallet
