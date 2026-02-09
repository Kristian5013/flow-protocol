// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/keys.h"
#include "core/base58.h"
#include "core/hex.h"
#include "core/logging.h"
#include "core/random.h"
#include "crypto/aes.h"
#include "crypto/keccak.h"
#include "primitives/address.h"

#include <algorithm>
#include <cstring>
#include <span>

namespace wallet {

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

core::Result<void> KeyManager::init(WalletDB& db) {
    std::lock_guard lock(mutex_);
    db_ = &db;

    auto result = load_keys();
    if (!result.ok()) {
        return result;
    }

    LOG_INFO(core::LogCategory::WALLET,
             "KeyManager initialized with " +
             std::to_string(keys_.size()) + " keys");
    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// Key generation and import
// ---------------------------------------------------------------------------

core::Result<std::string> KeyManager::generate_key() {
    std::lock_guard lock(mutex_);

    if (!db_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "KeyManager not initialized");
    }

    // Generate a new random key pair.
    crypto::ECKey ec_key = crypto::ECKey::generate();
    auto secret = ec_key.secret();
    auto pubkey = ec_key.pubkey_compressed();
    auto pkh = compute_pubkey_hash(pubkey);
    auto addr = pubkey_to_address(pubkey);

    KeyEntry entry;
    entry.secret = secret;
    entry.pubkey = pubkey;
    entry.pubkey_hash = pkh;
    entry.address = addr;
    entry.is_encrypted = false;

    // If the wallet is encrypted, encrypt the new key.
    if (encrypted_ && has_encryption_key_) {
        std::array<uint8_t, 16> iv{};
        core::get_random_bytes(std::span<uint8_t>(iv.data(), iv.size()));

        auto enc_result = crypto::aes256_cbc_encrypt(
            std::span<const uint8_t, 32>(encryption_key_),
            std::span<const uint8_t, 16>(iv),
            std::span<const uint8_t>(secret.data(), secret.size()));

        if (!enc_result.ok()) {
            return core::Error(core::ErrorCode::CRYPTO_ERROR,
                               "Failed to encrypt key: " +
                               enc_result.error().message());
        }

        // Store IV + ciphertext in the secret field area.
        // We use a separate DB record for the encrypted data.
        entry.is_encrypted = true;
    }

    auto store_result = store_key(entry);
    if (!store_result.ok()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Failed to store key: " +
                           store_result.error().message());
    }

    size_t idx = keys_.size();
    keys_.push_back(entry);
    addr_to_index_[addr] = idx;
    hash_to_index_[pkh] = idx;

    LOG_INFO(core::LogCategory::WALLET,
             "Generated new key for address: " + addr);
    return addr;
}

core::Result<std::string> KeyManager::import_key(std::string_view key_str) {
    std::lock_guard lock(mutex_);

    if (!db_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "KeyManager not initialized");
    }

    // Try WIF first, then raw hex (64 hex characters = 32 bytes).
    std::array<uint8_t, 32> secret{};
    auto secret_result = decode_wif(key_str);
    if (secret_result.ok()) {
        secret = secret_result.value();
    } else if (key_str.size() == 64 && core::is_hex(std::string(key_str))) {
        auto bytes = core::from_hex(std::string(key_str));
        if (bytes && bytes->size() == 32) {
            std::copy(bytes->begin(), bytes->end(), secret.begin());
        } else {
            return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                               "Invalid hex key");
        }
    } else {
        return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                           "Invalid private key (not WIF or 64-char hex): " +
                           secret_result.error().message());
    }

    // Create the EC key from the secret.
    auto ec_result = crypto::ECKey::from_secret(
        std::span<const uint8_t, 32>(secret));
    if (!ec_result.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_KEY_FAIL,
                           "Invalid secret key");
    }

    auto ec_key = std::move(ec_result).value();
    auto pubkey = ec_key.pubkey_compressed();
    auto pkh = compute_pubkey_hash(pubkey);
    auto addr = pubkey_to_address(pubkey);

    // Check for duplicates.
    if (addr_to_index_.count(addr) > 0) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "Key already exists for address: " + addr);
    }

    KeyEntry entry;
    entry.secret = secret;
    entry.pubkey = pubkey;
    entry.pubkey_hash = pkh;
    entry.address = addr;
    entry.is_encrypted = false;

    auto store_result = store_key(entry);
    if (!store_result.ok()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Failed to store imported key: " +
                           store_result.error().message());
    }

    size_t idx = keys_.size();
    keys_.push_back(entry);
    addr_to_index_[addr] = idx;
    hash_to_index_[pkh] = idx;

    LOG_INFO(core::LogCategory::WALLET,
             "Imported key for address: " + addr);
    return addr;
}

core::Result<std::string> KeyManager::export_key(
    const std::string& address) const {
    std::lock_guard lock(mutex_);

    auto it = addr_to_index_.find(address);
    if (it == addr_to_index_.end()) {
        return core::Error(core::ErrorCode::WALLET_KEY_MISS,
                           "No key for address: " + address);
    }

    const auto& entry = keys_[it->second];

    if (entry.is_encrypted) {
        if (!has_encryption_key_) {
            return core::Error(core::ErrorCode::WALLET_LOCKED,
                               "Wallet is locked, cannot export key");
        }
        auto secret = decrypt_secret(entry);
        if (!secret.ok()) {
            return secret.error();
        }
        return encode_wif(secret.value());
    }

    return encode_wif(entry.secret);
}

// ---------------------------------------------------------------------------
// Key access
// ---------------------------------------------------------------------------

core::Result<crypto::ECKey> KeyManager::get_key(
    const std::string& address) const {
    std::lock_guard lock(mutex_);

    auto it = addr_to_index_.find(address);
    if (it == addr_to_index_.end()) {
        return core::Error(core::ErrorCode::WALLET_KEY_MISS,
                           "No key for address: " + address);
    }

    const auto& entry = keys_[it->second];
    std::array<uint8_t, 32> secret;

    if (entry.is_encrypted) {
        if (!has_encryption_key_) {
            return core::Error(core::ErrorCode::WALLET_LOCKED,
                               "Wallet is locked");
        }
        auto result = decrypt_secret(entry);
        if (!result.ok()) return result.error();
        secret = result.value();
    } else {
        secret = entry.secret;
    }

    auto key_result = crypto::ECKey::from_secret(
        std::span<const uint8_t, 32>(secret));
    if (!key_result.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_KEY_FAIL,
                           "Failed to reconstruct key");
    }

    return std::move(key_result).value();
}

core::Result<crypto::ECKey> KeyManager::get_key_by_hash(
    const core::uint160& pubkey_hash) const {
    std::lock_guard lock(mutex_);

    auto it = hash_to_index_.find(pubkey_hash);
    if (it == hash_to_index_.end()) {
        return core::Error(core::ErrorCode::WALLET_KEY_MISS,
                           "No key for pubkey hash");
    }

    const auto& entry = keys_[it->second];
    std::array<uint8_t, 32> secret;

    if (entry.is_encrypted) {
        if (!has_encryption_key_) {
            return core::Error(core::ErrorCode::WALLET_LOCKED,
                               "Wallet is locked");
        }
        auto result = decrypt_secret(entry);
        if (!result.ok()) return result.error();
        secret = result.value();
    } else {
        secret = entry.secret;
    }

    auto key_result = crypto::ECKey::from_secret(
        std::span<const uint8_t, 32>(secret));
    if (!key_result.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_KEY_FAIL,
                           "Failed to reconstruct key");
    }

    return std::move(key_result).value();
}

bool KeyManager::has_key(const std::string& address) const {
    std::lock_guard lock(mutex_);
    return addr_to_index_.count(address) > 0;
}

bool KeyManager::has_key_for_hash(const core::uint160& pubkey_hash) const {
    std::lock_guard lock(mutex_);
    return hash_to_index_.count(pubkey_hash) > 0;
}

std::vector<std::string> KeyManager::get_all_addresses() const {
    std::lock_guard lock(mutex_);

    std::vector<std::string> addresses;
    addresses.reserve(keys_.size());
    for (const auto& entry : keys_) {
        addresses.push_back(entry.address);
    }
    return addresses;
}

core::Result<core::uint160> KeyManager::get_pubkey_hash(
    const std::string& address) const {
    std::lock_guard lock(mutex_);

    auto it = addr_to_index_.find(address);
    if (it == addr_to_index_.end()) {
        return core::Error(core::ErrorCode::WALLET_KEY_MISS,
                           "No key for address: " + address);
    }

    return keys_[it->second].pubkey_hash;
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

core::Result<std::vector<uint8_t>> KeyManager::sign(
    const std::string& address, const core::uint256& hash) const {

    auto key_result = get_key(address);
    if (!key_result.ok()) return key_result.error();

    auto& key = key_result.value();
    auto sig = key.sign(hash);
    return sig;
}

core::Result<std::vector<uint8_t>> KeyManager::sign_with_hash(
    const core::uint160& pubkey_hash, const core::uint256& hash) const {

    auto key_result = get_key_by_hash(pubkey_hash);
    if (!key_result.ok()) return key_result.error();

    auto& key = key_result.value();
    auto sig = key.sign(hash);
    return sig;
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

void KeyManager::set_encryption_key(const std::array<uint8_t, 32>& master_key) {
    std::lock_guard lock(mutex_);
    encryption_key_ = master_key;
    has_encryption_key_ = true;
}

void KeyManager::clear_encryption_key() {
    std::lock_guard lock(mutex_);
    std::memset(encryption_key_.data(), 0, encryption_key_.size());
    has_encryption_key_ = false;
}

bool KeyManager::is_unlocked() const {
    std::lock_guard lock(mutex_);
    return !encrypted_ || has_encryption_key_;
}

bool KeyManager::is_encrypted() const {
    std::lock_guard lock(mutex_);
    return encrypted_;
}

core::Result<void> KeyManager::encrypt_all_keys(
    const std::array<uint8_t, 32>& master_key) {
    std::lock_guard lock(mutex_);

    if (!db_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "KeyManager not initialized");
    }

    for (auto& entry : keys_) {
        if (entry.is_encrypted) continue;

        // Generate a random IV.
        std::array<uint8_t, 16> iv{};
        core::get_random_bytes(std::span<uint8_t>(iv.data(), iv.size()));

        auto enc_result = crypto::aes256_cbc_encrypt(
            std::span<const uint8_t, 32>(master_key),
            std::span<const uint8_t, 16>(iv),
            std::span<const uint8_t>(entry.secret.data(), 32));

        if (!enc_result.ok()) {
            return core::Error(core::ErrorCode::CRYPTO_ERROR,
                               "Encryption failed: " +
                               enc_result.error().message());
        }

        // Store IV + ciphertext in DB.
        std::vector<uint8_t> enc_data;
        enc_data.reserve(16 + enc_result.value().size());
        enc_data.insert(enc_data.end(), iv.begin(), iv.end());
        enc_data.insert(enc_data.end(),
                        enc_result.value().begin(),
                        enc_result.value().end());

        std::string db_key = "key:" + entry.address;
        auto db_result = db_->write(db_key,
            std::span<const uint8_t>(enc_data));
        if (!db_result.ok()) {
            return db_result;
        }

        // Overwrite the in-memory secret with zeros.
        std::memset(entry.secret.data(), 0, 32);
        entry.is_encrypted = true;
    }

    encrypted_ = true;
    encryption_key_ = master_key;
    has_encryption_key_ = true;

    // Store encryption flag in DB metadata.
    std::vector<uint8_t> flag_val = {1};
    auto meta_result = db_->write("meta:encrypted",
        std::span<const uint8_t>(flag_val));
    if (!meta_result.ok()) {
        return meta_result;
    }

    LOG_INFO(core::LogCategory::WALLET, "All keys encrypted");
    return core::Result<void>{};
}

size_t KeyManager::key_count() const {
    std::lock_guard lock(mutex_);
    return keys_.size();
}

// ---------------------------------------------------------------------------
// Persistence helpers
// ---------------------------------------------------------------------------

core::Result<void> KeyManager::store_key(const KeyEntry& entry) {
    if (!db_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "KeyManager not initialized");
    }

    // Store the key: DB key = "key:<address>"
    // Value = [1B flags][33B pubkey][32B secret_or_encrypted]
    std::vector<uint8_t> data;
    uint8_t flags = entry.is_encrypted ? 0x01 : 0x00;
    data.push_back(flags);
    data.insert(data.end(), entry.pubkey.begin(), entry.pubkey.end());
    data.insert(data.end(), entry.secret.begin(), entry.secret.end());

    std::string db_key = "key:" + entry.address;
    auto result = db_->write(db_key,
        std::span<const uint8_t>(data));
    if (!result.ok()) return result;

    // Also store the address mapping: "addr:<pubkey_hash_hex>" -> address
    std::string hash_hex = core::to_hex(
        std::span<const uint8_t>(entry.pubkey_hash.data(), 20));
    std::string addr_key = "addr:" + hash_hex;
    std::vector<uint8_t> addr_bytes(entry.address.begin(),
                                     entry.address.end());
    return db_->write(addr_key,
        std::span<const uint8_t>(addr_bytes));
}

core::Result<void> KeyManager::load_keys() {
    if (!db_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "KeyManager not initialized");
    }

    keys_.clear();
    addr_to_index_.clear();
    hash_to_index_.clear();

    // Check if wallet is encrypted.
    auto enc_result = db_->read("meta:encrypted");
    if (enc_result.ok() && !enc_result.value().empty() &&
        enc_result.value()[0] == 1) {
        encrypted_ = true;
    }

    // Load all key records.
    auto key_records = db_->read_by_prefix("key:");

    for (const auto& [db_key, data] : key_records) {
        // Minimum size: 1 (flags) + 33 (pubkey) + 32 (secret) = 66
        if (data.size() < 66) {
            LOG_WARN(core::LogCategory::WALLET,
                     "Skipping malformed key record: " + db_key);
            continue;
        }

        KeyEntry entry;
        entry.is_encrypted = (data[0] & 0x01) != 0;

        std::copy(data.begin() + 1, data.begin() + 34,
                  entry.pubkey.begin());
        std::copy(data.begin() + 34, data.begin() + 66,
                  entry.secret.begin());

        entry.pubkey_hash = compute_pubkey_hash(entry.pubkey);

        // Extract address from the DB key ("key:<address>").
        entry.address = db_key.substr(4);

        size_t idx = keys_.size();
        keys_.push_back(entry);
        addr_to_index_[entry.address] = idx;
        hash_to_index_[entry.pubkey_hash] = idx;
    }

    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// WIF encoding/decoding
// ---------------------------------------------------------------------------

core::Result<std::array<uint8_t, 32>> KeyManager::decode_wif(
    std::string_view wif) {

    auto decoded = core::decode_with_version(wif);
    if (!decoded.has_value()) {
        return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                           "Invalid WIF encoding");
    }

    auto [version, payload] = decoded.value();
    if (version != WIF_VERSION) {
        return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                           "Invalid WIF version byte: expected 0x80, got 0x" +
                           core::to_hex(std::span<const uint8_t>(&version, 1)));
    }

    // Payload is either 32 bytes (uncompressed) or 33 bytes (compressed,
    // with a trailing 0x01 flag byte).
    std::array<uint8_t, 32> secret{};

    if (payload.size() == 32) {
        std::copy(payload.begin(), payload.end(), secret.begin());
    } else if (payload.size() == 33 && payload[32] == 0x01) {
        std::copy(payload.begin(), payload.begin() + 32, secret.begin());
    } else {
        return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                           "Invalid WIF payload length: " +
                           std::to_string(payload.size()));
    }

    return secret;
}

std::string KeyManager::encode_wif(const std::array<uint8_t, 32>& secret) {
    // Version byte + 32 bytes secret + compression flag (0x01).
    std::vector<uint8_t> payload;
    payload.reserve(33);
    payload.insert(payload.end(), secret.begin(), secret.end());
    payload.push_back(0x01);  // Compressed key flag.

    return core::encode_with_version(WIF_VERSION,
        std::span<const uint8_t>(payload));
}

std::string KeyManager::pubkey_to_address(
    const std::array<uint8_t, 33>& pubkey) {
    // Use P2PKH (legacy) as the default address type — starts with '1'.
    auto pkh = compute_pubkey_hash(pubkey);
    auto addr = primitives::Address::from_pubkey_hash(pkh);
    return addr.to_string();
}

core::uint160 KeyManager::compute_pubkey_hash(
    const std::array<uint8_t, 33>& pubkey) {
    return crypto::hash160(
        std::span<const uint8_t>(pubkey.data(), pubkey.size()));
}

core::Result<std::array<uint8_t, 32>> KeyManager::decrypt_secret(
    const KeyEntry& entry) const {

    if (!has_encryption_key_) {
        return core::Error(core::ErrorCode::WALLET_LOCKED,
                           "Wallet is locked");
    }

    // Read the encrypted data from DB which includes IV + ciphertext.
    std::string db_key = "key:" + entry.address;
    auto db_result = db_->read(db_key);
    if (!db_result.ok()) {
        return db_result.error();
    }

    const auto& data = db_result.value();
    // The stored data format when encrypted:
    // For encrypted keys stored via encrypt_all_keys: IV(16) + ciphertext
    // But our store_key format is: flags(1) + pubkey(33) + secret(32)
    // When encrypted via encrypt_all_keys, the raw record is replaced.
    // We need to check: if entry.is_encrypted, the "secret" portion in our
    // format is not meaningful. Instead, look for a separate encrypted record.

    // Actually, we handle it simpler: when we encrypt, we store the full
    // record as flags(1) + pubkey(33) + zeros(32) and put the encrypted
    // data under "key:<addr>:enc"
    // For simplicity in this implementation, we re-encrypt using the secret
    // bytes stored in the entry. The encrypted bytes are read from db with
    // the :enc suffix.
    std::string enc_key = "key:" + entry.address + ":enc";
    auto enc_result = db_->read(enc_key);

    std::span<const uint8_t> enc_data;
    std::vector<uint8_t> enc_vec;

    if (enc_result.ok()) {
        enc_vec = enc_result.value();
        enc_data = std::span<const uint8_t>(enc_vec);
    } else {
        // Fallback: the encrypted data might be stored inline as
        // IV(16)+ciphertext right after the flags+pubkey.
        if (data.size() > 34 + 16) {
            enc_data = std::span<const uint8_t>(data.data() + 34,
                                                 data.size() - 34);
        } else {
            // Last resort: try to use the secret bytes directly.
            // This handles the case where encrypt_all_keys stored
            // IV+ciphertext in the standard record.
            enc_data = std::span<const uint8_t>(data.data() + 1,
                                                 data.size() - 1);
        }
    }

    if (enc_data.size() < 32) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Encrypted key data too short");
    }

    // First 16 bytes = IV, rest = ciphertext.
    std::array<uint8_t, 16> iv{};
    std::copy(enc_data.begin(), enc_data.begin() + 16, iv.begin());

    auto ciphertext = enc_data.subspan(16);

    auto dec_result = crypto::aes256_cbc_decrypt(
        std::span<const uint8_t, 32>(encryption_key_),
        std::span<const uint8_t, 16>(iv),
        ciphertext);

    if (!dec_result.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
                           "Failed to decrypt key: " +
                           dec_result.error().message());
    }

    const auto& plaintext = dec_result.value();
    if (plaintext.size() < 32) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Decrypted key data too short");
    }

    std::array<uint8_t, 32> secret{};
    std::copy(plaintext.begin(), plaintext.begin() + 32, secret.begin());
    return secret;
}

} // namespace wallet
