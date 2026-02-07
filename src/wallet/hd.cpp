// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/hd.h"
#include "core/logging.h"
#include "crypto/bip39.h"

#include <sstream>

namespace wallet {

// ---------------------------------------------------------------------------
// Factory methods
// ---------------------------------------------------------------------------

core::Result<HDWallet> HDWallet::from_mnemonic(
    const std::vector<std::string>& words,
    std::string_view passphrase) {

    LOG_INFO(core::LogCategory::WALLET, "from_mnemonic: validating mnemonic...");
    if (!crypto::validate_mnemonic(words)) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "Invalid BIP39 mnemonic");
    }

    LOG_INFO(core::LogCategory::WALLET, "from_mnemonic: deriving seed (PBKDF2)...");
    auto seed_result = crypto::mnemonic_to_seed(words, passphrase);
    if (!seed_result.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
                           "Failed to derive seed from mnemonic: " +
                           seed_result.error().message());
    }

    LOG_INFO(core::LogCategory::WALLET, "from_mnemonic: seed derived, creating HD wallet from seed...");
    return from_seed(std::span<const uint8_t>(seed_result.value()));
}

core::Result<HDWallet> HDWallet::from_seed(
    std::span<const uint8_t> seed_bytes) {

    if (seed_bytes.size() < 16 || seed_bytes.size() > 64) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "Seed must be 16-64 bytes, got " +
                           std::to_string(seed_bytes.size()));
    }

    LOG_INFO(core::LogCategory::WALLET, "from_seed: deriving master key (BIP32)...");
    auto master_result = crypto::ExtendedKey::from_seed(seed_bytes);
    if (!master_result.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
                           "Failed to derive master key from seed: " +
                           master_result.error().message());
    }

    LOG_INFO(core::LogCategory::WALLET, "from_seed: master key derived, building wallet...");
    HDWallet wallet;
    wallet.seed_.assign(seed_bytes.begin(), seed_bytes.end());
    wallet.master_key_ = std::move(master_result).value();
    wallet.initialized_ = true;

    // Pre-derive default key pool.
    LOG_INFO(core::LogCategory::WALLET, "from_seed: pre-deriving key pool (200 keys)...");
    auto pool_result = wallet.top_up_key_pool(0, DEFAULT_KEY_POOL_SIZE);
    if (!pool_result.ok()) {
        LOG_WARN(core::LogCategory::WALLET,
                 "Failed to pre-derive key pool: " +
                 pool_result.error().message());
    }

    LOG_INFO(core::LogCategory::WALLET,
             "HD wallet initialized from seed");
    return wallet;
}

core::Result<std::pair<std::vector<std::string>, HDWallet>>
HDWallet::generate(size_t strength) {
    size_t word_count;
    switch (strength) {
        case 128: word_count = 12; break;
        case 160: word_count = 15; break;
        case 192: word_count = 18; break;
        case 224: word_count = 21; break;
        case 256: word_count = 24; break;
        default:
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                               "Invalid entropy strength: " +
                               std::to_string(strength) +
                               " (must be 128, 160, 192, 224, or 256)");
    }

    auto words = crypto::generate_mnemonic(word_count);
    auto wallet_result = from_mnemonic(words);
    if (!wallet_result.ok()) {
        return wallet_result.error();
    }

    return std::make_pair(std::move(words),
                          std::move(wallet_result).value());
}

// ---------------------------------------------------------------------------
// Mnemonic generation
// ---------------------------------------------------------------------------

std::vector<std::string> HDWallet::generate_mnemonic(size_t strength) {
    size_t word_count;
    switch (strength) {
        case 128: word_count = 12; break;
        case 160: word_count = 15; break;
        case 192: word_count = 18; break;
        case 224: word_count = 21; break;
        case 256: word_count = 24; break;
        default:  word_count = 12; break;
    }
    return crypto::generate_mnemonic(word_count);
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

core::Result<crypto::ECKey> HDWallet::derive_key(
    uint32_t account, uint32_t change, uint32_t index) const {
    std::lock_guard lock(*mutex_);

    if (!initialized_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "HD wallet not initialized");
    }

    std::string path = build_bip44_path(account, change, index);
    auto derived = master_key_.derive_path(path);
    if (!derived.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_KEY_FAIL,
                           "BIP32 derivation failed at path " + path +
                           ": " + derived.error().message());
    }

    return derived.value().key();
}

core::Result<crypto::ECKey> HDWallet::derive_path(
    std::string_view path) const {
    std::lock_guard lock(*mutex_);

    if (!initialized_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "HD wallet not initialized");
    }

    auto derived = master_key_.derive_path(path);
    if (!derived.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_KEY_FAIL,
                           "BIP32 derivation failed at path " +
                           std::string(path) + ": " +
                           derived.error().message());
    }

    return derived.value().key();
}

core::Result<crypto::ECKey> HDWallet::get_next_receiving_key(
    uint32_t account) {
    std::lock_guard lock(*mutex_);

    if (!initialized_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "HD wallet not initialized");
    }

    auto& state = get_account(account);
    uint32_t idx = state.next_receiving;

    std::string path = build_bip44_path(account, 0, idx);
    auto derived = master_key_.derive_path(path);
    if (!derived.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_KEY_FAIL,
                           "BIP32 derivation failed: " +
                           derived.error().message());
    }

    state.next_receiving = idx + 1;

    LOG_DEBUG(core::LogCategory::WALLET,
              "Derived receiving key at " + path);
    return derived.value().key();
}

core::Result<crypto::ECKey> HDWallet::get_next_change_key(
    uint32_t account) {
    std::lock_guard lock(*mutex_);

    if (!initialized_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "HD wallet not initialized");
    }

    auto& state = get_account(account);
    uint32_t idx = state.next_change;

    std::string path = build_bip44_path(account, 1, idx);
    auto derived = master_key_.derive_path(path);
    if (!derived.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_KEY_FAIL,
                           "BIP32 derivation failed: " +
                           derived.error().message());
    }

    state.next_change = idx + 1;

    LOG_DEBUG(core::LogCategory::WALLET,
              "Derived change key at " + path);
    return derived.value().key();
}

// ---------------------------------------------------------------------------
// Extended key serialization
// ---------------------------------------------------------------------------

std::string HDWallet::get_xpub() const {
    std::lock_guard lock(*mutex_);
    if (!initialized_) return {};
    return master_key_.neuter().to_base58();
}

std::string HDWallet::get_xpriv() const {
    std::lock_guard lock(*mutex_);
    if (!initialized_) return {};
    return master_key_.to_base58();
}

core::Result<std::string> HDWallet::get_account_xpub(
    uint32_t account) const {
    std::lock_guard lock(*mutex_);

    if (!initialized_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "HD wallet not initialized");
    }

    // Derive m/44'/FTC_COIN_TYPE'/account'
    std::string path = "m/44'/" + std::to_string(FTC_COIN_TYPE) +
                       "'/" + std::to_string(account) + "'";
    auto derived = master_key_.derive_path(path);
    if (!derived.ok()) {
        return derived.error();
    }

    return derived.value().neuter().to_base58();
}

// ---------------------------------------------------------------------------
// Key pool
// ---------------------------------------------------------------------------

core::Result<void> HDWallet::top_up_key_pool(
    uint32_t account, size_t count) {
    std::lock_guard lock(*mutex_);

    if (!initialized_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "HD wallet not initialized");
    }

    auto& state = get_account(account);

    // Pre-derive receiving keys.
    for (size_t i = 0; i < count; ++i) {
        uint32_t idx = state.next_receiving + static_cast<uint32_t>(i);
        std::string path = build_bip44_path(account, 0, idx);
        auto derived = master_key_.derive_path(path);
        if (!derived.ok()) {
            return core::Error(core::ErrorCode::CRYPTO_KEY_FAIL,
                               "Failed to derive key at " + path);
        }

        PoolEntry entry;
        entry.pubkey = derived.value().pubkey();
        entry.account = account;
        entry.change = 0;
        entry.index = idx;
        key_pool_.push_back(entry);
    }

    // Pre-derive change keys.
    for (size_t i = 0; i < count; ++i) {
        uint32_t idx = state.next_change + static_cast<uint32_t>(i);
        std::string path = build_bip44_path(account, 1, idx);
        auto derived = master_key_.derive_path(path);
        if (!derived.ok()) {
            return core::Error(core::ErrorCode::CRYPTO_KEY_FAIL,
                               "Failed to derive key at " + path);
        }

        PoolEntry entry;
        entry.pubkey = derived.value().pubkey();
        entry.account = account;
        entry.change = 1;
        entry.index = idx;
        key_pool_.push_back(entry);
    }

    LOG_INFO(core::LogCategory::WALLET,
             "Key pool topped up: " + std::to_string(count) +
             " receiving + " + std::to_string(count) +
             " change keys for account " + std::to_string(account));
    return core::Result<void>{};
}

std::vector<std::array<uint8_t, 33>> HDWallet::get_pool_pubkeys() const {
    std::lock_guard lock(*mutex_);

    std::vector<std::array<uint8_t, 33>> result;
    result.reserve(key_pool_.size());
    for (const auto& entry : key_pool_) {
        result.push_back(entry.pubkey);
    }
    return result;
}

uint32_t HDWallet::next_receiving_index(uint32_t account) const {
    std::lock_guard lock(*mutex_);
    auto it = accounts_.find(account);
    return (it != accounts_.end()) ? it->second.next_receiving : 0;
}

uint32_t HDWallet::next_change_index(uint32_t account) const {
    std::lock_guard lock(*mutex_);
    auto it = accounts_.find(account);
    return (it != accounts_.end()) ? it->second.next_change : 0;
}

bool HDWallet::is_initialized() const {
    std::lock_guard lock(*mutex_);
    return initialized_;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

std::string HDWallet::build_bip44_path(
    uint32_t account, uint32_t change, uint32_t index) {
    std::ostringstream oss;
    oss << "m/" << BIP44_PURPOSE << "'/"
        << FTC_COIN_TYPE << "'/"
        << account << "'/"
        << change << "/"
        << index;
    return oss.str();
}

HDWallet::AccountState& HDWallet::get_account(uint32_t account) const {
    auto it = accounts_.find(account);
    if (it == accounts_.end()) {
        accounts_[account] = AccountState{};
        return accounts_[account];
    }
    return it->second;
}

} // namespace wallet
