#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "core/types.h"
#include "crypto/bip32.h"
#include "crypto/secp256k1.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace wallet {

// ---------------------------------------------------------------------------
// HDWallet -- Hierarchical Deterministic key derivation (BIP32/BIP39/BIP44)
// ---------------------------------------------------------------------------
// Derives keys along the BIP44 path:
//   m / 44' / FTC_COIN_TYPE' / account' / change / index
//
// The key pool pre-derives the next N keys (default 100) for both the
// external (receiving) and internal (change) chains.
// ---------------------------------------------------------------------------

class HDWallet {
public:
    /// FTC coin type for BIP44 derivation.
    static constexpr uint32_t FTC_COIN_TYPE = 555;

    /// Default key pool size: number of keys pre-derived ahead.
    static constexpr size_t DEFAULT_KEY_POOL_SIZE = 100;

    /// BIP44 purpose constant.
    static constexpr uint32_t BIP44_PURPOSE = 44;

    HDWallet() = default;

    // -- Factory methods ----------------------------------------------------

    /// Create an HD wallet from a BIP39 mnemonic phrase.
    static core::Result<HDWallet> from_mnemonic(
        const std::vector<std::string>& words,
        std::string_view passphrase = "");

    /// Create an HD wallet from raw seed bytes (typically 64 bytes).
    static core::Result<HDWallet> from_seed(
        std::span<const uint8_t> seed_bytes);

    /// Generate a new random BIP39 mnemonic and create the HD wallet.
    /// @param strength  Entropy bits: 128 = 12 words, 256 = 24 words.
    static core::Result<std::pair<std::vector<std::string>, HDWallet>>
    generate(size_t strength = 128);

    // -- Mnemonic -----------------------------------------------------------

    /// Generate a new random mnemonic without creating a wallet.
    /// @param strength  Entropy bits (128, 160, 192, 224, or 256).
    static std::vector<std::string> generate_mnemonic(
        size_t strength = 128);

    // -- Key derivation -----------------------------------------------------

    /// Derive a key at BIP44 path: m/44'/FTC_COIN_TYPE'/account'/change/index.
    core::Result<crypto::ECKey> derive_key(
        uint32_t account, uint32_t change, uint32_t index) const;

    /// Derive a key at an arbitrary BIP32 path string.
    core::Result<crypto::ECKey> derive_path(std::string_view path) const;

    /// Get the next unused receiving key for the given account.
    core::Result<crypto::ECKey> get_next_receiving_key(
        uint32_t account = 0);

    /// Get the next unused change key for the given account.
    core::Result<crypto::ECKey> get_next_change_key(
        uint32_t account = 0);

    // -- Extended key serialization -----------------------------------------

    /// Serialize the master extended public key (xpub) in base58.
    std::string get_xpub() const;

    /// Serialize the master extended private key (xpriv) in base58.
    /// This is sensitive data -- handle with care.
    std::string get_xpriv() const;

    /// Get the account-level extended public key (m/44'/coin'/account').
    core::Result<std::string> get_account_xpub(uint32_t account = 0) const;

    // -- Key pool -----------------------------------------------------------

    /// Pre-derive keys for both receiving and change chains.
    /// @param count  Number of keys to pre-derive on each chain.
    core::Result<void> top_up_key_pool(
        uint32_t account = 0,
        size_t count = DEFAULT_KEY_POOL_SIZE);

    /// Get all pre-derived compressed public keys in the key pool.
    std::vector<std::array<uint8_t, 33>> get_pool_pubkeys() const;

    /// Current index counters.
    [[nodiscard]] uint32_t next_receiving_index(uint32_t account = 0) const;
    [[nodiscard]] uint32_t next_change_index(uint32_t account = 0) const;

    /// Returns true if the HD wallet has been initialized from a seed.
    [[nodiscard]] bool is_initialized() const;

    /// Get the raw seed (sensitive!).
    [[nodiscard]] const std::vector<uint8_t>& seed() const { return seed_; }

private:
    mutable std::unique_ptr<std::mutex> mutex_{std::make_unique<std::mutex>()};
    std::vector<uint8_t> seed_;
    crypto::ExtendedKey master_key_;
    bool initialized_ = false;

    /// Per-account derivation indices.
    struct AccountState {
        uint32_t next_receiving = 0;
        uint32_t next_change = 0;
    };
    mutable std::unordered_map<uint32_t, AccountState> accounts_;

    /// Cached pool of pre-derived public keys.
    struct PoolEntry {
        std::array<uint8_t, 33> pubkey;
        uint32_t account;
        uint32_t change;
        uint32_t index;
    };
    std::vector<PoolEntry> key_pool_;

    /// Build the BIP44 path string.
    static std::string build_bip44_path(
        uint32_t account, uint32_t change, uint32_t index);

    /// Get or create account state.
    AccountState& get_account(uint32_t account) const;
};

} // namespace wallet
