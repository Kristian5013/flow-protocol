#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "core/types.h"
#include "core/error.h"
#include "crypto/keccak.h"
#include "crypto/secp256k1.h"

namespace crypto {

// BIP32 Hierarchical Deterministic Key Derivation adapted for Keccak-256.
//
// Standard BIP32 uses HMAC-SHA512 producing 64 bytes. For FTC we use
// HMAC-Keccak256 called twice to produce the equivalent 64 bytes:
//   IL = HMAC-Keccak256(key, 0x00 || data)  -- 32 bytes, secret key material
//   IR = HMAC-Keccak256(key, 0x01 || data)  -- 32 bytes, chain code
class ExtendedKey {
public:
    ExtendedKey() = default;

    // Create master key from seed (BIP32 master key generation).
    // Seed should be 16..64 bytes (typically 64 bytes from BIP39).
    static core::Result<ExtendedKey> from_seed(std::span<const uint8_t> seed);

    // Derive a child key at the given normal (non-hardened) index.
    // Index must be < 0x80000000.
    core::Result<ExtendedKey> derive(uint32_t index) const;

    // Derive a child key at the given hardened index.
    // The HARDENED_BIT is added internally; pass the logical index (0, 1, ...).
    core::Result<ExtendedKey> derive_hardened(uint32_t index) const;

    // Derive along a full path such as "m/44'/0'/0'/0/0".
    // Apostrophe or 'h' after an index denotes hardened derivation.
    core::Result<ExtendedKey> derive_path(std::string_view path) const;

    // Access the underlying EC key (only valid when is_private() is true).
    ECKey key() const;

    // Compressed public key (33 bytes).
    std::array<uint8_t, 33> pubkey() const;

    // Chain code (32 bytes).
    std::array<uint8_t, 32> chain_code() const;

    // Depth in the derivation tree (0 for master).
    uint8_t depth() const;

    // Parent fingerprint: first 4 bytes of Hash160(parent pubkey).
    // For the master key this is 0x00000000.
    uint32_t fingerprint() const;

    // Child number used to derive this key.
    uint32_t child_number() const;

    // Serialize to Base58Check (xprv / xpub format, 78 payload bytes).
    // Layout: 4 version | 1 depth | 4 fingerprint | 4 child | 32 chain | 33 key
    std::string to_base58() const;

    // Deserialize from Base58Check xprv/xpub string.
    static core::Result<ExtendedKey> from_base58(std::string_view str);

    // Return a public-key-only copy (neutered key). Can only perform
    // non-hardened child derivation.
    ExtendedKey neuter() const;

    // True if this extended key contains the private key material.
    bool is_private() const;

private:
    std::array<uint8_t, 32> key_{};        // private key (zeroed if neutered)
    std::array<uint8_t, 33> pubkey_{};     // compressed public key
    std::array<uint8_t, 32> chain_code_{}; // chain code
    uint8_t depth_ = 0;
    uint32_t fingerprint_ = 0;            // parent fingerprint
    uint32_t child_number_ = 0;
    bool is_private_ = true;

    static constexpr uint32_t HARDENED_BIT = 0x80000000;

    // Version bytes for Base58Check serialization.
    static constexpr uint32_t XPRV_VERSION = 0x0488ADE4;
    static constexpr uint32_t XPUB_VERSION = 0x0488B21E;

    // Internal: derive child key at raw index (hardened bit already set if needed).
    core::Result<ExtendedKey> derive_child(uint32_t index) const;

    // Internal: compute this key's own fingerprint (first 4 bytes of
    // Keccak256(pubkey) truncated -- analogous to Hash160).
    uint32_t compute_fingerprint() const;

    // Split HMAC: produce 64 bytes (IL || IR) from key and data using
    // two HMAC-Keccak256 calls.
    static std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 32>>
    hmac_split(std::span<const uint8_t> key, std::span<const uint8_t> data);
};

} // namespace crypto
