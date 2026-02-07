#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// TransportCrypto -- BIP324-style V2 encrypted P2P transport.
//
// Implements a simplified encrypted transport layer using:
//   - secp256k1 ECDH for key agreement
//   - Keccak-256 as the KDF (HKDF-Extract + Expand analogue)
//   - ChaCha20-Poly1305 AEAD for message encryption
//
// Each direction gets an independent symmetric key and nonce counter,
// derived from the shared secret and the roles (initiator / responder).
// ---------------------------------------------------------------------------

#include "core/error.h"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace net {

class TransportCrypto {
public:
    TransportCrypto() = default;
    ~TransportCrypto() = default;

    // Non-copyable (holds key material).
    TransportCrypto(const TransportCrypto&) = delete;
    TransportCrypto& operator=(const TransportCrypto&) = delete;

    // Movable.
    TransportCrypto(TransportCrypto&& other) noexcept;
    TransportCrypto& operator=(TransportCrypto&& other) noexcept;

    // -- Key generation -----------------------------------------------------

    /// Ephemeral ECDH key pair for the V2 handshake.
    struct HandshakeKeys {
        std::vector<uint8_t> our_pubkey;   // 33 bytes (compressed SEC1)
        std::vector<uint8_t> our_privkey;  // 32 bytes (raw scalar)
    };

    /// Generate a fresh ephemeral ECDH key pair.
    [[nodiscard]] static HandshakeKeys generate_keys();

    // -- Session initialization ---------------------------------------------

    /// Derive session keys from our private key and the peer's public key.
    ///
    /// @param our_privkey   Our 32-byte ECDH private key.
    /// @param their_pubkey  The peer's compressed public key (33 bytes).
    /// @param initiator     True if we initiated the connection (determines
    ///                      which derived key is used for send vs. recv).
    core::Result<void> initialize(
        std::span<const uint8_t> our_privkey,
        std::span<const uint8_t> their_pubkey,
        bool initiator);

    // -- Encrypt / Decrypt --------------------------------------------------

    /// Encrypt a plaintext payload.  Returns ciphertext with the 12-byte
    /// nonce prepended and 16-byte Poly1305 tag appended:
    ///   [ nonce (12) | ciphertext (N) | tag (16) ]
    [[nodiscard]] core::Result<std::vector<uint8_t>> encrypt(
        std::span<const uint8_t> plaintext);

    /// Decrypt a ciphertext produced by encrypt().  Expects the format:
    ///   [ nonce (12) | ciphertext (N) | tag (16) ]
    [[nodiscard]] core::Result<std::vector<uint8_t>> decrypt(
        std::span<const uint8_t> ciphertext);

    /// Returns true once initialize() has completed successfully.
    [[nodiscard]] bool is_initialized() const;

private:
    /// 32-byte symmetric keys for send and receive directions.
    std::vector<uint8_t> send_key_;
    std::vector<uint8_t> recv_key_;

    /// Per-direction nonce counters (incremented after every operation).
    uint64_t send_nonce_ = 0;
    uint64_t recv_nonce_ = 0;

    /// True after a successful call to initialize().
    bool initialized_ = false;

    /// Build a 12-byte nonce from a 64-bit counter.
    /// Layout: [ 4 zero bytes | 8 little-endian counter bytes ].
    static std::array<uint8_t, 12> make_nonce(uint64_t counter);

    /// HKDF-like key derivation: Keccak256(salt || ikm || info).
    static std::vector<uint8_t> derive_key(
        std::span<const uint8_t> salt,
        std::span<const uint8_t> ikm,
        std::span<const uint8_t> info);
};

} // namespace net
