#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "core/types.h"
#include "core/error.h"

namespace crypto {

class ECKey;  // forward declaration

/// BIP-340 Schnorr signature key, operating on secp256k1 with x-only pubkeys.
///
/// This implementation uses OpenSSL BN/EC primitives for the underlying field
/// and group arithmetic but implements the BIP-340 signing/verification
/// algorithm directly (OpenSSL does not natively support BIP-340).
class SchnorrKey {
public:
    SchnorrKey() = default;

    /// Construct from a raw 32-byte secret.  The scalar must be in [1, n-1].
    static core::Result<SchnorrKey> from_secret(
        std::span<const uint8_t, 32> secret);

    /// Construct from an existing ECKey (copies the secret).
    static SchnorrKey from_eckey(const ECKey& key);

    /// Return the 32-byte x-only public key (BIP-340 format).
    std::array<uint8_t, 32> pubkey() const;

    /// Sign a 32-byte message hash using BIP-340.
    /// Generates random auxiliary randomness internally.
    std::array<uint8_t, 64> sign(const core::uint256& hash) const;

    /// Sign with caller-supplied 32-byte auxiliary randomness.
    std::array<uint8_t, 64> sign(
        const core::uint256& hash,
        std::span<const uint8_t, 32> aux_rand) const;

    /// Verify a BIP-340 Schnorr signature against an x-only pubkey.
    static bool verify(std::span<const uint8_t, 32> pubkey,
                       const core::uint256& hash,
                       std::span<const uint8_t, 64> sig);

    /// True if this object holds a valid private key.
    bool is_valid() const;

private:
    std::array<uint8_t, 32> secret_{};
    bool has_key_ = false;
};

}  // namespace crypto
