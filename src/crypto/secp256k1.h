#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include "core/types.h"
#include "core/error.h"

typedef struct evp_pkey_st EVP_PKEY;

namespace crypto {

/// ECDSA key pair on the secp256k1 curve using OpenSSL 3.0+ EVP API.
/// Owns a 32-byte secret and lazily builds the corresponding EVP_PKEY.
class ECKey {
public:
    ECKey() = default;
    ~ECKey();

    ECKey(const ECKey&) = delete;
    ECKey& operator=(const ECKey&) = delete;

    ECKey(ECKey&& other) noexcept;
    ECKey& operator=(ECKey&& other) noexcept;

    /// Generate a new random key pair via OpenSSL.
    static ECKey generate();

    /// Construct from an existing 32-byte secret scalar.
    /// Returns an error if the scalar is zero or >= curve order.
    static core::Result<ECKey> from_secret(std::span<const uint8_t, 32> secret);

    /// True when this object holds a valid private key.
    bool is_valid() const;

    /// Raw 32-byte secret scalar (big-endian).
    std::array<uint8_t, 32> secret() const;

    /// SEC1 compressed public key (33 bytes: 0x02/0x03 || x).
    std::array<uint8_t, 33> pubkey_compressed() const;

    /// SEC1 uncompressed public key (65 bytes: 0x04 || x || y).
    std::array<uint8_t, 65> pubkey_uncompressed() const;

    /// ECDSA sign -- returns a DER-encoded signature with low-S normalization.
    std::vector<uint8_t> sign(const core::uint256& hash) const;

    /// ECDSA sign compact (64 bytes r||s) plus a recovery id in [0,3].
    std::pair<std::array<uint8_t, 64>, int> sign_compact(
        const core::uint256& hash) const;

    /// Verify a DER-encoded ECDSA signature against the given public key.
    static bool verify(std::span<const uint8_t> pubkey,
                       const core::uint256& hash,
                       std::span<const uint8_t> der_sig);

    /// Verify a 64-byte compact (r||s) ECDSA signature.
    static bool verify_compact(std::span<const uint8_t> pubkey,
                               const core::uint256& hash,
                               std::span<const uint8_t, 64> sig);

    /// Recover the compressed public key from a compact signature + recovery id.
    static core::Result<std::array<uint8_t, 33>> recover_compact(
        const core::uint256& hash,
        std::span<const uint8_t, 64> sig,
        int recovery_id);

    /// ECDH: derive a shared secret (x-coordinate of shared point, hashed).
    core::Result<core::uint256> ecdh(
        std::span<const uint8_t> other_pubkey) const;

    /// Add a 32-byte tweak to the private key (key += tweak mod n).
    ECKey& tweak_add(std::span<const uint8_t, 32> tweak);

    /// Multiply the private key by a 32-byte tweak (key *= tweak mod n).
    ECKey& tweak_mul(std::span<const uint8_t, 32> tweak);

private:
    std::array<uint8_t, 32> secret_{};
    bool has_key_ = false;
    EVP_PKEY* pkey_ = nullptr;

    /// (Re)build the EVP_PKEY from secret_. Frees any previous pkey_.
    void rebuild_pkey();
};

/// Normalize the S value in a DER-encoded ECDSA signature to the lower half
/// of the curve order (BIP-62 "low-S" rule).  Returns true if the signature
/// was mutated.
bool ecdsa_normalize_s(std::vector<uint8_t>& der_sig);

/// Return true if the byte sequence is a valid SEC1 public key
/// (compressed 33 bytes starting 0x02/0x03, or uncompressed 65 bytes
/// starting 0x04).
bool is_valid_pubkey(std::span<const uint8_t> pubkey);

}  // namespace crypto
