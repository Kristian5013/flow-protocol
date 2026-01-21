#ifndef FTC_CRYPTO_SECP256K1_H
#define FTC_CRYPTO_SECP256K1_H

#include <cstdint>
#include <array>
#include <vector>
#include <string>
#include <optional>

namespace ftc {
namespace crypto {

// Key sizes
constexpr size_t PRIVATE_KEY_SIZE = 32;
constexpr size_t PUBLIC_KEY_SIZE = 33;           // Compressed
constexpr size_t PUBLIC_KEY_UNCOMPRESSED_SIZE = 65;
constexpr size_t SIGNATURE_SIZE = 64;            // Compact (r, s)
constexpr size_t SIGNATURE_DER_MAX_SIZE = 72;    // DER encoded

// Key types
using PrivateKey = std::array<uint8_t, PRIVATE_KEY_SIZE>;
using PublicKey = std::array<uint8_t, PUBLIC_KEY_SIZE>;
using PublicKeyUncompressed = std::array<uint8_t, PUBLIC_KEY_UNCOMPRESSED_SIZE>;
using Signature = std::array<uint8_t, SIGNATURE_SIZE>;

/**
 * secp256k1 elliptic curve operations
 *
 * Used for:
 * - Key generation
 * - Transaction signing
 * - Signature verification
 */
class Secp256k1 {
public:
    Secp256k1();
    ~Secp256k1();

    // Non-copyable
    Secp256k1(const Secp256k1&) = delete;
    Secp256k1& operator=(const Secp256k1&) = delete;

    // Key generation
    bool generateKeyPair(PrivateKey& privkey, PublicKey& pubkey);

    // Derive public key from private key
    bool derivePublicKey(const PrivateKey& privkey, PublicKey& pubkey);
    bool derivePublicKeyUncompressed(const PrivateKey& privkey,
                                      PublicKeyUncompressed& pubkey);

    // Signing (signs 32-byte message hash)
    bool sign(const uint8_t* msg32, const PrivateKey& privkey, Signature& sig);

    // Verification
    bool verify(const uint8_t* msg32, const Signature& sig, const PublicKey& pubkey);

    // Key validation
    bool isValidPrivateKey(const PrivateKey& key);
    bool isValidPublicKey(const PublicKey& key);

    // Public key compression/decompression
    bool compressPublicKey(const PublicKeyUncompressed& uncompressed, PublicKey& compressed);
    bool decompressPublicKey(const PublicKey& compressed, PublicKeyUncompressed& uncompressed);

    // Signature serialization
    std::vector<uint8_t> signatureToDER(const Signature& sig);
    bool signatureFromDER(const std::vector<uint8_t>& der, Signature& sig);

    // Utilities
    static std::string toHex(const PrivateKey& key);
    static std::string toHex(const PublicKey& key);
    static std::string toHex(const Signature& sig);

    static std::optional<PrivateKey> privateKeyFromHex(const std::string& hex);
    static std::optional<PublicKey> publicKeyFromHex(const std::string& hex);

    // Singleton access
    static Secp256k1& instance();

private:
    void* ctx_;  // secp256k1_context*
};

// Convenience functions using singleton
bool generateKeyPair(PrivateKey& privkey, PublicKey& pubkey);
bool sign(const uint8_t* msg32, const PrivateKey& privkey, Signature& sig);
bool verify(const uint8_t* msg32, const Signature& sig, const PublicKey& pubkey);

} // namespace crypto
} // namespace ftc

#endif // FTC_CRYPTO_SECP256K1_H
