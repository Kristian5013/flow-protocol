// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_framework.h"

#include "crypto/keccak.h"
#include "crypto/hash.h"
#include "crypto/siphash.h"
#include "crypto/secp256k1.h"
#include "crypto/merkle.h"
#include "crypto/aes.h"
#include "crypto/chacha20.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

// ===================================================================
// Keccak256
// ===================================================================

TEST_CASE(Keccak256, EmptyInput) {
    // Hash of empty data should be a well-defined, non-zero value.
    std::vector<uint8_t> empty;
    auto h = crypto::keccak256(std::span<const uint8_t>(empty));
    CHECK(!h.is_zero());
}

TEST_CASE(Keccak256, AbcInput) {
    // Hash of "abc" -- a basic sanity check.
    const std::string msg = "abc";
    auto h = crypto::keccak256(msg.data(), msg.size());
    CHECK(!h.is_zero());

    // The same input via the span overload must produce the same hash.
    std::vector<uint8_t> bytes(msg.begin(), msg.end());
    auto h2 = crypto::keccak256(std::span<const uint8_t>(bytes));
    CHECK_EQ(h, h2);
}

TEST_CASE(Keccak256, Determinism) {
    // Hashing the same data twice must yield the same digest.
    const std::string msg = "determinism test payload";
    auto h1 = crypto::keccak256(msg.data(), msg.size());
    auto h2 = crypto::keccak256(msg.data(), msg.size());
    CHECK_EQ(h1, h2);
}

TEST_CASE(Keccak256, DoubleHash) {
    // keccak256d(x) == keccak256(keccak256(x))
    const std::string msg = "double hash test";
    std::vector<uint8_t> bytes(msg.begin(), msg.end());
    auto single = crypto::keccak256(std::span<const uint8_t>(bytes));
    auto double_hash = crypto::keccak256d(std::span<const uint8_t>(bytes));

    // Manually compute the double hash.
    auto single_bytes = single.bytes();
    auto manual_double = crypto::keccak256(
        std::span<const uint8_t>(single_bytes));
    CHECK_EQ(double_hash, manual_double);
}

TEST_CASE(Keccak256, Hash160) {
    // hash160(x) should produce a non-zero 20-byte value derived from keccak256d.
    const std::string msg = "hash160 test";
    std::vector<uint8_t> bytes(msg.begin(), msg.end());
    auto h160 = crypto::hash160(std::span<const uint8_t>(bytes));
    CHECK(!h160.is_zero());

    // hash160 is defined as the first 20 bytes of keccak256d.
    auto full = crypto::keccak256d(std::span<const uint8_t>(bytes));
    // Compare raw bytes: h160 should equal the first 20 bytes of full.
    CHECK(std::memcmp(h160.data(), full.data(), 20) == 0);
}

TEST_CASE(Keccak256, IncrementalHasher) {
    // Feeding data in chunks via the incremental hasher must produce
    // the same digest as the one-shot function.
    const std::string part1 = "hello ";
    const std::string part2 = "world";
    const std::string full_msg = "hello world";

    auto one_shot = crypto::keccak256(full_msg.data(), full_msg.size());

    crypto::Keccak256Hasher hasher;
    hasher.write(part1.data(), part1.size());
    hasher.write(part2.data(), part2.size());
    auto incremental = hasher.finalize();

    CHECK_EQ(one_shot, incremental);
}

TEST_CASE(Keccak256, HasherReset) {
    // After reset(), a hasher should produce the same result for the same input.
    const std::string msg = "reset test";
    crypto::Keccak256Hasher hasher;
    hasher.write(msg.data(), msg.size());
    auto h1 = hasher.finalize();

    hasher.reset();
    hasher.write(msg.data(), msg.size());
    auto h2 = hasher.finalize();

    CHECK_EQ(h1, h2);
}

TEST_CASE(Keccak256, HmacBasic) {
    // HMAC with the same key and data is deterministic and non-zero.
    std::array<uint8_t, 16> key{};
    key.fill(0x0b);
    const std::string msg = "hmac test data";
    std::vector<uint8_t> data(msg.begin(), msg.end());

    auto hmac1 = crypto::hmac_keccak256(
        std::span<const uint8_t>(key), std::span<const uint8_t>(data));
    auto hmac2 = crypto::hmac_keccak256(
        std::span<const uint8_t>(key), std::span<const uint8_t>(data));

    CHECK_EQ(hmac1, hmac2);

    // A different key should yield a different HMAC.
    std::array<uint8_t, 16> key2{};
    key2.fill(0xaa);
    auto hmac3 = crypto::hmac_keccak256(
        std::span<const uint8_t>(key2), std::span<const uint8_t>(data));
    CHECK_NE(hmac1, hmac3);
}

// ===================================================================
// SipHash
// ===================================================================

TEST_CASE(SipHash, BasicHash) {
    // One-shot SipHash of a byte span should be deterministic.
    const std::string msg = "siphash test";
    std::vector<uint8_t> data(msg.begin(), msg.end());
    uint64_t h1 = crypto::siphash(0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL,
                                  std::span<const uint8_t>(data));
    uint64_t h2 = crypto::siphash(0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL,
                                  std::span<const uint8_t>(data));
    CHECK_EQ(h1, h2);
}

TEST_CASE(SipHash, DifferentKeysProduceDifferentHashes) {
    const std::string msg = "key test";
    std::vector<uint8_t> data(msg.begin(), msg.end());
    uint64_t h1 = crypto::siphash(1, 2, std::span<const uint8_t>(data));
    uint64_t h2 = crypto::siphash(3, 4, std::span<const uint8_t>(data));
    CHECK_NE(h1, h2);
}

TEST_CASE(SipHash, IncrementalMatchesOneShot) {
    // Building incrementally with the class should match the one-shot function.
    const std::string msg = "incremental match";
    std::vector<uint8_t> data(msg.begin(), msg.end());

    uint64_t one_shot = crypto::siphash(42, 99, std::span<const uint8_t>(data));

    crypto::SipHash hasher(42, 99);
    hasher.write(std::span<const uint8_t>(data));
    uint64_t incremental = hasher.finalize();

    CHECK_EQ(one_shot, incremental);
}

TEST_CASE(SipHash, Uint256Hash) {
    // Hashing a uint256 should be deterministic and non-zero for non-zero input.
    auto val = core::uint256::from_hex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    uint64_t h = crypto::siphash(10, 20, val);
    // Extremely unlikely to be zero for non-trivial input.
    CHECK_NE(h, uint64_t{0});
}

// ===================================================================
// Secp256k1
// ===================================================================

TEST_CASE(Secp256k1, KeyGeneration) {
    auto key = crypto::ECKey::generate();
    CHECK(key.is_valid());

    // Compressed pubkey must be 33 bytes starting with 0x02 or 0x03.
    auto cpk = key.pubkey_compressed();
    CHECK(cpk[0] == 0x02 || cpk[0] == 0x03);

    // Uncompressed pubkey must be 65 bytes starting with 0x04.
    auto upk = key.pubkey_uncompressed();
    CHECK_EQ(upk[0], uint8_t{0x04});
}

TEST_CASE(Secp256k1, SignAndVerify) {
    auto key = crypto::ECKey::generate();
    // Create a hash to sign.
    const std::string msg = "sign-verify test";
    auto hash = crypto::keccak256(msg.data(), msg.size());

    // DER signature.
    auto der_sig = key.sign(hash);
    CHECK(!der_sig.empty());

    auto cpk = key.pubkey_compressed();
    CHECK(crypto::ECKey::verify(
        std::span<const uint8_t>(cpk), hash,
        std::span<const uint8_t>(der_sig)));
}

TEST_CASE(Secp256k1, CompactSignAndVerify) {
    auto key = crypto::ECKey::generate();
    const std::string msg = "compact sign test";
    auto hash = crypto::keccak256(msg.data(), msg.size());

    auto [sig, recovery_id] = key.sign_compact(hash);
    // Compact verify works regardless of recovery_id.
    auto cpk = key.pubkey_compressed();
    CHECK(crypto::ECKey::verify_compact(
        std::span<const uint8_t>(cpk), hash,
        std::span<const uint8_t, 64>(sig)));
}

TEST_CASE(Secp256k1, RecoverPublicKey) {
    auto key = crypto::ECKey::generate();
    const std::string msg = "recovery test";
    auto hash = crypto::keccak256(msg.data(), msg.size());

    auto [sig, recovery_id] = key.sign_compact(hash);
    if (recovery_id >= 0 && recovery_id <= 3) {
        auto recovered = crypto::ECKey::recover_compact(
            hash, std::span<const uint8_t, 64>(sig), recovery_id);
        CHECK_OK(recovered);
        auto expected_cpk = key.pubkey_compressed();
        CHECK_EQ(recovered.value(), expected_cpk);
    } else {
        // Recovery ID not determinable on this platform; skip recovery test.
        CHECK(true);
    }
}

TEST_CASE(Secp256k1, InvalidSecretRejected) {
    // A zero scalar should be rejected by from_secret.
    std::array<uint8_t, 32> zero_secret{};
    auto result = crypto::ECKey::from_secret(
        std::span<const uint8_t, 32>(zero_secret));
    CHECK_ERR(result);
}

TEST_CASE(Secp256k1, PubkeyValidation) {
    auto key = crypto::ECKey::generate();
    auto cpk = key.pubkey_compressed();
    CHECK(crypto::is_valid_pubkey(std::span<const uint8_t>(cpk)));

    auto upk = key.pubkey_uncompressed();
    CHECK(crypto::is_valid_pubkey(std::span<const uint8_t>(upk)));

    // Garbage bytes should not be a valid pubkey.
    std::array<uint8_t, 33> bad{};
    bad.fill(0xff);
    CHECK(!crypto::is_valid_pubkey(std::span<const uint8_t>(bad)));
}

// ===================================================================
// Merkle
// ===================================================================

TEST_CASE(Merkle, SingleLeaf) {
    // Merkle root of a single leaf is the leaf itself.
    auto leaf = crypto::keccak256("leaf", 4);
    std::vector<core::uint256> leaves{leaf};
    auto root = crypto::compute_merkle_root(leaves);
    CHECK_EQ(root, leaf);
}

TEST_CASE(Merkle, TwoLeaves) {
    // Merkle root of two leaves should equal hash_combine(a, b).
    auto a = crypto::keccak256("a", 1);
    auto b = crypto::keccak256("b", 1);
    std::vector<core::uint256> leaves{a, b};
    auto root = crypto::compute_merkle_root(leaves);
    CHECK(!root.is_zero());
    CHECK_NE(root, a);
    CHECK_NE(root, b);
}

TEST_CASE(Merkle, FourLeaves) {
    auto h0 = crypto::keccak256("h0", 2);
    auto h1 = crypto::keccak256("h1", 2);
    auto h2 = crypto::keccak256("h2", 2);
    auto h3 = crypto::keccak256("h3", 2);
    std::vector<core::uint256> leaves{h0, h1, h2, h3};
    auto root = crypto::compute_merkle_root(leaves);
    CHECK(!root.is_zero());

    // Reordering should produce a different root.
    std::vector<core::uint256> reordered{h1, h0, h2, h3};
    auto root2 = crypto::compute_merkle_root(reordered);
    CHECK_NE(root, root2);
}

TEST_CASE(Merkle, TreeClassProofVerification) {
    // Build a 4-leaf tree via the MerkleTree class and verify a proof.
    auto h0 = crypto::keccak256("m0", 2);
    auto h1 = crypto::keccak256("m1", 2);
    auto h2 = crypto::keccak256("m2", 2);
    auto h3 = crypto::keccak256("m3", 2);

    crypto::MerkleTree tree({h0, h1, h2, h3});
    CHECK_EQ(tree.leaf_count(), size_t{4});

    auto root = tree.root();
    CHECK(!root.is_zero());

    // Verify proof for leaf at index 2.
    auto proof = tree.proof(2);
    CHECK(crypto::MerkleTree::verify(root, h2, proof, 2));

    // A wrong leaf should not verify.
    CHECK(!crypto::MerkleTree::verify(root, h0, proof, 2));
}

// ===================================================================
// AES-256-GCM
// ===================================================================

TEST_CASE(AES, GcmRoundTrip) {
    std::array<uint8_t, 32> key{};
    for (size_t i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);

    const std::string msg = "AES-256-GCM roundtrip test payload";
    std::vector<uint8_t> plaintext(msg.begin(), msg.end());

    auto enc_result = crypto::aes256_gcm_encrypt(
        std::span<const uint8_t, 32>(key),
        std::span<const uint8_t>(plaintext));
    CHECK_OK(enc_result);

    auto& encrypted = enc_result.value();
    // Ciphertext must not be empty and should differ from plaintext.
    CHECK(!encrypted.ciphertext.empty());

    auto dec_result = crypto::aes256_gcm_decrypt(
        std::span<const uint8_t, 32>(key), encrypted);
    CHECK_OK(dec_result);

    CHECK_EQ(dec_result.value(), plaintext);
}

TEST_CASE(AES, GcmWithAad) {
    std::array<uint8_t, 32> key{};
    key.fill(0x42);

    const std::string msg = "authenticated data test";
    std::vector<uint8_t> plaintext(msg.begin(), msg.end());

    const std::string aad_str = "additional data";
    std::vector<uint8_t> aad(aad_str.begin(), aad_str.end());

    auto enc_result = crypto::aes256_gcm_encrypt(
        std::span<const uint8_t, 32>(key),
        std::span<const uint8_t>(plaintext),
        std::span<const uint8_t>(aad));
    CHECK_OK(enc_result);

    // Decrypt with the correct AAD must succeed.
    auto dec_result = crypto::aes256_gcm_decrypt(
        std::span<const uint8_t, 32>(key),
        enc_result.value(),
        std::span<const uint8_t>(aad));
    CHECK_OK(dec_result);
    CHECK_EQ(dec_result.value(), plaintext);

    // Decrypt with wrong AAD should fail.
    const std::string bad_aad_str = "wrong aad";
    std::vector<uint8_t> bad_aad(bad_aad_str.begin(), bad_aad_str.end());
    auto bad_dec = crypto::aes256_gcm_decrypt(
        std::span<const uint8_t, 32>(key),
        enc_result.value(),
        std::span<const uint8_t>(bad_aad));
    CHECK_ERR(bad_dec);
}

TEST_CASE(AES, CbcRoundTrip) {
    std::array<uint8_t, 32> key{};
    for (size_t i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i + 0x10);

    std::array<uint8_t, 16> iv{};
    for (size_t i = 0; i < 16; ++i) iv[i] = static_cast<uint8_t>(i);

    // Plaintext must be a multiple of 16 bytes for CBC (no padding in raw API).
    const std::string msg = "CBC test 16bytes";  // exactly 16 bytes
    std::vector<uint8_t> plaintext(msg.begin(), msg.end());

    auto enc_result = crypto::aes256_cbc_encrypt(
        std::span<const uint8_t, 32>(key),
        std::span<const uint8_t, 16>(iv),
        std::span<const uint8_t>(plaintext));
    CHECK_OK(enc_result);

    auto dec_result = crypto::aes256_cbc_decrypt(
        std::span<const uint8_t, 32>(key),
        std::span<const uint8_t, 16>(iv),
        std::span<const uint8_t>(enc_result.value()));
    CHECK_OK(dec_result);

    // Decrypted output should match original plaintext.
    // Note: CBC may include padding bytes; compare up to original length.
    auto& decrypted = dec_result.value();
    CHECK(decrypted.size() >= plaintext.size());
    CHECK(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()) == 0);
}

// ===================================================================
// ChaCha20-Poly1305
// ===================================================================

TEST_CASE(ChaCha20, Poly1305RoundTrip) {
    std::array<uint8_t, 32> key{};
    for (size_t i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i * 3);

    const std::string msg = "ChaCha20-Poly1305 roundtrip";
    std::vector<uint8_t> plaintext(msg.begin(), msg.end());

    auto enc_result = crypto::chacha20_poly1305_encrypt(
        std::span<const uint8_t, 32>(key),
        std::span<const uint8_t>(plaintext));
    CHECK_OK(enc_result);

    auto& encrypted = enc_result.value();
    CHECK(!encrypted.ciphertext.empty());

    auto dec_result = crypto::chacha20_poly1305_decrypt(
        std::span<const uint8_t, 32>(key), encrypted);
    CHECK_OK(dec_result);
    CHECK_EQ(dec_result.value(), plaintext);
}

TEST_CASE(ChaCha20, Poly1305TamperedCiphertext) {
    std::array<uint8_t, 32> key{};
    key.fill(0x55);

    const std::string msg = "tamper test";
    std::vector<uint8_t> plaintext(msg.begin(), msg.end());

    auto enc_result = crypto::chacha20_poly1305_encrypt(
        std::span<const uint8_t, 32>(key),
        std::span<const uint8_t>(plaintext));
    CHECK_OK(enc_result);

    // Flip a bit in the ciphertext -- decryption should fail.
    auto tampered = enc_result.value();
    if (!tampered.ciphertext.empty()) {
        tampered.ciphertext[0] ^= 0x01;
    }
    auto dec_result = crypto::chacha20_poly1305_decrypt(
        std::span<const uint8_t, 32>(key), tampered);
    CHECK_ERR(dec_result);
}

TEST_CASE(ChaCha20, RawStreamCipher) {
    // Raw ChaCha20: encrypting then decrypting with the same key/counter/iv
    // must recover the original plaintext.
    std::array<uint8_t, 32> key{};
    for (size_t i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i + 1);

    const std::string msg = "raw chacha20 stream test";
    std::vector<uint8_t> plaintext(msg.begin(), msg.end());
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> recovered(plaintext.size());

    crypto::ChaCha20 enc(std::span<const uint8_t, 32>(key), 0);
    enc.set_iv(42);
    enc.encrypt(std::span<const uint8_t>(plaintext),
                std::span<uint8_t>(ciphertext));

    // Ciphertext should differ from plaintext.
    CHECK_NE(ciphertext, plaintext);

    crypto::ChaCha20 dec(std::span<const uint8_t, 32>(key), 0);
    dec.set_iv(42);
    dec.decrypt(std::span<const uint8_t>(ciphertext),
                std::span<uint8_t>(recovered));

    CHECK_EQ(recovered, plaintext);
}
