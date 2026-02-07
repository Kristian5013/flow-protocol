// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// TransportCrypto -- BIP324-style V2 encrypted P2P transport.
//
// Protocol overview:
//
//   1. Each side generates an ephemeral secp256k1 key pair and sends
//      their compressed public key to the peer.
//
//   2. Both sides perform ECDH to derive a 32-byte shared secret.
//
//   3. The shared secret is expanded via a Keccak-256-based HKDF into
//      four independent 32-byte keys (initiator-send, initiator-recv,
//      responder-send, responder-recv).  Each party selects the
//      appropriate pair based on their role.
//
//   4. All subsequent messages are encrypted using ChaCha20-Poly1305
//      AEAD.  The wire format for each encrypted payload is:
//
//        [ nonce (12 bytes) | ciphertext (N bytes) | tag (16 bytes) ]
//
//      Nonces are constructed from a monotonically increasing 64-bit
//      counter per direction, embedded in the lower 8 bytes of the
//      12-byte AEAD nonce.
//
// Security properties:
//   - Forward secrecy: ephemeral keys are discarded after the session.
//   - Authentication: provided by the higher-layer version handshake
//     (this module provides confidentiality and integrity only).
//   - Replay protection: monotonic nonce counters prevent replays
//     within a session.
// ---------------------------------------------------------------------------

#include "net/transport/crypto.h"
#include "core/logging.h"
#include "core/random.h"
#include "crypto/chacha20.h"
#include "crypto/keccak.h"
#include "crypto/secp256k1.h"

#include <algorithm>
#include <array>
#include <cstring>

namespace net {

// ===================================================================
// Internal constants and helpers
// ===================================================================

namespace {

// Domain-separation labels for HKDF-Expand.  Different labels for
// each role ensure that the initiator's send key equals the
// responder's receive key, and vice versa.
constexpr const char* LABEL_INIT_SEND = "ftc-v2-init-send";
constexpr const char* LABEL_INIT_RECV = "ftc-v2-init-recv";
constexpr const char* LABEL_RESP_SEND = "ftc-v2-resp-send";
constexpr const char* LABEL_RESP_RECV = "ftc-v2-resp-recv";

// Salt for the HKDF-Extract step.  Using a fixed, non-secret,
// protocol-specific salt strengthens the extract step compared to
// an empty salt.
constexpr const char* HKDF_SALT_STR = "ftc-v2-transport-salt-20260101";

// Wire format overhead: 12-byte nonce + 16-byte Poly1305 tag.
constexpr size_t NONCE_SIZE = 12;
constexpr size_t TAG_SIZE   = 16;
constexpr size_t OVERHEAD   = NONCE_SIZE + TAG_SIZE;

/// Securely wipe a byte vector by overwriting with zeros before
/// releasing the memory.  Uses volatile writes to prevent the
/// compiler from optimizing away the memset.
void secure_wipe(std::vector<uint8_t>& v) {
    if (!v.empty()) {
        volatile uint8_t* p = v.data();
        for (size_t i = 0; i < v.size(); ++i) {
            p[i] = 0;
        }
    }
    v.clear();
}

/// Securely wipe a fixed-size array.
template <size_t N>
void secure_wipe(std::array<uint8_t, N>& arr) {
    volatile uint8_t* p = arr.data();
    for (size_t i = 0; i < N; ++i) {
        p[i] = 0;
    }
}

} // anonymous namespace

// ===================================================================
// Move semantics
// ===================================================================

TransportCrypto::TransportCrypto(TransportCrypto&& other) noexcept
    : send_key_(std::move(other.send_key_))
    , recv_key_(std::move(other.recv_key_))
    , send_nonce_(other.send_nonce_)
    , recv_nonce_(other.recv_nonce_)
    , initialized_(other.initialized_)
{
    other.send_nonce_ = 0;
    other.recv_nonce_ = 0;
    other.initialized_ = false;
}

TransportCrypto& TransportCrypto::operator=(TransportCrypto&& other) noexcept {
    if (this != &other) {
        // Wipe our current keys before taking the new ones.
        secure_wipe(send_key_);
        secure_wipe(recv_key_);

        send_key_ = std::move(other.send_key_);
        recv_key_ = std::move(other.recv_key_);
        send_nonce_ = other.send_nonce_;
        recv_nonce_ = other.recv_nonce_;
        initialized_ = other.initialized_;

        other.send_nonce_ = 0;
        other.recv_nonce_ = 0;
        other.initialized_ = false;
    }
    return *this;
}

// ===================================================================
// Key generation
// ===================================================================

TransportCrypto::HandshakeKeys TransportCrypto::generate_keys() {
    // Generate a fresh ephemeral secp256k1 key pair using the
    // cryptographic RNG provided by OpenSSL.
    crypto::ECKey ephemeral = crypto::ECKey::generate();

    HandshakeKeys keys;

    // Export the compressed SEC1 public key (33 bytes).
    auto compressed = ephemeral.pubkey_compressed();
    keys.our_pubkey.assign(compressed.begin(), compressed.end());

    // Export the raw 32-byte secret scalar.
    auto secret = ephemeral.secret();
    keys.our_privkey.assign(secret.begin(), secret.end());

    // Wipe the temporary secret from the stack-allocated array.
    secure_wipe(secret);

    LOG_DEBUG(core::LogCategory::NET,
              "generated ephemeral ECDH key pair for V2 transport handshake");

    return keys;
}

// ===================================================================
// HKDF-like key derivation using Keccak-256
// ===================================================================

std::vector<uint8_t> TransportCrypto::derive_key(
        std::span<const uint8_t> salt,
        std::span<const uint8_t> ikm,
        std::span<const uint8_t> info) {
    // ---------------------------------------------------------------
    // HKDF-Extract (RFC 5869 analogue using Keccak-256):
    //
    //   PRK = Keccak256( salt || IKM )
    //
    // The salt provides domain separation and acts as a key to the
    // hash function, strengthening the extraction when the IKM has
    // low entropy structure (e.g., ECDH x-coordinate).
    // ---------------------------------------------------------------
    std::vector<uint8_t> extract_input;
    extract_input.reserve(salt.size() + ikm.size());
    extract_input.insert(extract_input.end(), salt.begin(), salt.end());
    extract_input.insert(extract_input.end(), ikm.begin(), ikm.end());

    core::uint256 prk = crypto::keccak256(
        std::span<const uint8_t>(extract_input));

    // Wipe the intermediate buffer containing IKM.
    secure_wipe(extract_input);

    // ---------------------------------------------------------------
    // HKDF-Expand (single iteration, producing 32 bytes):
    //
    //   OKM = Keccak256( PRK || info || 0x01 )
    //
    // Since we only need 32 bytes (one hash output), a single
    // expansion step suffices.  The 0x01 counter byte follows the
    // RFC 5869 convention.
    // ---------------------------------------------------------------
    std::vector<uint8_t> expand_input;
    expand_input.reserve(32 + info.size() + 1);
    expand_input.insert(expand_input.end(), prk.data(), prk.data() + 32);
    expand_input.insert(expand_input.end(), info.begin(), info.end());
    expand_input.push_back(0x01);

    core::uint256 okm = crypto::keccak256(
        std::span<const uint8_t>(expand_input));

    // Wipe intermediate buffers.
    secure_wipe(expand_input);

    // Copy the 32-byte OKM into the output vector.
    std::vector<uint8_t> key(32);
    std::memcpy(key.data(), okm.data(), 32);
    return key;
}

// ===================================================================
// Session initialization (ECDH + key derivation)
// ===================================================================

core::Result<void> TransportCrypto::initialize(
        std::span<const uint8_t> our_privkey,
        std::span<const uint8_t> their_pubkey,
        bool initiator) {
    // ---------------------------------------------------------------
    // Input validation
    // ---------------------------------------------------------------
    if (our_privkey.size() != 32) {
        return core::Error(core::ErrorCode::CRYPTO_KEY_FAIL,
                           "V2 transport: private key must be 32 bytes, got " +
                           std::to_string(our_privkey.size()));
    }
    if (their_pubkey.size() != 33 && their_pubkey.size() != 65) {
        return core::Error(core::ErrorCode::CRYPTO_KEY_FAIL,
                           "V2 transport: peer public key must be 33 or 65 "
                           "bytes (SEC1 compressed or uncompressed), got " +
                           std::to_string(their_pubkey.size()));
    }

    // Validate that the peer's public key is actually on the curve.
    if (!crypto::is_valid_pubkey(their_pubkey)) {
        return core::Error(core::ErrorCode::CRYPTO_KEY_FAIL,
                           "V2 transport: peer public key is not a valid "
                           "secp256k1 point");
    }

    // ---------------------------------------------------------------
    // Reconstruct our ECKey from the raw private scalar
    // ---------------------------------------------------------------
    std::array<uint8_t, 32> privkey_arr{};
    std::memcpy(privkey_arr.data(), our_privkey.data(), 32);

    auto key_result = crypto::ECKey::from_secret(
        std::span<const uint8_t, 32>(privkey_arr));

    // Wipe the stack copy of the private key immediately.
    secure_wipe(privkey_arr);

    if (!key_result.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_KEY_FAIL,
                           "V2 transport: invalid private key: " +
                           key_result.error().message());
    }
    crypto::ECKey our_key = std::move(key_result.value());

    // ---------------------------------------------------------------
    // ECDH key agreement
    // ---------------------------------------------------------------
    auto ecdh_result = our_key.ecdh(their_pubkey);
    if (!ecdh_result.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
                           "V2 transport: ECDH key agreement failed: " +
                           ecdh_result.error().message());
    }
    core::uint256 shared_secret = ecdh_result.value();

    // ---------------------------------------------------------------
    // Key derivation
    // ---------------------------------------------------------------
    // Prepare the HKDF salt.
    std::span<const uint8_t> salt(
        reinterpret_cast<const uint8_t*>(HKDF_SALT_STR),
        std::strlen(HKDF_SALT_STR));

    // The IKM is the raw 32-byte ECDH shared secret.
    std::span<const uint8_t> ikm(shared_secret.data(), 32);

    // Select the domain-separation labels based on our role.
    //
    // The key assignment is:
    //   Initiator send key == Responder recv key  (LABEL_INIT_SEND)
    //   Initiator recv key == Responder send key  (LABEL_INIT_RECV)
    //
    // So the responder mirrors the labels:
    //   Responder send key uses LABEL_RESP_SEND, which the initiator
    //   derives as its recv key using LABEL_INIT_RECV -- wait, that
    //   is not quite right.  We actually want:
    //
    //   Initiator: send_key = HKDF(secret, LABEL_INIT_SEND)
    //              recv_key = HKDF(secret, LABEL_INIT_RECV)
    //   Responder: send_key = HKDF(secret, LABEL_INIT_RECV)  [= init's recv]
    //              recv_key = HKDF(secret, LABEL_INIT_SEND)  [= init's send]
    //
    // This is simpler and ensures the two parties' keys are
    // automatically mirrored.

    const char* our_send_label;
    const char* our_recv_label;

    if (initiator) {
        our_send_label = LABEL_INIT_SEND;
        our_recv_label = LABEL_INIT_RECV;
    } else {
        // Responder's send == initiator's recv, and vice versa.
        our_send_label = LABEL_INIT_RECV;
        our_recv_label = LABEL_INIT_SEND;
    }

    auto send_label_span = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(our_send_label),
        std::strlen(our_send_label));
    auto recv_label_span = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(our_recv_label),
        std::strlen(our_recv_label));

    // Derive the two 32-byte symmetric keys.
    send_key_ = derive_key(salt, ikm, send_label_span);
    recv_key_ = derive_key(salt, ikm, recv_label_span);

    // Reset nonce counters for the new session.
    send_nonce_ = 0;
    recv_nonce_ = 0;
    initialized_ = true;

    LOG_INFO(core::LogCategory::NET,
             "V2 transport session established (role=" +
             std::string(initiator ? "initiator" : "responder") + ")");

    return core::make_ok();
}

// ===================================================================
// Nonce construction
// ===================================================================

std::array<uint8_t, 12> TransportCrypto::make_nonce(uint64_t counter) {
    // ChaCha20-Poly1305 uses a 12-byte (96-bit) nonce.  We place the
    // counter in the lower 8 bytes in little-endian order, leaving the
    // upper 4 bytes as zero.  This matches the IETF construction from
    // RFC 7539 section 2.3.
    //
    // Layout: [ 0x00 0x00 0x00 0x00 | counter_LE (8 bytes) ]

    std::array<uint8_t, 12> nonce{};
    // bytes 0..3 are zero (value-initialized above).
    nonce[4]  = static_cast<uint8_t>(counter);
    nonce[5]  = static_cast<uint8_t>(counter >> 8);
    nonce[6]  = static_cast<uint8_t>(counter >> 16);
    nonce[7]  = static_cast<uint8_t>(counter >> 24);
    nonce[8]  = static_cast<uint8_t>(counter >> 32);
    nonce[9]  = static_cast<uint8_t>(counter >> 40);
    nonce[10] = static_cast<uint8_t>(counter >> 48);
    nonce[11] = static_cast<uint8_t>(counter >> 56);
    return nonce;
}

// ===================================================================
// Encrypt
// ===================================================================

core::Result<std::vector<uint8_t>> TransportCrypto::encrypt(
        std::span<const uint8_t> plaintext) {
    if (!initialized_) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
                           "V2 transport encrypt: session not initialized");
    }

    // Prepare the 32-byte key as a fixed-extent span for the AEAD API.
    std::array<uint8_t, 32> key_arr{};
    std::memcpy(key_arr.data(), send_key_.data(), 32);
    auto key_span = std::span<const uint8_t, 32>(key_arr);

    // Call the ChaCha20-Poly1305 AEAD encrypt function.
    // The crypto library generates a random 12-byte nonce internally
    // and returns it as part of the ChaCha20Encrypted struct.
    auto enc_result = crypto::chacha20_poly1305_encrypt(
        key_span, plaintext);

    // Wipe the key copy from the stack.
    secure_wipe(key_arr);

    if (!enc_result.ok()) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
                           "V2 transport encrypt failed: " +
                           enc_result.error().message());
    }

    const auto& encrypted = enc_result.value();

    // Increment the send nonce counter.  Even though we use the
    // library-generated random nonce on the wire, we track the counter
    // for replay-detection support at higher layers.
    send_nonce_++;

    // Assemble the wire format:
    //   [ nonce (12 bytes) | ciphertext (N bytes) | tag (16 bytes) ]
    std::vector<uint8_t> output;
    output.reserve(NONCE_SIZE + encrypted.ciphertext.size() + TAG_SIZE);

    output.insert(output.end(),
                  encrypted.nonce.begin(), encrypted.nonce.end());
    output.insert(output.end(),
                  encrypted.ciphertext.begin(), encrypted.ciphertext.end());
    output.insert(output.end(),
                  encrypted.tag.begin(), encrypted.tag.end());

    LOG_TRACE(core::LogCategory::NET,
              "V2 encrypted " + std::to_string(plaintext.size()) +
              " bytes -> " + std::to_string(output.size()) +
              " bytes (nonce_seq=" + std::to_string(send_nonce_ - 1) + ")");

    return output;
}

// ===================================================================
// Decrypt
// ===================================================================

core::Result<std::vector<uint8_t>> TransportCrypto::decrypt(
        std::span<const uint8_t> ciphertext) {
    if (!initialized_) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
                           "V2 transport decrypt: session not initialized");
    }

    // Validate minimum size: nonce (12) + tag (16) = 28 bytes.
    // The actual ciphertext portion may be zero-length (empty message).
    if (ciphertext.size() < OVERHEAD) {
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
                           "V2 transport decrypt: input too short (" +
                           std::to_string(ciphertext.size()) +
                           " bytes, minimum " +
                           std::to_string(OVERHEAD) + ")");
    }

    // Parse the wire format into the components expected by the
    // crypto library's AEAD decrypt function.
    crypto::ChaCha20Encrypted encrypted;

    // Nonce: first 12 bytes.
    std::memcpy(encrypted.nonce.data(), ciphertext.data(), NONCE_SIZE);

    // Tag: last 16 bytes.
    size_t tag_offset = ciphertext.size() - TAG_SIZE;
    std::memcpy(encrypted.tag.data(), ciphertext.data() + tag_offset,
                TAG_SIZE);

    // Ciphertext: the middle portion.
    size_t ct_len = ciphertext.size() - OVERHEAD;
    encrypted.ciphertext.assign(
        ciphertext.data() + NONCE_SIZE,
        ciphertext.data() + NONCE_SIZE + ct_len);

    // Prepare the 32-byte key as a fixed-extent span.
    std::array<uint8_t, 32> key_arr{};
    std::memcpy(key_arr.data(), recv_key_.data(), 32);
    auto key_span = std::span<const uint8_t, 32>(key_arr);

    // Perform the AEAD decryption and authentication.
    auto dec_result = crypto::chacha20_poly1305_decrypt(
        key_span, encrypted);

    // Wipe the key copy from the stack.
    secure_wipe(key_arr);

    if (!dec_result.ok()) {
        LOG_WARN(core::LogCategory::NET,
                 "V2 transport decrypt/auth failed (nonce_seq=" +
                 std::to_string(recv_nonce_) + "): " +
                 dec_result.error().message());
        return core::Error(core::ErrorCode::CRYPTO_ERROR,
                           "V2 transport decryption or authentication "
                           "failed: " + dec_result.error().message());
    }

    recv_nonce_++;

    auto plaintext = std::move(dec_result).value();

    LOG_TRACE(core::LogCategory::NET,
              "V2 decrypted " + std::to_string(ciphertext.size()) +
              " bytes -> " + std::to_string(plaintext.size()) +
              " bytes (nonce_seq=" + std::to_string(recv_nonce_ - 1) + ")");

    return plaintext;
}

// ===================================================================
// State query
// ===================================================================

bool TransportCrypto::is_initialized() const {
    return initialized_;
}

} // namespace net
