// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/script/verify.h"

#include "crypto/secp256k1.h"
#include "primitives/script/interpreter.h"
#include "primitives/script/script.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

namespace primitives::script {

// =========================================================================
// DER signature structure validation
// =========================================================================

bool is_valid_signature_encoding(std::span<const uint8_t> sig) {
    // A DER-encoded ECDSA signature has the form:
    //   0x30 <total_len> 0x02 <r_len> <r> 0x02 <s_len> <s>
    //
    // Minimum: 0x30 0x06 0x02 0x01 <r> 0x02 0x01 <s> = 8 bytes
    // Maximum: 0x30 0x44 ... = 70 bytes (for secp256k1)

    if (sig.size() < 8) return false;
    if (sig.size() > 72) return false;

    // Byte 0: compound type tag
    if (sig[0] != 0x30) return false;

    // Byte 1: total length of the remaining data
    if (sig[1] != sig.size() - 2) return false;

    // Byte 2: integer type tag for R
    if (sig[2] != 0x02) return false;

    // Byte 3: length of R
    size_t r_len = sig[3];
    if (r_len == 0) return false;

    // 5 = 1 (0x30) + 1 (total_len) + 1 (0x02) + 1 (r_len) + 1 (at least
    // one byte past R for the S integer tag)
    if (5 + r_len >= sig.size()) return false;

    // The byte after R must be the integer tag for S
    size_t s_tag_pos = 4 + r_len;
    if (sig[s_tag_pos] != 0x02) return false;

    // Length of S
    size_t s_len = sig[s_tag_pos + 1];
    if (s_len == 0) return false;

    // Check that the total length matches:
    //   total_len = 2 (R header) + r_len + 2 (S header) + s_len
    if (static_cast<size_t>(sig[1]) != 2 + r_len + 2 + s_len) {
        return false;
    }

    // Check total size consistency
    if (s_tag_pos + 2 + s_len != sig.size()) return false;

    // R value must not have unnecessary leading zeros (negative flag)
    // A leading 0x00 is only acceptable if the next byte has high bit set.
    if ((sig[4] & 0x80) != 0) return false;  // R must be positive
    if (r_len > 1 && sig[4] == 0x00 && (sig[5] & 0x80) == 0) {
        return false;  // Unnecessary leading zero
    }

    // S value must not have unnecessary leading zeros
    size_t s_start = s_tag_pos + 2;
    if ((sig[s_start] & 0x80) != 0) return false;  // S must be positive
    if (s_len > 1 && sig[s_start] == 0x00 &&
        (sig[s_start + 1] & 0x80) == 0) {
        return false;  // Unnecessary leading zero
    }

    return true;
}

bool is_low_der_signature(std::span<const uint8_t> sig) {
    if (!is_valid_signature_encoding(sig)) return false;

    // Extract the S value from the DER encoding
    size_t r_len = sig[3];
    size_t s_tag_pos = 4 + r_len;
    size_t s_len = sig[s_tag_pos + 1];
    size_t s_start = s_tag_pos + 2;

    // secp256k1 curve order / 2 (half-order):
    // 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    static constexpr std::array<uint8_t, 32> HALF_ORDER = {
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
        0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
    };

    // Pad S to 32 bytes for comparison (big-endian, left-padded with zeros)
    std::array<uint8_t, 32> s_padded{};
    if (s_len > 32) return false;
    size_t offset = 32 - s_len;
    std::memcpy(s_padded.data() + offset, sig.data() + s_start, s_len);

    // Compare S <= half-order (big-endian byte comparison)
    for (size_t i = 0; i < 32; ++i) {
        if (s_padded[i] < HALF_ORDER[i]) return true;
        if (s_padded[i] > HALF_ORDER[i]) return false;
    }
    return true;  // Equal to half-order is also acceptable
}

// =========================================================================
// Encoding checks
// =========================================================================

bool check_signature_encoding(std::span<const uint8_t> sig,
                              ScriptFlags flags) {
    // Empty signatures are always accepted (they just fail CHECKSIG).
    if (sig.empty()) return true;

    // The last byte is the hashtype; the DER signature is everything before.
    auto der_part = sig.subspan(0, sig.size() - 1);

    // DERSIG: require strict DER encoding
    if (has_flag(flags, ScriptFlags::DERSIG)) {
        if (!is_valid_signature_encoding(der_part)) return false;
    }

    // LOW_S: require the S value to be in the lower half of the order
    if (has_flag(flags, ScriptFlags::LOW_S)) {
        if (!is_low_der_signature(der_part)) return false;
    }

    // STRICTENC: validate the hash type byte
    if (has_flag(flags, ScriptFlags::STRICTENC)) {
        uint8_t hash_type = sig.back();
        uint8_t base_type = hash_type & 0x1f;
        if (base_type < Transaction::SIGHASH_ALL ||
            base_type > Transaction::SIGHASH_SINGLE) {
            return false;
        }
    }

    return true;
}

bool check_pubkey_encoding(std::span<const uint8_t> pubkey,
                           ScriptFlags flags) {
    if (pubkey.empty()) return false;

    if (has_flag(flags, ScriptFlags::STRICTENC)) {
        // Must be a valid SEC1 public key
        if (!crypto::is_valid_pubkey(pubkey)) return false;
    }

    // For witness scripts, only compressed public keys are allowed.
    if (has_flag(flags, ScriptFlags::WITNESS_PUBKEYTYPE)) {
        if (pubkey.size() != 33) return false;
        if (pubkey[0] != 0x02 && pubkey[0] != 0x03) return false;
    }

    return true;
}

// =========================================================================
// verify_input
// =========================================================================

bool verify_input(
    const Transaction& tx,
    size_t input_index,
    const Script& script_pubkey,
    Amount amount,
    ScriptFlags flags,
    ScriptError* error_out) {

    if (input_index >= tx.vin().size()) {
        if (error_out) *error_out = ScriptError::UNKNOWN;
        return false;
    }

    const auto& input = tx.vin()[input_index];

    // Build the scriptSig Script object
    Script script_sig(input.script_sig);

    // Build the signature checker for this input
    TransactionSignatureChecker checker(&tx, input_index, amount);

    // Run the full verification: scriptSig + scriptPubKey (+ witness + P2SH)
    return verify_script(script_sig, script_pubkey, input.witness,
                         flags, checker, error_out);
}

// =========================================================================
// verify_transaction
// =========================================================================

bool verify_transaction(
    const Transaction& tx,
    const std::vector<std::pair<Script, Amount>>& spent_outputs,
    ScriptFlags flags,
    ScriptError* error_out) {

    if (spent_outputs.size() != tx.vin().size()) {
        if (error_out) *error_out = ScriptError::UNKNOWN;
        return false;
    }

    for (size_t i = 0; i < tx.vin().size(); ++i) {
        // Skip coinbase inputs -- they have no scriptPubKey to verify
        if (tx.is_coinbase()) {
            continue;
        }

        const auto& [script_pubkey, amount] = spent_outputs[i];

        ScriptError input_error = ScriptError::OK;
        if (!verify_input(tx, i, script_pubkey, amount,
                          flags, &input_error)) {
            if (error_out) *error_out = input_error;
            return false;
        }
    }

    return true;
}

} // namespace primitives::script
