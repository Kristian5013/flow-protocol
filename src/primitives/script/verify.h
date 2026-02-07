#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/amount.h"
#include "primitives/script/interpreter.h"
#include "primitives/script/script.h"
#include "primitives/transaction.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace primitives::script {

// ---------------------------------------------------------------------------
// High-level transaction verification
// ---------------------------------------------------------------------------

/// Verify all inputs of a transaction against their corresponding spent
/// outputs.
///
/// @param tx             The transaction to verify.
/// @param spent_outputs  A vector of (scriptPubKey, amount) pairs, one per
///                       input, in the same order as tx.vin().
/// @param flags          Script verification flags.
/// @param error_out      If non-null, receives the error code of the first
///                       failing input.
/// @returns true if every input passes script verification.
bool verify_transaction(
    const Transaction& tx,
    const std::vector<std::pair<Script, Amount>>& spent_outputs,
    ScriptFlags flags,
    ScriptError* error_out = nullptr);

/// Verify a single input of a transaction.
///
/// @param tx             The transaction containing the input.
/// @param input_index    Index into tx.vin().
/// @param script_pubkey  The scriptPubKey of the output being spent.
/// @param amount         The amount of the output being spent (needed for
///                       segwit signature hashing).
/// @param flags          Script verification flags.
/// @param error_out      If non-null, receives the error code on failure.
/// @returns true if script verification succeeds.
bool verify_input(
    const Transaction& tx,
    size_t input_index,
    const Script& script_pubkey,
    Amount amount,
    ScriptFlags flags,
    ScriptError* error_out = nullptr);

// ---------------------------------------------------------------------------
// Signature / pubkey encoding validation
// ---------------------------------------------------------------------------

/// Validate the encoding of an ECDSA signature according to the active
/// script flags (DER strictness, low-S, hash type byte, etc.).
bool check_signature_encoding(std::span<const uint8_t> sig,
                              ScriptFlags flags);

/// Validate the encoding of a public key according to the active script
/// flags (compressed-only for witness, valid SEC1 format, etc.).
bool check_pubkey_encoding(std::span<const uint8_t> pubkey,
                           ScriptFlags flags);

/// Return true if @p sig is a valid strict-DER encoded ECDSA signature
/// (without the trailing hashtype byte).  This checks the DER structure
/// only, not the mathematical validity of the signature values.
bool is_valid_signature_encoding(std::span<const uint8_t> sig);

/// Return true if the S value in a DER-encoded signature is in the lower
/// half of the secp256k1 curve order (BIP-62 low-S rule).
bool is_low_der_signature(std::span<const uint8_t> sig);

} // namespace primitives::script
