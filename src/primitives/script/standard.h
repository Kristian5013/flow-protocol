#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/script/script.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace primitives::script {

// ---------------------------------------------------------------------------
// Standard transaction output types
// ---------------------------------------------------------------------------

enum class TxoutType {
    NONSTANDARD,
    PUBKEY,                  // <pubkey> OP_CHECKSIG
    PUBKEYHASH,              // OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
    SCRIPTHASH,              // OP_HASH160 <hash> OP_EQUAL
    MULTISIG,                // m <pk>... n OP_CHECKMULTISIG
    NULL_DATA,               // OP_RETURN <data>
    WITNESS_V0_KEYHASH,      // OP_0 <20-byte hash>
    WITNESS_V0_SCRIPTHASH,   // OP_0 <32-byte hash>
    WITNESS_V1_TAPROOT,      // OP_1 <32-byte key>
    WITNESS_UNKNOWN,         // OP_n <program> (future witness versions)
};

/// Human-readable name of a TxoutType value.
std::string_view txout_type_name(TxoutType type);

/// Classify a scriptPubKey into one of the recognised standard types.
TxoutType classify(const Script& script);

// ---------------------------------------------------------------------------
// Script solution -- extracted components from standard scripts
// ---------------------------------------------------------------------------

struct ScriptSolution {
    TxoutType type = TxoutType::NONSTANDARD;

    /// For PUBKEY: {pubkey}
    /// For PUBKEYHASH: {pubkey_hash_20}
    /// For SCRIPTHASH: {script_hash_20}
    /// For MULTISIG: {pk1, pk2, ...}
    /// For NULL_DATA: {data_payload}
    /// For WITNESS_V0_KEYHASH: {keyhash_20}
    /// For WITNESS_V0_SCRIPTHASH: {scripthash_32}
    /// For WITNESS_V1_TAPROOT: {output_key_32}
    /// For WITNESS_UNKNOWN: {program}
    std::vector<std::vector<uint8_t>> solutions;

    /// Number of required signatures (meaningful for MULTISIG).
    int required_sigs = 0;
};

/// Classify a scriptPubKey and extract the solution components.
ScriptSolution solve(const Script& script);

/// Check if a scriptPubKey is considered a "standard" output that should be
/// relayed and mined under default policy.  Non-standard outputs include
/// oversized OP_RETURN payloads and unrecognised script templates.
bool is_standard_tx_output(const Script& script);

/// Maximum number of bytes allowed in an OP_RETURN data carrier output
/// (including the OP_RETURN opcode itself and push opcodes).
static constexpr size_t MAX_OP_RETURN_RELAY = 83;

/// Maximum number of public keys in a standard bare multisig output.
static constexpr int MAX_STANDARD_MULTISIG_KEYS = 3;

} // namespace primitives::script
