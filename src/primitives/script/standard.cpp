// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/script/standard.h"

#include "primitives/script/opcodes.h"

#include <cstdint>

namespace primitives::script {

// ---------------------------------------------------------------------------
// txout_type_name
// ---------------------------------------------------------------------------

std::string_view txout_type_name(TxoutType type) {
    switch (type) {
        case TxoutType::NONSTANDARD:           return "nonstandard";
        case TxoutType::PUBKEY:                return "pubkey";
        case TxoutType::PUBKEYHASH:            return "pubkeyhash";
        case TxoutType::SCRIPTHASH:            return "scripthash";
        case TxoutType::MULTISIG:              return "multisig";
        case TxoutType::NULL_DATA:             return "nulldata";
        case TxoutType::WITNESS_V0_KEYHASH:    return "witness_v0_keyhash";
        case TxoutType::WITNESS_V0_SCRIPTHASH: return "witness_v0_scripthash";
        case TxoutType::WITNESS_V1_TAPROOT:    return "witness_v1_taproot";
        case TxoutType::WITNESS_UNKNOWN:       return "witness_unknown";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// Internal helpers for script byte inspection
// ---------------------------------------------------------------------------

namespace {

/// Check whether a script byte sequence matches the P2PKH template:
///   OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
/// Total length: 25 bytes
bool match_p2pkh(const std::vector<uint8_t>& s) {
    return s.size() == 25 &&
           s[0] == static_cast<uint8_t>(Opcode::OP_DUP) &&
           s[1] == static_cast<uint8_t>(Opcode::OP_HASH160) &&
           s[2] == 0x14 &&  // push 20 bytes
           s[23] == static_cast<uint8_t>(Opcode::OP_EQUALVERIFY) &&
           s[24] == static_cast<uint8_t>(Opcode::OP_CHECKSIG);
}

/// Check for P2SH: OP_HASH160 <20 bytes> OP_EQUAL
/// Total length: 23 bytes
bool match_p2sh(const std::vector<uint8_t>& s) {
    return s.size() == 23 &&
           s[0] == static_cast<uint8_t>(Opcode::OP_HASH160) &&
           s[1] == 0x14 &&  // push 20 bytes
           s[22] == static_cast<uint8_t>(Opcode::OP_EQUAL);
}

/// Check for bare pubkey: <33 or 65 bytes> OP_CHECKSIG
bool match_pubkey(const std::vector<uint8_t>& s) {
    // Compressed: 0x21 <33 bytes> OP_CHECKSIG = 35 bytes
    if (s.size() == 35 && s[0] == 0x21 &&
        s[34] == static_cast<uint8_t>(Opcode::OP_CHECKSIG)) {
        uint8_t prefix = s[1];
        return prefix == 0x02 || prefix == 0x03;
    }
    // Uncompressed: 0x41 <65 bytes> OP_CHECKSIG = 67 bytes
    if (s.size() == 67 && s[0] == 0x41 &&
        s[66] == static_cast<uint8_t>(Opcode::OP_CHECKSIG)) {
        return s[1] == 0x04;
    }
    return false;
}

/// Check for OP_RETURN (null data): OP_RETURN [push data]
bool match_null_data(const std::vector<uint8_t>& s) {
    if (s.size() < 1 || s[0] != static_cast<uint8_t>(Opcode::OP_RETURN)) {
        return false;
    }
    // All remaining bytes must be push-only data.
    // Validate that we can parse the remainder as push operations.
    size_t pos = 1;
    while (pos < s.size()) {
        uint8_t op = s[pos];
        if (op <= 0x4b) {
            // OP_PUSHBYTES_N
            pos += 1 + op;
        } else if (op == static_cast<uint8_t>(Opcode::OP_PUSHDATA1)) {
            if (pos + 1 >= s.size()) return false;
            uint8_t len = s[pos + 1];
            pos += 2 + len;
        } else if (op == static_cast<uint8_t>(Opcode::OP_PUSHDATA2)) {
            if (pos + 2 >= s.size()) return false;
            uint16_t len = static_cast<uint16_t>(s[pos + 1]) |
                           (static_cast<uint16_t>(s[pos + 2]) << 8);
            pos += 3 + len;
        } else if (op == static_cast<uint8_t>(Opcode::OP_PUSHDATA4)) {
            if (pos + 4 >= s.size()) return false;
            uint32_t len = static_cast<uint32_t>(s[pos + 1]) |
                           (static_cast<uint32_t>(s[pos + 2]) << 8) |
                           (static_cast<uint32_t>(s[pos + 3]) << 16) |
                           (static_cast<uint32_t>(s[pos + 4]) << 24);
            pos += 5 + len;
        } else {
            // Non-push opcode after OP_RETURN -- not valid null data.
            return false;
        }
    }
    return pos == s.size();
}

/// Try to match a bare multisig:
///   OP_m <pk1> ... <pkN> OP_n OP_CHECKMULTISIG
/// Returns {true, m, n, vector_of_pubkeys} on match.
struct MultisigMatch {
    bool matched = false;
    int required = 0;
    int total = 0;
    std::vector<std::vector<uint8_t>> pubkeys;
};

MultisigMatch match_multisig(const std::vector<uint8_t>& s) {
    MultisigMatch result;
    if (s.size() < 3) return result;

    // Last byte must be OP_CHECKMULTISIG
    if (s.back() != static_cast<uint8_t>(Opcode::OP_CHECKMULTISIG)) {
        return result;
    }

    // First byte: OP_1..OP_16 for required count
    auto m_opt = decode_small_int(static_cast<Opcode>(s[0]));
    if (!m_opt || *m_opt < 1) return result;
    int m = *m_opt;

    // Second-to-last byte before OP_CHECKMULTISIG: OP_1..OP_16 for total
    auto n_opt = decode_small_int(
        static_cast<Opcode>(s[s.size() - 2]));
    if (!n_opt || *n_opt < 1 || *n_opt > MAX_PUBKEYS_PER_MULTISIG) {
        return result;
    }
    int n = *n_opt;

    if (m > n) return result;

    // Parse the pubkeys between the first and last opcode pair
    size_t pos = 1;
    std::vector<std::vector<uint8_t>> pubkeys;
    for (int i = 0; i < n; ++i) {
        if (pos >= s.size() - 2) return result;
        uint8_t push_len = s[pos];
        // Valid pubkey pushes are 33 (compressed) or 65 (uncompressed)
        if (push_len != 33 && push_len != 65) return result;
        pos++;
        if (pos + push_len > s.size() - 2) return result;
        pubkeys.emplace_back(s.begin() + pos,
                             s.begin() + pos + push_len);
        pos += push_len;
    }

    // After parsing all pubkeys, pos should point to the OP_N byte
    if (pos != s.size() - 2) return result;

    result.matched = true;
    result.required = m;
    result.total = n;
    result.pubkeys = std::move(pubkeys);
    return result;
}

/// Try to match a witness program: OP_n <2-40 byte program>
/// version 0: OP_0 + (20 or 32 bytes)
/// version 1-16: OP_1..OP_16 + (2-40 bytes)
struct WitnessMatch {
    bool matched = false;
    int version = -1;
    std::vector<uint8_t> program;
};

WitnessMatch match_witness(const std::vector<uint8_t>& s) {
    WitnessMatch result;
    // Minimum: OP_n + push_len_byte + 2 bytes program = 4 bytes
    // Maximum: OP_n + push_len_byte + 40 bytes program = 42 bytes
    if (s.size() < 4 || s.size() > 42) return result;

    // First byte must be a small integer opcode: OP_0..OP_16
    auto ver_opt = decode_small_int(static_cast<Opcode>(s[0]));
    if (!ver_opt) return result;
    int ver = *ver_opt;

    // Second byte is a direct push length (OP_PUSHBYTES_N)
    uint8_t push_len = s[1];
    if (push_len < 2 || push_len > 40) return result;

    // Total length check: 1 (version) + 1 (push_len) + push_len
    if (s.size() != static_cast<size_t>(2 + push_len)) return result;

    result.matched = true;
    result.version = ver;
    result.program.assign(s.begin() + 2, s.end());
    return result;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// classify
// ---------------------------------------------------------------------------

TxoutType classify(const Script& script) {
    const auto& s = script.data();

    if (s.empty()) return TxoutType::NONSTANDARD;

    // Check witness programs first (they are the most common in modern usage)
    auto wit = match_witness(s);
    if (wit.matched) {
        if (wit.version == 0) {
            if (wit.program.size() == 20) {
                return TxoutType::WITNESS_V0_KEYHASH;
            }
            if (wit.program.size() == 32) {
                return TxoutType::WITNESS_V0_SCRIPTHASH;
            }
            // Witness v0 with invalid program length is nonstandard
            return TxoutType::NONSTANDARD;
        }
        if (wit.version == 1 && wit.program.size() == 32) {
            return TxoutType::WITNESS_V1_TAPROOT;
        }
        if (wit.version >= 2) {
            return TxoutType::WITNESS_UNKNOWN;
        }
        // version 1 with non-32-byte program
        return TxoutType::WITNESS_UNKNOWN;
    }

    if (match_p2pkh(s))    return TxoutType::PUBKEYHASH;
    if (match_p2sh(s))     return TxoutType::SCRIPTHASH;
    if (match_pubkey(s))   return TxoutType::PUBKEY;
    if (match_null_data(s)) return TxoutType::NULL_DATA;

    auto ms = match_multisig(s);
    if (ms.matched) return TxoutType::MULTISIG;

    return TxoutType::NONSTANDARD;
}

// ---------------------------------------------------------------------------
// solve
// ---------------------------------------------------------------------------

ScriptSolution solve(const Script& script) {
    ScriptSolution sol;
    const auto& s = script.data();

    if (s.empty()) {
        sol.type = TxoutType::NONSTANDARD;
        return sol;
    }

    // Witness programs
    auto wit = match_witness(s);
    if (wit.matched) {
        if (wit.version == 0 && wit.program.size() == 20) {
            sol.type = TxoutType::WITNESS_V0_KEYHASH;
            sol.solutions.push_back(std::move(wit.program));
            sol.required_sigs = 1;
            return sol;
        }
        if (wit.version == 0 && wit.program.size() == 32) {
            sol.type = TxoutType::WITNESS_V0_SCRIPTHASH;
            sol.solutions.push_back(std::move(wit.program));
            return sol;
        }
        if (wit.version == 1 && wit.program.size() == 32) {
            sol.type = TxoutType::WITNESS_V1_TAPROOT;
            sol.solutions.push_back(std::move(wit.program));
            sol.required_sigs = 1;
            return sol;
        }
        sol.type = TxoutType::WITNESS_UNKNOWN;
        sol.solutions.push_back(std::move(wit.program));
        return sol;
    }

    // P2PKH
    if (match_p2pkh(s)) {
        sol.type = TxoutType::PUBKEYHASH;
        // Extract the 20-byte hash (bytes 3..22 inclusive)
        sol.solutions.emplace_back(s.begin() + 3, s.begin() + 23);
        sol.required_sigs = 1;
        return sol;
    }

    // P2SH
    if (match_p2sh(s)) {
        sol.type = TxoutType::SCRIPTHASH;
        // Extract the 20-byte hash (bytes 2..21 inclusive)
        sol.solutions.emplace_back(s.begin() + 2, s.begin() + 22);
        return sol;
    }

    // Bare pubkey
    if (match_pubkey(s)) {
        sol.type = TxoutType::PUBKEY;
        if (s.size() == 35) {
            // Compressed: bytes 1..33
            sol.solutions.emplace_back(s.begin() + 1, s.begin() + 34);
        } else {
            // Uncompressed: bytes 1..65
            sol.solutions.emplace_back(s.begin() + 1, s.begin() + 66);
        }
        sol.required_sigs = 1;
        return sol;
    }

    // OP_RETURN
    if (match_null_data(s)) {
        sol.type = TxoutType::NULL_DATA;
        // Extract all push data after OP_RETURN
        size_t pos = 1;
        while (pos < s.size()) {
            uint8_t op = s[pos];
            size_t data_start = 0;
            size_t data_len = 0;
            if (op <= 0x4b) {
                data_start = pos + 1;
                data_len = op;
                pos += 1 + op;
            } else if (op ==
                       static_cast<uint8_t>(Opcode::OP_PUSHDATA1)) {
                data_len = s[pos + 1];
                data_start = pos + 2;
                pos += 2 + data_len;
            } else if (op ==
                       static_cast<uint8_t>(Opcode::OP_PUSHDATA2)) {
                data_len = static_cast<uint16_t>(s[pos + 1]) |
                           (static_cast<uint16_t>(s[pos + 2]) << 8);
                data_start = pos + 3;
                pos += 3 + data_len;
            } else {
                // OP_PUSHDATA4
                data_len = static_cast<uint32_t>(s[pos + 1]) |
                           (static_cast<uint32_t>(s[pos + 2]) << 8) |
                           (static_cast<uint32_t>(s[pos + 3]) << 16) |
                           (static_cast<uint32_t>(s[pos + 4]) << 24);
                data_start = pos + 5;
                pos += 5 + data_len;
            }
            sol.solutions.emplace_back(
                s.begin() + data_start,
                s.begin() + data_start + data_len);
        }
        sol.required_sigs = 0;
        return sol;
    }

    // Multisig
    auto ms = match_multisig(s);
    if (ms.matched) {
        sol.type = TxoutType::MULTISIG;
        sol.required_sigs = ms.required;
        sol.solutions = std::move(ms.pubkeys);
        return sol;
    }

    sol.type = TxoutType::NONSTANDARD;
    return sol;
}

// ---------------------------------------------------------------------------
// is_standard_tx_output
// ---------------------------------------------------------------------------

bool is_standard_tx_output(const Script& script) {
    TxoutType type = classify(script);

    switch (type) {
        case TxoutType::NONSTANDARD:
            return false;

        case TxoutType::NULL_DATA:
            // OP_RETURN outputs are standard only if total size is within
            // the relay limit.
            return script.size() <= MAX_OP_RETURN_RELAY;

        case TxoutType::MULTISIG: {
            // Only standard if the number of keys is within the limit.
            auto ms = match_multisig(script.data());
            if (!ms.matched) return false;
            return ms.total <= MAX_STANDARD_MULTISIG_KEYS;
        }

        case TxoutType::PUBKEY:
        case TxoutType::PUBKEYHASH:
        case TxoutType::SCRIPTHASH:
        case TxoutType::WITNESS_V0_KEYHASH:
        case TxoutType::WITNESS_V0_SCRIPTHASH:
        case TxoutType::WITNESS_V1_TAPROOT:
        case TxoutType::WITNESS_UNKNOWN:
            return true;
    }

    return false;
}

} // namespace primitives::script
