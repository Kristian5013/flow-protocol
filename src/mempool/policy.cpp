// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Mempool relay policy implementation
// ---------------------------------------------------------------------------
// This file implements the "standardness" checks that determine whether a
// transaction is eligible for relay and mempool admission. These are
// policy rules, not consensus rules: a transaction that fails them can
// still be included in a block by a miner, but it will not be relayed by
// nodes running the default policy.
//
// The standardness checks exist to:
//   1. Prevent resource exhaustion by rejecting excessively large or
//      complex transactions.
//   2. Discourage dust outputs that bloat the UTXO set without economic
//      justification.
//   3. Reject non-standard script types that may be used for spam.
//   4. Enforce minimum relay fees to prevent free-riding on network
//      bandwidth.
//   5. Maintain forward compatibility by allowing well-known script types
//      and future witness versions while rejecting arbitrary scripts.
//
// All policy checks return core::Result<void>, where an error indicates
// rejection with a human-readable reason. The caller (Mempool::add) logs
// the rejection reason and returns it to the upstream caller.
// ---------------------------------------------------------------------------

#include "mempool/policy.h"

#include "core/error.h"
#include "core/logging.h"
#include "core/types.h"
#include "primitives/amount.h"
#include "primitives/transaction.h"
#include "primitives/txin.h"
#include "primitives/txout.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace mempool {

// ---------------------------------------------------------------------------
// Script type classification
// ---------------------------------------------------------------------------
// These are simplified pattern-match checks on the raw scriptPubKey bytes.
// They cover the most common standard output types. Unknown witness versions
// are classified as WITNESS_UNKNOWN to allow forward-compatible relay.
// ---------------------------------------------------------------------------

ScriptType classify_script(const std::vector<uint8_t>& script_pubkey) {
    const size_t sz = script_pubkey.size();

    if (sz == 0) {
        return ScriptType::NONSTANDARD;
    }

    // OP_RETURN: starts with 0x6a
    if (script_pubkey[0] == 0x6a) {
        return ScriptType::OP_RETURN;
    }

    // P2PKH: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
    // Bytes: 76 a9 14 <20 bytes> 88 ac  (total 25 bytes)
    if (sz == 25
        && script_pubkey[0] == 0x76
        && script_pubkey[1] == 0xa9
        && script_pubkey[2] == 0x14
        && script_pubkey[23] == 0x88
        && script_pubkey[24] == 0xac) {
        return ScriptType::P2PKH;
    }

    // P2SH: OP_HASH160 <20> <hash> OP_EQUAL
    // Bytes: a9 14 <20 bytes> 87  (total 23 bytes)
    if (sz == 23
        && script_pubkey[0] == 0xa9
        && script_pubkey[1] == 0x14
        && script_pubkey[22] == 0x87) {
        return ScriptType::P2SH;
    }

    // Witness programs: version byte (0x00-0x10) followed by a push of
    // 2-40 bytes.
    // OP_0 = 0x00; OP_1..OP_16 = 0x51..0x60
    if (sz >= 4 && sz <= 42) {
        uint8_t version_opcode = script_pubkey[0];
        bool is_witness_version = (version_opcode == 0x00)
            || (version_opcode >= 0x51 && version_opcode <= 0x60);

        if (is_witness_version) {
            uint8_t push_size = script_pubkey[1];
            // The push opcode should directly encode the length (2-40).
            if (push_size >= 2 && push_size <= 40
                && static_cast<size_t>(push_size + 2) == sz) {
                int witness_version = (version_opcode == 0x00)
                    ? 0
                    : (version_opcode - 0x50);

                if (witness_version == 0 && push_size == 20) {
                    return ScriptType::P2WPKH;
                }
                if (witness_version == 0 && push_size == 32) {
                    return ScriptType::P2WSH;
                }
                if (witness_version == 1 && push_size == 32) {
                    return ScriptType::P2TR;
                }
                // Future witness versions (2-16) or non-standard lengths
                // for v0/v1 are relay-permitted under BIP141.
                if (witness_version >= 2) {
                    return ScriptType::WITNESS_UNKNOWN;
                }
                // Witness v0 with wrong push size, or v1 with wrong push
                // size, is nonstandard.
                return ScriptType::NONSTANDARD;
            }
        }
    }

    // P2PK: <33 or 65 bytes pubkey> OP_CHECKSIG
    // Compressed: 21 <33 bytes> ac  (total 35)
    // Uncompressed: 41 <65 bytes> ac  (total 67)
    if ((sz == 35 && script_pubkey[0] == 0x21
         && script_pubkey[34] == 0xac)
        || (sz == 67 && script_pubkey[0] == 0x41
            && script_pubkey[66] == 0xac)) {
        return ScriptType::P2PK;
    }

    // Bare multisig: OP_m <pubkeys...> OP_n OP_CHECKMULTISIG
    // OP_1..OP_16 = 0x51..0x60; OP_CHECKMULTISIG = 0xae
    if (sz >= 37 && script_pubkey[sz - 1] == 0xae) {
        uint8_t last_n = script_pubkey[sz - 2];
        uint8_t first_m = script_pubkey[0];
        if (first_m >= 0x51 && first_m <= 0x60
            && last_n >= 0x51 && last_n <= 0x60) {
            int m = first_m - 0x50;
            int n = last_n - 0x50;
            if (m >= 1 && n >= 1 && m <= n
                && static_cast<size_t>(n) <= MAX_STANDARD_MULTISIG_KEYS) {
                return ScriptType::MULTISIG;
            }
        }
    }

    return ScriptType::NONSTANDARD;
}

// ---------------------------------------------------------------------------
// Estimated spending input sizes
// ---------------------------------------------------------------------------

size_t estimated_input_vsize(ScriptType type) {
    switch (type) {
        case ScriptType::P2PKH:
            // outpoint(36) + sequence(4) + scriptSig(1+~107) = ~148 bytes
            return 148;
        case ScriptType::P2SH:
            // Assuming P2SH-P2WPKH: outpoint(36) + sequence(4)
            // + scriptSig(1+23) + witness(~107/4) = ~91 vbytes
            return 91;
        case ScriptType::P2WPKH:
            // outpoint(36) + sequence(4) + scriptSig(1)
            // + witness(1+1+72+1+33)/4 = ~68 vbytes
            return 68;
        case ScriptType::P2WSH:
            // outpoint(36) + sequence(4) + scriptSig(1)
            // + witness(~252/4) = ~104 vbytes
            return 104;
        case ScriptType::P2TR:
            // outpoint(36) + sequence(4) + scriptSig(1)
            // + witness(1+65)/4 = ~57.5 vbytes, round up to 58
            return 58;
        case ScriptType::P2PK:
            // outpoint(36) + sequence(4) + scriptSig(1+72) = ~113 bytes
            return 113;
        case ScriptType::MULTISIG:
            // 1-of-3 bare multisig: ~~195 bytes
            return 195;
        case ScriptType::WITNESS_UNKNOWN:
            // Conservative estimate for future witness types.
            return 110;
        case ScriptType::OP_RETURN:
            // OP_RETURN outputs are provably unspendable; the cost of
            // spending them is effectively infinite, but we return 0
            // since they should never be counted.
            return 0;
        case ScriptType::NONSTANDARD:
        default:
            // Fallback: 32 + script_pubkey size is used when we have the
            // actual script. For the generic case, use a conservative value.
            return 178;
    }
}

size_t estimated_input_vsize(const std::vector<uint8_t>& script_pubkey) {
    ScriptType type = classify_script(script_pubkey);
    if (type == ScriptType::NONSTANDARD || type == ScriptType::OP_RETURN) {
        // For nonstandard scripts, estimate based on the script length:
        // outpoint(36) + sequence(4) + scriptSig(1) + ~(32 + scriptLen)
        return 32 + script_pubkey.size() + 41;
    }
    return estimated_input_vsize(type);
}

// ---------------------------------------------------------------------------
// OP_RETURN detection
// ---------------------------------------------------------------------------

bool is_op_return(const std::vector<uint8_t>& script_pubkey) {
    return !script_pubkey.empty() && script_pubkey[0] == 0x6a;
}

// ---------------------------------------------------------------------------
// Dust threshold computation
// ---------------------------------------------------------------------------

primitives::Amount get_dust_threshold(const primitives::TxOutput& output,
                                      int64_t min_relay_fee) {
    // The dust threshold is the minimum output value such that the cost of
    // creating and later spending the output does not exceed its value.
    //
    // spending cost = estimated_input_vsize * fee_rate
    // creation cost = output_vsize * fee_rate
    //   where output_vsize = 8 (amount) + compact_size(scriptLen) + scriptLen
    //
    // A transaction paying less than this is considered uneconomical.

    // Compute the serialized size of the output itself.
    size_t output_size = 8; // amount (int64)
    size_t script_len = output.script_pubkey.size();
    if (script_len < 253) {
        output_size += 1; // compact size: 1 byte
    } else if (script_len < 0x10000) {
        output_size += 3;
    } else {
        output_size += 5;
    }
    output_size += script_len;

    // Estimated virtual bytes to spend this output.
    size_t spend_size = estimated_input_vsize(output.script_pubkey);

    // OP_RETURN outputs are unspendable and should always be allowed
    // (they are provably prunable).
    if (is_op_return(output.script_pubkey)) {
        return primitives::Amount{0};
    }

    // Total cost = (output_size + spend_size) * fee_rate / 1000
    // (fee_rate is in sat/kvB, so divide by 1000)
    // Round up to avoid rounding below the threshold.
    size_t total_size = output_size + spend_size;
    int64_t threshold = (static_cast<int64_t>(total_size)
                         * min_relay_fee + 999) / 1000;

    return primitives::Amount{threshold};
}

bool is_dust(const primitives::TxOutput& output, int64_t min_relay_fee) {
    // OP_RETURN is never dust (it is unspendable by design).
    if (is_op_return(output.script_pubkey)) {
        return false;
    }

    primitives::Amount threshold = get_dust_threshold(output, min_relay_fee);
    return output.amount < threshold;
}

// ---------------------------------------------------------------------------
// Virtual fee computation
// ---------------------------------------------------------------------------

int64_t get_virtual_fee(const primitives::Transaction& tx,
                        int64_t fee_rate) {
    size_t vs = tx.vsize();
    // fee = vsize * fee_rate / 1000 (fee_rate is sat/kvB)
    // Round up.
    return (static_cast<int64_t>(vs) * fee_rate + 999) / 1000;
}

// ---------------------------------------------------------------------------
// Minimum relay fee check
// ---------------------------------------------------------------------------

core::Result<void> check_min_relay_fee(const primitives::Transaction& tx,
                                       primitives::Amount fee) {
    int64_t required = get_virtual_fee(tx, MIN_RELAY_FEE);
    if (fee.value() < required) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "insufficient fee: have " + std::to_string(fee.value())
            + " sat, need at least " + std::to_string(required)
            + " sat (min relay fee " + std::to_string(MIN_RELAY_FEE)
            + " sat/kvB)");
    }
    return core::make_ok();
}

// ---------------------------------------------------------------------------
// Dust check for all outputs
// ---------------------------------------------------------------------------

core::Result<void> check_dust(const primitives::Transaction& tx,
                              int64_t min_relay_fee) {
    for (size_t i = 0; i < tx.vout().size(); ++i) {
        const auto& output = tx.vout()[i];
        if (is_dust(output, min_relay_fee)) {
            primitives::Amount threshold =
                get_dust_threshold(output, min_relay_fee);
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "output " + std::to_string(i) + " is dust: amount "
                + std::to_string(output.amount.value())
                + " sat < threshold " + std::to_string(threshold.value())
                + " sat");
        }
    }
    return core::make_ok();
}

// ---------------------------------------------------------------------------
// Bare multisig check
// ---------------------------------------------------------------------------

core::Result<void> check_bare_multisig(const primitives::Transaction& tx) {
    for (size_t i = 0; i < tx.vout().size(); ++i) {
        ScriptType type = classify_script(tx.vout()[i].script_pubkey);
        if (type == ScriptType::MULTISIG) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "output " + std::to_string(i) + " is bare multisig, "
                "which is non-standard for relay");
        }
    }
    return core::make_ok();
}

// ---------------------------------------------------------------------------
// check_standard -- full standardness check
// ---------------------------------------------------------------------------

core::Result<void> check_standard(const primitives::Transaction& tx) {
    // --- Version check ---
    int32_t ver = tx.version();
    if (ver < 1 || ver > 2) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "non-standard transaction version: " + std::to_string(ver));
    }

    // --- Size checks ---
    size_t total = tx.total_size();
    if (total > MAX_STANDARD_TX_SIZE) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "transaction size " + std::to_string(total)
            + " exceeds maximum standard size "
            + std::to_string(MAX_STANDARD_TX_SIZE));
    }

    size_t w = tx.weight();
    if (w > MAX_STANDARD_TX_WEIGHT) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "transaction weight " + std::to_string(w)
            + " exceeds maximum standard weight "
            + std::to_string(MAX_STANDARD_TX_WEIGHT));
    }

    // --- Empty inputs/outputs ---
    if (tx.vin().empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "transaction has no inputs");
    }
    if (tx.vout().empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "transaction has no outputs");
    }

    // --- Input/output count limits ---
    if (tx.vin().size() > MAX_STANDARD_TX_INPUTS) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "transaction has " + std::to_string(tx.vin().size())
            + " inputs, exceeding maximum "
            + std::to_string(MAX_STANDARD_TX_INPUTS));
    }
    if (tx.vout().size() > MAX_STANDARD_TX_OUTPUTS) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "transaction has " + std::to_string(tx.vout().size())
            + " outputs, exceeding maximum "
            + std::to_string(MAX_STANDARD_TX_OUTPUTS));
    }

    // --- scriptSig size limits ---
    for (size_t i = 0; i < tx.vin().size(); ++i) {
        const auto& input = tx.vin()[i];
        if (input.script_sig.size() > MAX_STANDARD_SCRIPTSIG_SIZE) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "input " + std::to_string(i) + " scriptSig size "
                + std::to_string(input.script_sig.size())
                + " exceeds maximum " + std::to_string(
                    MAX_STANDARD_SCRIPTSIG_SIZE));
        }
    }

    // --- Output amount and type checks ---
    for (size_t i = 0; i < tx.vout().size(); ++i) {
        const auto& output = tx.vout()[i];

        // Non-negative amounts.
        if (output.amount.value() < 0) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "output " + std::to_string(i) + " has negative amount "
                + std::to_string(output.amount.value()));
        }

        // Check that amounts are within the valid money range.
        if (!output.amount.is_valid()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "output " + std::to_string(i) + " amount "
                + std::to_string(output.amount.value())
                + " exceeds MAX_MONEY");
        }

        // OP_RETURN outputs with non-zero value are wasteful but we allow
        // them (they are unspendable regardless). Some protocols use
        // valued OP_RETURN for token burns. We only enforce the dust check
        // on spendable outputs.

        // Check output script type for standardness.
        ScriptType type = classify_script(output.script_pubkey);
        if (type == ScriptType::NONSTANDARD) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "output " + std::to_string(i)
                + " has non-standard script type");
        }
    }

    // --- Bare multisig check ---
    {
        auto result = check_bare_multisig(tx);
        if (!result.ok()) {
            return result;
        }
    }

    // --- Coinbase transactions are not relayable ---
    if (tx.is_coinbase()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "coinbase transactions are not standard for relay");
    }

    // --- Check total output value does not exceed MAX_MONEY ---
    {
        int64_t total_output = 0;
        for (size_t i = 0; i < tx.vout().size(); ++i) {
            const auto& output = tx.vout()[i];
            total_output += output.amount.value();

            // Check for overflow (unlikely with valid amounts, but defensive).
            if (total_output < 0 || total_output > primitives::Amount::MAX_MONEY) {
                return core::Error(core::ErrorCode::VALIDATION_ERROR,
                    "cumulative output value " + std::to_string(total_output)
                    + " exceeds MAX_MONEY at output " + std::to_string(i));
            }
        }
    }

    // --- Check for duplicate inputs ---
    {
        struct OutPointHashLocal {
            std::size_t operator()(const primitives::OutPoint& op) const noexcept {
                return std::hash<primitives::OutPoint>{}(op);
            }
        };
        std::unordered_set<primitives::OutPoint, OutPointHashLocal> seen_inputs;
        for (size_t i = 0; i < tx.vin().size(); ++i) {
            const auto& input = tx.vin()[i];
            if (!seen_inputs.insert(input.prevout).second) {
                return core::Error(core::ErrorCode::VALIDATION_ERROR,
                    "duplicate input: " + input.prevout.txid.to_hex()
                    + ":" + std::to_string(input.prevout.n)
                    + " at input " + std::to_string(i));
            }
        }
    }

    // --- Witness program version checks ---
    // For outputs with witness programs, verify that the witness version
    // is within the currently supported range. Future witness versions
    // (v2-v16) are allowed for forward compatibility, but witness v0
    // programs must have the correct push sizes (20 or 32 bytes).
    for (size_t i = 0; i < tx.vout().size(); ++i) {
        const auto& output = tx.vout()[i];
        const auto& spk = output.script_pubkey;

        if (spk.size() >= 4 && spk.size() <= 42) {
            uint8_t version_opcode = spk[0];
            bool is_witness_version = (version_opcode == 0x00)
                || (version_opcode >= 0x51 && version_opcode <= 0x60);

            if (is_witness_version) {
                uint8_t push_size = spk[1];
                int witness_version = (version_opcode == 0x00)
                    ? 0 : (version_opcode - 0x50);

                // Witness v0: must be exactly 20 (P2WPKH) or 32 (P2WSH).
                if (witness_version == 0
                    && push_size != 20 && push_size != 32) {
                    return core::Error(core::ErrorCode::VALIDATION_ERROR,
                        "output " + std::to_string(i)
                        + " has witness v0 program with invalid size "
                        + std::to_string(push_size)
                        + " (expected 20 or 32)");
                }

                // Witness v1 (taproot): must be exactly 32 bytes.
                if (witness_version == 1 && push_size != 32) {
                    return core::Error(core::ErrorCode::VALIDATION_ERROR,
                        "output " + std::to_string(i)
                        + " has witness v1 (taproot) program with invalid "
                        "size " + std::to_string(push_size)
                        + " (expected 32)");
                }
            }
        }
    }

    // --- Locktime sanity ---
    // A transaction with locktime in the far future (beyond year 2106)
    // is suspicious. We don't reject it, but log a warning.
    if (tx.locktime() > 0xEFFFFFFF) {
        LOG_WARN(core::LogCategory::MEMPOOL,
            "transaction " + tx.txid().to_hex()
            + " has unusually high locktime: "
            + std::to_string(tx.locktime()));
    }

    // --- Input witness checks ---
    // For segwit inputs, verify that witness stacks are not excessively large.
    for (size_t i = 0; i < tx.vin().size(); ++i) {
        const auto& input = tx.vin()[i];
        if (!input.witness.empty()) {
            // Check total witness size for this input.
            size_t witness_size = 0;
            for (const auto& item : input.witness) {
                witness_size += item.size();
            }

            // A single input's witness data should not exceed ~10 KB
            // (this is a heuristic, not a consensus rule).
            constexpr size_t MAX_STANDARD_WITNESS_SIZE = 10000;
            if (witness_size > MAX_STANDARD_WITNESS_SIZE) {
                return core::Error(core::ErrorCode::VALIDATION_ERROR,
                    "input " + std::to_string(i)
                    + " witness size " + std::to_string(witness_size)
                    + " exceeds standard limit "
                    + std::to_string(MAX_STANDARD_WITNESS_SIZE));
            }

            // Check number of witness items.
            constexpr size_t MAX_STANDARD_WITNESS_ITEMS = 100;
            if (input.witness.size() > MAX_STANDARD_WITNESS_ITEMS) {
                return core::Error(core::ErrorCode::VALIDATION_ERROR,
                    "input " + std::to_string(i) + " has "
                    + std::to_string(input.witness.size())
                    + " witness items, exceeding limit "
                    + std::to_string(MAX_STANDARD_WITNESS_ITEMS));
            }
        }
    }

    LOG_DEBUG(core::LogCategory::MEMPOOL,
        "check_standard: tx " + tx.txid().to_hex() + " passed all checks");

    return core::make_ok();
}

// ---------------------------------------------------------------------------
// Script type name helper
// ---------------------------------------------------------------------------

const char* script_type_name(ScriptType type) {
    switch (type) {
        case ScriptType::NONSTANDARD:     return "nonstandard";
        case ScriptType::P2PKH:           return "p2pkh";
        case ScriptType::P2SH:            return "p2sh";
        case ScriptType::P2WPKH:          return "p2wpkh";
        case ScriptType::P2WSH:           return "p2wsh";
        case ScriptType::P2TR:            return "p2tr";
        case ScriptType::OP_RETURN:       return "nulldata";
        case ScriptType::MULTISIG:        return "multisig";
        case ScriptType::P2PK:            return "p2pk";
        case ScriptType::WITNESS_UNKNOWN: return "witness_unknown";
        default:                          return "unknown";
    }
}

// ---------------------------------------------------------------------------
// Comprehensive transaction policy summary
// ---------------------------------------------------------------------------

std::string summarize_policy_check(const primitives::Transaction& tx,
                                   primitives::Amount fee) {
    std::string summary;

    // Basic stats.
    summary += "Policy summary for tx " + tx.txid().to_hex() + ":\n";
    summary += "  version:    " + std::to_string(tx.version()) + "\n";
    summary += "  total_size: " + std::to_string(tx.total_size()) + " bytes\n";
    summary += "  vsize:      " + std::to_string(tx.vsize()) + " vB\n";
    summary += "  weight:     " + std::to_string(tx.weight()) + " WU\n";
    summary += "  inputs:     " + std::to_string(tx.vin().size()) + "\n";
    summary += "  outputs:    " + std::to_string(tx.vout().size()) + "\n";
    summary += "  fee:        " + std::to_string(fee.value()) + " sat\n";

    // Fee rate.
    if (tx.vsize() > 0) {
        double rate = static_cast<double>(fee.value())
                    / static_cast<double>(tx.vsize());
        summary += "  fee_rate:   " + std::to_string(rate) + " sat/vB\n";
    }

    // Required minimum fee.
    int64_t min_fee = get_virtual_fee(tx, MIN_RELAY_FEE);
    summary += "  min_fee:    " + std::to_string(min_fee) + " sat\n";
    summary += "  fee_ok:     " + std::string(
        fee.value() >= min_fee ? "yes" : "no") + "\n";

    // Output types.
    for (size_t i = 0; i < tx.vout().size(); ++i) {
        const auto& output = tx.vout()[i];
        ScriptType type = classify_script(output.script_pubkey);
        summary += "  output[" + std::to_string(i) + "]: "
                 + std::to_string(output.amount.value()) + " sat, type="
                 + script_type_name(type);

        if (is_dust(output, MIN_RELAY_FEE)) {
            summary += " (DUST)";
        }
        summary += "\n";
    }

    // Witness status.
    summary += "  has_witness: " + std::string(
        tx.has_witness() ? "yes" : "no") + "\n";
    summary += "  is_coinbase: " + std::string(
        tx.is_coinbase() ? "yes" : "no") + "\n";

    return summary;
}

// ---------------------------------------------------------------------------
// Output type analysis
// ---------------------------------------------------------------------------

std::vector<std::pair<ScriptType, size_t>>
count_output_types(const primitives::Transaction& tx) {
    // Count per type.
    std::array<size_t, 10> counts{};
    for (const auto& output : tx.vout()) {
        ScriptType type = classify_script(output.script_pubkey);
        counts[static_cast<uint8_t>(type)]++;
    }

    // Build result for non-zero counts.
    std::vector<std::pair<ScriptType, size_t>> result;
    for (size_t i = 0; i < counts.size(); ++i) {
        if (counts[i] > 0) {
            result.emplace_back(static_cast<ScriptType>(i), counts[i]);
        }
    }
    return result;
}

bool all_outputs_standard(const primitives::Transaction& tx) {
    for (const auto& output : tx.vout()) {
        ScriptType type = classify_script(output.script_pubkey);
        if (type == ScriptType::NONSTANDARD) {
            return false;
        }
    }
    return true;
}

bool has_witness_outputs(const primitives::Transaction& tx) {
    for (const auto& output : tx.vout()) {
        ScriptType type = classify_script(output.script_pubkey);
        if (type == ScriptType::P2WPKH || type == ScriptType::P2WSH
            || type == ScriptType::P2TR
            || type == ScriptType::WITNESS_UNKNOWN) {
            return true;
        }
    }
    return false;
}

int64_t compute_total_dust_deficit(const primitives::Transaction& tx,
                                    int64_t min_relay_fee) {
    int64_t total_deficit = 0;
    for (const auto& output : tx.vout()) {
        if (is_op_return(output.script_pubkey)) continue;

        primitives::Amount threshold = get_dust_threshold(output, min_relay_fee);
        if (output.amount.value() < threshold.value()) {
            total_deficit += threshold.value() - output.amount.value();
        }
    }
    return total_deficit;
}

size_t count_op_return_outputs(const primitives::Transaction& tx) {
    size_t count = 0;
    for (const auto& output : tx.vout()) {
        if (is_op_return(output.script_pubkey)) {
            ++count;
        }
    }
    return count;
}

size_t total_op_return_data_size(const primitives::Transaction& tx) {
    size_t total = 0;
    for (const auto& output : tx.vout()) {
        if (is_op_return(output.script_pubkey)
            && output.script_pubkey.size() > 1) {
            // OP_RETURN is byte 0; the rest is data (possibly with push opcodes).
            total += output.script_pubkey.size() - 1;
        }
    }
    return total;
}

// ---------------------------------------------------------------------------
// PolicyCheckResult::to_string
// ---------------------------------------------------------------------------

std::string PolicyCheckResult::to_string() const {
    std::string result;
    result += "PolicyCheckResult {\n";
    result += "  is_standard:   " + std::string(is_standard ? "yes" : "no") + "\n";
    result += "  fee_ok:        " + std::string(fee_ok ? "yes" : "no") + "\n";
    result += "  dust_ok:       " + std::string(dust_ok ? "yes" : "no") + "\n";
    result += "  multisig_ok:   " + std::string(multisig_ok ? "yes" : "no") + "\n";
    result += "  all_passed:    " + std::string(all_passed() ? "yes" : "no") + "\n";

    if (!rejection_reason.empty()) {
        result += "  reason:        " + rejection_reason + "\n";
    }

    result += "  fee_rate:      " + std::to_string(fee_rate) + " sat/vB\n";
    result += "  min_req_fee:   " + std::to_string(min_required_fee) + " sat\n";
    result += "  dust_outputs:  " + std::to_string(dust_output_count) + "\n";
    result += "  nonstandard:   " + std::to_string(nonstandard_output_count) + "\n";
    result += "}\n";

    return result;
}

// ---------------------------------------------------------------------------
// run_all_policy_checks
// ---------------------------------------------------------------------------

PolicyCheckResult run_all_policy_checks(const primitives::Transaction& tx,
                                         primitives::Amount fee) {
    PolicyCheckResult result;

    // Compute fee rate.
    size_t vs = tx.vsize();
    if (vs > 0) {
        result.fee_rate = static_cast<double>(fee.value())
                        / static_cast<double>(vs);
    }
    result.min_required_fee = get_virtual_fee(tx, MIN_RELAY_FEE);

    // Count non-standard and dust outputs.
    for (const auto& output : tx.vout()) {
        ScriptType type = classify_script(output.script_pubkey);
        if (type == ScriptType::NONSTANDARD) {
            result.nonstandard_output_count++;
        }
        if (is_dust(output, MIN_RELAY_FEE)) {
            result.dust_output_count++;
        }
    }

    // Run standardness check.
    {
        auto std_result = check_standard(tx);
        result.is_standard = std_result.ok();
        if (!std_result.ok()) {
            result.rejection_reason = std_result.error().message();
        }
    }

    // Run fee check.
    {
        auto fee_result = check_min_relay_fee(tx, fee);
        result.fee_ok = fee_result.ok();
        if (!fee_result.ok() && result.rejection_reason.empty()) {
            result.rejection_reason = fee_result.error().message();
        }
    }

    // Run dust check.
    {
        auto dust_result = check_dust(tx, MIN_RELAY_FEE);
        result.dust_ok = dust_result.ok();
        if (!dust_result.ok() && result.rejection_reason.empty()) {
            result.rejection_reason = dust_result.error().message();
        }
    }

    // Run bare multisig check.
    {
        auto ms_result = check_bare_multisig(tx);
        result.multisig_ok = ms_result.ok();
        if (!ms_result.ok() && result.rejection_reason.empty()) {
            result.rejection_reason = ms_result.error().message();
        }
    }

    return result;
}

// ===========================================================================
// Policy design notes
// ===========================================================================
//
// DUST THRESHOLD RATIONALE
// ------------------------
// The dust threshold exists to prevent creation of economically unspendable
// outputs that permanently bloat the UTXO set. An output is "dust" if the
// cost to spend it (in fees) exceeds its value. Since the UTXO set must be
// kept in memory by all full nodes, minimizing its size is important for
// network health.
//
// The threshold depends on the output type because different script types
// require different amounts of data to spend:
//
//   P2PKH  (25-byte script): ~148-byte input => 148 sat at 1 sat/vB => 546 sat
//     (The 546 sat value comes from (148 + 34) * 3 = 546, using the original
//     Bitcoin formula which accounts for both creation and spending cost.)
//
//   P2WPKH (22-byte script): ~68-vbyte input => 294 sat at 1 sat/vB
//     (Witness inputs are cheaper because the witness data is discounted
//     by a factor of 4 in the weight calculation.)
//
//   P2TR   (34-byte script): ~58-vbyte input => 330 sat at 1 sat/vB
//     (Taproot key-path spends are even cheaper than P2WPKH because they
//     use a single Schnorr signature instead of ECDSA.)
//
// OP_RETURN outputs are exempt from dust checks because they are provably
// unspendable and can be immediately pruned from the UTXO set.
//
// STANDARDNESS vs. CONSENSUS
// --------------------------
// It is critical to distinguish between standardness (policy) and
// consensus rules:
//
//   - Consensus rules determine whether a transaction is VALID and can
//     be included in a block. Violating consensus leads to an invalid
//     block that is rejected by all nodes.
//
//   - Policy rules determine whether a transaction is RELAYED and
//     ACCEPTED INTO THE MEMPOOL by default. A transaction that fails
//     policy checks can still be valid on-chain if a miner includes it.
//
// Examples of policy-only rules (not enforced by consensus):
//   - Minimum relay fee
//   - Dust threshold
//   - Maximum transaction weight (400,000 WU vs. consensus 4,000,000 WU)
//   - Non-standard script type rejection
//   - Bare multisig rejection
//
// Miners can and do include policy-violating transactions (e.g., very
// large transactions, non-standard scripts, dust outputs). Users who
// need non-standard transactions must submit them directly to a miner.
//

} // namespace mempool
