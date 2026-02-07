// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/tx_verify.h"
#include "consensus/params.h"
#include "primitives/amount.h"
#include "primitives/outpoint.h"
#include "primitives/script/opcodes.h"
#include "primitives/script/script.h"
#include "primitives/txin.h"
#include "primitives/txout.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <set>
#include <span>

namespace consensus {

// =========================================================================
// Internal helpers
// =========================================================================

namespace {

/// Count the number of "sigop" opcodes in a raw script byte vector.
/// Each OP_CHECKSIG / OP_CHECKSIGVERIFY counts as 1.
/// Each OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY counts as max_keys
/// (conservatively 20) unless the preceding opcode encodes a small int,
/// in which case we use that value.
int64_t count_script_sig_ops(const std::vector<uint8_t>& script_bytes,
                             bool accurate) {
    using namespace primitives::script;

    int64_t n_sig_ops = 0;
    Opcode last_opcode = Opcode::OP_INVALIDOPCODE;

    Script script(script_bytes);
    auto it = script.begin_iter();

    while (auto elem = it.next()) {
        Opcode op = elem->opcode;

        if (op == Opcode::OP_CHECKSIG ||
            op == Opcode::OP_CHECKSIGVERIFY) {
            n_sig_ops += 1;
        } else if (op == Opcode::OP_CHECKMULTISIG ||
                   op == Opcode::OP_CHECKMULTISIGVERIFY) {
            if (accurate) {
                auto small = decode_small_int(last_opcode);
                if (small.has_value() && *small >= 0 &&
                    *small <= MAX_PUBKEYS_PER_MULTISIG) {
                    n_sig_ops += *small;
                } else {
                    n_sig_ops += MAX_PUBKEYS_PER_MULTISIG;
                }
            } else {
                n_sig_ops += MAX_PUBKEYS_PER_MULTISIG;
            }
        }

        last_opcode = op;
    }

    return n_sig_ops;
}

/// Extract the last push-data element from a serialized script (used to
/// recover the redeemScript for P2SH sigop counting).
std::vector<uint8_t> get_last_push_data(
    const std::vector<uint8_t>& script_bytes) {
    using namespace primitives::script;

    std::vector<uint8_t> last_data;
    Script script(script_bytes);
    auto it = script.begin_iter();

    while (auto elem = it.next()) {
        if (!elem->data.empty()) {
            last_data.assign(elem->data.begin(), elem->data.end());
        }
    }

    return last_data;
}

/// Determine if a scriptPubKey is a witness program (version 0-16, program
/// 2-40 bytes).  Layout: <OP_N> <push-N-bytes> <program>
bool is_witness_program(const std::vector<uint8_t>& spk,
                        int& version_out,
                        std::span<const uint8_t>& program_out) {
    if (spk.size() < 4 || spk.size() > 42) {
        return false;
    }

    uint8_t first = spk[0];
    // OP_0 = 0x00, OP_1..OP_16 = 0x51..0x60
    if (first != 0x00 && (first < 0x51 || first > 0x60)) {
        return false;
    }

    uint8_t push_len = spk[1];
    if (static_cast<size_t>(push_len) + 2 != spk.size()) {
        return false;
    }
    if (push_len < 2 || push_len > 40) {
        return false;
    }

    version_out = (first == 0x00) ? 0 : (first - 0x50);
    program_out = std::span<const uint8_t>(spk.data() + 2, push_len);
    return true;
}

/// Count witness sigops for a single input.
/// - P2WPKH: 1 sigop
/// - P2WSH:  count from the witness script (last witness stack element)
int64_t count_witness_sig_ops(int witness_version,
                              std::span<const uint8_t> witness_program,
                              const std::vector<std::vector<uint8_t>>& witness) {
    if (witness_version == 0) {
        if (witness_program.size() == 20) {
            // P2WPKH: exactly one signature check
            return 1;
        }
        if (witness_program.size() == 32 && !witness.empty()) {
            // P2WSH: the last witness stack item is the witness script
            const auto& witness_script = witness.back();
            return count_script_sig_ops(witness_script, /*accurate=*/true);
        }
    }

    // Unknown witness versions: conservatively count 0 sigops
    // (soft-fork safe: future witness versions are anyone-can-spend).
    return 0;
}

} // anonymous namespace

// =========================================================================
// check_transaction  (context-free)
// =========================================================================

core::Result<void> check_transaction(const primitives::Transaction& tx) {
    // 1. vin must not be empty
    if (tx.vin().empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "bad-txns-vin-empty");
    }

    // 2. vout must not be empty
    if (tx.vout().empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "bad-txns-vout-empty");
    }

    // 3. Transaction weight must not exceed the maximum
    if (tx.weight() > MAX_TX_WEIGHT) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "bad-txns-oversize");
    }

    // 4. Check individual output amounts and sum
    int64_t total_out = 0;

    for (const auto& out : tx.vout()) {
        if (out.amount.value() < 0) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                               "bad-txns-vout-negative");
        }

        if (out.amount.value() > primitives::Amount::MAX_MONEY) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                               "bad-txns-vout-toolarge");
        }

        total_out += out.amount.value();
        if (total_out < 0 || total_out > primitives::Amount::MAX_MONEY) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                               "bad-txns-txouttotal-toolarge");
        }
    }

    // 5. Check for duplicate inputs (unique prevouts)
    {
        std::set<primitives::OutPoint> seen_prevouts;
        for (const auto& in : tx.vin()) {
            auto [it, inserted] = seen_prevouts.insert(in.prevout);
            if (!inserted) {
                return core::Error(core::ErrorCode::VALIDATION_ERROR,
                                   "bad-txns-inputs-duplicate");
            }
        }
    }

    // 6. Coinbase-specific checks
    if (tx.is_coinbase()) {
        const auto& script_sig = tx.vin()[0].script_sig;
        if (script_sig.size() < 2 || script_sig.size() > 100) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                               "bad-cb-length");
        }
    } else {
        // 7. Non-coinbase: no null prevouts
        for (const auto& in : tx.vin()) {
            if (in.prevout.is_null()) {
                return core::Error(core::ErrorCode::VALIDATION_ERROR,
                                   "bad-txns-prevout-null");
            }
        }
    }

    return core::make_ok();
}

// =========================================================================
// check_transaction_contextual  (context-dependent)
// =========================================================================

core::Result<void> check_transaction_contextual(
    const primitives::Transaction& tx,
    int height,
    int64_t median_time_past,
    const ConsensusParams& params) {

    // -----------------------------------------------------------------------
    // BIP65 (CLTV): locktime enforcement
    // -----------------------------------------------------------------------
    // If BIP65 is active, the transaction's locktime must be satisfied.
    // A locktime of 0 is always valid.  Otherwise:
    //   - If locktime < 500'000'000, it is a block height: must be <= height.
    //   - If locktime >= 500'000'000, it is a Unix timestamp: must be <=
    //     median_time_past.
    // The transaction is only subject to locktime enforcement if at least
    // one input has a non-final sequence number.

    if (height >= params.bip65_height) {
        uint32_t lock = tx.locktime();
        if (lock != 0) {
            // Determine whether any input opts in to locktime enforcement.
            bool has_non_final_input = false;
            for (const auto& in : tx.vin()) {
                if (in.sequence != primitives::TxInput::SEQUENCE_FINAL) {
                    has_non_final_input = true;
                    break;
                }
            }

            if (has_non_final_input) {
                static constexpr uint32_t LOCKTIME_THRESHOLD = 500'000'000;

                if (lock < LOCKTIME_THRESHOLD) {
                    // Block-height-based locktime
                    if (static_cast<int64_t>(lock) > static_cast<int64_t>(height)) {
                        return core::Error(
                            core::ErrorCode::VALIDATION_ERROR,
                            "bad-txns-nonfinal-locktime-height");
                    }
                } else {
                    // Timestamp-based locktime
                    if (static_cast<int64_t>(lock) > median_time_past) {
                        return core::Error(
                            core::ErrorCode::VALIDATION_ERROR,
                            "bad-txns-nonfinal-locktime-time");
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // BIP68 (relative lock-time): sequence-number-based constraints
    // -----------------------------------------------------------------------
    // Only applies to transactions with version >= 2.
    // For each input whose sequence number does NOT have the disable flag
    // set (bit 31), the relative lock-time is enforced:
    //   - If bit 22 (TYPE_FLAG) is clear: the low 16 bits encode a block
    //     count.  The input's prevout must have at least that many
    //     confirmations (height - prevout_height >= mask_value).
    //   - If bit 22 is set: the low 16 bits encode a time in 512-second
    //     granularity.  The input's prevout must be at least that old
    //     relative to the median time past.
    //
    // Since we do not have UTXO context here (prevout height / time),
    // we perform only structural validity checks: ensure the sequence
    // encoding is well-formed.  Full enforcement occurs during
    // ConnectBlock / ATMP when UTXO data is available.

    if (tx.version() >= 2) {
        for (const auto& in : tx.vin()) {
            uint32_t seq = in.sequence;

            // If the disable flag is set, relative locktime is inactive
            // for this input -- nothing to check.
            if (seq & primitives::TxInput::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
                continue;
            }

            // The low 16 bits must not exceed a reasonable bound.
            // In practice any 16-bit value is structurally valid, but we
            // reject values whose masked portion exceeds the sequence mask,
            // which would indicate data corruption.
            uint32_t masked = seq & primitives::TxInput::SEQUENCE_LOCKTIME_MASK;

            // BIP68 requires the relative lock-time value to be
            // representable in 16 bits (it always is, by definition of
            // the mask).  We verify the mask itself for defence in depth.
            if (masked > 0xFFFF) {
                return core::Error(
                    core::ErrorCode::VALIDATION_ERROR,
                    "bad-txns-bip68-sequence-overflow");
            }
        }
    }

    return core::make_ok();
}

// =========================================================================
// get_transaction_sig_op_cost
// =========================================================================

int64_t get_transaction_sig_op_cost(const primitives::Transaction& tx,
                                    bool is_coinbase) {
    int64_t cost = 0;

    // Count sigops in inputs (scriptSig).
    // For coinbase transactions the scriptSig is not a real script, so we
    // skip accurate counting and just do a conservative pass.
    for (const auto& in : tx.vin()) {
        cost += count_script_sig_ops(in.script_sig, /*accurate=*/false)
                * WITNESS_SCALE_FACTOR;
    }

    // Count sigops in outputs (scriptPubKey).
    for (const auto& out : tx.vout()) {
        cost += count_script_sig_ops(out.script_pubkey, /*accurate=*/false)
                * WITNESS_SCALE_FACTOR;
    }

    // For non-coinbase transactions, account for P2SH and witness sigops.
    if (!is_coinbase) {
        for (const auto& in : tx.vin()) {
            // We do not have the prevout scriptPubKey here in the general
            // case.  However, for witness inputs we can count sigops from
            // the witness data itself.

            // Attempt witness sigop counting from the scriptSig and witness.
            // The prevout scriptPubKey would be needed for full accuracy;
            // we use a heuristic: if the input has witness data, try to
            // determine the witness version from the scriptSig (for P2SH-
            // wrapped witness) or assume the prevout is a native witness
            // program.

            if (!in.witness.empty()) {
                // Heuristic for P2SH-wrapped witness: the scriptSig is a
                // single push of a witness program.
                std::vector<uint8_t> program_script;
                if (!in.script_sig.empty()) {
                    program_script = get_last_push_data(in.script_sig);
                }

                int wit_version = -1;
                std::span<const uint8_t> wit_program;

                if (!program_script.empty() &&
                    is_witness_program(program_script, wit_version,
                                       wit_program)) {
                    // P2SH-wrapped witness
                    int64_t wit_sigops = count_witness_sig_ops(
                        wit_version, wit_program, in.witness);
                    cost += wit_sigops;
                } else {
                    // Native witness -- without the prevout script we use a
                    // conservative heuristic based on witness stack layout.
                    // P2WPKH has a 2-element witness stack; P2WSH has more.
                    if (in.witness.size() == 2) {
                        // Likely P2WPKH: 1 sigop
                        cost += 1;
                    } else if (in.witness.size() > 2) {
                        // Likely P2WSH: count from last stack element
                        const auto& witness_script = in.witness.back();
                        cost += count_script_sig_ops(witness_script,
                                                     /*accurate=*/true);
                    }
                }
            }
        }
    }

    return cost;
}

} // namespace consensus
