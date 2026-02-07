// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner/block_assembler.h"

#include "core/logging.h"
#include "mempool/policy.h"
#include "primitives/script/script.h"

#include <algorithm>
#include <queue>
#include <unordered_map>
#include <unordered_set>

namespace miner {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

BlockAssembler::BlockAssembler()
    : max_weight_(DEFAULT_BLOCK_MAX_WEIGHT),
      max_sigops_(DEFAULT_BLOCK_MAX_SIGOPS),
      min_fee_rate_(0.0) {}

BlockAssembler::BlockAssembler(int64_t max_weight, int max_sigops)
    : max_weight_(max_weight),
      max_sigops_(max_sigops),
      min_fee_rate_(0.0) {}

// ---------------------------------------------------------------------------
// estimate_sigops
// ---------------------------------------------------------------------------

int BlockAssembler::estimate_sigops(const primitives::Transaction& tx) {
    // Estimate the number of signature operations in a transaction.
    //
    // For standard transaction types:
    //   - P2PKH: 1 sigop per input
    //   - P2SH: estimate 1 sigop per input (conservative; actual depends on
    //           redeem script)
    //   - P2WPKH: 1 sigop per input (counted as 1/4 due to witness discount)
    //   - P2WSH: estimate 1 sigop per input
    //   - P2TR: 1 sigop per input (Schnorr)
    //   - Multisig: N sigops per input (up to 20)
    //
    // Outputs:
    //   - P2PKH, P2SH: 0 sigops in the output
    //   - OP_CHECKSIG in output: 1 sigop (for P2PK outputs)
    //
    // For simplicity, we count 1 sigop per input (since most standard
    // transactions have 1 signature per input) and scale by the witness
    // discount factor for segwit inputs.

    int sigops = 0;

    for (const auto& input : tx.vin()) {
        // Each input is assumed to contribute at least 1 sigop.
        // If the input has witness data, the sigop is discounted (counted
        // as 1 in the context of block sigops with the witness scale factor
        // of 4, effectively contributing 0.25 sigops per weight unit).
        if (input.has_witness()) {
            // Witness sigops are counted at 1/4 weight, so we count 1 here
            // as the witness-scaled sigop.
            sigops += 1;
        } else {
            // Legacy sigops count fully.
            sigops += 1;
        }

        // Scan the scriptSig for OP_CHECKSIG and OP_CHECKMULTISIG.
        // Each OP_CHECKSIG adds 1, each OP_CHECKMULTISIG adds up to 20.
        for (size_t i = 0; i < input.script_sig.size(); ++i) {
            uint8_t op = input.script_sig[i];
            if (op == static_cast<uint8_t>(
                    primitives::script::Opcode::OP_CHECKSIG) ||
                op == static_cast<uint8_t>(
                    primitives::script::Opcode::OP_CHECKSIGVERIFY)) {
                sigops += 1;
            } else if (op == static_cast<uint8_t>(
                    primitives::script::Opcode::OP_CHECKMULTISIG) ||
                       op == static_cast<uint8_t>(
                    primitives::script::Opcode::OP_CHECKMULTISIGVERIFY)) {
                // Conservative estimate: 20 sigops for multisig.
                sigops += 20;
            }
            // Skip push data to avoid false positives on data bytes.
            if (op > 0 && op <= 75) {
                i += op;  // skip push data
            } else if (op == 0x4c) {
                if (i + 1 < input.script_sig.size()) {
                    i += 1 + input.script_sig[i + 1];
                }
            } else if (op == 0x4d) {
                if (i + 2 < input.script_sig.size()) {
                    uint16_t len = static_cast<uint16_t>(
                        input.script_sig[i + 1]) |
                        (static_cast<uint16_t>(input.script_sig[i + 2]) << 8);
                    i += 2 + len;
                }
            }
        }
    }

    // Count sigops in output scripts (OP_CHECKSIG in P2PK outputs).
    for (const auto& output : tx.vout()) {
        for (size_t i = 0; i < output.script_pubkey.size(); ++i) {
            uint8_t op = output.script_pubkey[i];
            if (op == static_cast<uint8_t>(
                    primitives::script::Opcode::OP_CHECKSIG) ||
                op == static_cast<uint8_t>(
                    primitives::script::Opcode::OP_CHECKSIGVERIFY)) {
                sigops += 1;
            } else if (op == static_cast<uint8_t>(
                    primitives::script::Opcode::OP_CHECKMULTISIG) ||
                       op == static_cast<uint8_t>(
                    primitives::script::Opcode::OP_CHECKMULTISIGVERIFY)) {
                sigops += 20;
            }
            // Skip push data.
            if (op > 0 && op <= 75) {
                i += op;
            } else if (op == 0x4c && i + 1 < output.script_pubkey.size()) {
                i += 1 + output.script_pubkey[i + 1];
            } else if (op == 0x4d && i + 2 < output.script_pubkey.size()) {
                uint16_t len = static_cast<uint16_t>(
                    output.script_pubkey[i + 1]) |
                    (static_cast<uint16_t>(output.script_pubkey[i + 2]) << 8);
                i += 2 + len;
            }
        }
    }

    return sigops;
}

// ---------------------------------------------------------------------------
// assemble
// ---------------------------------------------------------------------------

AssemblyResult BlockAssembler::assemble(
    const mempool::Mempool& mempool,
    int64_t max_weight_override,
    int max_sigops_override) const {

    AssemblyResult result;
    result.total_fees = primitives::Amount(0);

    int64_t weight_limit = max_weight_override > 0
        ? max_weight_override : max_weight_;
    int sigop_limit = max_sigops_override > 0
        ? max_sigops_override : max_sigops_;

    // Reserve space for the coinbase transaction.
    int64_t remaining_weight = weight_limit - COINBASE_WEIGHT_RESERVE;
    int remaining_sigops = sigop_limit;

    if (remaining_weight <= 0) {
        LOG_WARN(core::LogCategory::MINING,
            "Block weight limit too small for coinbase reservation");
        return result;
    }

    // Get transactions sorted by mining score (ancestor fee rate).
    // The mempool's select_for_block does the heavy lifting of the
    // ancestor-feerate algorithm with topological ordering.
    auto selected = mempool.select_for_block(
        static_cast<size_t>(weight_limit),
        static_cast<int64_t>(min_fee_rate_ * 1000.0));  // Convert sat/vB to sat/kvB

    // Track which transactions we've included (by txid) to avoid duplicates
    // and detect conflicts.
    std::unordered_set<core::uint256, std::hash<core::uint256>> included_txids;

    // Track spent outpoints to detect conflicts among selected transactions.
    std::unordered_set<primitives::OutPoint,
        std::hash<primitives::OutPoint>> spent_outpoints;

    size_t skipped = 0;

    for (auto& entry : selected) {
        // Skip if already included (can happen with ancestor packages).
        if (included_txids.count(entry.txid) > 0) {
            continue;
        }

        // Estimate weight and sigops for this transaction.
        int64_t tx_weight = static_cast<int64_t>(entry.weight());
        int tx_sigops = estimate_sigops(entry.tx);

        // Check weight limit.
        if (result.total_weight + tx_weight > remaining_weight) {
            ++skipped;
            continue;
        }

        // Check sigop limit.
        if (result.total_sigops + tx_sigops > remaining_sigops) {
            ++skipped;
            continue;
        }

        // Check for outpoint conflicts with already-selected transactions.
        bool has_conflict = false;
        for (const auto& input : entry.tx.vin()) {
            if (spent_outpoints.count(input.prevout) > 0) {
                has_conflict = true;
                break;
            }
        }
        if (has_conflict) {
            ++skipped;
            continue;
        }

        // Check minimum fee rate.
        if (min_fee_rate_ > 0.0 && entry.fee_rate() < min_fee_rate_) {
            ++skipped;
            continue;
        }

        // Add the transaction.
        for (const auto& input : entry.tx.vin()) {
            spent_outpoints.insert(input.prevout);
        }
        included_txids.insert(entry.txid);

        result.total_weight += tx_weight;
        result.total_sigops += tx_sigops;
        result.total_fees += entry.fee;
        result.transactions.push_back(std::move(entry.tx));
        ++result.tx_count;

        // If we're getting close to limits, stop early.
        if (result.total_weight >= remaining_weight - 400) {
            break;
        }
    }

    result.skipped_count = skipped;

    LOG_INFO(core::LogCategory::MINING,
        "Block assembly: selected " + std::to_string(result.tx_count) +
        " txs, weight=" + std::to_string(result.total_weight) +
        " sigops=" + std::to_string(result.total_sigops) +
        " fees=" + std::to_string(result.total_fees.value()) +
        " skipped=" + std::to_string(skipped));

    return result;
}

} // namespace miner
