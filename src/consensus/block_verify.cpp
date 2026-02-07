// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/block_verify.h"
#include "consensus/params.h"
#include "consensus/tx_verify.h"
#include "crypto/hash.h"
#include "crypto/keccak.h"
#include "crypto/merkle.h"
#include "primitives/amount.h"
#include "primitives/script/opcodes.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace consensus {

// =========================================================================
// Internal helpers
// =========================================================================

namespace {

/// Decode the compact "nBits" target representation into a full uint256.
/// nBits encodes a 256-bit target as a 3-byte mantissa with a 1-byte
/// exponent: target = mantissa * 256^(exponent - 3).
core::uint256 nbits_to_target(uint32_t nbits) {
    uint32_t exponent = nbits >> 24;
    bool negative = (nbits & 0x00800000) != 0;
    uint32_t mantissa = nbits & 0x007FFFFF;

    core::uint256 target;

    if (exponent <= 3) {
        mantissa >>= 8 * (3 - exponent);
        // Place mantissa at the lowest bytes (LE storage).
        uint8_t* p = target.data();
        p[0] = static_cast<uint8_t>(mantissa & 0xFF);
        p[1] = static_cast<uint8_t>((mantissa >> 8) & 0xFF);
        p[2] = static_cast<uint8_t>((mantissa >> 16) & 0xFF);
    } else {
        // The mantissa occupies bytes [exponent-3 .. exponent-1] in LE.
        uint32_t offset = exponent - 3;
        uint8_t* p = target.data();
        if (offset < 32) {
            p[offset] = static_cast<uint8_t>(mantissa & 0xFF);
        }
        if (offset + 1 < 32) {
            p[offset + 1] = static_cast<uint8_t>((mantissa >> 8) & 0xFF);
        }
        if (offset + 2 < 32) {
            p[offset + 2] = static_cast<uint8_t>((mantissa >> 16) & 0xFF);
        }
    }

    if (negative) {
        // Negative targets are not valid in our protocol -- return zero.
        return core::uint256{};
    }

    return target;
}

/// Check that a block header hash satisfies the proof-of-work target
/// encoded in its nBits field.
///
/// Returns core::make_ok() on success.
core::Result<void> check_proof_of_work(const primitives::BlockHeader& header,
                                       const core::uint256& pow_limit) {
    // Decode the target from nBits.
    core::uint256 target = nbits_to_target(header.bits);

    // Target must be positive.
    if (target.is_zero()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "bad-diffbits-zero-target");
    }

    // Target must not exceed the PoW limit.
    if (target > pow_limit) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "bad-diffbits-above-limit");
    }

    // The header hash must be at most the target (LE comparison:
    // the hash interpreted as a big unsigned integer must be <= target).
    core::uint256 header_hash = header.hash();
    if (header_hash > target) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "high-hash");
    }

    return core::make_ok();
}

/// Determine whether a block contains any witness data.
bool block_has_witness(const primitives::Block& block) {
    for (const auto& tx : block.transactions()) {
        if (tx.has_witness()) {
            return true;
        }
    }
    return false;
}

} // anonymous namespace

// =========================================================================
// check_block_header
// =========================================================================

core::Result<void> check_block_header(const primitives::BlockHeader& header,
                                      const ConsensusParams& params,
                                      int64_t adjusted_time) {
    // 1. Proof-of-work check.
    FTC_TRY_VOID(check_proof_of_work(header, params.pow_limit));

    // 2. Timestamp must not be too far in the future.
    if (adjusted_time > 0) {
        if (static_cast<int64_t>(header.timestamp) >
            adjusted_time + MAX_FUTURE_BLOCK_TIME) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                               "time-too-new");
        }
    }

    return core::make_ok();
}

// =========================================================================
// check_block
// =========================================================================

core::Result<void> check_block(const primitives::Block& block,
                                const ConsensusParams& params,
                                int64_t adjusted_time) {
    const auto& txs = block.transactions();

    // 1. Validate the header.
    FTC_TRY_VOID(check_block_header(block.header(), params, adjusted_time));

    // 2. Block must contain at least one transaction.
    if (txs.empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "bad-blk-length");
    }

    // 3. First transaction must be coinbase.
    if (!txs[0].is_coinbase()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "bad-cb-missing");
    }

    // 4. No other transaction may be coinbase.
    for (size_t i = 1; i < txs.size(); ++i) {
        if (txs[i].is_coinbase()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                               "bad-cb-multiple");
        }
    }

    // 5. Merkle root must match the transactions.
    if (!block.is_valid_merkle_root()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "bad-txnmrklroot");
    }

    // 6. Check each transaction individually (context-free).
    for (const auto& tx : txs) {
        FTC_TRY_VOID(check_transaction(tx));
    }

    // 7. Total block weight must not exceed the maximum.
    size_t total_weight = block.weight();
    if (total_weight > params.max_block_weight) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "bad-blk-weight");
    }

    // 8. Total signature operation cost must not exceed the limit.
    int64_t total_sigops = 0;
    for (size_t i = 0; i < txs.size(); ++i) {
        total_sigops += get_transaction_sig_op_cost(txs[i],
                                                    /*is_coinbase=*/i == 0);
        if (total_sigops > MAX_BLOCK_SIGOPS_COST) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                               "bad-blk-sigops");
        }
    }

    // 9. Witness commitment verification (if segwit is active and block
    //    contains witness data).
    if (block_has_witness(block)) {
        FTC_TRY_VOID(check_witness_commitment(block, params));
    }

    return core::make_ok();
}

// =========================================================================
// check_witness_commitment
// =========================================================================

core::Result<void> check_witness_commitment(
    const primitives::Block& block,
    const ConsensusParams& params) {
    const auto& txs = block.transactions();

    if (txs.empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "bad-witness-no-txs");
    }

    const auto& coinbase = txs[0];

    // -------------------------------------------------------------------
    // 1. Find the witness commitment output in the coinbase.
    //    Scan the coinbase outputs in reverse order; the first match wins.
    //    The commitment is in a scriptPubKey that begins with:
    //        0x6a  (OP_RETURN)
    //        0x24  (push 36 bytes)
    //        0xaa 0x21 0xa9 0xed  (witness commitment header)
    //        <32 bytes of commitment hash>
    //    Total scriptPubKey length: 1 + 1 + 4 + 32 = 38 bytes.
    // -------------------------------------------------------------------

    int commitment_index = -1;
    for (int i = static_cast<int>(coinbase.vout().size()) - 1; i >= 0; --i) {
        const auto& spk = coinbase.vout()[i].script_pubkey;

        if (spk.size() >= 38 &&
            spk[0] == 0x6a &&   // OP_RETURN
            spk[1] == 0x24 &&   // push 36 bytes
            spk[2] == 0xaa &&
            spk[3] == 0x21 &&
            spk[4] == 0xa9 &&
            spk[5] == 0xed) {
            commitment_index = i;
            break;
        }
    }

    if (commitment_index < 0) {
        // No witness commitment found. This is an error if any non-coinbase
        // transaction has witness data.
        bool has_witness = false;
        for (size_t i = 1; i < txs.size(); ++i) {
            if (txs[i].has_witness()) {
                has_witness = true;
                break;
            }
        }

        if (has_witness) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                               "bad-witness-commitment-missing");
        }

        // No witness data and no commitment -- that is acceptable.
        return core::make_ok();
    }

    // -------------------------------------------------------------------
    // 2. Extract the 32-byte commitment hash from the coinbase output.
    // -------------------------------------------------------------------
    const auto& spk = coinbase.vout()[commitment_index].script_pubkey;

    // Bytes [6..38) contain the 32-byte commitment hash.
    std::array<uint8_t, 32> commitment_hash{};
    std::memcpy(commitment_hash.data(), spk.data() + 6, 32);

    // -------------------------------------------------------------------
    // 3. Extract the witness nonce from the coinbase's witness stack.
    //    The coinbase input must have a witness stack with exactly one
    //    element that is 32 bytes (by convention, all zeros).
    // -------------------------------------------------------------------
    if (coinbase.vin().empty() ||
        coinbase.vin()[0].witness.empty() ||
        coinbase.vin()[0].witness[0].size() != 32) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "bad-witness-nonce-size");
    }

    const auto& witness_nonce = coinbase.vin()[0].witness[0];

    // -------------------------------------------------------------------
    // 4. Compute the witness merkle root.
    //    The coinbase's wtxid is replaced with 32 zero bytes; all other
    //    transactions use their wtxid.
    // -------------------------------------------------------------------
    std::vector<core::uint256> wtxids;
    wtxids.reserve(txs.size());

    // Coinbase entry: all zeros
    wtxids.emplace_back();

    for (size_t i = 1; i < txs.size(); ++i) {
        wtxids.push_back(txs[i].wtxid());
    }

    core::uint256 witness_merkle_root =
        crypto::compute_witness_merkle_root(std::move(wtxids));

    // -------------------------------------------------------------------
    // 5. Compute the expected commitment:
    //    keccak256d( witness_merkle_root || witness_nonce )
    // -------------------------------------------------------------------
    std::array<uint8_t, 64> commitment_preimage{};
    std::memcpy(commitment_preimage.data(),
                witness_merkle_root.data(), 32);
    std::memcpy(commitment_preimage.data() + 32,
                witness_nonce.data(), 32);

    core::uint256 expected = crypto::keccak256d(
        std::span<const uint8_t>(commitment_preimage.data(), 64));

    // -------------------------------------------------------------------
    // 6. Compare the computed commitment with the one in the coinbase.
    // -------------------------------------------------------------------
    if (std::memcmp(expected.data(), commitment_hash.data(), 32) != 0) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "bad-witness-merkle-match");
    }

    return core::make_ok();
}

} // namespace consensus
