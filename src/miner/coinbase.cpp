// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner/coinbase.h"

#include "core/logging.h"
#include "core/stream.h"
#include "crypto/keccak.h"
#include "primitives/outpoint.h"
#include "primitives/script/opcodes.h"
#include "primitives/txin.h"
#include "primitives/txout.h"

#include <algorithm>
#include <cstring>

namespace miner {

// ---------------------------------------------------------------------------
// encode_height
// ---------------------------------------------------------------------------

std::vector<uint8_t> encode_height(int height) {
    // BIP34: encode the height as a CScriptNum push in the coinbase scriptSig.
    // CScriptNum encoding: little-endian, minimal, signed.
    //
    // Special cases:
    //   height == 0 -> OP_0 (0x00)
    //   height == -1 -> OP_1NEGATE (0x4f) -- should not occur for block heights
    //   height in [1, 16] -> OP_1..OP_16

    std::vector<uint8_t> result;

    if (height == 0) {
        result.push_back(0x01);  // push 1 byte
        result.push_back(0x00);  // value 0
        return result;
    }

    // Encode the height as a little-endian byte sequence.
    // For BIP34 we always use the serialized number form, not small-int opcodes.
    std::vector<uint8_t> height_bytes;
    int64_t value = height;
    bool negative = value < 0;
    uint64_t abs_val = negative ? static_cast<uint64_t>(-value)
                                : static_cast<uint64_t>(value);

    while (abs_val > 0) {
        height_bytes.push_back(static_cast<uint8_t>(abs_val & 0xFF));
        abs_val >>= 8;
    }

    // If the high bit is set on the last byte, append an extra byte for the
    // sign bit (positive numbers need a 0x00 byte, negative need 0x80).
    if (!height_bytes.empty() && (height_bytes.back() & 0x80)) {
        height_bytes.push_back(negative ? 0x80 : 0x00);
    } else if (negative && !height_bytes.empty()) {
        height_bytes.back() |= 0x80;
    }

    // The push opcode for the height data.
    // For data of length 1-75, the opcode is the length itself.
    result.push_back(static_cast<uint8_t>(height_bytes.size()));
    result.insert(result.end(), height_bytes.begin(), height_bytes.end());

    return result;
}

// ---------------------------------------------------------------------------
// build_coinbase_script
// ---------------------------------------------------------------------------

std::vector<uint8_t> build_coinbase_script(int height, uint64_t extra_nonce) {
    std::vector<uint8_t> script;

    // 1. Block height (BIP34).
    auto height_push = encode_height(height);
    script.insert(script.end(), height_push.begin(), height_push.end());

    // 2. Extra nonce (8 bytes, little-endian).
    std::vector<uint8_t> nonce_bytes(8);
    for (int i = 0; i < 8; ++i) {
        nonce_bytes[i] = static_cast<uint8_t>((extra_nonce >> (i * 8)) & 0xFF);
    }
    script.push_back(static_cast<uint8_t>(nonce_bytes.size()));
    script.insert(script.end(), nonce_bytes.begin(), nonce_bytes.end());

    // 3. Miner identification tag.
    std::string tag(MINER_TAG);
    if (!tag.empty()) {
        auto tag_data = reinterpret_cast<const uint8_t*>(tag.data());
        size_t tag_len = tag.size();

        if (tag_len <= 75) {
            script.push_back(static_cast<uint8_t>(tag_len));
        } else {
            // OP_PUSHDATA1 for tags > 75 bytes (unlikely).
            script.push_back(0x4c);  // OP_PUSHDATA1
            script.push_back(static_cast<uint8_t>(tag_len & 0xFF));
        }
        script.insert(script.end(), tag_data, tag_data + tag_len);
    }

    return script;
}

// ---------------------------------------------------------------------------
// compute_witness_commitment
// ---------------------------------------------------------------------------

core::uint256 compute_witness_commitment(const core::uint256& witness_merkle_root) {
    // The witness commitment is:
    //   keccak256d(witness_merkle_root || witness_reserved_value)
    // where witness_reserved_value is 32 zero bytes.

    std::vector<uint8_t> data(64, 0);
    std::memcpy(data.data(), witness_merkle_root.data(), 32);
    // Second 32 bytes are already zero (witness_reserved_value = 0x00...00).

    return crypto::keccak256d(
        std::span<const uint8_t>(data.data(), data.size()));
}

// ---------------------------------------------------------------------------
// build_witness_commitment_script
// ---------------------------------------------------------------------------

std::vector<uint8_t> build_witness_commitment_script(
    const core::uint256& witness_merkle_root) {

    core::uint256 commitment = compute_witness_commitment(witness_merkle_root);

    // OP_RETURN followed by a 36-byte push:
    //   [4-byte header: 0xaa21a9ed] [32-byte commitment hash]
    std::vector<uint8_t> script;
    script.push_back(static_cast<uint8_t>(
        primitives::script::Opcode::OP_RETURN));

    // 36 bytes of data (4 header + 32 commitment).
    constexpr size_t payload_size = 4 + 32;
    script.push_back(static_cast<uint8_t>(payload_size));

    // Commitment header.
    script.insert(script.end(),
        WITNESS_COMMITMENT_HEADER,
        WITNESS_COMMITMENT_HEADER + 4);

    // Commitment hash.
    script.insert(script.end(),
        commitment.data(),
        commitment.data() + 32);

    return script;
}

// ---------------------------------------------------------------------------
// create_coinbase
// ---------------------------------------------------------------------------

core::Result<primitives::Transaction> create_coinbase(
    int height,
    const primitives::Address& coinbase_addr,
    primitives::Amount fees,
    primitives::Amount subsidy,
    uint64_t extra_nonce,
    bool include_witness,
    const core::uint256& witness_merkle_root) {

    // Validate inputs.
    if (height < 0) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Coinbase height must be non-negative");
    }

    if (!coinbase_addr.is_valid()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Invalid coinbase address");
    }

    // Compute total reward = subsidy + fees.
    int64_t total_reward = subsidy.value() + fees.value();
    if (total_reward < 0 || total_reward > primitives::Amount::MAX_MONEY) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Coinbase reward out of valid range");
    }

    // Build the coinbase input.
    primitives::TxInput coinbase_input;
    coinbase_input.prevout = primitives::OutPoint{};  // null outpoint
    coinbase_input.script_sig = build_coinbase_script(height, extra_nonce);
    coinbase_input.sequence = 0xFFFFFFFF;

    // Validate scriptSig size.
    if (coinbase_input.script_sig.size() < 2 ||
        coinbase_input.script_sig.size() > MAX_COINBASE_SCRIPTSIG_SIZE) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Coinbase scriptSig size out of range: " +
            std::to_string(coinbase_input.script_sig.size()));
    }

    // If witness commitment is included, the coinbase must have a witness
    // stack with a single 32-byte zero item (the witness reserved value).
    if (include_witness) {
        std::vector<uint8_t> witness_nonce(32, 0x00);
        coinbase_input.witness.push_back(std::move(witness_nonce));
    }

    // Build outputs.
    std::vector<primitives::TxOutput> outputs;

    // Output 0: miner reward payment.
    primitives::TxOutput reward_output;
    reward_output.amount = primitives::Amount(total_reward);
    auto payout_script = coinbase_addr.to_script();
    reward_output.script_pubkey = payout_script.data();
    outputs.push_back(std::move(reward_output));

    // Output 1 (optional): witness commitment.
    if (include_witness) {
        primitives::TxOutput witness_output;
        witness_output.amount = primitives::Amount(0);
        witness_output.script_pubkey =
            build_witness_commitment_script(witness_merkle_root);
        outputs.push_back(std::move(witness_output));
    }

    // Construct the transaction.
    std::vector<primitives::TxInput> inputs;
    inputs.push_back(std::move(coinbase_input));

    primitives::Transaction tx(
        std::move(inputs),
        std::move(outputs),
        2,   // version
        0    // locktime
    );

    LOG_DEBUG(core::LogCategory::MINING,
        "Created coinbase tx for height " + std::to_string(height) +
        " reward=" + std::to_string(total_reward) +
        " witness=" + (include_witness ? "yes" : "no"));

    return tx;
}

// ---------------------------------------------------------------------------
// validate_coinbase
// ---------------------------------------------------------------------------

core::Result<void> validate_coinbase(
    const primitives::Transaction& tx,
    int height,
    primitives::Amount subsidy,
    primitives::Amount fees) {

    // Must be a coinbase transaction.
    if (!tx.is_coinbase()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Transaction is not a coinbase");
    }

    // Must have exactly one input.
    if (tx.vin().size() != 1) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Coinbase must have exactly one input, got " +
            std::to_string(tx.vin().size()));
    }

    // Input must have a null outpoint.
    const auto& input = tx.vin()[0];
    if (!input.prevout.is_null()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Coinbase input must have a null outpoint");
    }

    // ScriptSig size check.
    if (input.script_sig.size() < 2) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Coinbase scriptSig too small: " +
            std::to_string(input.script_sig.size()));
    }
    if (input.script_sig.size() > MAX_COINBASE_SCRIPTSIG_SIZE) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Coinbase scriptSig too large: " +
            std::to_string(input.script_sig.size()));
    }

    // Must have at least one output.
    if (tx.vout().empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Coinbase must have at least one output");
    }

    // Total output value must not exceed subsidy + fees.
    int64_t total_output = 0;
    for (const auto& out : tx.vout()) {
        if (out.amount.value() < 0) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "Coinbase output has negative amount");
        }
        total_output += out.amount.value();
        if (total_output < 0 || total_output > primitives::Amount::MAX_MONEY) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "Coinbase output total overflow");
        }
    }

    int64_t max_reward = subsidy.value() + fees.value();
    if (total_output > max_reward) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Coinbase output value " + std::to_string(total_output) +
            " exceeds allowed reward " + std::to_string(max_reward));
    }

    // Verify BIP34 height encoding.
    // The first item pushed in the scriptSig should decode to the block height.
    if (height >= 0) {
        auto expected_height_push = encode_height(height);
        if (input.script_sig.size() < expected_height_push.size()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "Coinbase scriptSig too short for BIP34 height");
        }

        bool height_ok = std::equal(
            expected_height_push.begin(),
            expected_height_push.end(),
            input.script_sig.begin());

        if (!height_ok) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "Coinbase does not contain correct BIP34 height encoding");
        }
    }

    return core::Result<void>{};
}

} // namespace miner
