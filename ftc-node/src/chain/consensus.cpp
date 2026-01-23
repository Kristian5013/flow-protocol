#include "chain/consensus.h"
#include "script/script.h"
#include "script/interpreter.h"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <cmath>
#include <set>
#include <sstream>

namespace ftc {
namespace chain {

using namespace crypto;

//-----------------------------------------------------------------------------
// ConsensusParams
//-----------------------------------------------------------------------------

ConsensusParams::ConsensusParams() {
    // FTC Mainnet parameters

    // Genesis (will be set when genesis block is created)
    genesis_hash = ZERO_HASH;

    // Proof of work - start with low difficulty for testing
    // Maximum target: leading 1 byte of zeros
    pow_limit_bits = 0x1f00ffff;  // Very low difficulty for initial launch
    std::memset(pow_limit.data(), 0, 32);
    pow_limit[0] = 0x00;
    pow_limit[1] = 0xff;
    pow_limit[2] = 0xff;
    pow_limit[3] = 0xff;
    for (int i = 4; i < 32; i++) pow_limit[i] = 0xff;

    // Block timing - 60 second blocks
    target_spacing = 60;  // 60 seconds
    target_timespan = DIFFICULTY_ADJUSTMENT_INTERVAL * target_spacing;  // 2016 * 60 = ~33.6 hours
    difficulty_adjustment_interval = DIFFICULTY_ADJUSTMENT_INTERVAL;  // 2016 blocks

    // Rewards
    initial_reward = INITIAL_BLOCK_REWARD;  // 50 FTC
    halving_interval = HALVING_INTERVAL;    // 210,000 blocks
    max_money = MAX_SUPPLY;                 // 21 million FTC

    // Block limits
    max_block_size = MAX_BLOCK_SIZE;        // 1 MB
    max_block_sigops = 80000;               // Max signature operations
    max_block_weight = 4000000;             // 4 MB weight

    // Transaction limits
    max_tx_size = 1000000;                  // 1 MB max tx
    max_tx_sigops = 16000;                  // Max tx sigops

    // Script flags - all enabled from genesis
    mandatory_script_flags = ftc::script::SCRIPT_VERIFY_P2SH;
    standard_script_flags = ftc::script::SCRIPT_STANDARD_FLAGS;

    // Softfork activation - all active from genesis for FTC
    bip16_height = 0;   // P2SH
    bip34_height = 0;   // Height in coinbase
    bip65_height = 0;   // CHECKLOCKTIMEVERIFY
    bip66_height = 0;   // Strict DER
    bip68_height = 0;   // Sequence locks
    segwit_height = 0;  // SegWit

    // Coinbase maturity
    coinbase_maturity = 100;  // 100 blocks
}

ConsensusParams ConsensusParams::testnet() {
    ConsensusParams params;

    // Lower difficulty for testnet
    params.pow_limit_bits = 0x1f7fffff;

    // Faster block times for testing
    params.target_spacing = 30;  // 30 seconds
    params.target_timespan = 2016 * 30;

    // Shorter halving for testing
    params.halving_interval = 1000;

    // Lower coinbase maturity
    params.coinbase_maturity = 10;

    return params;
}

uint64_t ConsensusParams::getBlockReward(uint64_t height) const {
    uint64_t halvings = height / halving_interval;

    // After 64 halvings, reward is 0
    if (halvings >= 64) {
        return 0;
    }

    return initial_reward >> halvings;
}

bool ConsensusParams::isDifficultyAdjustment(uint64_t height) const {
    return height % difficulty_adjustment_interval == 0;
}

//-----------------------------------------------------------------------------
// ValidationState
//-----------------------------------------------------------------------------

std::string ValidationState::toString() const {
    std::ostringstream oss;
    oss << "ValidationState{";
    oss << "result=" << static_cast<int>(result);
    if (!reason.empty()) oss << ", reason=\"" << reason << "\"";
    if (!debug_message.empty()) oss << ", debug=\"" << debug_message << "\"";
    oss << "}";
    return oss.str();
}

//-----------------------------------------------------------------------------
// Consensus Constructor
//-----------------------------------------------------------------------------

Consensus::Consensus(const ConsensusParams& params)
    : params_(params) {
}

//-----------------------------------------------------------------------------
// Block Header Validation
//-----------------------------------------------------------------------------

bool Consensus::checkBlockHeader(const BlockHeader& header, ValidationState& state) const {
    // Check proof of work
    Hash256 hash = header.getHash();
    if (!checkProofOfWork(hash, header.bits)) {
        state.invalid(ValidationResult::INVALID_POW, "high-hash",
                      "proof of work failed");
        return false;
    }

    // Check timestamp is not too far in the future (2 hours)
    uint32_t max_future = static_cast<uint32_t>(
        std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now() + std::chrono::hours(2)));

    if (header.timestamp > max_future) {
        state.invalid(ValidationResult::INVALID_TIMESTAMP, "time-too-new",
                      "block timestamp too far in the future");
        return false;
    }

    return true;
}

//-----------------------------------------------------------------------------
// Block Validation (context-free)
//-----------------------------------------------------------------------------

bool Consensus::checkBlock(const Block& block, ValidationState& state) const {
    // Check header
    if (!checkBlockHeader(block.header, state)) {
        return false;
    }

    // Check block size
    if (!checkBlockSize(block, state)) {
        return false;
    }

    // Check for empty block
    if (block.transactions.empty()) {
        state.invalid(ValidationResult::INVALID_TX, "bad-blk-empty",
                      "block contains no transactions");
        return false;
    }

    // First transaction must be coinbase
    if (!block.transactions[0].isCoinbase()) {
        state.invalid(ValidationResult::INVALID_COINBASE, "bad-cb-missing",
                      "first tx is not coinbase");
        return false;
    }

    // Check for duplicate coinbase
    for (size_t i = 1; i < block.transactions.size(); i++) {
        if (block.transactions[i].isCoinbase()) {
            state.invalid(ValidationResult::INVALID_COINBASE, "bad-cb-multiple",
                          "more than one coinbase");
            return false;
        }
    }

    // Check merkle root
    if (!checkMerkleRoot(block, state)) {
        return false;
    }

    // Check for duplicate transactions
    if (!checkDuplicateTxids(block, state)) {
        return false;
    }

    // Check each transaction
    for (const auto& tx : block.transactions) {
        if (!checkTransaction(tx, state)) {
            return false;
        }
    }

    return true;
}

//-----------------------------------------------------------------------------
// Contextual Block Validation
//-----------------------------------------------------------------------------

bool Consensus::contextualCheckBlock(const Block& block,
                                       const BlockValidationContext& ctx,
                                       ValidationState& state) const {
    // Check that previous block hash matches
    if (block.header.prev_hash != ctx.prev_hash) {
        state.invalid(ValidationResult::BLOCK_MISSING_PREV, "bad-prevblk",
                      "previous block hash mismatch");
        return false;
    }

    // Check timestamp is greater than median time past (BIP113)
    if (block.header.timestamp <= ctx.median_time_past) {
        state.invalid(ValidationResult::INVALID_TIMESTAMP, "time-too-old",
                      "block's timestamp is too early");
        return false;
    }

    // Check block weight
    if (!checkBlockWeight(block, state)) {
        return false;
    }

    // BIP34: Check that coinbase includes block height
    if (ctx.bip34_active) {
        const auto& coinbase = block.transactions[0];
        if (!coinbase.inputs.empty()) {
            const auto& script_sig = coinbase.inputs[0].script_sig;
            if (!script_sig.empty()) {
                // First byte should be push of height
                uint8_t push_size = script_sig[0];
                if (push_size <= 4 && script_sig.size() > push_size) {
                    uint64_t height_in_cb = 0;
                    for (uint8_t i = 0; i < push_size; i++) {
                        height_in_cb |= static_cast<uint64_t>(script_sig[1 + i]) << (8 * i);
                    }
                    if (height_in_cb != ctx.height) {
                        state.invalid(ValidationResult::INVALID_COINBASE, "bad-cb-height",
                                      "block height in coinbase is wrong");
                        return false;
                    }
                }
            }
        }
    }

    return true;
}

//-----------------------------------------------------------------------------
// Block Connection (Full Validation + UTXO Update)
//-----------------------------------------------------------------------------

bool Consensus::connectBlock(const Block& block,
                              const BlockValidationContext& ctx,
                              UTXOSet& utxo_set,
                              ValidationState& state) const {
    uint64_t fees = 0;

    // Validate each transaction and collect fees
    for (size_t i = 0; i < block.transactions.size(); i++) {
        const auto& tx = block.transactions[i];
        bool is_coinbase = (i == 0);

        if (is_coinbase) {
            continue;  // Validate coinbase after we know the fees
        }

        // Get inputs from UTXO set
        std::vector<std::pair<Outpoint, TxOutput>> inputs;
        uint64_t input_value = 0;

        for (const auto& input : tx.inputs) {
            Outpoint outpoint{input.prevout.txid, input.prevout.index};
            auto utxo = utxo_set.getUTXO(outpoint);
            if (!utxo) {
                state.invalid(ValidationResult::MISSING_INPUTS, "bad-txns-inputs-missingorspent",
                              "input missing or already spent");
                return false;
            }

            // Check coinbase maturity
            if (utxo->coinbase) {
                if (!isCoinbaseMature(utxo->height, ctx.height)) {
                    state.invalid(ValidationResult::PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase",
                                  "tried to spend coinbase before maturity");
                    return false;
                }
            }

            TxOutput prev_output;
            prev_output.value = utxo->value;
            prev_output.script_pubkey = utxo->script_pubkey;
            inputs.emplace_back(outpoint, prev_output);
            input_value += utxo->value;
        }

        // Calculate output value
        uint64_t output_value = 0;
        for (const auto& output : tx.outputs) {
            output_value += output.value;
        }

        // Check value balance
        if (input_value < output_value) {
            state.invalid(ValidationResult::BAD_TX_OUTPUTS, "bad-txns-in-belowout",
                          "input value less than output value");
            return false;
        }

        fees += input_value - output_value;

        // Verify scripts
        if (!checkInputs(tx, inputs, ctx.script_flags, state)) {
            return false;
        }
    }

    // Validate coinbase
    uint64_t block_reward = params_.getBlockReward(ctx.height);
    if (!checkCoinbase(block.transactions[0], ctx.height, block_reward, fees, state)) {
        return false;
    }

    // Update UTXO set using its built-in connectBlock
    if (!utxo_set.connectBlock(block.transactions, ctx.height)) {
        state.invalid(ValidationResult::ERROR, "utxo-error", "failed to update UTXO set");
        return false;
    }

    return true;
}

//-----------------------------------------------------------------------------
// Block Disconnection
//-----------------------------------------------------------------------------

bool Consensus::disconnectBlock(const Block& block,
                                 uint64_t height,
                                 UTXOSet& utxo_set,
                                 ValidationState& state) const {
    // For proper block disconnection, we need undo data
    // This is generated when the block is connected
    CoinViewDelta undo_data = utxo_set.generateUndoData(block.transactions);

    if (!utxo_set.disconnectBlock(block.transactions, static_cast<int32_t>(height), undo_data)) {
        state.invalid(ValidationResult::ERROR, "utxo-error", "failed to disconnect block from UTXO set");
        return false;
    }

    return true;
}

//-----------------------------------------------------------------------------
// Transaction Validation
//-----------------------------------------------------------------------------

bool Consensus::checkTransaction(const Transaction& tx, ValidationState& state) const {
    // Check structure
    if (!checkTxStructure(tx, state)) {
        return false;
    }

    // Check inputs
    if (!checkTxInputs(tx, state)) {
        return false;
    }

    // Check outputs
    if (!checkTxOutputs(tx, state)) {
        return false;
    }

    return true;
}

bool Consensus::checkTxStructure(const Transaction& tx, ValidationState& state) const {
    // Check for empty inputs
    if (tx.inputs.empty()) {
        state.invalid(ValidationResult::BAD_TX_INPUTS, "bad-txns-vin-empty",
                      "vin empty");
        return false;
    }

    // Check for empty outputs
    if (tx.outputs.empty()) {
        state.invalid(ValidationResult::BAD_TX_OUTPUTS, "bad-txns-vout-empty",
                      "vout empty");
        return false;
    }

    // Check size
    size_t tx_size = tx.getSize();
    if (tx_size > params_.max_tx_size) {
        state.invalid(ValidationResult::INVALID_TX, "bad-txns-oversize",
                      "transaction too large");
        return false;
    }

    return true;
}

bool Consensus::checkTxInputs(const Transaction& tx, ValidationState& state) const {
    // Check for duplicate inputs
    std::set<OutPoint> seen_inputs;
    for (const auto& input : tx.inputs) {
        if (seen_inputs.count(input.prevout)) {
            state.invalid(ValidationResult::BAD_TX_INPUTS, "bad-txns-inputs-duplicate",
                          "duplicate inputs");
            return false;
        }
        seen_inputs.insert(input.prevout);
    }

    // For coinbase, check that prevout is null
    if (tx.isCoinbase()) {
        if (tx.inputs.size() != 1) {
            state.invalid(ValidationResult::INVALID_COINBASE, "bad-cb-length",
                          "coinbase must have exactly one input");
            return false;
        }

        // Coinbase scriptSig size check
        size_t script_size = tx.inputs[0].script_sig.size();
        if (script_size < 2 || script_size > 100) {
            state.invalid(ValidationResult::INVALID_COINBASE, "bad-cb-length",
                          "coinbase script has wrong size");
            return false;
        }
    } else {
        // Non-coinbase: check that no input is null
        for (const auto& input : tx.inputs) {
            if (input.prevout.isNull()) {
                state.invalid(ValidationResult::BAD_TX_INPUTS, "bad-txns-prevout-null",
                              "non-coinbase has null prevout");
                return false;
            }
        }
    }

    return true;
}

bool Consensus::checkTxOutputs(const Transaction& tx, ValidationState& state) const {
    uint64_t total_value = 0;

    for (const auto& output : tx.outputs) {
        // Check for negative value
        if (output.value > params_.max_money) {
            state.invalid(ValidationResult::BAD_TX_OUTPUTS, "bad-txns-vout-toolarge",
                          "output value too large");
            return false;
        }

        total_value += output.value;

        // Check for overflow
        if (total_value > params_.max_money) {
            state.invalid(ValidationResult::BAD_TX_OUTPUTS, "bad-txns-txouttotal-toolarge",
                          "total output value too large");
            return false;
        }
    }

    return true;
}

bool Consensus::contextualCheckTransaction(const Transaction& tx,
                                            const TxValidationContext& ctx,
                                            ValidationState& state) const {
    // Check locktime
    if (tx.locktime > 0) {
        bool locktime_valid = checkLocktime(tx.locktime, ctx.block_height, ctx.block_time);
        if (!locktime_valid) {
            state.invalid(ValidationResult::INVALID_TX, "bad-txns-nonfinal",
                          "transaction is not final");
            return false;
        }
    }

    // Check sequence locks (BIP68)
    if (ctx.script_flags & ftc::script::SCRIPT_VERIFY_CHECKSEQUENCEVERIFY) {
        for (const auto& input : tx.inputs) {
            uint32_t seq = input.sequence;
            if (seq & (1 << 31)) {
                continue;  // Sequence lock disabled
            }

            // Get relative lock time
            // bool time_based = (seq & (1 << 22)) != 0;
            // uint32_t lock_value = seq & 0xffff;

            // Simplified - in full implementation need UTXO heights for proper checks
        }
    }

    return true;
}

bool Consensus::checkInputs(const Transaction& tx,
                             const std::vector<std::pair<Outpoint, TxOutput>>& inputs,
                             uint32_t flags,
                             ValidationState& state) const {
    // Verify input count matches
    if (tx.inputs.size() != inputs.size()) {
        state.invalid(ValidationResult::BAD_TX_INPUTS, "bad-txns-inputs-mismatch",
                      "input count mismatch");
        return false;
    }

    // Skip signature verification for coinbase transactions
    if (tx.isCoinbase()) {
        return true;
    }

    // Build precomputed transaction data for efficient signature verification
    std::vector<TxOutput> spent_outputs;
    spent_outputs.reserve(inputs.size());
    for (const auto& [outpoint, output] : inputs) {
        spent_outputs.push_back(output);
    }

    ftc::script::PrecomputedTransactionData precomputed;
    precomputed.init(tx, spent_outputs);

    // Create interpreter instance
    ftc::script::Interpreter interpreter;

    // Verify each input's script
    for (size_t i = 0; i < tx.inputs.size(); i++) {
        const auto& input = tx.inputs[i];
        const auto& [outpoint, spent_output] = inputs[i];

        // Create scripts from raw data
        ftc::script::Script scriptSig(input.script_sig);
        ftc::script::Script scriptPubKey(spent_output.script_pubkey);

        // Create signature checker for this input
        ftc::script::TransactionSignatureChecker checker(&tx, static_cast<unsigned int>(i),
                                                          spent_output.value, &precomputed);

        // Get witness data if available
        const std::vector<std::vector<uint8_t>>* witness = nullptr;
        if (i < tx.witness.size() && !tx.witness[i].empty()) {
            witness = &tx.witness[i];
        }

        // Verify the script
        ftc::script::ScriptError serror = ftc::script::ScriptError::UNKNOWN_ERROR;
        if (!interpreter.verifyScript(scriptSig, scriptPubKey, witness, flags, checker, &serror)) {
            std::string error_msg = "Script verification failed: ";
            error_msg += ftc::script::ScriptErrorString(serror);

            state.invalid(ValidationResult::SCRIPT_FAILED, "mandatory-script-verify-flag-failed",
                          error_msg);
            return false;
        }
    }

    return true;
}

//-----------------------------------------------------------------------------
// Proof of Work
//-----------------------------------------------------------------------------

bool Consensus::checkProofOfWork(const Hash256& hash, uint32_t bits) const {
    // Check that bits is not lower than minimum
    if (bits < params_.pow_limit_bits) {
        return false;
    }

    // Convert bits to target
    Hash256 target = bitsToTarget(bits);

    // Compare hash against target (hash must be <= target)
    return compareTargets(hash, target) <= 0;
}

uint32_t Consensus::getNextWorkRequired(uint64_t height,
                                          const BlockHeader& last_header,
                                          const std::function<BlockHeader(uint64_t)>& getHeader) const {
    // Special case: genesis block
    if (height == 0) {
        return params_.pow_limit_bits;
    }

    // Only adjust difficulty at interval boundaries
    if (!params_.isDifficultyAdjustment(height)) {
        return last_header.bits;
    }

    // Get first block of this difficulty period
    uint64_t first_height = height - params_.difficulty_adjustment_interval;
    BlockHeader first_header = getHeader(first_height);

    // Calculate actual timespan
    int64_t actual_timespan = last_header.timestamp - first_header.timestamp;

    // Limit adjustment to 4x in either direction
    int64_t target_timespan = static_cast<int64_t>(params_.target_timespan);
    if (actual_timespan < target_timespan / 4) {
        actual_timespan = target_timespan / 4;
    }
    if (actual_timespan > target_timespan * 4) {
        actual_timespan = target_timespan * 4;
    }

    // Calculate new target
    Hash256 current_target = bitsToTarget(last_header.bits);

    // new_target = current_target * actual_timespan / target_timespan
    // This is a simplified calculation - proper implementation needs big integer math
    // For now, we'll do a rough approximation

    double ratio = static_cast<double>(actual_timespan) / static_cast<double>(target_timespan);

    // Convert target to a work estimate and adjust
    uint32_t new_bits = last_header.bits;

    if (ratio > 1.0) {
        // Make easier (increase target)
        // Increase exponent or mantissa
        new_bits += static_cast<uint32_t>((ratio - 1.0) * 0x10000);
    } else {
        // Make harder (decrease target)
        new_bits -= static_cast<uint32_t>((1.0 - ratio) * 0x10000);
    }

    // Don't exceed pow_limit
    if (new_bits > params_.pow_limit_bits) {
        new_bits = params_.pow_limit_bits;
    }

    return new_bits;
}

Hash256 Consensus::getBlockProof(const BlockHeader& header) const {
    Hash256 target = bitsToTarget(header.bits);

    // Work = 2^256 / (target + 1)
    // For simplicity, we'll use a rough approximation

    Hash256 work;
    std::memset(work.data(), 0, 32);

    // Count leading zero bytes in target
    int leading_zeros = 0;
    for (int i = 31; i >= 0; i--) {
        if (target[i] == 0) {
            leading_zeros++;
        } else {
            break;
        }
    }

    // Work is approximately 2^(8 * leading_zeros)
    if (leading_zeros < 32) {
        work[leading_zeros] = 1;
    }

    return work;
}

//-----------------------------------------------------------------------------
// Coinbase Validation
//-----------------------------------------------------------------------------

bool Consensus::checkCoinbase(const Transaction& tx,
                               uint64_t height,
                               uint64_t block_reward,
                               uint64_t fees,
                               ValidationState& state) const {
    if (!tx.isCoinbase()) {
        state.invalid(ValidationResult::INVALID_COINBASE, "bad-cb-missing",
                      "expected coinbase transaction");
        return false;
    }

    // Calculate total allowed coinbase value
    uint64_t max_value = block_reward + fees;

    // Sum outputs
    uint64_t total_output = 0;
    for (const auto& output : tx.outputs) {
        total_output += output.value;
    }

    if (total_output > max_value) {
        state.invalid(ValidationResult::BAD_CB_AMOUNT, "bad-cb-amount",
                      "coinbase pays too much");
        return false;
    }

    return true;
}

bool Consensus::isCoinbaseMature(uint64_t coinbase_height, uint64_t spending_height) const {
    return spending_height >= coinbase_height + params_.coinbase_maturity;
}

//-----------------------------------------------------------------------------
// Difficulty Utilities
//-----------------------------------------------------------------------------

Hash256 Consensus::bitsToTarget(uint32_t bits) {
    Hash256 target;
    std::memset(target.data(), 0, 32);

    // Compact format: XXYYZZWW where XX is exponent and YYZZ is mantissa
    uint32_t exponent = bits >> 24;
    uint32_t mantissa = bits & 0x007fffff;

    // Handle negative
    if (bits & 0x00800000) {
        mantissa |= 0x00800000;
    }

    if (exponent <= 3) {
        mantissa >>= 8 * (3 - exponent);
        target[0] = mantissa & 0xff;
        target[1] = (mantissa >> 8) & 0xff;
        target[2] = (mantissa >> 16) & 0xff;
    } else {
        int offset = exponent - 3;
        if (offset < 29) {
            target[offset] = mantissa & 0xff;
            target[offset + 1] = (mantissa >> 8) & 0xff;
            target[offset + 2] = (mantissa >> 16) & 0xff;
        }
    }

    return target;
}

uint32_t Consensus::targetToBits(const Hash256& target) {
    // Find highest non-zero byte
    int n = 31;
    while (n > 0 && target[n] == 0) {
        n--;
    }

    uint32_t mantissa = 0;
    if (n >= 2) {
        mantissa = (static_cast<uint32_t>(target[n]) << 16) |
                   (static_cast<uint32_t>(target[n-1]) << 8) |
                   static_cast<uint32_t>(target[n-2]);
    } else if (n == 1) {
        mantissa = (static_cast<uint32_t>(target[n]) << 16) |
                   (static_cast<uint32_t>(target[n-1]) << 8);
    } else {
        mantissa = static_cast<uint32_t>(target[n]) << 16;
    }

    uint32_t exponent = n + 1;

    // Normalize
    if (mantissa & 0x00800000) {
        mantissa >>= 8;
        exponent++;
    }

    return (exponent << 24) | mantissa;
}

double Consensus::getDifficulty(uint32_t bits) {
    // Difficulty = max_target / current_target
    // We use a simplified calculation

    uint32_t exponent = bits >> 24;
    uint32_t mantissa = bits & 0x007fffff;

    double target = static_cast<double>(mantissa) * std::pow(256.0, exponent - 3);

    // Max target (difficulty 1)
    double max_target = static_cast<double>(0x00ffff) * std::pow(256.0, 0x1d - 3);

    return max_target / target;
}

int Consensus::compareTargets(const Hash256& a, const Hash256& b) {
    // Compare as big-endian numbers
    for (int i = 31; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

//-----------------------------------------------------------------------------
// Script Flags
//-----------------------------------------------------------------------------

uint32_t Consensus::getScriptFlags(uint64_t height) const {
    uint32_t flags = 0;

    // P2SH (BIP16)
    if (height >= params_.bip16_height) {
        flags |= ftc::script::SCRIPT_VERIFY_P2SH;
    }

    // Strict DER (BIP66)
    if (height >= params_.bip66_height) {
        flags |= ftc::script::SCRIPT_VERIFY_DERSIG;
    }

    // CHECKLOCKTIMEVERIFY (BIP65)
    if (height >= params_.bip65_height) {
        flags |= ftc::script::SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // CHECKSEQUENCEVERIFY (BIP68/112)
    if (height >= params_.bip68_height) {
        flags |= ftc::script::SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    }

    // SegWit
    if (height >= params_.segwit_height) {
        flags |= ftc::script::SCRIPT_VERIFY_WITNESS;
        flags |= ftc::script::SCRIPT_VERIFY_NULLDUMMY;
    }

    return flags;
}

//-----------------------------------------------------------------------------
// Merkle Tree
//-----------------------------------------------------------------------------

Hash256 Consensus::computeMerkleRoot(const std::vector<Transaction>& txs) {
    std::vector<Hash256> hashes;
    hashes.reserve(txs.size());

    for (const auto& tx : txs) {
        hashes.push_back(tx.getTxId());
    }

    return computeMerkleRoot(hashes);
}

Hash256 Consensus::computeMerkleRoot(const std::vector<Hash256>& hashes) {
    if (hashes.empty()) {
        return ZERO_HASH;
    }

    if (hashes.size() == 1) {
        return hashes[0];
    }

    std::vector<Hash256> current = hashes;

    while (current.size() > 1) {
        // If odd number, duplicate last element
        if (current.size() % 2 != 0) {
            current.push_back(current.back());
        }

        std::vector<Hash256> next;
        next.reserve(current.size() / 2);

        for (size_t i = 0; i < current.size(); i += 2) {
            // Concatenate and double-hash
            std::vector<uint8_t> combined;
            combined.reserve(64);
            combined.insert(combined.end(), current[i].begin(), current[i].end());
            combined.insert(combined.end(), current[i+1].begin(), current[i+1].end());

            Hash256 first_hash = keccak256(combined.data(), combined.size());
            next.push_back(keccak256(first_hash.data(), first_hash.size()));
        }

        current = std::move(next);
    }

    return current[0];
}

bool Consensus::verifyMerkleProof(const Hash256& txid,
                                   const Hash256& root,
                                   const std::vector<Hash256>& proof,
                                   uint32_t index) {
    Hash256 current = txid;

    for (const auto& sibling : proof) {
        std::vector<uint8_t> combined;
        combined.reserve(64);

        if (index % 2 == 0) {
            combined.insert(combined.end(), current.begin(), current.end());
            combined.insert(combined.end(), sibling.begin(), sibling.end());
        } else {
            combined.insert(combined.end(), sibling.begin(), sibling.end());
            combined.insert(combined.end(), current.begin(), current.end());
        }

        Hash256 first_hash = keccak256(combined.data(), combined.size());
        current = keccak256(first_hash.data(), first_hash.size());

        index /= 2;
    }

    return current == root;
}

//-----------------------------------------------------------------------------
// Internal Helpers
//-----------------------------------------------------------------------------

bool Consensus::checkBlockSize(const Block& block, ValidationState& state) const {
    size_t size = block.getSize();
    if (size > params_.max_block_size) {
        state.invalid(ValidationResult::INVALID_BLOCK_SIZE, "bad-blk-length",
                      "block size exceeds maximum");
        return false;
    }
    return true;
}

bool Consensus::checkBlockWeight(const Block& block, ValidationState& state) const {
    size_t weight = getBlockWeight(block);
    if (weight > params_.max_block_weight) {
        state.invalid(ValidationResult::BLOCK_WEIGHT_TOO_HIGH, "bad-blk-weight",
                      "block weight exceeds maximum");
        return false;
    }
    return true;
}

bool Consensus::checkDuplicateTxids(const Block& block, ValidationState& state) const {
    std::set<Hash256> seen;
    for (const auto& tx : block.transactions) {
        Hash256 txid = tx.getTxId();
        if (seen.count(txid)) {
            state.invalid(ValidationResult::DUPLICATE_TX, "bad-txns-duplicate",
                          "duplicate transaction");
            return false;
        }
        seen.insert(txid);
    }
    return true;
}

bool Consensus::checkMerkleRoot(const Block& block, ValidationState& state) const {
    Hash256 computed = computeMerkleRoot(block.transactions);
    if (computed != block.header.merkle_root) {
        state.invalid(ValidationResult::INVALID_MERKLE_ROOT, "bad-txnmrklroot",
                      "merkle root mismatch");
        return false;
    }
    return true;
}

//-----------------------------------------------------------------------------
// Utility Functions
//-----------------------------------------------------------------------------

uint32_t getMedianTimePast(uint64_t height,
                            const std::function<uint32_t(uint64_t)>& getBlockTime) {
    std::vector<uint32_t> times;
    times.reserve(11);

    for (uint64_t i = 0; i < 11 && height > i; i++) {
        times.push_back(getBlockTime(height - i));
    }

    std::sort(times.begin(), times.end());

    return times[times.size() / 2];
}

bool checkLocktime(int64_t locktime, uint64_t block_height, uint32_t block_time) {
    if (locktime < 500000000) {
        // Block height lock
        return locktime <= static_cast<int64_t>(block_height);
    } else {
        // Timestamp lock
        return locktime <= static_cast<int64_t>(block_time);
    }
}

bool checkSequence(uint32_t sequence, uint64_t age_blocks, uint32_t age_seconds) {
    // Sequence lock disabled
    if (sequence & (1 << 31)) {
        return true;
    }

    bool time_based = (sequence & (1 << 22)) != 0;
    uint32_t lock_value = sequence & 0xffff;

    if (time_based) {
        // Time-based: units of 512 seconds
        return age_seconds >= lock_value * 512;
    } else {
        // Block-based
        return age_blocks >= lock_value;
    }
}

size_t countBlockSigOps(const Block& block) {
    size_t count = 0;
    for (const auto& tx : block.transactions) {
        count += countTxSigOps(tx, true);
    }
    return count;
}

size_t countTxSigOps(const Transaction& tx, bool accurate) {
    // Simplified sig op counting - counts OP_CHECKSIG patterns
    // Full implementation would parse scripts properly
    size_t count = 0;

    // Rough estimate: 1 sigop per input (P2PKH assumption)
    count += tx.inputs.size();

    // Check outputs for multisig patterns (simplified)
    for (const auto& output : tx.outputs) {
        // P2PKH outputs have 1 sigop
        if (output.script_pubkey.size() == 25) {
            count += 1;
        }
    }

    return count;
}

size_t getTxWeight(const Transaction& tx) {
    // Weight = base_size * 4 (no witness support yet)
    // When witness is added: weight = base_size * 3 + total_size
    return tx.getSize() * 4;
}

size_t getBlockWeight(const Block& block) {
    size_t weight = 80 * 4;  // Header weight

    for (const auto& tx : block.transactions) {
        weight += getTxWeight(tx);
    }

    return weight;
}

} // namespace chain
} // namespace ftc
