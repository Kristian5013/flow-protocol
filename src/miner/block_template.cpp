// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner/block_template.h"

#include "consensus/merkle.h"
#include "consensus/subsidy.h"
#include "core/logging.h"
#include "core/time.h"

#include <algorithm>
#include <string>

namespace miner {

// ---------------------------------------------------------------------------
// BlockTemplate member functions
// ---------------------------------------------------------------------------

bool BlockTemplate::has_witness() const {
    for (const auto& tx : txs) {
        if (tx.has_witness()) {
            return true;
        }
    }
    return false;
}

primitives::Block BlockTemplate::to_block() const {
    return primitives::Block(header, txs);
}

// ---------------------------------------------------------------------------
// create_block_template
// ---------------------------------------------------------------------------

core::Result<BlockTemplate> create_block_template(
    chain::ChainstateManager& chainstate,
    const mempool::Mempool& mempool,
    const primitives::Address& coinbase_addr,
    uint64_t extra_nonce) {

    if (!coinbase_addr.is_valid()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Invalid coinbase address");
    }

    // Get the current chain tip.
    const auto& chain = chainstate.active_chain();
    auto* tip = chain.tip();
    if (tip == nullptr) {
        return core::Error(core::ErrorCode::INTERNAL_ERROR,
            "No active chain tip available");
    }

    BlockTemplate tmpl;

    // The new block height is tip + 1.
    tmpl.height = tip->height + 1;

    // Determine the difficulty target (bits).
    // If we're at a difficulty adjustment boundary, compute the new target.
    // Otherwise, use the same target as the previous block.
    const auto& params = chainstate.params();

    int64_t adjustment_interval = params.difficulty_adjustment_interval();
    if (tmpl.height % adjustment_interval == 0 && tmpl.height > 0) {
        // Difficulty adjustment: find the first block of the previous period.
        int first_height = tmpl.height - static_cast<int>(adjustment_interval);
        auto* first_block = chain.at(first_height);
        if (first_block == nullptr) {
            return core::Error(core::ErrorCode::INTERNAL_ERROR,
                "Cannot find first block of difficulty period at height " +
                std::to_string(first_height));
        }
        tmpl.bits = calculate_next_work_required(*tip, *first_block, params);
    } else {
        // Use the same difficulty as the previous block.
        tmpl.bits = tip->bits;
    }

    tmpl.target = bits_to_target(tmpl.bits);

    // Get the block subsidy for this height.
    tmpl.subsidy = consensus::get_block_subsidy(tmpl.height, params);

    // Assemble transactions from the mempool.
    BlockAssembler assembler;
    auto assembly = assembler.assemble(mempool);

    tmpl.total_weight = assembly.total_weight;
    tmpl.total_sigops = assembly.total_sigops;
    tmpl.fees = assembly.total_fees;

    // Check if any selected transaction has witness data.
    bool has_segwit = false;
    for (const auto& tx : assembly.transactions) {
        if (tx.has_witness()) {
            has_segwit = true;
            break;
        }
    }

    // If we have segwit transactions, compute the witness merkle root for
    // the witness commitment. We need the complete transaction list including
    // the coinbase to do this, but the coinbase wtxid is replaced with zero.
    // For now, compute a preliminary witness merkle root.
    core::uint256 witness_merkle_root;

    if (has_segwit) {
        // Build a temporary block with a placeholder coinbase to compute
        // the witness merkle root.
        std::vector<core::uint256> wtxids;
        wtxids.push_back(core::uint256{});  // coinbase wtxid = 0

        for (const auto& tx : assembly.transactions) {
            wtxids.push_back(tx.wtxid());
        }

        witness_merkle_root = consensus::compute_merkle_root(wtxids);
    }

    // Create the coinbase transaction.
    auto coinbase_result = create_coinbase(
        tmpl.height,
        coinbase_addr,
        tmpl.fees,
        tmpl.subsidy,
        extra_nonce,
        has_segwit,
        witness_merkle_root);

    if (!coinbase_result.ok()) {
        return core::Error(coinbase_result.error().code(),
            "Failed to create coinbase: " + coinbase_result.error().message());
    }

    // Build the transaction list: coinbase first, then mempool transactions.
    tmpl.txs.clear();
    tmpl.txs.reserve(1 + assembly.transactions.size());
    tmpl.txs.push_back(std::move(coinbase_result.value()));

    for (auto& tx : assembly.transactions) {
        tmpl.txs.push_back(std::move(tx));
    }

    // Compute the merkle root from all transaction IDs.
    std::vector<core::uint256> txids;
    txids.reserve(tmpl.txs.size());
    for (const auto& tx : tmpl.txs) {
        txids.push_back(tx.txid());
    }

    core::uint256 merkle_root = consensus::compute_merkle_root(txids);

    // Set the block header fields.
    tmpl.header.version = 0x20000000;  // BIP9 versionbits base
    tmpl.header.prev_hash = tip->block_hash;
    tmpl.header.merkle_root = merkle_root;
    tmpl.header.timestamp = static_cast<uint32_t>(
        std::max(
            static_cast<int64_t>(tip->get_median_time_past() + 1),
            core::get_adjusted_time()));
    tmpl.header.bits = tmpl.bits;
    tmpl.header.nonce = 0;

    // Account for coinbase weight.
    tmpl.total_weight += static_cast<int64_t>(tmpl.txs[0].weight());

    LOG_INFO(core::LogCategory::MINING,
        "Created block template: height=" + std::to_string(tmpl.height) +
        " txs=" + std::to_string(tmpl.txs.size()) +
        " fees=" + std::to_string(tmpl.fees.value()) +
        " subsidy=" + std::to_string(tmpl.subsidy.value()) +
        " weight=" + std::to_string(tmpl.total_weight) +
        " target=" + tmpl.target.to_hex().substr(0, 16) + "...");

    return tmpl;
}

// ---------------------------------------------------------------------------
// update_block_template
// ---------------------------------------------------------------------------

core::Result<void> update_block_template(
    BlockTemplate& tmpl,
    chain::ChainstateManager& chainstate,
    const mempool::Mempool& mempool,
    const primitives::Address& coinbase_addr,
    uint64_t extra_nonce) {

    if (!coinbase_addr.is_valid()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Invalid coinbase address");
    }

    // Check if the chain tip has changed.
    const auto& chain = chainstate.active_chain();
    auto* tip = chain.tip();
    if (tip == nullptr) {
        return core::Error(core::ErrorCode::INTERNAL_ERROR,
            "No active chain tip");
    }

    // If the tip has changed, the caller should create a new template
    // rather than updating the existing one.
    if (tip->block_hash != tmpl.header.prev_hash) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Chain tip has changed; create a new template instead of updating");
    }

    // Re-assemble transactions from the current mempool.
    BlockAssembler assembler;
    auto assembly = assembler.assemble(mempool);

    tmpl.fees = assembly.total_fees;
    tmpl.total_weight = assembly.total_weight;
    tmpl.total_sigops = assembly.total_sigops;

    // Check for segwit transactions.
    bool has_segwit = false;
    for (const auto& tx : assembly.transactions) {
        if (tx.has_witness()) {
            has_segwit = true;
            break;
        }
    }

    // Compute witness merkle root if needed.
    core::uint256 witness_merkle_root;
    if (has_segwit) {
        std::vector<core::uint256> wtxids;
        wtxids.push_back(core::uint256{});  // coinbase wtxid = 0
        for (const auto& tx : assembly.transactions) {
            wtxids.push_back(tx.wtxid());
        }
        witness_merkle_root = consensus::compute_merkle_root(wtxids);
    }

    // Recreate the coinbase transaction with updated fees.
    auto coinbase_result = create_coinbase(
        tmpl.height,
        coinbase_addr,
        tmpl.fees,
        tmpl.subsidy,
        extra_nonce,
        has_segwit,
        witness_merkle_root);

    if (!coinbase_result.ok()) {
        return core::Error(coinbase_result.error().code(),
            "Failed to update coinbase: " + coinbase_result.error().message());
    }

    // Rebuild the transaction list.
    tmpl.txs.clear();
    tmpl.txs.reserve(1 + assembly.transactions.size());
    tmpl.txs.push_back(std::move(coinbase_result.value()));

    for (auto& tx : assembly.transactions) {
        tmpl.txs.push_back(std::move(tx));
    }

    // Recompute the merkle root.
    std::vector<core::uint256> txids;
    txids.reserve(tmpl.txs.size());
    for (const auto& tx : tmpl.txs) {
        txids.push_back(tx.txid());
    }

    tmpl.header.merkle_root = consensus::compute_merkle_root(txids);

    // Update the timestamp (advance if needed, but don't go backward).
    uint32_t new_time = static_cast<uint32_t>(
        std::max(
            static_cast<int64_t>(tip->get_median_time_past() + 1),
            core::get_adjusted_time()));
    if (new_time > tmpl.header.timestamp) {
        tmpl.header.timestamp = new_time;
    }

    // Reset nonce for the new template variant.
    tmpl.header.nonce = 0;

    // Update total weight including coinbase.
    tmpl.total_weight += static_cast<int64_t>(tmpl.txs[0].weight());

    LOG_DEBUG(core::LogCategory::MINING,
        "Updated block template: txs=" + std::to_string(tmpl.txs.size()) +
        " fees=" + std::to_string(tmpl.fees.value()) +
        " weight=" + std::to_string(tmpl.total_weight));

    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// validate_block_template
// ---------------------------------------------------------------------------

core::Result<void> validate_block_template(const BlockTemplate& tmpl) {
    // Must have at least the coinbase transaction.
    if (tmpl.txs.empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Block template has no transactions");
    }

    // First transaction must be a coinbase.
    if (!tmpl.txs[0].is_coinbase()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "First transaction in block template is not a coinbase");
    }

    // No other transaction may be a coinbase.
    for (size_t i = 1; i < tmpl.txs.size(); ++i) {
        if (tmpl.txs[i].is_coinbase()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "Non-first transaction at index " + std::to_string(i) +
                " is a coinbase");
        }
    }

    // Verify the merkle root.
    std::vector<core::uint256> txids;
    txids.reserve(tmpl.txs.size());
    for (const auto& tx : tmpl.txs) {
        txids.push_back(tx.txid());
    }
    core::uint256 computed_merkle = consensus::compute_merkle_root(txids);

    if (computed_merkle != tmpl.header.merkle_root) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Merkle root mismatch: header=" +
            tmpl.header.merkle_root.to_hex() +
            " computed=" + computed_merkle.to_hex());
    }

    // Verify the coinbase output value doesn't exceed subsidy + fees.
    int64_t coinbase_output_total = 0;
    for (const auto& out : tmpl.txs[0].vout()) {
        coinbase_output_total += out.amount.value();
    }

    int64_t max_reward = tmpl.subsidy.value() + tmpl.fees.value();
    if (coinbase_output_total > max_reward) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Coinbase output (" + std::to_string(coinbase_output_total) +
            ") exceeds allowed reward (" + std::to_string(max_reward) + ")");
    }

    // Verify block weight is within limits.
    if (tmpl.total_weight > MAX_BLOCK_WEIGHT) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Block template weight (" + std::to_string(tmpl.total_weight) +
            ") exceeds maximum (" + std::to_string(MAX_BLOCK_WEIGHT) + ")");
    }

    // Verify sigop count is within limits.
    if (tmpl.total_sigops > MAX_BLOCK_SIGOPS) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Block template sigops (" + std::to_string(tmpl.total_sigops) +
            ") exceeds maximum (" + std::to_string(MAX_BLOCK_SIGOPS) + ")");
    }

    // Verify height is positive.
    if (tmpl.height < 0) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Block template height is negative: " +
            std::to_string(tmpl.height));
    }

    // Verify target is non-zero.
    if (tmpl.target.is_zero()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Block template target is zero");
    }

    return core::Result<void>{};
}

} // namespace miner
