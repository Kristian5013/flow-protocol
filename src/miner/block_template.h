#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Block template management for FTC mining.
//
// A BlockTemplate contains everything needed to mine a new block:
// the fully assembled block header, the set of transactions (including
// the coinbase), the expected fees and subsidy, and the target.
//
// Templates are created from the current chain state and mempool, and
// can be incrementally updated when the mempool changes without needing
// to rebuild from scratch.
// ---------------------------------------------------------------------------

#include "chain/chainstate.h"
#include "core/error.h"
#include "core/types.h"
#include "mempool/mempool.h"
#include "miner/block_assembler.h"
#include "miner/coinbase.h"
#include "miner/difficulty.h"
#include "primitives/address.h"
#include "primitives/amount.h"
#include "primitives/block.h"
#include "primitives/block_header.h"
#include "primitives/transaction.h"

#include <cstdint>
#include <vector>

namespace miner {

// ---------------------------------------------------------------------------
// BlockTemplate
// ---------------------------------------------------------------------------

/// Complete data needed to mine a new block.
///
/// Contains the fully populated block header (ready for nonce iteration),
/// all transactions (including the coinbase at index 0), fee/subsidy
/// information, and the difficulty target.
struct BlockTemplate {
    /// The block header with all fields set except nonce.
    /// The miner iterates the nonce field while solving.
    primitives::BlockHeader header;

    /// All transactions in the block, with the coinbase at index 0.
    std::vector<primitives::Transaction> txs;

    /// Total fees collected from non-coinbase transactions.
    primitives::Amount fees;

    /// Block subsidy (newly created coins).
    primitives::Amount subsidy;

    /// The height of this block.
    int height = 0;

    /// The 256-bit difficulty target.
    /// A valid proof-of-work must produce a hash <= this value.
    core::uint256 target;

    /// The compact target representation (bits field).
    uint32_t bits = 0;

    /// Total weight of the block (including coinbase).
    int64_t total_weight = 0;

    /// Total signature operations in the block.
    int total_sigops = 0;

    /// Number of transactions (including coinbase).
    [[nodiscard]] size_t tx_count() const { return txs.size(); }

    /// Whether this template includes witness (segwit) transactions.
    [[nodiscard]] bool has_witness() const;

    /// Construct a full Block from this template.
    [[nodiscard]] primitives::Block to_block() const;
};

// ---------------------------------------------------------------------------
// Template creation
// ---------------------------------------------------------------------------

/// Create a new block template from the current chain state and mempool.
///
/// This is the primary entry point for block template construction. It:
///   1. Determines the block height, previous hash, and difficulty target
///      from the active chain tip.
///   2. Assembles transactions from the mempool using BlockAssembler.
///   3. Creates the coinbase transaction with the appropriate reward.
///   4. Computes the merkle root.
///   5. Sets the block header fields (version, prev_hash, merkle_root,
///      timestamp, bits, nonce=0).
///
/// @param chainstate     The chainstate manager (provides chain tip info).
/// @param mempool        The transaction mempool (provides candidate txs).
/// @param coinbase_addr  The miner's payout address.
/// @param extra_nonce    Extra nonce for the coinbase transaction.
/// @returns              A fully populated BlockTemplate, or an error.
[[nodiscard]] core::Result<BlockTemplate> create_block_template(
    chain::ChainstateManager& chainstate,
    const mempool::Mempool& mempool,
    const primitives::Address& coinbase_addr,
    uint64_t extra_nonce = 0);

/// Update an existing block template with fresh mempool transactions.
///
/// This is more efficient than creating a template from scratch when
/// only the mempool contents have changed (no new chain tip). It:
///   1. Re-assembles transactions from the current mempool.
///   2. Rebuilds the coinbase transaction (fees may have changed).
///   3. Recomputes the merkle root.
///   4. Updates the timestamp if needed.
///
/// @param tmpl           The existing template to update (modified in place).
/// @param chainstate     The chainstate manager.
/// @param mempool        The transaction mempool.
/// @param coinbase_addr  The miner's payout address.
/// @param extra_nonce    Extra nonce for the coinbase transaction.
/// @returns              core::make_ok() on success, or an error.
[[nodiscard]] core::Result<void> update_block_template(
    BlockTemplate& tmpl,
    chain::ChainstateManager& chainstate,
    const mempool::Mempool& mempool,
    const primitives::Address& coinbase_addr,
    uint64_t extra_nonce = 0);

/// Validate that a block template is internally consistent.
///
/// Checks:
///   - The coinbase is at index 0 and is valid.
///   - The merkle root matches the transactions.
///   - The total fees and subsidy are correct.
///   - The block weight is within limits.
///
/// @param tmpl  The template to validate.
/// @returns     core::make_ok() on success, or an error.
[[nodiscard]] core::Result<void> validate_block_template(
    const BlockTemplate& tmpl);

} // namespace miner
