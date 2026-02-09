// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/chainstate.h"

#include "chain/block_index.h"
#include "chain/chain.h"
#include "chain/coins.h"
#include "chain/reorg.h"
#include "chain/storage/block_store.h"
#include "chain/storage/index_db.h"
#include "chain/utxo/cache.h"
#include "chain/utxo/db.h"
#include "consensus/params.h"
#include "consensus/pow.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "core/error.h"
#include "core/logging.h"
#include "core/serialize.h"
#include "core/stream.h"
#include "core/types.h"
#include "primitives/amount.h"
#include "primitives/block.h"
#include "primitives/block_header.h"
#include "primitives/outpoint.h"
#include "primitives/transaction.h"
#include "primitives/txout.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace chain {

// ===========================================================================
// Uint256Hash
// ===========================================================================
// Use the first 8 bytes of the hash (which are effectively random for
// block hashes) as a size_t.  This avoids the overhead of a full hash
// computation and provides excellent distribution.
// ===========================================================================

size_t ChainstateManager::Uint256Hash::operator()(
    const core::uint256& h) const noexcept
{
    size_t result = 0;
    static_assert(sizeof(size_t) <= 8);
    std::memcpy(&result, h.data(), sizeof(result));
    return result;
}

// ===========================================================================
// Construction / Destruction
// ===========================================================================

ChainstateManager::ChainstateManager(
    const consensus::ConsensusParams& params,
    const std::filesystem::path& data_dir)
    : params_(params)
    , data_dir_(data_dir)
{
}

ChainstateManager::~ChainstateManager() {
    // Attempt a clean flush on destruction.  Errors are logged but cannot
    // be propagated from a destructor.
    auto result = shutdown();
    if (!result.ok()) {
        LOG_ERROR(core::LogCategory::CHAIN,
                  "Error during ChainstateManager destruction: " +
                  result.error().message());
    }
}

// ===========================================================================
// init
// ===========================================================================
// Initialization sequence:
//   1. Open (or create) the block store and index database.
//   2. Load all block index entries from the index database into the
//      in-memory block_index_ map.
//   3. Compute the best header (most chain work).
//   4. Rebuild the active chain from genesis to the last fully-validated
//      tip.
//   5. Open the UTXO database and load the cache.
// ===========================================================================

core::Result<void> ChainstateManager::init() {
    LOG_INFO(core::LogCategory::CHAIN,
             "Initializing chainstate from " + data_dir_.string());

    // --- Open block storage ------------------------------------------------
    block_store_ = std::make_unique<storage::BlockStore>(data_dir_);
    FTC_TRY_VOID(block_store_->init());

    LOG_INFO(core::LogCategory::CHAIN, "Block store initialized");

    // --- Open and load block index database --------------------------------
    index_db_ = std::make_unique<storage::IndexDB>(data_dir_ / "index.dat");
    auto index_entries = index_db_->load();

    if (index_entries.ok() && !index_entries.value().empty()) {
        const auto& entries = index_entries.value();
        LOG_INFO(core::LogCategory::CHAIN,
                 "Loading " + std::to_string(entries.size()) +
                 " block index entries from disk");

        // Pass 1: Create all BlockIndex entries in the map.
        for (const auto& entry : entries) {
            auto bi = std::make_unique<BlockIndex>();
            bi->block_hash       = entry.block_hash;
            bi->version          = entry.version;
            bi->hash_merkle_root = entry.hash_merkle_root;
            bi->time             = entry.time;
            bi->bits             = entry.bits;
            bi->nonce            = entry.nonce;
            bi->height           = entry.height;
            bi->chain_work       = entry.chain_work;
            bi->status           = entry.status;
            bi->data_pos         = entry.data_pos;
            bi->undo_pos         = entry.undo_pos;
            bi->tx_count         = entry.tx_count;
            block_index_.emplace(entry.block_hash, std::move(bi));
        }

        // Pass 2: Resolve parent pointers via prev_hash.
        for (const auto& entry : entries) {
            if (entry.prev_hash.is_zero()) continue;
            auto it = block_index_.find(entry.block_hash);
            if (it == block_index_.end()) continue;
            auto parent_it = block_index_.find(entry.prev_hash);
            if (parent_it != block_index_.end()) {
                it->second->prev = parent_it->second.get();
            }
        }

        // Pass 3: Compute chain_tx (cumulative tx count) in height order.
        // IMPORTANT: Only propagate chain_tx through blocks that have full
        // data on disk AND whose parent also has a valid chain_tx.  This
        // ensures that chain_tx > 0 means "every block from genesis to here
        // has data available" -- which find_best_candidate() relies on.
        std::vector<BlockIndex*> by_height;
        by_height.reserve(block_index_.size());
        for (auto& [hash, idx] : block_index_) {
            by_height.push_back(idx.get());
        }
        std::sort(by_height.begin(), by_height.end(),
                  [](const BlockIndex* a, const BlockIndex* b) {
                      return a->height < b->height;
                  });
        for (BlockIndex* bi : by_height) {
            if (!bi->has_data()) {
                bi->chain_tx = 0;
                continue;
            }
            if (bi->height == 0) {
                // Genesis always has data; tx_count may be 0 if genesis
                // was added via add_to_block_index (header only) rather
                // than accept_block.  Use at least 1 so chain_tx > 0.
                bi->chain_tx = std::max(bi->tx_count, 1);
            } else if (bi->prev != nullptr && bi->prev->chain_tx > 0) {
                bi->chain_tx = bi->prev->chain_tx + bi->tx_count;
            } else {
                bi->chain_tx = 0;
            }
        }

        LOG_INFO(core::LogCategory::CHAIN,
                 "Block index reconstructed: " +
                 std::to_string(block_index_.size()) + " entries");
    } else {
        LOG_INFO(core::LogCategory::CHAIN,
                 "No block index database found, starting fresh");
    }

    // --- Ensure genesis block is in the index -----------------------------
    auto genesis_hash = params_.genesis_block.hash();
    if (block_index_.find(genesis_hash) == block_index_.end()) {
        BlockIndex* genesis = add_to_block_index(params_.genesis_block);
        genesis->raise_validity(BlockIndex::BLOCK_VALID_SCRIPTS);
        genesis->status |= BlockIndex::BLOCK_HAVE_DATA;
        genesis->tx_count = 1;  // genesis always has 1 coinbase tx
        genesis->chain_tx = 1;
    }

    // --- Determine best header and active chain tip -----------------------
    best_header_ = nullptr;
    BlockIndex* best_valid_tip = nullptr;

    for (auto& [hash, index] : block_index_) {
        BlockIndex* bi = index.get();

        // Track the header with the most cumulative work.
        if (best_header_ == nullptr ||
            bi->chain_work > best_header_->chain_work) {
            best_header_ = bi;
        }

        // Track the best fully-validated block with data on disk.
        if (bi->is_valid(BlockIndex::BLOCK_VALID_SCRIPTS) &&
            bi->has_data()) {
            if (best_valid_tip == nullptr ||
                bi->chain_work > best_valid_tip->chain_work) {
                best_valid_tip = bi;
            }
        }
    }

    // --- Set the active chain to the best validated tip --------------------
    if (best_valid_tip != nullptr) {
        active_chain_.set_tip(best_valid_tip);
    }

    LOG_INFO(core::LogCategory::CHAIN,
             "Block index loaded: " + std::to_string(block_index_.size()) +
             " entries, active chain height " +
             std::to_string(active_chain_.height()));

    // --- Open UTXO database and load snapshot if available -----------------
    utxo_db_ = std::make_unique<utxo::UtxoDB>(data_dir_ / "utxo.dat");
    utxo_cache_ = std::make_unique<utxo::UtxoCache>();

    if (utxo_db_->has_snapshot()) {
        LOG_INFO(core::LogCategory::CHAIN, "Loading UTXO snapshot from disk");
        auto load_result = utxo_db_->load_snapshot(*utxo_cache_);
        if (load_result.ok()) {
            LOG_INFO(core::LogCategory::CHAIN,
                     "UTXO snapshot loaded: " +
                     std::to_string(utxo_cache_->size()) + " coins, best block " +
                     utxo_cache_->get_best_block().to_hex());
        } else {
            LOG_ERROR(core::LogCategory::CHAIN,
                      "Failed to load UTXO snapshot: " +
                      load_result.error().message() +
                      ", will rebuild from blocks");
            utxo_cache_->clear();
        }
    }

    // If UTXO cache is empty, seed genesis and replay blocks to rebuild.
    if (utxo_cache_->size() == 0) {
        LOG_INFO(core::LogCategory::CHAIN,
                 "Seeding genesis coinbase into UTXO set");
        primitives::Transaction genesis_cb = params_.create_genesis_coinbase();
        const core::uint256& txid = genesis_cb.txid();

        for (uint32_t i = 0;
             i < static_cast<uint32_t>(genesis_cb.vout().size());
             ++i)
        {
            primitives::OutPoint outpoint(txid, i);
            Coin coin(genesis_cb.vout()[i], /*height=*/0, /*is_coinbase=*/true);
            utxo_cache_->add_coin(outpoint, std::move(coin));
        }
        utxo_cache_->set_best_block(genesis_hash);

        // Replay blocks from height 1 to tip to rebuild the UTXO set.
        if (active_chain_.height() > 0) {
            LOG_INFO(core::LogCategory::CHAIN,
                     "Replaying " + std::to_string(active_chain_.height()) +
                     " blocks to rebuild UTXO set");
            for (int h = 1; h <= active_chain_.height(); ++h) {
                BlockIndex* bi = active_chain_.at(h);
                if (!bi || !bi->has_data()) {
                    LOG_ERROR(core::LogCategory::CHAIN,
                              "Missing block data at height " +
                              std::to_string(h) + ", UTXO rebuild incomplete");
                    break;
                }
                auto block_result = block_store_->read_block(bi->data_pos);
                if (!block_result.ok()) {
                    LOG_ERROR(core::LogCategory::CHAIN,
                              "Failed to read block at height " +
                              std::to_string(h) + ": " +
                              block_result.error().message());
                    break;
                }
                auto cn_result = connect_block(bi, block_result.value());
                if (!cn_result.ok()) {
                    LOG_ERROR(core::LogCategory::CHAIN,
                              "Failed to connect block at height " +
                              std::to_string(h) + ": " +
                              cn_result.error().message());
                    break;
                }
            }
            LOG_INFO(core::LogCategory::CHAIN,
                     "UTXO rebuild complete: " +
                     std::to_string(utxo_cache_->size()) + " coins");
        }
    }

    LOG_INFO(core::LogCategory::CHAIN, "Chainstate initialization complete");

    return core::make_ok();
}

// ===========================================================================
// shutdown
// ===========================================================================

core::Result<void> ChainstateManager::shutdown() {
    LOG_INFO(core::LogCategory::CHAIN, "Shutting down chainstate");

    // Flush UTXO cache and block index to disk.
    FTC_TRY_VOID(flush());

    // Release resources.
    utxo_cache_.reset();
    utxo_db_.reset();
    index_db_.reset();
    block_store_.reset();

    LOG_INFO(core::LogCategory::CHAIN, "Chainstate shutdown complete");
    return core::make_ok();
}

// ===========================================================================
// accept_block_header
// ===========================================================================
// Validation steps:
//   1. Check if the header is already known (by hash).  If so, return
//      the existing index entry.
//   2. Validate proof-of-work (hash <= target, target <= pow_limit).
//   3. Locate the parent block in the index.
//   4. Validate that the timestamp is greater than the median of the
//      last 11 blocks (median-time-past rule).
//   5. Add the header to the block index.
// ===========================================================================

core::Result<BlockIndex*> ChainstateManager::accept_block_header(
    const primitives::BlockHeader& header)
{
    std::lock_guard<std::recursive_mutex> lock(cs_main_);
    const core::uint256 hash = header.hash();

    // --- Already known? ---------------------------------------------------
    auto it = block_index_.find(hash);
    if (it != block_index_.end()) {
        BlockIndex* existing = it->second.get();
        if (existing->is_failed()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "block header previously marked invalid: " + hash.to_hex());
        }
        return existing;
    }

    // --- Proof of work ----------------------------------------------------
    if (!consensus::check_proof_of_work(hash, header.bits, params_)) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "proof-of-work check failed for header " + hash.to_hex());
    }

    // --- Parent lookup ----------------------------------------------------
    // The genesis block has a zero prev_hash and is added during init(),
    // so every subsequent header must connect to a known parent.
    BlockIndex* parent = lookup_block_index(header.prev_hash);
    if (parent == nullptr) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "previous block not found: " + header.prev_hash.to_hex());
    }

    if (parent->is_failed()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "previous block is invalid: " + header.prev_hash.to_hex());
    }

    // --- Timestamp check: must be > median time past of parent chain ------
    int64_t median_time = parent->get_median_time_past();
    if (static_cast<int64_t>(header.timestamp) <= median_time) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "block timestamp " + std::to_string(header.timestamp) +
            " is not greater than median-time-past " +
            std::to_string(median_time));
    }

    // --- Difficulty check: bits must match expected difficulty --------------
    int new_height = parent->height + 1;
    uint32_t expected_bits;
    if (new_height % params_.difficulty_adjustment_interval() == 0 &&
        new_height > 0) {
        // Retarget boundary — calculate expected difficulty from the
        // actual timespan of the previous 2016 blocks.
        auto* first_block = parent->get_ancestor(
            new_height - params_.difficulty_adjustment_interval());
        if (!first_block) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "cannot find retarget interval start block at height " +
                std::to_string(new_height -
                               params_.difficulty_adjustment_interval()));
        }
        expected_bits = consensus::get_next_work_required(
            new_height, parent->time, first_block->time,
            parent->bits, params_);
    } else {
        // Non-retarget block: same difficulty as parent.
        expected_bits = parent->bits;
    }

    if (header.bits != expected_bits) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "incorrect proof-of-work difficulty for height " +
            std::to_string(new_height) + ": got " +
            std::to_string(header.bits) + " expected " +
            std::to_string(expected_bits));
    }

    // --- Add to the block index -------------------------------------------
    BlockIndex* new_index = add_to_block_index(header);
    new_index->raise_validity(BlockIndex::BLOCK_VALID_TREE);

    // --- Update best header if this has more work -------------------------
    if (best_header_ == nullptr ||
        new_index->chain_work > best_header_->chain_work) {
        best_header_ = new_index;
    }

    LOG_DEBUG(core::LogCategory::CHAIN,
              "Accepted block header " + hash.to_hex() +
              " at height " + std::to_string(new_index->height));

    return new_index;
}

// ===========================================================================
// accept_block
// ===========================================================================
// Accepts a full block:
//   1. Accept the header (or retrieve if already known).
//   2. If block data is already stored, return early.
//   3. Validate the block's transactions (context-free checks).
//   4. Verify the merkle root.
//   5. Store the block on disk.
//   6. Mark the index entry as having data.
// ===========================================================================

core::Result<bool> ChainstateManager::accept_block(
    const primitives::Block& block)
{
    std::lock_guard<std::recursive_mutex> lock(cs_main_);
    // --- Accept header (idempotent) ---------------------------------------
    auto header_result = accept_block_header(block.header());
    if (!header_result.ok()) {
        return std::move(header_result).error();
    }
    BlockIndex* index = header_result.value();

    // --- Already have block data? -----------------------------------------
    if (index->has_data()) {
        LOG_DEBUG(core::LogCategory::CHAIN,
                  "Block already stored: " + index->block_hash.to_hex());
        return false;
    }

    // --- Context-free transaction validation ------------------------------
    const auto& txs = block.transactions();
    if (txs.empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "block has no transactions");
    }

    // First transaction must be coinbase.
    if (!txs[0].is_coinbase()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "first transaction is not coinbase");
    }

    // Validate each transaction individually.
    for (size_t i = 0; i < txs.size(); ++i) {
        auto tx_result = consensus::check_transaction(txs[i]);
        if (!tx_result.ok()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "transaction " + std::to_string(i) +
                " failed validation: " + tx_result.error().message());
        }

        // Non-coinbase transactions must not be coinbase.
        if (i > 0 && txs[i].is_coinbase()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "multiple coinbase transactions in block");
        }
    }

    // --- Merkle root verification -----------------------------------------
    if (!block.is_valid_merkle_root()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "merkle root mismatch for block " + index->block_hash.to_hex());
    }

    // --- Store block on disk ----------------------------------------------
    if (!block_store_) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "block store not initialized");
    }

    auto write_result = block_store_->write_block(block);
    if (!write_result.ok()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "failed to write block to disk: " + write_result.error().message());
    }
    int64_t data_pos = write_result.value();

    // --- Update block index -----------------------------------------------
    index->data_pos = data_pos;
    index->status |= BlockIndex::BLOCK_HAVE_DATA;
    index->tx_count = static_cast<int>(txs.size());

    // Propagate cumulative transaction count.  Only propagate if the
    // parent has a valid chain_tx (meaning the entire chain from genesis
    // to the parent has data).  This prevents find_best_candidate() from
    // selecting blocks whose reorg path includes data-less gaps.
    if (index->prev == nullptr) {
        // Genesis block.
        index->chain_tx = std::max(index->tx_count, 1);
    } else if (index->prev->chain_tx > 0) {
        index->chain_tx = index->prev->chain_tx + index->tx_count;
    } else if (index->prev->height == 0 && index->prev->has_data()) {
        // Parent is genesis with chain_tx = 0 (legacy DB). Fix it up.
        index->prev->chain_tx = std::max(index->prev->tx_count, 1);
        index->chain_tx = index->prev->chain_tx + index->tx_count;
    } else {
        index->chain_tx = 0;  // gap in chain data
    }

    // Forward-propagate: if this block fills a gap, update descendants
    // that have data but were waiting for their parent's chain_tx.
    if (index->chain_tx > 0) {
        propagate_chain_tx(index);
    }

    index->raise_validity(BlockIndex::BLOCK_VALID_TRANSACTIONS);

    LOG_INFO(core::LogCategory::CHAIN,
             "Accepted block " + index->block_hash.to_hex() +
             " at height " + std::to_string(index->height) +
             " (" + std::to_string(txs.size()) + " txs)");

    return true;
}

// ===========================================================================
// activate_best_chain
// ===========================================================================
// Switches the active chain to the tip with the most cumulative work:
//   1. Find the best candidate (most work, data available).
//   2. If it's already the active tip, nothing to do.
//   3. Compute the reorg path (blocks to disconnect / connect).
//   4. Check reorg safety limits.
//   5. Disconnect blocks from the current tip back to the fork point.
//   6. Connect blocks from the fork point forward to the new tip.
//   7. Update the active chain.
// ===========================================================================

core::Result<bool> ChainstateManager::activate_best_chain() {
    std::lock_guard<std::recursive_mutex> lock(cs_main_);
    BlockIndex* best_candidate = find_best_candidate();
    if (best_candidate == nullptr) {
        // No blocks with data available -- nothing to activate.
        return false;
    }

    // Already at the best tip?
    if (active_chain_.tip() == best_candidate) {
        return false;
    }

    // Compute reorg path.
    ReorgPath path = compute_reorg_path(active_chain_, best_candidate);

    // Safety check: refuse excessively deep reorgs.
    if (!is_reorg_safe(path)) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "reorganization of " +
            std::to_string(path.to_disconnect.size()) +
            " blocks exceeds safety limit of " +
            std::to_string(MAX_REORG_DEPTH));
    }

    // Pre-flight: verify ALL blocks in the connect path have data on disk.
    // This prevents a partial reorg where we disconnect old blocks but
    // cannot connect the new ones (leaving the chain in a broken state).
    for (BlockIndex* bi : path.to_connect) {
        if (!bi->has_data()) {
            LOG_WARN(core::LogCategory::CHAIN,
                     "Reorg aborted: block data not available at height " +
                     std::to_string(bi->height) +
                     " (need blocks from peer)");
            return false;
        }
    }

    // --- Disconnect phase -------------------------------------------------
    for (BlockIndex* bi : path.to_disconnect) {
        LOG_INFO(core::LogCategory::CHAIN,
                 "Disconnecting block " + bi->block_hash.to_hex() +
                 " at height " + std::to_string(bi->height));

        auto dc_result = disconnect_block(bi);
        if (!dc_result.ok()) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "failed to disconnect block at height " +
                std::to_string(bi->height) + ": " +
                dc_result.error().message());
        }
    }

    // After disconnecting, set the active chain to the fork point.
    if (path.fork_point != nullptr) {
        active_chain_.set_tip(path.fork_point);
    } else if (!path.to_disconnect.empty()) {
        // Disconnected everything -- empty chain.
        active_chain_.set_tip(nullptr);
    }

    // --- Connect phase ----------------------------------------------------
    const size_t total_to_connect = path.to_connect.size();
    size_t connected_count = 0;
    for (BlockIndex* bi : path.to_connect) {
        // Log progress: first, last, and every 100 blocks.
        if (connected_count == 0 || connected_count % 100 == 0 ||
            connected_count == total_to_connect - 1) {
            LOG_INFO(core::LogCategory::CHAIN,
                     "Connecting block at height " + std::to_string(bi->height) +
                     " (" + std::to_string(connected_count + 1) + "/" +
                     std::to_string(total_to_connect) + ")");
        }

        // Read the block from disk.
        if (!bi->has_data()) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "block data not available for height " +
                std::to_string(bi->height));
        }

        auto read_result = block_store_->read_block(bi->data_pos);
        if (!read_result.ok()) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "failed to read block at height " +
                std::to_string(bi->height) + ": " +
                read_result.error().message());
        }

        auto cn_result = connect_block(bi, read_result.value());
        if (!cn_result.ok()) {
            // Mark this block (and descendants) as failed.
            bi->status |= BlockIndex::BLOCK_FAILED_VALID;

            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "failed to connect block at height " +
                std::to_string(bi->height) + ": " +
                cn_result.error().message());
        }

        // Advance the active chain tip.
        active_chain_.set_tip(bi);
        ++connected_count;
    }

    LOG_INFO(core::LogCategory::CHAIN,
             "Best chain activated: tip " +
             (active_chain_.tip()
                 ? active_chain_.tip()->block_hash.to_hex()
                 : "null") +
             " at height " + std::to_string(active_chain_.height()));

    return true;
}

// ===========================================================================
// connect_block
// ===========================================================================
// Applies a block to the UTXO set:
//   1. For each transaction in the block:
//      a. For non-coinbase: remove spent UTXOs (record them as undo data).
//      b. Add new UTXOs for each output.
//   2. Serialize undo data and write to disk.
//   3. Raise the block's validity level.
// ===========================================================================

core::Result<bool> ChainstateManager::connect_block(
    BlockIndex* index, const primitives::Block& block)
{
    if (!utxo_cache_) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "UTXO cache not initialized");
    }

    const auto& txs = block.transactions();
    const int block_height = index->height;
    const bool is_genesis = (index->prev == nullptr);

    // Undo data: for each transaction (except coinbase), store the coins
    // that were spent.  This allows disconnecting the block later.
    // Structure: vector of (per-tx vector of spent coins).
    std::vector<std::vector<Coin>> tx_undo_data;
    tx_undo_data.reserve(txs.size());

    for (size_t tx_idx = 0; tx_idx < txs.size(); ++tx_idx) {
        const auto& tx = txs[tx_idx];
        const bool is_coinbase_tx = tx.is_coinbase();
        std::vector<Coin> spent_coins;

        // --- Spend inputs (non-coinbase only) -----------------------------
        if (!is_coinbase_tx) {
            spent_coins.reserve(tx.vin().size());

            for (const auto& input : tx.vin()) {
                // Look up the coin being spent.
                const Coin* coin = utxo_cache_->get_coin(input.prevout);
                if (coin == nullptr || coin->is_spent()) {
                    return core::Error(core::ErrorCode::VALIDATION_ERROR,
                        "input coin not found: " + input.prevout.to_string() +
                        " in tx " + std::to_string(tx_idx));
                }

                // Record for undo.
                spent_coins.push_back(*coin);

                // Remove from UTXO set.
                utxo_cache_->spend_coin(input.prevout);
            }
        }

        tx_undo_data.push_back(std::move(spent_coins));

        // --- Add outputs as new UTXOs -------------------------------------
        const core::uint256& txid = tx.txid();
        for (uint32_t out_idx = 0;
             out_idx < static_cast<uint32_t>(tx.vout().size());
             ++out_idx)
        {
            const auto& txout = tx.vout()[out_idx];
            primitives::OutPoint outpoint(txid, out_idx);
            Coin coin(txout, static_cast<int32_t>(block_height),
                      is_coinbase_tx);
            utxo_cache_->add_coin(outpoint, std::move(coin));
        }
    }

    // --- Serialize and store undo data ------------------------------------
    // Skip undo for genesis block (nothing to undo).
    if (!is_genesis && block_store_) {
        core::DataStream undo_stream;

        // Write number of transactions (excluding coinbase, which has no
        // undo data).  We still serialize an entry for coinbase (empty
        // vector) to keep indexing simple.
        core::ser_write_compact_size(undo_stream,
                                     static_cast<uint64_t>(tx_undo_data.size()));

        for (const auto& spent_coins : tx_undo_data) {
            core::ser_write_compact_size(undo_stream,
                                         static_cast<uint64_t>(spent_coins.size()));
            for (const auto& coin : spent_coins) {
                auto coin_bytes = coin.serialize();
                core::ser_write_compact_size(undo_stream,
                    static_cast<uint64_t>(coin_bytes.size()));
                core::ser_write_bytes(undo_stream,
                    std::span<const uint8_t>(coin_bytes));
            }
        }

        std::vector<uint8_t> undo_bytes(
            undo_stream.data(),
            undo_stream.data() + undo_stream.size());

        auto undo_result = block_store_->write_undo(undo_bytes);
        if (!undo_result.ok()) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "failed to write undo data: " +
                undo_result.error().message());
        }
        index->undo_pos = undo_result.value();
        index->status |= BlockIndex::BLOCK_HAVE_UNDO;
    }

    // --- Update UTXO cache best block -------------------------------------
    utxo_cache_->set_best_block(index->block_hash);

    // --- Raise validity ---------------------------------------------------
    index->raise_validity(BlockIndex::BLOCK_VALID_SCRIPTS);

    LOG_DEBUG(core::LogCategory::CHAIN,
              "Connected block " + index->block_hash.to_hex() +
              " at height " + std::to_string(block_height) +
              " with " + std::to_string(txs.size()) + " txs");

    return true;
}

// ===========================================================================
// disconnect_block
// ===========================================================================
// Reverses the effects of connect_block:
//   1. Read the undo data from disk.
//   2. Walk the block's transactions in REVERSE order.
//   3. For each transaction, remove the outputs it created from the UTXO set.
//   4. For non-coinbase transactions, restore the spent coins.
//   5. Update the UTXO cache best block to the previous block.
// ===========================================================================

core::Result<bool> ChainstateManager::disconnect_block(BlockIndex* index) {
    if (!utxo_cache_) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "UTXO cache not initialized");
    }
    if (!block_store_) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "block store not initialized");
    }

    // Read the full block.
    if (!index->has_data()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "block data not available for disconnect at height " +
            std::to_string(index->height));
    }

    auto block_result = block_store_->read_block(index->data_pos);
    if (!block_result.ok()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "failed to read block for disconnect: " +
            block_result.error().message());
    }
    const primitives::Block& block = block_result.value();

    // Read undo data (unless genesis).
    std::vector<std::vector<Coin>> tx_undo_data;

    if (index->has_undo()) {
        auto undo_result = block_store_->read_undo(index->undo_pos);
        if (!undo_result.ok()) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "failed to read undo data: " +
                undo_result.error().message());
        }

        // Deserialize the undo data.
        const auto& undo_bytes = undo_result.value();
        core::SpanReader undo_reader{std::span<const uint8_t>{undo_bytes.data(), undo_bytes.size()}};

        uint64_t tx_count = core::ser_read_compact_size(undo_reader);
        tx_undo_data.resize(static_cast<size_t>(tx_count));

        for (size_t i = 0; i < static_cast<size_t>(tx_count); ++i) {
            uint64_t coin_count = core::ser_read_compact_size(undo_reader);
            tx_undo_data[i].reserve(static_cast<size_t>(coin_count));
            for (uint64_t j = 0; j < coin_count; ++j) {
                uint64_t byte_count = core::ser_read_compact_size(undo_reader);
                std::vector<uint8_t> coin_data(static_cast<size_t>(byte_count));
                core::ser_read_bytes(undo_reader,
                    std::span<uint8_t>(coin_data));
                auto coin_result = Coin::deserialize(
                    std::span<const uint8_t>(coin_data));
                if (!coin_result.ok()) {
                    return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                        "failed to deserialize undo coin: " +
                        coin_result.error().message());
                }
                tx_undo_data[i].push_back(std::move(coin_result).value());
            }
        }
    }

    const auto& txs = block.transactions();

    // Process transactions in reverse order.
    for (int tx_idx = static_cast<int>(txs.size()) - 1; tx_idx >= 0; --tx_idx) {
        const auto& tx = txs[static_cast<size_t>(tx_idx)];
        const core::uint256& txid = tx.txid();

        // --- Remove outputs created by this transaction -------------------
        for (uint32_t out_idx = 0;
             out_idx < static_cast<uint32_t>(tx.vout().size());
             ++out_idx)
        {
            primitives::OutPoint outpoint(txid, out_idx);
            utxo_cache_->spend_coin(outpoint);
        }

        // --- Restore spent inputs (non-coinbase only) ---------------------
        if (!tx.is_coinbase() &&
            static_cast<size_t>(tx_idx) < tx_undo_data.size())
        {
            const auto& spent_coins = tx_undo_data[static_cast<size_t>(tx_idx)];

            if (spent_coins.size() != tx.vin().size()) {
                return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                    "undo data coin count mismatch for tx " +
                    std::to_string(tx_idx) + ": expected " +
                    std::to_string(tx.vin().size()) + ", got " +
                    std::to_string(spent_coins.size()));
            }

            for (size_t in_idx = 0; in_idx < tx.vin().size(); ++in_idx) {
                utxo_cache_->add_coin(tx.vin()[in_idx].prevout,
                                      spent_coins[in_idx]);
            }
        }
    }

    // --- Update UTXO best block to the previous block ---------------------
    if (index->prev != nullptr) {
        utxo_cache_->set_best_block(index->prev->block_hash);
    } else {
        utxo_cache_->set_best_block(core::uint256{});
    }

    LOG_DEBUG(core::LogCategory::CHAIN,
              "Disconnected block " + index->block_hash.to_hex() +
              " at height " + std::to_string(index->height));

    return true;
}

// ===========================================================================
// add_to_block_index
// ===========================================================================
// Creates a new BlockIndex entry from a header and inserts it into the
// block_index_ map.  If the entry already exists, returns the existing one.
// ===========================================================================

BlockIndex* ChainstateManager::add_to_block_index(
    const primitives::BlockHeader& header)
{
    const core::uint256 hash = header.hash();

    // Check if already present.
    auto it = block_index_.find(hash);
    if (it != block_index_.end()) {
        return it->second.get();
    }

    // Create new index entry.
    auto new_index = std::make_unique<BlockIndex>();
    BlockIndex* bi = new_index.get();

    bi->block_hash     = hash;
    bi->version        = header.version;
    bi->hash_merkle_root = header.merkle_root;
    bi->time           = header.timestamp;
    bi->bits           = header.bits;
    bi->nonce          = header.nonce;

    // Link to parent.
    if (!header.prev_hash.is_zero()) {
        auto parent_it = block_index_.find(header.prev_hash);
        if (parent_it != block_index_.end()) {
            bi->prev   = parent_it->second.get();
            bi->height = bi->prev->height + 1;

            // Cumulative chain work = parent's work + this block's work.
            // chain_work = prev->chain_work + get_block_work()
            // We add using byte arithmetic since uint256 has no operator+.
            core::uint256 block_work = bi->get_block_work();
            core::uint256 cumulative = bi->prev->chain_work;

            // Byte-level addition: cumulative += block_work
            uint16_t carry = 0;
            for (size_t i = 0; i < 32; ++i) {
                uint16_t sum = static_cast<uint16_t>(cumulative.data()[i])
                             + static_cast<uint16_t>(block_work.data()[i])
                             + carry;
                cumulative.data()[i] = static_cast<uint8_t>(sum & 0xFF);
                carry = sum >> 8;
            }
            bi->chain_work = cumulative;
        }
    } else {
        // Genesis block: height 0, chain_work = own work.
        bi->height     = 0;
        bi->chain_work = bi->get_block_work();
    }

    // Insert into the map.
    block_index_.emplace(hash, std::move(new_index));

    return bi;
}

// ===========================================================================
// find_best_candidate
// ===========================================================================
// Scans the block index for the entry with the most cumulative work that
// has block data available on disk and has not been marked as failed.
// ===========================================================================

BlockIndex* ChainstateManager::find_best_candidate() const {
    // Start with the current tip as the default best candidate.
    // This ensures that when two chains have EQUAL chainwork (e.g. two
    // competing blocks at the same height), the existing active chain
    // wins the tiebreaker and no unnecessary reorg occurs.
    BlockIndex* best = active_chain_.tip();

    for (const auto& [hash, index] : block_index_) {
        BlockIndex* bi = index.get();

        if (bi->is_failed()) {
            continue;
        }
        if (!bi->has_data()) {
            continue;
        }

        // Ensure the entire chain back to genesis has data available.
        // We check this by verifying chain_tx > 0, which is only set when
        // the full block data has been processed.
        if (bi->chain_tx <= 0 && bi->height > 0) {
            continue;
        }

        if (best == nullptr || bi->chain_work > best->chain_work) {
            best = bi;
        }
    }

    return best;
}

// ===========================================================================
// propagate_chain_tx
// ===========================================================================
// When a block's chain_tx becomes valid (> 0), some of its descendants
// in the block index may already have data on disk but were unable to
// set chain_tx because their parent lacked it.  This method walks the
// block index looking for such descendants and propagates chain_tx
// forward so they become eligible for find_best_candidate().
// ===========================================================================

void ChainstateManager::propagate_chain_tx(BlockIndex* index) {
    // Simple BFS: collect children that have data but chain_tx == 0.
    std::vector<BlockIndex*> queue;

    // Find direct children of `index` in the block index.
    for (auto& [hash, child_ptr] : block_index_) {
        BlockIndex* child = child_ptr.get();
        if (child->prev == index && child->has_data() &&
            child->chain_tx <= 0) {
            child->chain_tx = index->chain_tx + child->tx_count;
            queue.push_back(child);
        }
    }

    // BFS forward through descendants.
    while (!queue.empty()) {
        BlockIndex* current = queue.back();
        queue.pop_back();

        for (auto& [hash, child_ptr] : block_index_) {
            BlockIndex* child = child_ptr.get();
            if (child->prev == current && child->has_data() &&
                child->chain_tx <= 0) {
                child->chain_tx = current->chain_tx + child->tx_count;
                queue.push_back(child);
            }
        }
    }
}

// ===========================================================================
// lookup_block_index
// ===========================================================================

BlockIndex* ChainstateManager::lookup_block_index(const core::uint256& hash) {
    auto it = block_index_.find(hash);
    if (it == block_index_.end()) {
        return nullptr;
    }
    return it->second.get();
}

const BlockIndex* ChainstateManager::lookup_block_index(
    const core::uint256& hash) const
{
    auto it = block_index_.find(hash);
    if (it == block_index_.end()) {
        return nullptr;
    }
    return it->second.get();
}

// ===========================================================================
// read_block
// ===========================================================================

core::Result<primitives::Block> ChainstateManager::read_block(const BlockIndex* index) const {
    if (!index || !index->has_data()) {
        return core::Error(core::ErrorCode::STORAGE_NOT_FOUND, "block data not available");
    }
    if (!block_store_) {
        return core::Error(core::ErrorCode::STORAGE_ERROR, "block store not initialized");
    }
    return block_store_->read_block(index->data_pos);
}

// ===========================================================================
// get_disk_usage
// ===========================================================================

core::Result<int64_t> ChainstateManager::get_disk_usage() const {
    if (!block_store_) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "block store not initialized");
    }
    return block_store_->total_size();
}

// ===========================================================================
// flush
// ===========================================================================
// Flushes all cached state to persistent storage:
//   1. Flush the UTXO cache to the UTXO database.
//   2. Flush the block store (fsync).
//   3. Save the block index to the index database.
// ===========================================================================

core::Result<void> ChainstateManager::flush() {
    LOG_INFO(core::LogCategory::CHAIN, "Flushing chainstate to disk");

    // Flush block store.
    if (block_store_) {
        FTC_TRY_VOID(block_store_->flush());
    }

    // Save block index to disk.
    if (index_db_ && !block_index_.empty()) {
        std::vector<storage::BlockIndexDiskEntry> entries;
        entries.reserve(block_index_.size());

        for (const auto& [hash, index] : block_index_) {
            const BlockIndex* bi = index.get();
            storage::BlockIndexDiskEntry entry;
            entry.block_hash       = bi->block_hash;
            entry.prev_hash        = bi->prev ? bi->prev->block_hash
                                              : core::uint256{};
            entry.version          = bi->version;
            entry.hash_merkle_root = bi->hash_merkle_root;
            entry.time             = bi->time;
            entry.bits             = bi->bits;
            entry.nonce            = bi->nonce;
            entry.height           = bi->height;
            entry.chain_work       = bi->chain_work;
            entry.status           = bi->status;
            entry.data_pos         = bi->data_pos;
            entry.undo_pos         = bi->undo_pos;
            entry.tx_count         = bi->tx_count;
            entries.push_back(entry);
        }

        auto save_result = index_db_->save(entries);
        if (!save_result.ok()) {
            LOG_ERROR(core::LogCategory::CHAIN,
                      "Failed to save block index: " +
                      save_result.error().message());
        } else {
            LOG_INFO(core::LogCategory::CHAIN,
                     "Block index saved: " +
                     std::to_string(entries.size()) + " entries");
        }
    }

    // Save UTXO snapshot to disk.
    if (utxo_db_ && utxo_cache_) {
        auto save_result = utxo_db_->save_snapshot(*utxo_cache_);
        if (!save_result.ok()) {
            LOG_ERROR(core::LogCategory::CHAIN,
                      "Failed to save UTXO snapshot: " +
                      save_result.error().message());
        } else {
            LOG_INFO(core::LogCategory::CHAIN,
                     "UTXO snapshot saved: " +
                     std::to_string(utxo_cache_->size()) + " coins");
        }
    }

    LOG_INFO(core::LogCategory::CHAIN, "Chainstate flush complete");
    return core::make_ok();
}

// ===========================================================================
// check_block_index (debug)
// ===========================================================================
// Performs consistency checks on the block index tree.  Called periodically
// in debug builds to detect corruption early.
// ===========================================================================

void ChainstateManager::check_block_index() {
#ifndef NDEBUG
    if (block_index_.empty()) {
        return;
    }

    // Every block (except genesis) must have a valid parent pointer.
    for (const auto& [hash, index] : block_index_) {
        const BlockIndex* bi = index.get();

        // Hash consistency: the stored hash must match the map key.
        assert(bi->block_hash == hash);

        if (bi->height > 0) {
            // Must have a parent.
            assert(bi->prev != nullptr);

            // Parent must be at the expected height.
            assert(bi->prev->height == bi->height - 1);

            // Parent must exist in the map.
            assert(block_index_.count(bi->prev->block_hash) > 0);
        }

        // If the block is in the active chain, verify the chain agrees.
        if (active_chain_.contains(bi)) {
            assert(active_chain_.at(bi->height) == bi);
        }

        // Chain work must be non-decreasing along the chain.
        if (bi->prev != nullptr) {
            assert(bi->chain_work >= bi->prev->chain_work);
        }
    }
#endif // NDEBUG
}

} // namespace chain
