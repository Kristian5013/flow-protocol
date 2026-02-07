#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// ChainstateManager -- central coordinator for the blockchain state
// ---------------------------------------------------------------------------
// This is the primary interface for block processing in the FTC node.
// It owns the block index (in-memory tree of all known block headers),
// the active chain (the best fully-validated chain from genesis to tip),
// the UTXO cache, and the on-disk block/undo storage.
//
// Thread safety: ChainstateManager is NOT inherently thread-safe.  The
// caller (typically the validation interface / message handler) must
// ensure that no two threads call mutating methods concurrently.  Read-
// only accessors may be called from any thread as long as no mutation
// is in progress.
// ---------------------------------------------------------------------------

#include "chain/block_index.h"
#include "chain/chain.h"
#include "chain/coins.h"
#include "chain/reorg.h"
#include "chain/storage/block_store.h"
#include "core/error.h"
#include "core/types.h"
#include "consensus/params.h"
#include "primitives/block.h"
#include "primitives/block_header.h"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

// Forward declarations to avoid pulling in full headers.
namespace chain::utxo {
    class UtxoCache;
    class UtxoDB;
} // namespace chain::utxo

namespace chain::storage {
    class IndexDB;
    struct BlockUndo;
} // namespace chain::storage

namespace chain {

class ChainstateManager {
public:
    /// Construct a chainstate manager.
    ///
    /// @param params    Consensus parameters (held by reference; must outlive
    ///                  this object).
    /// @param data_dir  Path to the data directory where block files, index
    ///                  databases, and UTXO databases are stored.
    explicit ChainstateManager(
        const consensus::ConsensusParams& params,
        const std::filesystem::path& data_dir);

    ~ChainstateManager();

    // Non-copyable, non-movable.
    ChainstateManager(const ChainstateManager&) = delete;
    ChainstateManager& operator=(const ChainstateManager&) = delete;
    ChainstateManager(ChainstateManager&&) = delete;
    ChainstateManager& operator=(ChainstateManager&&) = delete;

    // =======================================================================
    // Lifecycle
    // =======================================================================

    /// Initialize the chainstate: load the block index from disk, replay
    /// the UTXO set to the active chain tip, and validate internal
    /// consistency.  Must be called before any block processing methods.
    core::Result<void> init();

    /// Orderly shutdown: flush the UTXO cache and block index to disk,
    /// close all file handles.
    core::Result<void> shutdown();

    // =======================================================================
    // Block processing
    // =======================================================================

    /// Accept a new block header.  Validates proof-of-work, timestamps,
    /// and linkage to a known parent.  On success, returns the BlockIndex
    /// entry (either newly created or pre-existing).
    ///
    /// @param header  The block header to accept.
    /// @returns The BlockIndex pointer, or an error on validation failure.
    core::Result<BlockIndex*> accept_block_header(
        const primitives::BlockHeader& header);

    /// Accept a full block (header + transactions).  Validates the block
    /// at the consensus level and stores it on disk.  Does NOT activate
    /// the block; call activate_best_chain() afterwards.
    ///
    /// @param block  The full block to accept.
    /// @returns true if the block was accepted, false if it was already
    ///          known, or an error on validation failure.
    core::Result<bool> accept_block(const primitives::Block& block);

    /// Activate the best chain: walk from the current active tip to the
    /// best known header (highest cumulative work), disconnecting and
    /// connecting blocks as needed.
    ///
    /// @returns true if the tip changed, false if already at the best tip,
    ///          or an error if a block failed validation during connection.
    core::Result<bool> activate_best_chain();

    // =======================================================================
    // Accessors
    // =======================================================================

    const Chain& active_chain() const { return active_chain_; }
    Chain& active_chain() { return active_chain_; }

    const utxo::UtxoCache& utxo_set() const { return *utxo_cache_; }
    utxo::UtxoCache& utxo_set() { return *utxo_cache_; }

    /// Look up a block index entry by hash.  Returns nullptr if not found.
    BlockIndex* lookup_block_index(const core::uint256& hash);
    const BlockIndex* lookup_block_index(const core::uint256& hash) const;

    /// The best header we know of (may be ahead of the active chain tip
    /// if we haven't yet validated and connected all blocks).
    BlockIndex* best_header() const { return best_header_; }

    /// The consensus parameters for this chain.
    const consensus::ConsensusParams& params() const { return params_; }

    /// Main chainstate lock.  Callers that need atomic multi-step access
    /// (e.g. read UTXO set while no blocks are being connected) should
    /// lock this mutex.
    std::recursive_mutex& cs_main() const { return cs_main_; }

    /// Read a full block from disk given its block index.
    core::Result<primitives::Block> read_block(const BlockIndex* index) const;

    /// Total size of on-disk block storage in bytes.
    core::Result<int64_t> get_disk_usage() const;

    /// Flush the UTXO cache and block index to their respective databases.
    core::Result<void> flush();

private:
    // =======================================================================
    // Hash functor for uint256 keys in unordered_map
    // =======================================================================
    struct Uint256Hash {
        size_t operator()(const core::uint256& h) const noexcept;
    };

    // =======================================================================
    // Data members
    // =======================================================================

    const consensus::ConsensusParams& params_;
    std::filesystem::path data_dir_;

    /// Protects all mutable chainstate (block index, active chain, UTXO cache).
    /// Recursive so that accept_block -> activate_best_chain works.
    mutable std::recursive_mutex cs_main_;

    /// Block tree: all known block indices keyed by block hash.
    std::unordered_map<core::uint256, std::unique_ptr<BlockIndex>,
                       Uint256Hash> block_index_;

    /// The active (best fully-validated) chain.
    Chain active_chain_;

    /// Best known header (highest cumulative chain work).
    BlockIndex* best_header_ = nullptr;

    /// In-memory UTXO cache backed by a persistent UTXO database.
    std::unique_ptr<utxo::UtxoCache> utxo_cache_;

    /// On-disk block and undo storage (blockchain.dat).
    std::unique_ptr<storage::BlockStore> block_store_;

    /// Persistent block index database.
    std::unique_ptr<storage::IndexDB> index_db_;

    /// Persistent UTXO database (backing store for utxo_cache_).
    std::unique_ptr<utxo::UtxoDB> utxo_db_;

    // =======================================================================
    // Internal helpers
    // =======================================================================

    /// Create or retrieve a BlockIndex entry for the given header.
    /// Populates the index fields (height, chain_work, etc.) from the
    /// header and its parent.
    BlockIndex* add_to_block_index(const primitives::BlockHeader& header);

    /// Connect a block to the active chain: apply all transactions to the
    /// UTXO set, compute undo data, and store undo data on disk.
    ///
    /// @param index  The BlockIndex of the block being connected.
    /// @param block  The full block data.
    /// @returns true on success, or an error on validation failure.
    core::Result<bool> connect_block(
        BlockIndex* index, const primitives::Block& block);

    /// Disconnect the tip block from the active chain: read undo data from
    /// disk and reverse all UTXO changes.
    ///
    /// @param index  The BlockIndex of the block being disconnected (must
    ///               be the current tip).
    /// @returns true on success, or an error on failure.
    core::Result<bool> disconnect_block(BlockIndex* index);

    /// Find the block index with the most cumulative work that has its
    /// block data available on disk.
    BlockIndex* find_best_candidate() const;

    /// Validate internal block index consistency (debug builds).
    void check_block_index();
};

} // namespace chain
