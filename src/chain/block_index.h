#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/types.h"
#include "primitives/amount.h"
#include "primitives/block_header.h"

#include <cstdint>
#include <string>

namespace chain {

// ---------------------------------------------------------------------------
// BlockIndex -- a node in the block tree (all known block headers)
// ---------------------------------------------------------------------------
// Each BlockIndex represents a single block header that has been received
// and validated at the header level.  Together, BlockIndex nodes form a
// tree rooted at the genesis block, linked via the `prev` pointer.
//
// Fields are stored inline to avoid extra allocations per block.
// ---------------------------------------------------------------------------
class BlockIndex {
public:
    // Block hash (cached from the header)
    core::uint256 block_hash;

    // Pointer to previous block index (nullptr for the genesis block)
    BlockIndex* prev = nullptr;

    // Block header data (stored inline to avoid extra allocation)
    int32_t version = 0;
    core::uint256 hash_merkle_root;
    uint32_t time = 0;
    uint32_t bits = 0;
    uint32_t nonce = 0;

    // Chain state
    int height = -1;

    // Cumulative chain work (sum of work for all blocks up to this one).
    // Stored as uint256 for big number arithmetic.
    core::uint256 chain_work;

    // Transaction count in this block
    int tx_count = 0;

    // Cumulative transaction count in the chain up to and including this block
    int64_t chain_tx = 0;

    // Status flags
    enum Status : uint32_t {
        BLOCK_VALID_UNKNOWN      = 0,
        BLOCK_VALID_HEADER       = 1,  // parsed, version ok, hash satisfies claimed PoW
        BLOCK_VALID_TREE         = 2,  // parent found, difficulty matches, timestamp ok
        BLOCK_VALID_TRANSACTIONS = 3,  // block data available, all txs parseable
        BLOCK_VALID_CHAIN        = 4,  // outputs don't overspend, no double spends, etc.
        BLOCK_VALID_SCRIPTS      = 5,  // scripts and signatures ok
        BLOCK_VALID_MASK         = 0x07,

        BLOCK_HAVE_DATA          = 8,   // full block data stored on disk
        BLOCK_HAVE_UNDO          = 16,  // undo data stored on disk
        BLOCK_HAVE_MASK          = BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO,

        BLOCK_FAILED_VALID       = 32,  // stage after last reached validness failed
        BLOCK_FAILED_CHILD       = 64,  // descends from failed block
        BLOCK_FAILED_MASK        = BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD,
    };
    uint32_t status = BLOCK_VALID_UNKNOWN;

    // File position (offset into blockchain data files)
    int64_t data_pos = -1;    // position of block data
    int64_t undo_pos = -1;    // position of undo data

    // -- Accessors ----------------------------------------------------------

    /// Returns true if the block has reached at least the given validity level
    /// and has not been marked as failed.
    bool is_valid(Status up_to = BLOCK_VALID_SCRIPTS) const;

    /// Returns true if the full block data is available on disk.
    bool has_data() const { return (status & BLOCK_HAVE_DATA) != 0; }

    /// Returns true if undo data is available on disk.
    bool has_undo() const { return (status & BLOCK_HAVE_UNDO) != 0; }

    /// Returns true if this block or any descendant has failed validation.
    bool is_failed() const { return (status & BLOCK_FAILED_MASK) != 0; }

    /// Raise the validity level to at least `up_to`, if not already higher.
    /// Does not lower validity.  Has no effect if the block is marked failed.
    void raise_validity(Status up_to);

    // -- Ancestor lookup ----------------------------------------------------

    /// Walk the `prev` chain to find the ancestor at `target_height`.
    /// Returns nullptr if target_height is negative or exceeds this block's
    /// height.
    BlockIndex* get_ancestor(int target_height);
    const BlockIndex* get_ancestor(int target_height) const;

    // -- Work and difficulty ------------------------------------------------

    /// Compute the proof-of-work represented by this block's difficulty bits.
    /// Returns 2^256 / (target + 1), where target is decoded from `bits`.
    core::uint256 get_block_work() const;

    // -- Median time --------------------------------------------------------

    /// Return the median of the timestamps of the last 11 blocks ending
    /// at (and including) this one.  If fewer than 11 ancestors exist,
    /// the median of all available timestamps is returned.
    int64_t get_median_time_past() const;

    // -- Header reconstruction ----------------------------------------------

    /// Build a primitives::BlockHeader from the data stored in this index.
    primitives::BlockHeader get_block_header() const;

    // -- Debugging ----------------------------------------------------------

    /// Return a human-readable string describing this block index entry.
    std::string to_string() const;
};

} // namespace chain
