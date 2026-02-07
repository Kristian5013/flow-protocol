#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "core/stream.h"
#include "core/types.h"
#include "primitives/block_header.h"
#include "primitives/transaction.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace primitives {

// ---------------------------------------------------------------------------
// Block -- a block header together with its transactions
// ---------------------------------------------------------------------------
class Block {
public:
    Block() = default;

    Block(BlockHeader header, std::vector<Transaction> txs);

    // -- Accessors ----------------------------------------------------------

    [[nodiscard]] const BlockHeader& header() const { return header_; }
    BlockHeader& header() { return header_; }

    [[nodiscard]] const std::vector<Transaction>& transactions() const {
        return txs_;
    }
    std::vector<Transaction>& transactions() { return txs_; }

    // -- Hashes -------------------------------------------------------------

    /// Block hash (hash of the header).
    [[nodiscard]] core::uint256 hash() const { return header_.hash(); }

    /// Compute the merkle root of all transaction IDs.
    /// Uses Bitcoin-style binary merkle tree: if the leaf count is odd,
    /// the last hash is duplicated before pairing.
    [[nodiscard]] core::uint256 compute_merkle_root() const;

    /// Compute the witness merkle root.
    /// The coinbase wtxid is replaced with a zero hash (32 zero bytes).
    /// All other entries use the wtxid.
    [[nodiscard]] core::uint256 compute_witness_merkle_root() const;

    /// Check whether the header's merkle_root field matches the computed
    /// merkle root from the transactions.
    [[nodiscard]] bool is_valid_merkle_root() const;

    // -- Sizes --------------------------------------------------------------

    /// Total serialized size of the block in bytes (header + all txs).
    [[nodiscard]] size_t size() const;

    /// Block weight: sum of all transaction weights.
    [[nodiscard]] size_t weight() const;

    /// Number of transactions in the block.
    [[nodiscard]] size_t tx_count() const { return txs_.size(); }

    // -- Serialization ------------------------------------------------------

    /// Serialize the entire block (header + tx count + transactions).
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize a block from a DataStream.
    [[nodiscard]] static core::Result<Block> deserialize(
        core::DataStream& s);

private:
    BlockHeader header_;
    std::vector<Transaction> txs_;
};

} // namespace primitives
