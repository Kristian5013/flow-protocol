// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "core/error.h"
#include "core/serialize.h"
#include "core/stream.h"
#include "core/types.h"
#include "crypto/keccak.h"
#include "primitives/block_header.h"
#include "primitives/transaction.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace primitives {

// =========================================================================
// Construction
// =========================================================================

Block::Block(BlockHeader header, std::vector<Transaction> txs)
    : header_(std::move(header))
    , txs_(std::move(txs)) {}

// =========================================================================
// Merkle tree computation (Bitcoin-style)
// =========================================================================

namespace {

/// Compute a Bitcoin-style binary merkle root from a list of hashes.
/// If the number of leaves is odd, the last hash is duplicated before
/// pairing.  Returns the all-zero hash if the input is empty.
core::uint256 compute_merkle(std::vector<core::uint256> hashes) {
    if (hashes.empty()) {
        return core::uint256{};
    }

    while (hashes.size() > 1) {
        // If odd number of hashes, duplicate the last entry.
        if (hashes.size() % 2 != 0) {
            hashes.push_back(hashes.back());
        }

        std::vector<core::uint256> next_level;
        next_level.reserve(hashes.size() / 2);

        for (size_t i = 0; i < hashes.size(); i += 2) {
            // Concatenate the two 32-byte hashes and double-hash.
            uint8_t combined[64];
            std::memcpy(combined, hashes[i].data(), 32);
            std::memcpy(combined + 32, hashes[i + 1].data(), 32);

            next_level.push_back(crypto::keccak256d(
                std::span<const uint8_t>(combined, 64)));
        }

        hashes = std::move(next_level);
    }

    return hashes[0];
}

} // anonymous namespace

core::uint256 Block::compute_merkle_root() const {
    std::vector<core::uint256> leaves;
    leaves.reserve(txs_.size());
    for (const auto& tx : txs_) {
        leaves.push_back(tx.txid());
    }
    return compute_merkle(std::move(leaves));
}

core::uint256 Block::compute_witness_merkle_root() const {
    std::vector<core::uint256> leaves;
    leaves.reserve(txs_.size());
    for (size_t i = 0; i < txs_.size(); ++i) {
        if (i == 0) {
            // Coinbase wtxid is replaced with the zero hash.
            leaves.emplace_back();
        } else {
            leaves.push_back(txs_[i].wtxid());
        }
    }
    return compute_merkle(std::move(leaves));
}

bool Block::is_valid_merkle_root() const {
    return header_.merkle_root == compute_merkle_root();
}

// =========================================================================
// Sizes
// =========================================================================

size_t Block::size() const {
    core::DataStream s;

    // Header: always 80 bytes.
    header_.serialize(s);

    // Transaction count (compact size).
    core::ser_write_compact_size(s, txs_.size());

    // Each transaction, fully serialized.
    for (const auto& tx : txs_) {
        tx.serialize_to(s);
    }

    return s.size();
}

size_t Block::weight() const {
    size_t total_weight = 0;
    for (const auto& tx : txs_) {
        total_weight += tx.weight();
    }
    return total_weight;
}

// =========================================================================
// Serialization
// =========================================================================

std::vector<uint8_t> Block::serialize() const {
    core::DataStream s;

    // Header.
    header_.serialize(s);

    // Transaction count.
    core::ser_write_compact_size(s, txs_.size());

    // Transactions.
    for (const auto& tx : txs_) {
        tx.serialize_to(s);
    }

    return s.release();
}

core::Result<Block> Block::deserialize(core::DataStream& s) {
    try {
        Block block;

        // Deserialize header.
        block.header_ = BlockHeader::deserialize(s);

        // Deserialize transaction count.
        uint64_t tx_count = core::ser_read_compact_size(s);
        if (tx_count > core::MAX_VECTOR_SIZE) {
            return core::Error(
                core::ErrorCode::PARSE_OVERFLOW,
                "Block::deserialize: too many transactions");
        }

        // Deserialize each transaction.
        block.txs_.reserve(static_cast<size_t>(tx_count));
        for (uint64_t i = 0; i < tx_count; ++i) {
            auto tx_result = Transaction::deserialize(s);
            if (!tx_result.ok()) {
                return core::Error(
                    tx_result.error().code(),
                    std::string("Block::deserialize: tx[")
                        + std::to_string(i) + "] "
                        + tx_result.error().message());
            }
            block.txs_.push_back(std::move(tx_result).value());
        }

        return block;

    } catch (const std::exception& e) {
        return core::Error(
            core::ErrorCode::PARSE_ERROR,
            std::string("Block::deserialize: ") + e.what());
    }
}

} // namespace primitives
