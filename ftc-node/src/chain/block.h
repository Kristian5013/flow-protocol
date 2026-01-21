#ifndef FTC_CHAIN_BLOCK_H
#define FTC_CHAIN_BLOCK_H

#include "chain/transaction.h"
#include "crypto/keccak256.h"
#include "ftc/version.h"

#include <cstdint>
#include <vector>
#include <string>
#include <optional>

namespace ftc {
namespace chain {

// ============================================================================
// Constants
// ============================================================================

// Block size limit (1 MB)
constexpr size_t MAX_BLOCK_SIZE = 1000000;

// Target block time (60 seconds)
constexpr uint32_t TARGET_BLOCK_TIME = 60;

// Difficulty adjustment interval (2016 blocks ~ 2 weeks at 60s/block)
constexpr uint32_t DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;

// Initial block reward (50 FTC)
constexpr uint64_t INITIAL_BLOCK_REWARD = 50 * COIN;

// Halving interval (210,000 blocks ~ 4 years)
constexpr uint32_t HALVING_INTERVAL = 210000;

// Maximum supply (21 million FTC)
constexpr uint64_t MAX_SUPPLY = 21000000ULL * COIN;

// ============================================================================
// Block Header (80 bytes, same as Bitcoin)
// ============================================================================

#pragma pack(push, 1)
struct BlockHeader {
    uint32_t version;           // Block version
    crypto::Hash256 prev_hash;  // Previous block hash
    crypto::Hash256 merkle_root; // Merkle root of transactions
    uint32_t timestamp;         // Block timestamp (Unix time)
    uint32_t bits;              // Difficulty target (compact form)
    uint32_t nonce;             // Mining nonce

    BlockHeader();

    // Hash the header (for mining)
    crypto::Hash256 getHash() const;

    // Check if hash meets difficulty target
    bool checkProofOfWork() const;

    // Serialize
    std::vector<uint8_t> serialize() const;

    // Deserialize
    static std::optional<BlockHeader> deserialize(const uint8_t* data, size_t len);

    // Difficulty conversion
    static uint32_t targetToBits(const crypto::Hash256& target);
    static crypto::Hash256 bitsToTarget(uint32_t bits);

    // Get difficulty as double
    double getDifficulty() const;
};
#pragma pack(pop)

static_assert(sizeof(BlockHeader) == 80, "Block header must be 80 bytes");

// ============================================================================
// Block
// ============================================================================

class Block {
public:
    BlockHeader header;
    std::vector<Transaction> transactions;

    Block() = default;

    // Get block hash
    crypto::Hash256 getHash() const { return header.getHash(); }

    // Calculate merkle root
    crypto::Hash256 calculateMerkleRoot() const;

    // Update merkle root in header
    void updateMerkleRoot();

    // Serialize
    std::vector<uint8_t> serialize() const;

    // Deserialize
    static std::optional<Block> deserialize(const uint8_t* data, size_t len);
    static std::optional<Block> deserialize(const std::vector<uint8_t>& data);

    // Validation
    bool isValid() const;
    bool checkMerkleRoot() const;
    bool checkTransactions() const;

    // Get coinbase transaction
    const Transaction* getCoinbase() const;

    // Get block reward for height
    static uint64_t getBlockReward(uint64_t height);

    // Size
    size_t getSize() const;

    // Display
    std::string toString() const;
};

// ============================================================================
// Genesis Block
// ============================================================================

Block createGenesisBlock();

} // namespace chain
} // namespace ftc

#endif // FTC_CHAIN_BLOCK_H
