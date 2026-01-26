#include "chain/block.h"
#include "script/script.h"
#include "util/hex.h"

#include <cstring>
#include <sstream>
#include <iomanip>
#include <cmath>

namespace ftc {
namespace chain {

// ============================================================================
// BlockHeader
// ============================================================================

BlockHeader::BlockHeader()
    : version(1)
    , prev_hash(crypto::ZERO_HASH)
    , merkle_root(crypto::ZERO_HASH)
    , timestamp(0)
    , bits(0x1d00ffff)  // Initial difficulty
    , nonce(0) {
}

crypto::Hash256 BlockHeader::getHash() const {
    auto data = serialize();
    return crypto::Keccak256::hash(data);
}

std::vector<uint8_t> BlockHeader::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(80);

    // Version (4 bytes, little-endian)
    data.push_back(version & 0xFF);
    data.push_back((version >> 8) & 0xFF);
    data.push_back((version >> 16) & 0xFF);
    data.push_back((version >> 24) & 0xFF);

    // Previous hash (32 bytes)
    data.insert(data.end(), prev_hash.begin(), prev_hash.end());

    // Merkle root (32 bytes)
    data.insert(data.end(), merkle_root.begin(), merkle_root.end());

    // Timestamp (4 bytes, little-endian)
    data.push_back(timestamp & 0xFF);
    data.push_back((timestamp >> 8) & 0xFF);
    data.push_back((timestamp >> 16) & 0xFF);
    data.push_back((timestamp >> 24) & 0xFF);

    // Bits (4 bytes, little-endian)
    data.push_back(bits & 0xFF);
    data.push_back((bits >> 8) & 0xFF);
    data.push_back((bits >> 16) & 0xFF);
    data.push_back((bits >> 24) & 0xFF);

    // Nonce (4 bytes, little-endian)
    data.push_back(nonce & 0xFF);
    data.push_back((nonce >> 8) & 0xFF);
    data.push_back((nonce >> 16) & 0xFF);
    data.push_back((nonce >> 24) & 0xFF);

    return data;
}

std::optional<BlockHeader> BlockHeader::deserialize(const uint8_t* data, size_t len) {
    if (len < 80) return std::nullopt;

    BlockHeader header;

    // Version
    header.version = data[0] |
                    (static_cast<uint32_t>(data[1]) << 8) |
                    (static_cast<uint32_t>(data[2]) << 16) |
                    (static_cast<uint32_t>(data[3]) << 24);

    // Previous hash
    std::memcpy(header.prev_hash.data(), data + 4, 32);

    // Merkle root
    std::memcpy(header.merkle_root.data(), data + 36, 32);

    // Timestamp
    header.timestamp = data[68] |
                      (static_cast<uint32_t>(data[69]) << 8) |
                      (static_cast<uint32_t>(data[70]) << 16) |
                      (static_cast<uint32_t>(data[71]) << 24);

    // Bits
    header.bits = data[72] |
                 (static_cast<uint32_t>(data[73]) << 8) |
                 (static_cast<uint32_t>(data[74]) << 16) |
                 (static_cast<uint32_t>(data[75]) << 24);

    // Nonce
    header.nonce = data[76] |
                  (static_cast<uint32_t>(data[77]) << 8) |
                  (static_cast<uint32_t>(data[78]) << 16) |
                  (static_cast<uint32_t>(data[79]) << 24);

    return header;
}

crypto::Hash256 BlockHeader::bitsToTarget(uint32_t bits) {
    crypto::Hash256 target{};

    // Special case: bits=0 means maximum target (easiest difficulty)
    if (bits == 0) {
        std::memset(target.data(), 0xFF, 32);
        return target;
    }

    uint32_t exponent = (bits >> 24) & 0xFF;
    uint32_t mantissa = bits & 0x00FFFFFF;

    if (exponent <= 3) {
        mantissa >>= 8 * (3 - exponent);
        target[31] = mantissa & 0xFF;
        target[30] = (mantissa >> 8) & 0xFF;
        target[29] = (mantissa >> 16) & 0xFF;
    } else if (exponent >= 33) {
        // Target overflows 256 bits - set to maximum (easiest difficulty)
        std::memset(target.data(), 0xFF, 32);
    } else {
        int offset = 32 - exponent;
        if (offset >= 0 && offset < 32) {
            target[offset] = (mantissa >> 16) & 0xFF;
            if (offset + 1 < 32) target[offset + 1] = (mantissa >> 8) & 0xFF;
            if (offset + 2 < 32) target[offset + 2] = mantissa & 0xFF;
        }
    }

    return target;
}

uint32_t BlockHeader::targetToBits(const crypto::Hash256& target) {
    // Find first non-zero byte
    int first_non_zero = 0;
    while (first_non_zero < 32 && target[first_non_zero] == 0) {
        first_non_zero++;
    }

    if (first_non_zero == 32) {
        return 0;  // Zero target
    }

    uint32_t exponent = 32 - first_non_zero;
    uint32_t mantissa = 0;

    mantissa = static_cast<uint32_t>(target[first_non_zero]) << 16;
    if (first_non_zero + 1 < 32) {
        mantissa |= static_cast<uint32_t>(target[first_non_zero + 1]) << 8;
    }
    if (first_non_zero + 2 < 32) {
        mantissa |= target[first_non_zero + 2];
    }

    // Handle negative bit
    if (mantissa & 0x00800000) {
        mantissa >>= 8;
        exponent++;
    }

    return (exponent << 24) | mantissa;
}

bool BlockHeader::checkProofOfWork() const {
    auto hash = getHash();
    auto target = bitsToTarget(bits);

    // Hash must be less than or equal to target
    return crypto::Keccak256::compare(hash, target) <= 0;
}

double BlockHeader::getDifficulty() const {
    // Calculate difficulty relative to genesis target
    crypto::Hash256 genesis_target = bitsToTarget(0x1d00ffff);
    crypto::Hash256 current_target = bitsToTarget(bits);

    // Simplified difficulty calculation
    double genesis_diff = 0;
    double current_diff = 0;

    for (int i = 0; i < 32; i++) {
        genesis_diff = genesis_diff * 256 + genesis_target[i];
        current_diff = current_diff * 256 + current_target[i];
    }

    if (current_diff == 0) return std::numeric_limits<double>::infinity();
    return genesis_diff / current_diff;
}

// ============================================================================
// Block
// ============================================================================

crypto::Hash256 Block::calculateMerkleRoot() const {
    if (transactions.empty()) {
        return crypto::ZERO_HASH;
    }

    std::vector<crypto::Hash256> hashes;
    hashes.reserve(transactions.size());

    // Get transaction hashes
    for (const auto& tx : transactions) {
        hashes.push_back(tx.getTxId());
    }

    // Build merkle tree
    while (hashes.size() > 1) {
        std::vector<crypto::Hash256> new_hashes;

        for (size_t i = 0; i < hashes.size(); i += 2) {
            crypto::Hash256 left = hashes[i];
            crypto::Hash256 right = (i + 1 < hashes.size()) ? hashes[i + 1] : hashes[i];

            // Concatenate and hash
            std::vector<uint8_t> combined;
            combined.insert(combined.end(), left.begin(), left.end());
            combined.insert(combined.end(), right.begin(), right.end());

            new_hashes.push_back(crypto::Keccak256::hash(combined));
        }

        hashes = std::move(new_hashes);
    }

    return hashes[0];
}

void Block::updateMerkleRoot() {
    header.merkle_root = calculateMerkleRoot();
}

std::vector<uint8_t> Block::serialize() const {
    std::vector<uint8_t> data;

    // Header
    auto header_data = header.serialize();
    data.insert(data.end(), header_data.begin(), header_data.end());

    // Transaction count
    auto tx_count = varint::encode(transactions.size());
    data.insert(data.end(), tx_count.begin(), tx_count.end());

    // Transactions
    for (const auto& tx : transactions) {
        auto tx_data = tx.serialize();
        data.insert(data.end(), tx_data.begin(), tx_data.end());
    }

    return data;
}

std::optional<Block> Block::deserialize(const uint8_t* data, size_t len) {
    if (len < 80) return std::nullopt;

    Block block;

    // Header
    auto header = BlockHeader::deserialize(data, 80);
    if (!header) return std::nullopt;
    block.header = *header;

    size_t offset = 80;

    // Transaction count
    auto tx_count = varint::decode(data, len, offset);
    if (!tx_count) return std::nullopt;

    // Transactions
    for (uint64_t i = 0; i < *tx_count; i++) {
        // Read transaction size (we need to find the end)
        size_t tx_start = offset;
        auto tx = Transaction::deserialize(data + offset, len - offset);
        if (!tx) return std::nullopt;

        block.transactions.push_back(*tx);
        offset += tx->getSize();
    }

    return block;
}

std::optional<Block> Block::deserialize(const std::vector<uint8_t>& data) {
    return deserialize(data.data(), data.size());
}

bool Block::isValid() const {
    // Check header
    if (!header.checkProofOfWork()) return false;

    // Check merkle root
    if (!checkMerkleRoot()) return false;

    // Check transactions
    if (!checkTransactions()) return false;

    // Check size
    if (getSize() > MAX_BLOCK_SIZE) return false;

    return true;
}

bool Block::checkMerkleRoot() const {
    return calculateMerkleRoot() == header.merkle_root;
}

bool Block::checkTransactions() const {
    if (transactions.empty()) return false;

    // First transaction must be coinbase
    if (!transactions[0].isCoinbase()) return false;

    // Other transactions must not be coinbase
    for (size_t i = 1; i < transactions.size(); i++) {
        if (transactions[i].isCoinbase()) return false;
        if (!transactions[i].isValid()) return false;
    }

    return true;
}

const Transaction* Block::getCoinbase() const {
    if (transactions.empty()) return nullptr;
    if (!transactions[0].isCoinbase()) return nullptr;
    return &transactions[0];
}

uint64_t Block::getBlockReward(uint64_t height) {
    uint64_t halvings = height / HALVING_INTERVAL;

    if (halvings >= 64) {
        return 0;  // All coins mined
    }

    return INITIAL_BLOCK_REWARD >> halvings;
}

size_t Block::getSize() const {
    return serialize().size();
}

std::string Block::toString() const {
    std::ostringstream oss;
    oss << "Block " << crypto::Keccak256::toHex(getHash()) << "\n";
    oss << "  Version: " << header.version << "\n";
    oss << "  Prev: " << crypto::Keccak256::toHex(header.prev_hash) << "\n";
    oss << "  Merkle: " << crypto::Keccak256::toHex(header.merkle_root) << "\n";
    oss << "  Time: " << header.timestamp << "\n";
    oss << "  Bits: 0x" << std::hex << header.bits << std::dec << "\n";
    oss << "  Nonce: " << header.nonce << "\n";
    oss << "  Difficulty: " << header.getDifficulty() << "\n";
    oss << "  Transactions: " << transactions.size() << "\n";
    return oss.str();
}

// ============================================================================
// Genesis Block
// ============================================================================

Block createGenesisBlock() {
    Block genesis;

    // Header
    genesis.header.version = 1;
    genesis.header.prev_hash = crypto::ZERO_HASH;
    genesis.header.timestamp = FTC_GENESIS_TIME;  // 2026-01-20 00:00:00 UTC
    genesis.header.bits = 0x1d00ffff;  // Initial difficulty
    genesis.header.nonce = 0;  // Will be mined

    // Coinbase transaction
    Transaction coinbase;
    coinbase.version = 1;

    // Input (coinbase)
    TxInput input;
    input.prevout.txid = crypto::ZERO_HASH;
    input.prevout.index = 0xFFFFFFFF;

    // Genesis message in script_sig
    std::string message = FTC_GENESIS_MESSAGE;
    input.script_sig.push_back(static_cast<uint8_t>(message.size()));
    input.script_sig.insert(input.script_sig.end(), message.begin(), message.end());
    input.sequence = 0xFFFFFFFF;

    coinbase.inputs.push_back(input);

    // Output (50 FTC to burn address)
    TxOutput output;
    output.value = INITIAL_BLOCK_REWARD;

    // Create a "burn" address script (OP_RETURN)
    output.script_pubkey.push_back(script::OP_RETURN);

    coinbase.outputs.push_back(output);
    coinbase.locktime = 0;

    genesis.transactions.push_back(coinbase);

    // Calculate merkle root
    genesis.updateMerkleRoot();

    return genesis;
}

} // namespace chain
} // namespace ftc
