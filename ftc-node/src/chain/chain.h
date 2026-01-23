#ifndef FTC_CHAIN_CHAIN_H
#define FTC_CHAIN_CHAIN_H

#include "chain/block.h"
#include "chain/transaction.h"
#include "chain/validation.h"
#include "crypto/keccak256.h"
#include <string>
#include <vector>
#include <array>
#include <map>
#include <set>
#include <mutex>
#include <memory>
#include <functional>
#include <optional>

namespace ftc {
namespace chain {

// 256-bit unsigned integer for chain work calculations
// Stored as little-endian byte array
using uint256_t = std::array<uint8_t, 32>;

// Forward declarations
class UTXOSet;
class BlockStore;
class Consensus;

// Block status flags
enum class BlockStatus : uint32_t {
    UNKNOWN = 0,
    HEADER_VALID = 1 << 0,      // Header is valid
    DATA_AVAILABLE = 1 << 1,   // Block data is available
    SCRIPTS_VALID = 1 << 2,    // Scripts have been validated
    FAILED = 1 << 3,           // Block validation failed
    ON_MAIN_CHAIN = 1 << 4,    // Block is on the main chain
};

inline BlockStatus operator|(BlockStatus a, BlockStatus b) {
    return static_cast<BlockStatus>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline BlockStatus operator&(BlockStatus a, BlockStatus b) {
    return static_cast<BlockStatus>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline bool hasFlag(BlockStatus status, BlockStatus flag) {
    return (static_cast<uint32_t>(status) & static_cast<uint32_t>(flag)) != 0;
}

// Block index entry - metadata about a block
struct BlockIndex {
    crypto::Hash256 hash;           // Block hash
    crypto::Hash256 prev_hash;      // Previous block hash
    crypto::Hash256 merkle_root;    // Merkle root (needed for header serialization)
    int32_t height = -1;            // Height in chain (-1 if unknown)
    int32_t version = 0;            // Block version
    uint32_t timestamp = 0;         // Block timestamp
    uint32_t bits = 0;              // Difficulty target
    uint32_t nonce = 0;             // Mining nonce

    BlockStatus status = BlockStatus::UNKNOWN;
    uint64_t file_pos = 0;          // Position in block file
    uint32_t tx_count = 0;          // Number of transactions
    uint64_t total_tx = 0;          // Total transactions up to this block
    uint256_t chain_work;           // Total work up to this block

    BlockIndex* prev = nullptr;     // Pointer to previous block index
    BlockIndex* skip = nullptr;     // Skip pointer for fast traversal

    // Get ancestor at specific height
    BlockIndex* getAncestor(int32_t target_height);
    const BlockIndex* getAncestor(int32_t target_height) const;

    // Check if this is an ancestor of another block
    bool isAncestorOf(const BlockIndex* other) const;
};

// Chain tip information
struct ChainTip {
    crypto::Hash256 hash;
    int32_t height = -1;
    uint256_t work;
    bool is_active = false;
};

// ValidationResult is defined in chain/validation.h

// Callbacks
using BlockConnectedCallback = std::function<void(const Block&, const BlockIndex*)>;
using BlockDisconnectedCallback = std::function<void(const Block&, const BlockIndex*)>;
using NewTipCallback = std::function<void(const BlockIndex*)>;

// Block event for deferred callback invocation (prevents deadlock)
struct BlockEvent {
    enum Type { CONNECTED, DISCONNECTED };
    Type type;
    Block block;
    const BlockIndex* index;
};

/**
 * Chain - manages the blockchain
 *
 * Responsibilities:
 * - Block storage and retrieval
 * - Block validation
 * - Chain state management
 * - Reorganization handling
 * - Block locator generation
 */
class Chain {
public:
    // Chain configuration
    struct Config {
        std::string data_dir = "./blocks";
        uint32_t max_reorg_depth = 100;     // Maximum reorganization depth
        bool verify_scripts = true;          // Verify scripts on connect
        size_t block_cache_size = 32;        // Number of blocks to cache
    };

    // Consensus parameters (legacy - use Consensus class instead)
    struct Params {
        uint32_t block_time = 60;                   // Target block time in seconds
        uint32_t difficulty_adjustment_interval = 2016;
        uint64_t initial_reward = 50 * 100000000ULL; // 50 FTC in satoshis
        uint32_t halving_interval = 210000;
        uint64_t max_supply = 21000000ULL * 100000000ULL;
        uint32_t max_block_size = 1000000;          // 1 MB
        uint32_t max_block_sigops = 20000;
        int64_t max_time_adjustment = 70 * 60;      // 70 minutes
        uint32_t median_time_span = 11;

        // Genesis block
        crypto::Hash256 genesis_hash;
        uint32_t genesis_time = 1737331200;         // 2026-01-20 00:00:00 UTC

        // Checkpoints (height -> hash)
        std::map<int32_t, crypto::Hash256> checkpoints;
    };

    // Default constructor
    Chain();

    // Constructor with full dependencies
    Chain(const Config& config, Consensus* consensus, UTXOSet* utxo_set);

    ~Chain();

    // Non-copyable
    Chain(const Chain&) = delete;
    Chain& operator=(const Chain&) = delete;

    // Initialization
    bool load(const std::string& data_dir);
    bool initialize();  // Initialize chain (load from disk or create genesis)
    void close();
    void flush();       // Flush pending changes to disk

    // Set consensus parameters
    void setParams(const Params& params) { params_ = params; }
    const Params& getParams() const { return params_; }

    // Set callbacks
    void setBlockConnectedCallback(BlockConnectedCallback cb) { on_block_connected_ = cb; }
    void setBlockDisconnectedCallback(BlockDisconnectedCallback cb) { on_block_disconnected_ = cb; }
    void setNewTipCallback(NewTipCallback cb) { on_new_tip_ = cb; }

    // Chain state
    int32_t getHeight() const;
    crypto::Hash256 getBestHash() const;
    const BlockIndex* getTip() const;
    uint256_t getTotalWork() const;
    crypto::Hash256 getGenesisHash() const;  // Get genesis block hash

    // Block index access
    const BlockIndex* getBlockIndex(const crypto::Hash256& hash) const;
    const BlockIndex* getBlockIndex(int32_t height) const;
    bool hasBlock(const crypto::Hash256& hash) const;
    bool hasBlockData(const crypto::Hash256& hash) const;

    // Block data access
    std::optional<Block> getBlock(const crypto::Hash256& hash) const;
    std::optional<Block> getBlock(int32_t height) const;
    std::optional<BlockHeader> getHeader(const crypto::Hash256& hash) const;
    std::optional<BlockHeader> getBlockHeader(const crypto::Hash256& hash) const { return getHeader(hash); }

    // Height/hash lookups (aliases for message_handler compatibility)
    std::optional<int32_t> getBlockHeight(const crypto::Hash256& hash) const;
    std::optional<crypto::Hash256> getBlockHashAtHeight(int32_t height) const;

    // Transaction lookups
    bool hasTx(const crypto::Hash256& txid) const;
    std::optional<Transaction> getTx(const crypto::Hash256& txid) const;

    // Block processing
    ValidationResult processBlock(const Block& block, bool check_pow = true);
    ValidationResult addBlock(const Block& block, bool check_pow = true) { return processBlock(block, check_pow); }  // Alias
    ValidationResult processHeader(const BlockHeader& header);
    ValidationResult processHeaders(const std::vector<BlockHeader>& headers);

    // Block locator for sync
    std::vector<crypto::Hash256> getBlockLocator(const BlockIndex* index = nullptr) const;
    const BlockIndex* findForkPoint(const std::vector<crypto::Hash256>& locator) const;

    // Headers
    std::vector<BlockHeader> getHeaders(const std::vector<crypto::Hash256>& locator,
                                         const crypto::Hash256& stop_hash,
                                         size_t max_headers = 2000) const;

    // Chain tips
    std::vector<ChainTip> getChainTips() const;

    // Block reward calculation
    uint64_t getBlockReward(int32_t height) const;

    // Difficulty
    uint32_t getNextWorkRequired(const BlockIndex* prev, const BlockHeader* header = nullptr) const;
    uint256_t getBlockProof(uint32_t bits) const;

    // Genesis
    Block createGenesisBlock() const;

private:
    // Configuration
    Config config_;

    // External dependencies (optional, can be null for standalone usage)
    Consensus* consensus_ext_ = nullptr;
    UTXOSet* utxo_set_ext_ = nullptr;

    // Block validation
    ValidationResult validateBlockHeader(const BlockHeader& header, const BlockIndex* prev);
    ValidationResult validateBlock(const Block& block, const BlockIndex* index);
    ValidationResult checkBlockTransactions(const Block& block);
    bool checkProofOfWork(const crypto::Hash256& hash, uint32_t bits) const;

    // Block index management
    BlockIndex* addToBlockIndex(const BlockHeader& header);
    void removeFromBlockIndex(const crypto::Hash256& hash);

    // Chain management (events collected for deferred callback invocation)
    bool activateBestChain(std::vector<BlockEvent>& events, const BlockIndex*& out_new_tip);
    bool connectBlock(const Block& block, BlockIndex* index, std::vector<BlockEvent>& events);
    bool disconnectBlock(const Block& block, BlockIndex* index, std::vector<BlockEvent>& events);
    void invalidateBlock(BlockIndex* index);
    void reconsiderBlock(BlockIndex* index);

    // Skip list for fast ancestor lookup
    void buildSkipList(BlockIndex* index);
    int getSkipHeight(int height) const;

    // Median time calculation
    int64_t getMedianTimePast(const BlockIndex* index) const;

    // Storage
    bool loadBlockIndex();
    bool saveBlockIndex(const BlockIndex* index);
    bool loadBlock(const crypto::Hash256& hash, Block& block) const;
    bool saveBlock(const Block& block, uint64_t& file_pos);

    // Consensus parameters
    Params params_;

    // Block index (all known blocks)
    std::map<crypto::Hash256, std::unique_ptr<BlockIndex>> block_index_;
    mutable std::mutex index_mutex_;

    // Chain state
    BlockIndex* tip_ = nullptr;
    BlockIndex* genesis_ = nullptr;

    // Height index
    std::map<int32_t, BlockIndex*> height_index_;

    // Transaction index: txid -> (block_hash, tx_index)
    struct TxIndex {
        crypto::Hash256 block_hash;
        uint32_t tx_pos;  // Position in block's transaction list
    };
    std::map<crypto::Hash256, TxIndex> tx_index_;
    mutable std::mutex tx_index_mutex_;

    // Dirty block indices that need saving
    std::set<crypto::Hash256> dirty_indices_;

    // Block storage
    std::string data_dir_;
    std::unique_ptr<BlockStore> block_store_;

    // Callbacks
    BlockConnectedCallback on_block_connected_;
    BlockDisconnectedCallback on_block_disconnected_;
    NewTipCallback on_new_tip_;

    // Initialization flag
    bool loaded_ = false;
};

/**
 * BlockStore - persistent block storage
 */
class BlockStore {
public:
    BlockStore(const std::string& path);
    ~BlockStore();

    bool open();
    void close();

    bool writeBlock(const Block& block, uint64_t& pos);
    bool readBlock(uint64_t pos, Block& block) const;

    bool writeUndo(int32_t height, const std::vector<uint8_t>& data);
    bool readUndo(int32_t height, std::vector<uint8_t>& data) const;

    void flush();

private:
    std::string path_;
    FILE* block_file_ = nullptr;
    uint64_t write_pos_ = 0;
    mutable std::mutex mutex_;
};

} // namespace chain
} // namespace ftc

#endif // FTC_CHAIN_CHAIN_H
