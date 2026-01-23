#ifndef FTC_STORAGE_BLOCK_STORE_H
#define FTC_STORAGE_BLOCK_STORE_H

#include "storage/database.h"
#include "chain/block.h"
#include "chain/transaction.h"
#include "crypto/keccak256.h"
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <cstring>

namespace ftc {
namespace storage {

// Block file header
struct BlockFileHeader {
    uint32_t magic = 0x46544342;  // "FTCB"
    uint32_t version = 1;
    uint64_t num_blocks = 0;
    uint64_t total_size = 0;
};

// Block file info
struct BlockFileInfo {
    uint64_t file_number;
    uint64_t num_blocks;
    uint64_t size;
    uint64_t height_first;
    uint64_t height_last;
    int64_t time_first;
    int64_t time_last;
};

// Block position in file
struct BlockPos {
    uint64_t file_number = 0;
    uint64_t offset = 0;
    uint64_t size = 0;

    bool isNull() const { return file_number == 0 && offset == 0; }
};

// Transaction position
struct TxPos {
    BlockPos block_pos;
    uint32_t tx_index = 0;
    uint32_t tx_offset = 0;  // Offset within block
};

/**
 * BlockStore - persistent block storage
 *
 * Features:
 * - Stores blocks in numbered block files (blk00000.dat, blk00001.dat, etc.)
 * - Supports undo data for reorganizations
 * - Transaction index for fast tx lookups
 * - Block index stored in LevelDB
 *
 * File layout:
 * - blocks/blkNNNNN.dat - Raw block data
 * - blocks/revNNNNN.dat - Undo/revert data for disconnecting blocks
 * - index/ - LevelDB database for block index
 */
class BlockStore {
public:
    struct Config {
        std::string data_dir;
        uint64_t max_file_size = 128 * 1024 * 1024;  // 128 MB per file
        bool prune = false;
        uint64_t prune_target = 0;  // Target size in bytes when pruning
    };

    explicit BlockStore(const Config& config);
    ~BlockStore();

    // Non-copyable
    BlockStore(const BlockStore&) = delete;
    BlockStore& operator=(const BlockStore&) = delete;

    // Initialize/shutdown
    bool open();
    void close();
    bool isOpen() const { return opened_; }

    // Block operations
    bool writeBlock(const chain::Block& block, BlockPos& pos);
    bool readBlock(const BlockPos& pos, chain::Block& block) const;
    bool hasBlock(const crypto::Hash256& hash) const;

    // Block index
    bool writeBlockIndex(const crypto::Hash256& hash, const BlockPos& pos,
                         int32_t height, const crypto::Hash256& prev_hash);
    bool readBlockIndex(const crypto::Hash256& hash, BlockPos& pos,
                        int32_t& height, crypto::Hash256& prev_hash) const;

    // Undo data (for reorganizations)
    bool writeUndoData(int32_t height, const std::vector<uint8_t>& undo_data);
    bool readUndoData(int32_t height, std::vector<uint8_t>& undo_data) const;

    // Transaction index (optional)
    bool writeTxIndex(const crypto::Hash256& txid, const TxPos& pos);
    bool readTxIndex(const crypto::Hash256& txid, TxPos& pos) const;
    bool hasTx(const crypto::Hash256& txid) const;

    // Get block by hash (convenience method)
    std::optional<chain::Block> getBlock(const crypto::Hash256& hash) const;

    // Get block position
    std::optional<BlockPos> getBlockPos(const crypto::Hash256& hash) const;

    // Get best block hash (tip of chain from storage perspective)
    crypto::Hash256 getBestBlockHash() const;
    int32_t getBestHeight() const;
    bool setBestBlock(const crypto::Hash256& hash, int32_t height);

    // File management
    void flush();
    uint64_t getTotalSize() const;
    size_t getNumFiles() const;

    // Pruning
    void prune(uint64_t target_size);
    void pruneToHeight(int32_t height);

    // Iteration
    bool forEachBlock(std::function<bool(const crypto::Hash256& hash,
                                         int32_t height,
                                         const BlockPos& pos)> callback) const;

private:
    // File operations
    std::string blockFilePath(uint64_t file_num) const;
    std::string undoFilePath(uint64_t file_num) const;
    FILE* openBlockFile(uint64_t file_num, bool read_only = false);
    FILE* openUndoFile(uint64_t file_num, bool read_only = false);

    // Allocate space in current block file
    bool allocateSpace(uint64_t size, BlockPos& pos);

    // Database key encoding
    static std::string blockIndexKey(const crypto::Hash256& hash);
    static std::string txIndexKey(const crypto::Hash256& txid);
    static std::string fileInfoKey(uint64_t file_num);
    static std::string metaKey(const std::string& name);

    // Configuration
    Config config_;

    // State
    bool opened_ = false;
    uint64_t current_file_ = 0;
    uint64_t current_pos_ = 0;

    // Best block
    crypto::Hash256 best_block_hash_;
    int32_t best_height_ = -1;

    // File handles (cached)
    mutable std::map<uint64_t, FILE*> block_files_;
    mutable std::map<uint64_t, FILE*> undo_files_;
    mutable std::mutex file_mutex_;

    // File info cache
    std::map<uint64_t, BlockFileInfo> file_info_;

    // LevelDB index database
    std::unique_ptr<Database> index_db_;

    // Total size tracking
    std::atomic<uint64_t> total_size_{0};
};

/**
 * BlockBatch - batched block writes
 *
 * For efficient writing of multiple blocks
 */
class BlockBatch {
public:
    explicit BlockBatch(BlockStore& store);
    ~BlockBatch();

    void addBlock(const chain::Block& block, int32_t height);
    bool commit();
    void abort();

    size_t size() const { return blocks_.size(); }

private:
    BlockStore& store_;
    std::vector<std::pair<chain::Block, int32_t>> blocks_;
    bool committed_ = false;
};

/**
 * BlockReader - efficient block reading
 *
 * Provides sequential reading of blocks for initial sync
 */
class BlockReader {
public:
    explicit BlockReader(const BlockStore& store);
    ~BlockReader();

    // Sequential reading
    bool next(chain::Block& block, crypto::Hash256& hash, int32_t& height);
    bool seek(int32_t height);
    bool seek(const crypto::Hash256& hash);

    // Current position
    int32_t currentHeight() const { return current_height_; }
    crypto::Hash256 currentHash() const { return current_hash_; }

    // Status
    bool valid() const { return valid_; }
    bool atEnd() const { return at_end_; }

private:
    const BlockStore& store_;
    int32_t current_height_ = -1;
    crypto::Hash256 current_hash_;
    bool valid_ = false;
    bool at_end_ = false;
};

/**
 * UTXOStore - UTXO database storage
 *
 * Stores UTXO set for fast validation
 */
class UTXOStore {
public:
    struct UTXOKey {
        crypto::Hash256 txid;
        uint32_t vout;

        bool operator<(const UTXOKey& other) const {
            int cmp = std::memcmp(txid.data(), other.txid.data(), 32);
            if (cmp != 0) return cmp < 0;
            return vout < other.vout;
        }
    };

    struct UTXOValue {
        uint64_t amount;
        std::vector<uint8_t> script;
        int32_t height;
        bool coinbase;
    };

    explicit UTXOStore(const std::string& path);
    ~UTXOStore();

    bool open();
    void close();

    // UTXO operations
    bool addUTXO(const UTXOKey& key, const UTXOValue& value);
    bool removeUTXO(const UTXOKey& key);
    bool getUTXO(const UTXOKey& key, UTXOValue& value) const;
    bool hasUTXO(const UTXOKey& key) const;

    // Batch operations
    void startBatch();
    void addToBatch(const UTXOKey& key, const UTXOValue& value);
    void removeFromBatch(const UTXOKey& key);
    bool commitBatch();
    void abortBatch();

    // Statistics
    uint64_t size() const;
    uint64_t totalAmount() const;

    // Iteration
    bool forEach(std::function<bool(const UTXOKey&, const UTXOValue&)> callback) const;

private:
    std::string path_;
    std::unique_ptr<Database> db_;
    std::unique_ptr<WriteBatch> batch_;
    bool batch_active_ = false;
};

} // namespace storage
} // namespace ftc

#endif // FTC_STORAGE_BLOCK_STORE_H
