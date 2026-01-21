/**
 * FTC Chain Implementation
 * Full blockchain management with validation and storage
 */

#include "chain/chain.h"
#include "crypto/keccak256.h"
#include "util/logging.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <ctime>

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace ftc {
namespace chain {

namespace fs = std::filesystem;

// Forward declaration
static int getSkipHeight(int height);

// Add two uint256_t values (little-endian)
static uint256_t add256(const uint256_t& a, const uint256_t& b) {
    uint256_t result{};
    uint16_t carry = 0;
    for (int i = 0; i < 32; i++) {
        uint16_t sum = static_cast<uint16_t>(a[i]) + static_cast<uint16_t>(b[i]) + carry;
        result[i] = static_cast<uint8_t>(sum & 0xFF);
        carry = sum >> 8;
    }
    return result;
}

// Check if uint256_t is zero
static bool isZero256(const uint256_t& x) {
    for (int i = 0; i < 32; i++) {
        if (x[i] != 0) return false;
    }
    return true;
}

// Compare two uint256_t values (little-endian byte order)
// Returns: -1 if a < b, 0 if a == b, 1 if a > b
static int compare256(const uint256_t& a, const uint256_t& b) {
    for (int i = 31; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

// Multiply uint256 by uint64 (simplified, for small multipliers)
static uint256_t mul256_64(const uint256_t& a, uint64_t b) {
    uint256_t result{};
    uint64_t carry = 0;
    for (int i = 0; i < 32; i++) {
        uint64_t prod = static_cast<uint64_t>(a[i]) * b + carry;
        result[i] = static_cast<uint8_t>(prod & 0xFF);
        carry = prod >> 8;
    }
    return result;
}

// Divide uint256 by uint64 (simplified)
static uint256_t div256_64(const uint256_t& a, uint64_t b) {
    uint256_t result{};
    uint64_t remainder = 0;
    for (int i = 31; i >= 0; i--) {
        uint64_t dividend = (remainder << 8) | a[i];
        result[i] = static_cast<uint8_t>(dividend / b);
        remainder = dividend % b;
    }
    return result;
}

// Get max uint256 value
static uint256_t maxUint256() {
    uint256_t result;
    for (int i = 0; i < 32; i++) {
        result[i] = 0xff;
    }
    return result;
}

// Cross-platform count leading zeros
static int countLeadingZeros(unsigned int x) {
    if (x == 0) return 32;
#ifdef _MSC_VER
    unsigned long index;
    _BitScanReverse(&index, x);
    return 31 - static_cast<int>(index);
#else
    return __builtin_clz(x);
#endif
}

// ============================================================================
// BlockIndex implementation
// ============================================================================

BlockIndex* BlockIndex::getAncestor(int32_t target_height) {
    if (target_height > height || target_height < 0) {
        return nullptr;
    }

    BlockIndex* walk = this;
    int height_walk = height;

    while (height_walk > target_height) {
        int height_skip = getSkipHeight(height_walk);
        int height_skip_prev = getSkipHeight(height_walk - 1);

        if (walk->skip != nullptr &&
            (height_skip == target_height ||
             (height_skip > target_height && !(height_skip_prev < height_skip - 2 &&
                                               height_skip_prev >= target_height)))) {
            walk = walk->skip;
            height_walk = height_skip;
        } else {
            if (walk->prev == nullptr) return nullptr;
            walk = walk->prev;
            height_walk--;
        }
    }

    return walk;
}

const BlockIndex* BlockIndex::getAncestor(int32_t target_height) const {
    return const_cast<BlockIndex*>(this)->getAncestor(target_height);
}

bool BlockIndex::isAncestorOf(const BlockIndex* other) const {
    if (other == nullptr || other->height < height) {
        return false;
    }
    return other->getAncestor(height) == this;
}

static int getSkipHeight(int height) {
    if (height < 2) return 0;

    // Skip list: turn the lowest '1' bit of height to '0' and the '0' bits below it to '1's
    return (height & 1) ? height - 1 : height - (1 << (32 - countLeadingZeros(static_cast<unsigned int>(height))));
}

// ============================================================================
// Chain implementation
// ============================================================================

Chain::Chain() {}

Chain::~Chain() {
    close();
}

bool Chain::load(const std::string& data_dir) {
    if (loaded_) return true;

    data_dir_ = data_dir;

    // Create directories
    try {
        fs::create_directories(data_dir_);
        fs::create_directories(data_dir_ + "/blocks");
        fs::create_directories(data_dir_ + "/index");
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to create data directories: {}", e.what());
        return false;
    }

    // Open block store
    block_store_ = std::make_unique<BlockStore>(data_dir_ + "/blocks");
    if (!block_store_->open()) {
        LOG_ERROR("Failed to open block store");
        return false;
    }

    // Load or create genesis
    if (!loadBlockIndex()) {
        LOG_INFO("Creating new chain with genesis block");

        Block genesis = createGenesisBlock();
        crypto::Hash256 genesis_hash = genesis.getHash();

        // Add genesis to index
        auto index = std::make_unique<BlockIndex>();
        index->hash = genesis_hash;
        index->prev_hash = crypto::ZERO_HASH;
        index->merkle_root = genesis.header.merkle_root;
        index->height = 0;
        index->version = genesis.header.version;
        index->timestamp = genesis.header.timestamp;
        index->bits = genesis.header.bits;
        index->nonce = genesis.header.nonce;
        index->status = BlockStatus::HEADER_VALID | BlockStatus::DATA_AVAILABLE |
                        BlockStatus::SCRIPTS_VALID | BlockStatus::ON_MAIN_CHAIN;
        index->tx_count = static_cast<uint32_t>(genesis.transactions.size());
        index->total_tx = index->tx_count;
        index->chain_work = getBlockProof(genesis.header.bits);

        // Save genesis block
        uint64_t file_pos;
        if (!saveBlock(genesis, file_pos)) {
            LOG_ERROR("Failed to save genesis block");
            return false;
        }
        index->file_pos = file_pos;

        genesis_ = index.get();
        tip_ = index.get();
        height_index_[0] = index.get();

        block_index_[genesis_hash] = std::move(index);

        params_.genesis_hash = genesis_hash;

        LOG_INFO("Genesis block: {}", crypto::Keccak256::toHex(genesis_hash));
    }

    loaded_ = true;
    LOG_INFO("Chain loaded: height={} tip={}",
             getHeight(), crypto::Keccak256::toHex(getBestHash()).substr(0, 16));

    return true;
}

void Chain::close() {
    if (!loaded_) return;

    // Save entire block index to disk
    if (!dirty_indices_.empty()) {
        saveBlockIndex(nullptr);  // Save all blocks
    }
    dirty_indices_.clear();

    // Close block store
    if (block_store_) {
        block_store_->flush();
        block_store_->close();
        block_store_.reset();
    }

    loaded_ = false;
    LOG_INFO("Chain closed, index saved");
}

int32_t Chain::getHeight() const {
    std::lock_guard<std::mutex> lock(index_mutex_);
    return tip_ ? tip_->height : -1;
}

crypto::Hash256 Chain::getBestHash() const {
    std::lock_guard<std::mutex> lock(index_mutex_);
    return tip_ ? tip_->hash : crypto::ZERO_HASH;
}

const BlockIndex* Chain::getTip() const {
    std::lock_guard<std::mutex> lock(index_mutex_);
    return tip_;
}

uint256_t Chain::getTotalWork() const {
    std::lock_guard<std::mutex> lock(index_mutex_);
    return tip_ ? tip_->chain_work : uint256_t{};
}

const BlockIndex* Chain::getBlockIndex(const crypto::Hash256& hash) const {
    std::lock_guard<std::mutex> lock(index_mutex_);
    auto it = block_index_.find(hash);
    return it != block_index_.end() ? it->second.get() : nullptr;
}

const BlockIndex* Chain::getBlockIndex(int32_t height) const {
    std::lock_guard<std::mutex> lock(index_mutex_);
    auto it = height_index_.find(height);
    return it != height_index_.end() ? it->second : nullptr;
}

bool Chain::hasBlock(const crypto::Hash256& hash) const {
    std::lock_guard<std::mutex> lock(index_mutex_);
    return block_index_.count(hash) > 0;
}

bool Chain::hasBlockData(const crypto::Hash256& hash) const {
    std::lock_guard<std::mutex> lock(index_mutex_);
    auto it = block_index_.find(hash);
    return it != block_index_.end() &&
           hasFlag(it->second->status, BlockStatus::DATA_AVAILABLE);
}

std::optional<Block> Chain::getBlock(const crypto::Hash256& hash) const {
    std::lock_guard<std::mutex> lock(index_mutex_);

    auto it = block_index_.find(hash);
    if (it == block_index_.end() ||
        !hasFlag(it->second->status, BlockStatus::DATA_AVAILABLE)) {
        return std::nullopt;
    }

    Block block;
    if (!loadBlock(hash, block)) {
        return std::nullopt;
    }

    return block;
}

std::optional<Block> Chain::getBlock(int32_t height) const {
    std::lock_guard<std::mutex> lock(index_mutex_);

    auto it = height_index_.find(height);
    if (it == height_index_.end()) {
        return std::nullopt;
    }

    Block block;
    if (!loadBlock(it->second->hash, block)) {
        return std::nullopt;
    }

    return block;
}

std::optional<BlockHeader> Chain::getHeader(const crypto::Hash256& hash) const {
    std::lock_guard<std::mutex> lock(index_mutex_);

    auto it = block_index_.find(hash);
    if (it == block_index_.end()) {
        return std::nullopt;
    }

    BlockHeader header;
    header.version = it->second->version;
    header.prev_hash = it->second->prev_hash;
    header.merkle_root = it->second->merkle_root;
    header.timestamp = it->second->timestamp;
    header.bits = it->second->bits;
    header.nonce = it->second->nonce;

    return header;
}

ValidationResult Chain::processBlock(const Block& block, bool check_pow) {
    crypto::Hash256 hash = block.getHash();

    LOG_DEBUG("Processing block {}", crypto::Keccak256::toHex(hash).substr(0, 16));

    // Collect block events for deferred callback invocation (prevents deadlock)
    std::vector<BlockEvent> pending_events;
    const BlockIndex* new_tip = nullptr;

    ValidationResult result;
    {
        std::unique_lock<std::mutex> lock(index_mutex_);

        // Check if we already have this block
        auto it = block_index_.find(hash);
        if (it != block_index_.end()) {
            if (hasFlag(it->second->status, BlockStatus::DATA_AVAILABLE)) {
                return ValidationResult::VALID;
            }
        }

        // Find previous block
        BlockIndex* prev = nullptr;
        if (block.header.prev_hash != crypto::ZERO_HASH) {
            auto prev_it = block_index_.find(block.header.prev_hash);
            if (prev_it == block_index_.end()) {
                return ValidationResult::ORPHAN;
            }
            prev = prev_it->second.get();
        }

        // Validate header
        result = validateBlockHeader(block.header, prev);
        if (result != ValidationResult::VALID) {
            return result;
        }

        // Check proof of work
        if (check_pow && !checkProofOfWork(hash, block.header.bits)) {
            // Not a warning - expected for invalid submissions
            return ValidationResult::INVALID_POW;
        }

        // Add to index if not already there
        BlockIndex* index;
        if (it == block_index_.end()) {
            index = addToBlockIndex(block.header);
        } else {
            index = it->second.get();
        }

        // Validate block contents
        result = validateBlock(block, index);
        if (result != ValidationResult::VALID) {
            index->status = index->status | BlockStatus::FAILED;
            return result;
        }

        // Save block
        uint64_t file_pos;
        if (!saveBlock(block, file_pos)) {
            return ValidationResult::ERROR;
        }
        index->file_pos = file_pos;
        index->tx_count = static_cast<uint32_t>(block.transactions.size());
        index->status = index->status | BlockStatus::DATA_AVAILABLE | BlockStatus::SCRIPTS_VALID;

        dirty_indices_.insert(hash);

        // Try to activate best chain (collects events instead of calling callbacks)
        if (!activateBestChain(pending_events, new_tip)) {
            return ValidationResult::ERROR;
        }

        result = ValidationResult::VALID;
    } // Mutex released here

    // Invoke callbacks AFTER mutex is released (prevents deadlock)
    for (const auto& event : pending_events) {
        if (event.type == BlockEvent::CONNECTED && on_block_connected_) {
            on_block_connected_(event.block, event.index);
        } else if (event.type == BlockEvent::DISCONNECTED && on_block_disconnected_) {
            on_block_disconnected_(event.block, event.index);
        }
    }

    if (new_tip && on_new_tip_) {
        on_new_tip_(new_tip);
    }

    return result;
}

ValidationResult Chain::processHeader(const BlockHeader& header) {
    crypto::Hash256 hash = header.getHash();

    std::lock_guard<std::mutex> lock(index_mutex_);

    // Check if we already have this header
    if (block_index_.count(hash) > 0) {
        return ValidationResult::VALID;
    }

    // Find previous block
    BlockIndex* prev = nullptr;
    if (header.prev_hash != crypto::ZERO_HASH) {
        auto prev_it = block_index_.find(header.prev_hash);
        if (prev_it == block_index_.end()) {
            return ValidationResult::ORPHAN;
        }
        prev = prev_it->second.get();
    }

    // Validate header
    ValidationResult result = validateBlockHeader(header, prev);
    if (result != ValidationResult::VALID) {
        return result;
    }

    // Check proof of work
    if (!checkProofOfWork(hash, header.bits)) {
        return ValidationResult::INVALID_POW;
    }

    // Add to index
    addToBlockIndex(header);

    return ValidationResult::VALID;
}

ValidationResult Chain::processHeaders(const std::vector<BlockHeader>& headers) {
    for (const auto& header : headers) {
        ValidationResult result = processHeader(header);
        if (result != ValidationResult::VALID && result != ValidationResult::VALID) {
            return result;
        }
    }
    return ValidationResult::VALID;
}

ValidationResult Chain::validateBlockHeader(const BlockHeader& header, const BlockIndex* prev) {
    // Check version
    if (header.version < 1) {
        return ValidationResult::INVALID_BLOCK_HEADER;
    }

    // Check timestamp
    if (prev) {
        // Must be greater than median of last 11 blocks
        int64_t median = getMedianTimePast(prev);
        if (static_cast<int64_t>(header.timestamp) <= median) {
            LOG_WARN("Block timestamp {} <= median {}", header.timestamp, median);
            return ValidationResult::INVALID_TIMESTAMP;
        }
    }

    // Check timestamp not too far in future
    int64_t now = std::time(nullptr);
    if (static_cast<int64_t>(header.timestamp) > now + params_.max_time_adjustment) {
        LOG_WARN("Block timestamp {} too far in future", header.timestamp);
        return ValidationResult::INVALID_TIMESTAMP;
    }

    // Check difficulty
    if (prev) {
        uint32_t expected_bits = getNextWorkRequired(prev, &header);
        if (header.bits != expected_bits) {
            LOG_WARN("Block has incorrect difficulty: {} vs expected {}",
                     header.bits, expected_bits);
            return ValidationResult::INVALID_BLOCK_HEADER;
        }
    }

    // Check against checkpoints
    int32_t height = prev ? prev->height + 1 : 0;
    auto checkpoint = params_.checkpoints.find(height);
    if (checkpoint != params_.checkpoints.end()) {
        if (header.getHash() != checkpoint->second) {
            LOG_WARN("Block at height {} doesn't match checkpoint", height);
            return ValidationResult::CHECKPOINT_MISMATCH;
        }
    }

    return ValidationResult::VALID;
}

ValidationResult Chain::validateBlock(const Block& block, const BlockIndex* index) {
    // Check merkle root
    crypto::Hash256 merkle = block.calculateMerkleRoot();
    if (merkle != block.header.merkle_root) {
        LOG_WARN("Invalid merkle root");
        return ValidationResult::INVALID_MERKLE_ROOT;
    }

    // Check transactions
    return checkBlockTransactions(block);
}

ValidationResult Chain::checkBlockTransactions(const Block& block) {
    if (block.transactions.empty()) {
        return ValidationResult::INVALID_COINBASE;
    }

    // First transaction must be coinbase
    if (!block.transactions[0].isCoinbase()) {
        return ValidationResult::INVALID_COINBASE;
    }

    // Other transactions must not be coinbase
    for (size_t i = 1; i < block.transactions.size(); i++) {
        if (block.transactions[i].isCoinbase()) {
            return ValidationResult::INVALID_COINBASE;
        }
    }

    // Check block size
    size_t block_size = block.serialize().size();
    if (block_size > params_.max_block_size) {
        LOG_WARN("Block too large: {} > {}", block_size, params_.max_block_size);
        return ValidationResult::INVALID_TX;
    }

    // Basic transaction validation
    std::set<crypto::Hash256> tx_ids;
    for (const auto& tx : block.transactions) {
        crypto::Hash256 txid = tx.getTxId();

        // Check for duplicates within block
        if (tx_ids.count(txid) > 0) {
            return ValidationResult::INVALID_TX;
        }
        tx_ids.insert(txid);
    }

    return ValidationResult::VALID;
}

bool Chain::checkProofOfWork(const crypto::Hash256& hash, uint32_t bits) const {
    crypto::Hash256 target = BlockHeader::bitsToTarget(bits);

    // Compare hash against target (both are big-endian 256-bit values)
    // hash must be <= target for valid PoW
    return crypto::Keccak256::compare(hash, target) <= 0;
}

BlockIndex* Chain::addToBlockIndex(const BlockHeader& header) {
    crypto::Hash256 hash = header.getHash();

    auto index = std::make_unique<BlockIndex>();
    index->hash = hash;
    index->prev_hash = header.prev_hash;
    index->merkle_root = header.merkle_root;
    index->version = header.version;
    index->timestamp = header.timestamp;
    index->bits = header.bits;
    index->nonce = header.nonce;
    index->status = BlockStatus::HEADER_VALID;

    // Link to previous
    if (header.prev_hash != crypto::ZERO_HASH) {
        auto prev_it = block_index_.find(header.prev_hash);
        if (prev_it != block_index_.end()) {
            index->prev = prev_it->second.get();
            index->height = index->prev->height + 1;
            index->chain_work = add256(index->prev->chain_work, getBlockProof(header.bits));
        }
    } else {
        index->height = 0;
        index->chain_work = getBlockProof(header.bits);
    }

    // Build skip list
    buildSkipList(index.get());

    BlockIndex* ptr = index.get();
    block_index_[hash] = std::move(index);
    dirty_indices_.insert(hash);

    return ptr;
}

void Chain::removeFromBlockIndex(const crypto::Hash256& hash) {
    auto it = block_index_.find(hash);
    if (it != block_index_.end()) {
        // Remove from height index if on main chain
        if (hasFlag(it->second->status, BlockStatus::ON_MAIN_CHAIN)) {
            height_index_.erase(it->second->height);
        }
        block_index_.erase(it);
    }
    dirty_indices_.erase(hash);
}

bool Chain::activateBestChain(std::vector<BlockEvent>& events, const BlockIndex*& out_new_tip) {
    out_new_tip = nullptr;

    // Find the best tip (most work)
    BlockIndex* best_tip = tip_;

    for (auto& p : block_index_) {
        BlockIndex* index = p.second.get();

        // Must have data
        if (!hasFlag(index->status, BlockStatus::DATA_AVAILABLE)) {
            continue;
        }

        // Must not have failed
        if (hasFlag(index->status, BlockStatus::FAILED)) {
            continue;
        }

        // Check if more work (use compare256 for little-endian comparison)
        if (best_tip == nullptr || compare256(index->chain_work, best_tip->chain_work) > 0) {
            best_tip = index;
        }
    }

    if (best_tip == tip_) {
        return true;  // No change
    }

    // Find fork point
    BlockIndex* fork_point = tip_;
    BlockIndex* new_tip = best_tip;

    if (fork_point) {
        while (fork_point && new_tip && fork_point->height > new_tip->height) {
            fork_point = fork_point->prev;
        }
        while (fork_point && new_tip && new_tip->height > fork_point->height) {
            new_tip = new_tip->prev;
        }
        while (fork_point && new_tip && fork_point != new_tip) {
            fork_point = fork_point->prev;
            new_tip = new_tip->prev;
        }
    }

    // Disconnect blocks from old chain
    if (tip_ && fork_point) {
        std::vector<BlockIndex*> to_disconnect;
        BlockIndex* walk = tip_;
        while (walk && walk != fork_point) {
            to_disconnect.push_back(walk);
            walk = walk->prev;
        }

        for (auto* index : to_disconnect) {
            Block block;
            if (!loadBlock(index->hash, block)) {
                LOG_ERROR("Failed to load block for disconnect");
                return false;
            }

            if (!disconnectBlock(block, index, events)) {
                return false;
            }
        }
    }

    // Connect blocks to new chain
    std::vector<BlockIndex*> to_connect;
    new_tip = best_tip;
    while (new_tip && new_tip != fork_point) {
        to_connect.push_back(new_tip);
        new_tip = new_tip->prev;
    }
    std::reverse(to_connect.begin(), to_connect.end());

    for (auto* index : to_connect) {
        Block block;
        if (!loadBlock(index->hash, block)) {
            LOG_ERROR("Failed to load block for connect");
            return false;
        }

        if (!connectBlock(block, index, events)) {
            // Mark as failed
            index->status = index->status | BlockStatus::FAILED;
            dirty_indices_.insert(index->hash);
            return false;
        }
    }

    // Update tip
    BlockIndex* old_tip = tip_;
    tip_ = best_tip;

    if (old_tip != tip_) {
        LOG_INFO("New tip: height={} hash={}",
                 tip_->height, crypto::Keccak256::toHex(tip_->hash).substr(0, 16));

        out_new_tip = tip_;  // Caller will invoke on_new_tip_ callback
    }

    return true;
}

bool Chain::connectBlock(const Block& block, BlockIndex* index, std::vector<BlockEvent>& events) {
    LOG_DEBUG("Connecting block {} at height {}",
              crypto::Keccak256::toHex(index->hash).substr(0, 16), index->height);

    // Update status
    index->status = index->status | BlockStatus::ON_MAIN_CHAIN;

    // Update total tx
    if (index->prev) {
        index->total_tx = index->prev->total_tx + index->tx_count;
    } else {
        index->total_tx = index->tx_count;
    }

    // Update height index
    height_index_[index->height] = index;

    // Update transaction index
    {
        std::lock_guard<std::mutex> tx_lock(tx_index_mutex_);
        for (uint32_t i = 0; i < block.transactions.size(); ++i) {
            crypto::Hash256 txid = block.transactions[i].getTxId();
            TxIndex tx_idx;
            tx_idx.block_hash = index->hash;
            tx_idx.tx_pos = i;
            tx_index_[txid] = tx_idx;
        }
    }

    dirty_indices_.insert(index->hash);

    // Auto-save index every block for durability (protect against crashes/force-kill)
    saveBlockIndex(nullptr);
    dirty_indices_.clear();
    if (block_store_) {
        block_store_->flush();
    }

    // Add event for deferred callback (will be invoked after mutex is released)
    events.push_back({BlockEvent::CONNECTED, block, index});

    return true;
}

bool Chain::disconnectBlock(const Block& block, BlockIndex* index, std::vector<BlockEvent>& events) {
    LOG_DEBUG("Disconnecting block {} at height {}",
              crypto::Keccak256::toHex(index->hash).substr(0, 16), index->height);

    // Update status
    index->status = static_cast<BlockStatus>(
        static_cast<uint32_t>(index->status) & ~static_cast<uint32_t>(BlockStatus::ON_MAIN_CHAIN)
    );

    // Remove from height index
    height_index_.erase(index->height);

    // Remove transactions from index
    {
        std::lock_guard<std::mutex> tx_lock(tx_index_mutex_);
        for (const auto& tx : block.transactions) {
            tx_index_.erase(tx.getTxId());
        }
    }

    dirty_indices_.insert(index->hash);

    // Add event for deferred callback (will be invoked after mutex is released)
    events.push_back({BlockEvent::DISCONNECTED, block, index});

    return true;
}

void Chain::invalidateBlock(BlockIndex* index) {
    std::vector<BlockEvent> pending_events;
    const BlockIndex* new_tip = nullptr;

    {
        std::unique_lock<std::mutex> lock(index_mutex_);
        index->status = index->status | BlockStatus::FAILED;
        dirty_indices_.insert(index->hash);
        activateBestChain(pending_events, new_tip);
    }

    // Invoke callbacks after mutex release
    for (const auto& event : pending_events) {
        if (event.type == BlockEvent::CONNECTED && on_block_connected_) {
            on_block_connected_(event.block, event.index);
        } else if (event.type == BlockEvent::DISCONNECTED && on_block_disconnected_) {
            on_block_disconnected_(event.block, event.index);
        }
    }
    if (new_tip && on_new_tip_) {
        on_new_tip_(new_tip);
    }
}

void Chain::reconsiderBlock(BlockIndex* index) {
    std::vector<BlockEvent> pending_events;
    const BlockIndex* new_tip = nullptr;

    {
        std::unique_lock<std::mutex> lock(index_mutex_);
        index->status = static_cast<BlockStatus>(
            static_cast<uint32_t>(index->status) & ~static_cast<uint32_t>(BlockStatus::FAILED)
        );
        dirty_indices_.insert(index->hash);
        activateBestChain(pending_events, new_tip);
    }

    // Invoke callbacks after mutex release
    for (const auto& event : pending_events) {
        if (event.type == BlockEvent::CONNECTED && on_block_connected_) {
            on_block_connected_(event.block, event.index);
        } else if (event.type == BlockEvent::DISCONNECTED && on_block_disconnected_) {
            on_block_disconnected_(event.block, event.index);
        }
    }
    if (new_tip && on_new_tip_) {
        on_new_tip_(new_tip);
    }
}

void Chain::buildSkipList(BlockIndex* index) {
    if (index->height < 2) {
        index->skip = nullptr;
        return;
    }

    int skip_height = getSkipHeight(index->height);
    index->skip = index->prev ? index->prev->getAncestor(skip_height) : nullptr;
}

int Chain::getSkipHeight(int height) const {
    return ftc::chain::getSkipHeight(height);
}

int64_t Chain::getMedianTimePast(const BlockIndex* index) const {
    std::vector<int64_t> times;
    times.reserve(params_.median_time_span);

    const BlockIndex* walk = index;
    for (uint32_t i = 0; i < params_.median_time_span && walk; i++) {
        times.push_back(walk->timestamp);
        walk = walk->prev;
    }

    std::sort(times.begin(), times.end());
    return times[times.size() / 2];
}

std::vector<crypto::Hash256> Chain::getBlockLocator(const BlockIndex* index) const {
    std::lock_guard<std::mutex> lock(index_mutex_);

    std::vector<crypto::Hash256> locator;

    if (index == nullptr) {
        index = tip_;
    }

    if (index == nullptr) {
        return locator;
    }

    int step = 1;
    const BlockIndex* walk = index;

    while (walk) {
        locator.push_back(walk->hash);

        // Exponentially skip back
        for (int i = 0; i < step && walk; i++) {
            walk = walk->prev;
        }

        if (locator.size() > 10) {
            step *= 2;
        }
    }

    return locator;
}

const BlockIndex* Chain::findForkPoint(const std::vector<crypto::Hash256>& locator) const {
    std::lock_guard<std::mutex> lock(index_mutex_);

    for (const auto& hash : locator) {
        auto it = block_index_.find(hash);
        if (it != block_index_.end() &&
            hasFlag(it->second->status, BlockStatus::ON_MAIN_CHAIN)) {
            return it->second.get();
        }
    }

    return genesis_;
}

std::vector<BlockHeader> Chain::getHeaders(const std::vector<crypto::Hash256>& locator,
                                            const crypto::Hash256& stop_hash,
                                            size_t max_headers) const {
    std::lock_guard<std::mutex> lock(index_mutex_);

    std::vector<BlockHeader> headers;

    const BlockIndex* start = findForkPoint(locator);
    if (!start) {
        return headers;
    }

    // Start from the block after fork point
    int32_t height = start->height + 1;

    while (headers.size() < max_headers) {
        auto it = height_index_.find(height);
        if (it == height_index_.end()) {
            break;
        }

        const BlockIndex* index = it->second;

        BlockHeader header;
        header.version = index->version;
        header.prev_hash = index->prev_hash;
        header.timestamp = index->timestamp;
        header.bits = index->bits;
        header.nonce = index->nonce;

        headers.push_back(header);

        if (index->hash == stop_hash) {
            break;
        }

        height++;
    }

    return headers;
}

std::vector<ChainTip> Chain::getChainTips() const {
    std::lock_guard<std::mutex> lock(index_mutex_);

    std::set<BlockIndex*> tips;
    std::set<BlockIndex*> has_children;

    // Find all blocks that have children
    for (auto& p : block_index_) {
        if (p.second->prev) {
            has_children.insert(p.second->prev);
        }
    }

    // Blocks without children are tips
    for (auto& p : block_index_) {
        if (has_children.count(p.second.get()) == 0) {
            tips.insert(p.second.get());
        }
    }

    std::vector<ChainTip> result;
    for (auto* index : tips) {
        ChainTip tip;
        tip.hash = index->hash;
        tip.height = index->height;
        tip.work = index->chain_work;
        tip.is_active = (index == tip_);
        result.push_back(tip);
    }

    return result;
}

uint64_t Chain::getBlockReward(int32_t height) const {
    int halvings = height / params_.halving_interval;
    if (halvings >= 64) {
        return 0;
    }
    return params_.initial_reward >> halvings;
}

uint32_t Chain::getNextWorkRequired(const BlockIndex* prev, const BlockHeader* header) const {
    if (prev == nullptr) {
        // Genesis block
        return 0x1d00ffff;  // Initial difficulty
    }

    // Check if difficulty adjustment
    if ((prev->height + 1) % params_.difficulty_adjustment_interval != 0) {
        return prev->bits;
    }

    // Get first block of this interval
    int32_t first_height = prev->height - (params_.difficulty_adjustment_interval - 1);
    const BlockIndex* first = prev->getAncestor(first_height);
    if (!first) {
        return prev->bits;
    }

    // Calculate actual timespan
    int64_t actual_timespan = prev->timestamp - first->timestamp;

    // Limit adjustment
    int64_t target_timespan = params_.block_time * params_.difficulty_adjustment_interval;
    if (actual_timespan < target_timespan / 4) {
        actual_timespan = target_timespan / 4;
    }
    if (actual_timespan > target_timespan * 4) {
        actual_timespan = target_timespan * 4;
    }

    // Calculate new target
    // Note: Hash256 and uint256_t are both std::array<uint8_t, 32>
    crypto::Hash256 target_hash = BlockHeader::bitsToTarget(prev->bits);
    uint256_t target;
    std::copy(target_hash.begin(), target_hash.end(), target.begin());

    // Multiply by actual time, divide by target time
    target = mul256_64(target, static_cast<uint64_t>(actual_timespan));
    target = div256_64(target, static_cast<uint64_t>(target_timespan));

    // Ensure target doesn't exceed maximum
    crypto::Hash256 max_target_hash = BlockHeader::bitsToTarget(0x1d00ffff);
    uint256_t max_target;
    std::copy(max_target_hash.begin(), max_target_hash.end(), max_target.begin());
    if (compare256(target, max_target) > 0) {
        target = max_target;
    }

    crypto::Hash256 result;
    std::copy(target.begin(), target.end(), result.begin());
    return BlockHeader::targetToBits(result);
}

uint256_t Chain::getBlockProof(uint32_t bits) const {
    crypto::Hash256 target_hash = BlockHeader::bitsToTarget(bits);
    uint256_t target;
    std::copy(target_hash.begin(), target_hash.end(), target.begin());

    if (isZero256(target)) {
        return uint256_t{};
    }

    // Work = 2^256 / (target + 1)
    // Simplified approximation: return inverse scaled
    // For now, just return a simple difficulty estimate based on leading zeros
    uint256_t result{};
    int leading_zeros = 0;
    for (int i = 31; i >= 0; i--) {
        if (target[i] == 0) {
            leading_zeros += 8;
        } else {
            // Count leading zeros in this byte
            uint8_t b = target[i];
            while ((b & 0x80) == 0) {
                leading_zeros++;
                b <<= 1;
            }
            break;
        }
    }

    // Set result to approximate work (2^leading_zeros)
    int byte_idx = leading_zeros / 8;
    int bit_idx = leading_zeros % 8;
    if (byte_idx < 32) {
        result[byte_idx] = static_cast<uint8_t>(1 << bit_idx);
    }

    return result;
}

Block Chain::createGenesisBlock() const {
    // Use the canonical implementation from block.cpp
    return ftc::chain::createGenesisBlock();
}

bool Chain::loadBlockIndex() {
    std::string index_path = data_dir_ + "/index/chain.dat";

    if (!fs::exists(index_path)) {
        return false;
    }

    std::ifstream file(index_path, std::ios::binary);
    if (!file) {
        return false;
    }

    uint32_t count;
    file.read(reinterpret_cast<char*>(&count), sizeof(count));

    for (uint32_t i = 0; i < count; i++) {
        auto index = std::make_unique<BlockIndex>();

        file.read(reinterpret_cast<char*>(index->hash.data()), 32);
        file.read(reinterpret_cast<char*>(index->prev_hash.data()), 32);
        file.read(reinterpret_cast<char*>(index->merkle_root.data()), 32);
        file.read(reinterpret_cast<char*>(&index->height), sizeof(index->height));
        file.read(reinterpret_cast<char*>(&index->version), sizeof(index->version));
        file.read(reinterpret_cast<char*>(&index->timestamp), sizeof(index->timestamp));
        file.read(reinterpret_cast<char*>(&index->bits), sizeof(index->bits));
        file.read(reinterpret_cast<char*>(&index->nonce), sizeof(index->nonce));
        file.read(reinterpret_cast<char*>(&index->status), sizeof(index->status));
        file.read(reinterpret_cast<char*>(&index->file_pos), sizeof(index->file_pos));
        file.read(reinterpret_cast<char*>(&index->tx_count), sizeof(index->tx_count));
        file.read(reinterpret_cast<char*>(&index->total_tx), sizeof(index->total_tx));
        file.read(reinterpret_cast<char*>(index->chain_work.data()), 32);

        block_index_[index->hash] = std::move(index);
    }

    // Link prev pointers and find tips
    for (auto& p : block_index_) {
        if (p.second->prev_hash != crypto::ZERO_HASH) {
            auto prev_it = block_index_.find(p.second->prev_hash);
            if (prev_it != block_index_.end()) {
                p.second->prev = prev_it->second.get();
            }
        } else {
            genesis_ = p.second.get();
        }

        buildSkipList(p.second.get());

        // Build height index for main chain
        if (hasFlag(p.second->status, BlockStatus::ON_MAIN_CHAIN)) {
            height_index_[p.second->height] = p.second.get();
        }
    }

    // Find tip (highest main chain block)
    for (auto& p : height_index_) {
        if (tip_ == nullptr || p.first > tip_->height) {
            tip_ = p.second;
        }
    }

    // Build transaction index from main chain blocks
    if (tip_) {
        LOG_INFO("Building transaction index from {} blocks...", height_index_.size());
        int indexed = 0;
        for (const auto& [height, idx] : height_index_) {
            Block block;
            if (block_store_->readBlock(idx->file_pos, block)) {
                std::lock_guard<std::mutex> tx_lock(tx_index_mutex_);
                for (uint32_t i = 0; i < block.transactions.size(); ++i) {
                    crypto::Hash256 txid = block.transactions[i].getTxId();
                    TxIndex tx_idx;
                    tx_idx.block_hash = idx->hash;
                    tx_idx.tx_pos = i;
                    tx_index_[txid] = tx_idx;
                    indexed++;
                }
            }
        }
        LOG_INFO("Transaction index built: {} transactions indexed", indexed);
    }

    return tip_ != nullptr;
}

bool Chain::saveBlockIndex(const BlockIndex* index) {
    // Save entire block index to file
    std::string index_path = data_dir_ + "/index/chain.dat";

    std::ofstream file(index_path, std::ios::binary);
    if (!file) {
        LOG_ERROR("Failed to open chain index for writing: {}", index_path);
        return false;
    }

    uint32_t count = static_cast<uint32_t>(block_index_.size());
    file.write(reinterpret_cast<const char*>(&count), sizeof(count));

    for (const auto& p : block_index_) {
        const BlockIndex* idx = p.second.get();

        file.write(reinterpret_cast<const char*>(idx->hash.data()), 32);
        file.write(reinterpret_cast<const char*>(idx->prev_hash.data()), 32);
        file.write(reinterpret_cast<const char*>(idx->merkle_root.data()), 32);
        file.write(reinterpret_cast<const char*>(&idx->height), sizeof(idx->height));
        file.write(reinterpret_cast<const char*>(&idx->version), sizeof(idx->version));
        file.write(reinterpret_cast<const char*>(&idx->timestamp), sizeof(idx->timestamp));
        file.write(reinterpret_cast<const char*>(&idx->bits), sizeof(idx->bits));
        file.write(reinterpret_cast<const char*>(&idx->nonce), sizeof(idx->nonce));
        file.write(reinterpret_cast<const char*>(&idx->status), sizeof(idx->status));
        file.write(reinterpret_cast<const char*>(&idx->file_pos), sizeof(idx->file_pos));
        file.write(reinterpret_cast<const char*>(&idx->tx_count), sizeof(idx->tx_count));
        file.write(reinterpret_cast<const char*>(&idx->total_tx), sizeof(idx->total_tx));
        file.write(reinterpret_cast<const char*>(idx->chain_work.data()), 32);
    }

    file.flush();
    LOG_DEBUG("Saved block index with {} entries", count);
    return file.good();
}

bool Chain::loadBlock(const crypto::Hash256& hash, Block& block) const {
    auto it = block_index_.find(hash);
    if (it == block_index_.end()) {
        return false;
    }

    return block_store_->readBlock(it->second->file_pos, block);
}

bool Chain::saveBlock(const Block& block, uint64_t& file_pos) {
    return block_store_->writeBlock(block, file_pos);
}

// ============================================================================
// BlockStore implementation
// ============================================================================

BlockStore::BlockStore(const std::string& path) : path_(path) {}

BlockStore::~BlockStore() {
    close();
}

bool BlockStore::open() {
    std::string file_path = path_ + "/blocks.dat";

    block_file_ = fopen(file_path.c_str(), "a+b");
    if (!block_file_) {
        block_file_ = fopen(file_path.c_str(), "w+b");
    }

    if (!block_file_) {
        return false;
    }

    // Get current file size
    fseek(block_file_, 0, SEEK_END);
    write_pos_ = static_cast<uint64_t>(ftell(block_file_));

    return true;
}

void BlockStore::close() {
    if (block_file_) {
        fclose(block_file_);
        block_file_ = nullptr;
    }
}

bool BlockStore::writeBlock(const Block& block, uint64_t& pos) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!block_file_) return false;

    std::vector<uint8_t> data = block.serialize();

    // Write size first
    uint32_t size = static_cast<uint32_t>(data.size());

    pos = write_pos_;

    fseek(block_file_, static_cast<long>(write_pos_), SEEK_SET);
    if (fwrite(&size, sizeof(size), 1, block_file_) != 1) {
        return false;
    }
    if (fwrite(data.data(), 1, data.size(), block_file_) != data.size()) {
        return false;
    }

    write_pos_ += sizeof(size) + data.size();

    return true;
}

bool BlockStore::readBlock(uint64_t pos, Block& block) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!block_file_) return false;

    fseek(block_file_, static_cast<long>(pos), SEEK_SET);

    uint32_t size;
    if (fread(&size, sizeof(size), 1, block_file_) != 1) {
        return false;
    }

    std::vector<uint8_t> data(size);
    if (fread(data.data(), 1, size, block_file_) != size) {
        return false;
    }

    auto result = Block::deserialize(data.data(), data.size());
    if (!result) {
        return false;
    }
    block = std::move(*result);
    return true;
}

bool BlockStore::writeUndo(int32_t height, const std::vector<uint8_t>& data) {
    std::string file_path = path_ + "/undo_" + std::to_string(height) + ".dat";
    std::ofstream file(file_path, std::ios::binary);
    if (!file) return false;
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

bool BlockStore::readUndo(int32_t height, std::vector<uint8_t>& data) const {
    std::string file_path = path_ + "/undo_" + std::to_string(height) + ".dat";
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file) return false;

    auto size = file.tellg();
    file.seekg(0);

    data.resize(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(data.data()), size);

    return true;
}

void BlockStore::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (block_file_) {
        fflush(block_file_);
    }
}

// ============================================================================
// Chain - Additional implementations
// ============================================================================

Chain::Chain(const Config& config, Consensus* consensus, UTXOSet* utxo_set)
    : consensus_ext_(consensus), utxo_set_ext_(utxo_set) {
    data_dir_ = config.data_dir;
}

bool Chain::initialize() {
    return load(data_dir_);
}

void Chain::flush() {
    if (block_store_) {
        block_store_->flush();
    }
    // Save block index if there are changes
    if (!dirty_indices_.empty()) {
        saveBlockIndex(nullptr);  // Save all blocks
        dirty_indices_.clear();
    }
}

crypto::Hash256 Chain::getGenesisHash() const {
    return params_.genesis_hash;
}

std::optional<int32_t> Chain::getBlockHeight(const crypto::Hash256& hash) const {
    std::lock_guard<std::mutex> lock(index_mutex_);
    auto it = block_index_.find(hash);
    if (it != block_index_.end()) {
        return it->second->height;
    }
    return std::nullopt;
}

std::optional<crypto::Hash256> Chain::getBlockHashAtHeight(int32_t height) const {
    std::lock_guard<std::mutex> lock(index_mutex_);
    auto it = height_index_.find(height);
    if (it != height_index_.end()) {
        return it->second->hash;
    }
    return std::nullopt;
}

bool Chain::hasTx(const crypto::Hash256& txid) const {
    std::lock_guard<std::mutex> lock(tx_index_mutex_);
    return tx_index_.count(txid) > 0;
}

std::optional<Transaction> Chain::getTx(const crypto::Hash256& txid) const {
    TxIndex tx_idx;
    {
        std::lock_guard<std::mutex> lock(tx_index_mutex_);
        auto it = tx_index_.find(txid);
        if (it == tx_index_.end()) {
            return std::nullopt;
        }
        tx_idx = it->second;
    }

    // Load the block containing this transaction
    auto block_opt = getBlock(tx_idx.block_hash);
    if (!block_opt) {
        return std::nullopt;
    }

    // Return the specific transaction
    if (tx_idx.tx_pos < block_opt->transactions.size()) {
        return block_opt->transactions[tx_idx.tx_pos];
    }

    return std::nullopt;
}

} // namespace chain
} // namespace ftc
