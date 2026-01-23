#include "storage/block_store.h"
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace fs = std::filesystem;

namespace ftc {
namespace storage {

//-----------------------------------------------------------------------------
// BlockStore implementation
//-----------------------------------------------------------------------------

BlockStore::BlockStore(const Config& config) : config_(config) {}

BlockStore::~BlockStore() {
    close();
}

bool BlockStore::open() {
    if (opened_) {
        return true;
    }

    // Create directories if needed
    std::string blocks_dir = config_.data_dir + "/blocks";
    std::string index_dir = config_.data_dir + "/index";

    try {
        fs::create_directories(blocks_dir);
        fs::create_directories(index_dir);
    } catch (...) {
        return false;
    }

    // Open index database
    Options db_options;
    db_options.create_if_missing = true;
    db_options.write_buffer_size = 4 * 1024 * 1024;  // 4 MB

    std::unique_ptr<Database> db;
    Status s = Database::open(db_options, index_dir, &db);
    if (!s.ok()) {
        return false;
    }
    index_db_ = std::move(db);

    // Load metadata
    std::string value;
    ReadOptions read_opts;

    // Load current file number
    s = index_db_->get(read_opts, metaKey("current_file"), &value);
    if (s.ok() && value.size() >= 8) {
        current_file_ = decodeFixed64(value.data());
    }

    // Load current position
    s = index_db_->get(read_opts, metaKey("current_pos"), &value);
    if (s.ok() && value.size() >= 8) {
        current_pos_ = decodeFixed64(value.data());
    }

    // Load best block
    s = index_db_->get(read_opts, metaKey("best_hash"), &value);
    if (s.ok() && value.size() >= 32) {
        std::memcpy(best_block_hash_.data(), value.data(), 32);
    }

    s = index_db_->get(read_opts, metaKey("best_height"), &value);
    if (s.ok() && value.size() >= 4) {
        best_height_ = static_cast<int32_t>(decodeFixed32(value.data()));
    }

    // Load file info
    for (uint64_t i = 0; i <= current_file_; i++) {
        s = index_db_->get(read_opts, fileInfoKey(i), &value);
        if (s.ok() && value.size() >= 56) {
            BlockFileInfo info;
            const char* p = value.data();
            info.file_number = decodeFixed64(p); p += 8;
            info.num_blocks = decodeFixed64(p); p += 8;
            info.size = decodeFixed64(p); p += 8;
            info.height_first = decodeFixed64(p); p += 8;
            info.height_last = decodeFixed64(p); p += 8;
            info.time_first = static_cast<int64_t>(decodeFixed64(p)); p += 8;
            info.time_last = static_cast<int64_t>(decodeFixed64(p));

            file_info_[i] = info;
            total_size_ += info.size;
        }
    }

    opened_ = true;
    return true;
}

void BlockStore::close() {
    if (!opened_) {
        return;
    }

    // Save metadata
    if (index_db_) {
        WriteOptions write_opts;
        write_opts.sync = true;

        index_db_->put(write_opts, metaKey("current_file"), encodeFixed64(current_file_));
        index_db_->put(write_opts, metaKey("current_pos"), encodeFixed64(current_pos_));
        index_db_->put(write_opts, metaKey("best_hash"),
                      Slice(reinterpret_cast<const char*>(best_block_hash_.data()), 32));
        index_db_->put(write_opts, metaKey("best_height"),
                      encodeFixed32(static_cast<uint32_t>(best_height_)));

        // Save file info
        for (const auto& pair : file_info_) {
            std::string value;
            value += encodeFixed64(pair.second.file_number);
            value += encodeFixed64(pair.second.num_blocks);
            value += encodeFixed64(pair.second.size);
            value += encodeFixed64(pair.second.height_first);
            value += encodeFixed64(pair.second.height_last);
            value += encodeFixed64(static_cast<uint64_t>(pair.second.time_first));
            value += encodeFixed64(static_cast<uint64_t>(pair.second.time_last));
            index_db_->put(write_opts, fileInfoKey(pair.first), value);
        }
    }

    // Close file handles
    std::lock_guard<std::mutex> lock(file_mutex_);
    for (auto& pair : block_files_) {
        if (pair.second) {
            fclose(pair.second);
        }
    }
    block_files_.clear();

    for (auto& pair : undo_files_) {
        if (pair.second) {
            fclose(pair.second);
        }
    }
    undo_files_.clear();

    index_db_.reset();
    opened_ = false;
}

bool BlockStore::writeBlock(const chain::Block& block, BlockPos& pos) {
    if (!opened_) {
        return false;
    }

    // Serialize block
    std::vector<uint8_t> data = block.serialize();

    // Allocate space
    if (!allocateSpace(data.size(), pos)) {
        return false;
    }

    // Open file for writing
    std::lock_guard<std::mutex> lock(file_mutex_);
    FILE* file = openBlockFile(pos.file_number, false);
    if (!file) {
        return false;
    }

    // Seek to position
    if (fseek(file, static_cast<long>(pos.offset), SEEK_SET) != 0) {
        return false;
    }

    // Write magic (4 bytes) + size (4 bytes) + data
    uint32_t magic = 0x46544342;  // "FTCB"
    uint32_t size = static_cast<uint32_t>(data.size());

    if (fwrite(&magic, 4, 1, file) != 1) return false;
    if (fwrite(&size, 4, 1, file) != 1) return false;
    if (fwrite(data.data(), 1, data.size(), file) != data.size()) return false;

    fflush(file);

    // Update file info
    auto& info = file_info_[pos.file_number];
    info.num_blocks++;
    info.size = current_pos_;

    total_size_ += 8 + data.size();

    return true;
}

bool BlockStore::readBlock(const BlockPos& pos, chain::Block& block) const {
    if (!opened_ || pos.isNull()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(file_mutex_);
    FILE* file = const_cast<BlockStore*>(this)->openBlockFile(pos.file_number, true);
    if (!file) {
        return false;
    }

    // Seek to position
    if (fseek(file, static_cast<long>(pos.offset), SEEK_SET) != 0) {
        return false;
    }

    // Read magic and size
    uint32_t magic, size;
    if (fread(&magic, 4, 1, file) != 1) return false;
    if (fread(&size, 4, 1, file) != 1) return false;

    if (magic != 0x46544342) {
        return false;  // Invalid magic
    }

    // Read block data
    std::vector<uint8_t> data(size);
    if (fread(data.data(), 1, size, file) != size) {
        return false;
    }

    // Deserialize
    auto result = chain::Block::deserialize(data);
    if (!result) {
        return false;
    }
    block = std::move(*result);
    return true;
}

bool BlockStore::hasBlock(const crypto::Hash256& hash) const {
    if (!opened_) {
        return false;
    }

    std::string value;
    ReadOptions opts;
    Status s = index_db_->get(opts, blockIndexKey(hash), &value);
    return s.ok();
}

bool BlockStore::writeBlockIndex(const crypto::Hash256& hash, const BlockPos& pos,
                                 int32_t height, const crypto::Hash256& prev_hash) {
    if (!opened_) {
        return false;
    }

    // Encode value: file_number (8) + offset (8) + size (8) + height (4) + prev_hash (32)
    std::string value;
    value += encodeFixed64(pos.file_number);
    value += encodeFixed64(pos.offset);
    value += encodeFixed64(pos.size);
    value += encodeFixed32(static_cast<uint32_t>(height));
    value.append(reinterpret_cast<const char*>(prev_hash.data()), 32);

    WriteOptions opts;
    Status s = index_db_->put(opts, blockIndexKey(hash), value);
    return s.ok();
}

bool BlockStore::readBlockIndex(const crypto::Hash256& hash, BlockPos& pos,
                                int32_t& height, crypto::Hash256& prev_hash) const {
    if (!opened_) {
        return false;
    }

    std::string value;
    ReadOptions opts;
    Status s = index_db_->get(opts, blockIndexKey(hash), &value);
    if (!s.ok() || value.size() < 60) {
        return false;
    }

    const char* p = value.data();
    pos.file_number = decodeFixed64(p); p += 8;
    pos.offset = decodeFixed64(p); p += 8;
    pos.size = decodeFixed64(p); p += 8;
    height = static_cast<int32_t>(decodeFixed32(p)); p += 4;
    std::memcpy(prev_hash.data(), p, 32);

    return true;
}

bool BlockStore::writeUndoData(int32_t height, const std::vector<uint8_t>& undo_data) {
    if (!opened_) {
        return false;
    }

    // Determine which file to use
    uint64_t file_num = height / 1000;  // ~1000 blocks per undo file

    std::lock_guard<std::mutex> lock(file_mutex_);
    FILE* file = openUndoFile(file_num, false);
    if (!file) {
        return false;
    }

    // Seek to end
    fseek(file, 0, SEEK_END);

    // Write: height (4) + size (4) + data
    uint32_t h = static_cast<uint32_t>(height);
    uint32_t size = static_cast<uint32_t>(undo_data.size());

    if (fwrite(&h, 4, 1, file) != 1) return false;
    if (fwrite(&size, 4, 1, file) != 1) return false;
    if (fwrite(undo_data.data(), 1, size, file) != size) return false;

    fflush(file);
    return true;
}

bool BlockStore::readUndoData(int32_t height, std::vector<uint8_t>& undo_data) const {
    if (!opened_) {
        return false;
    }

    // Determine file
    uint64_t file_num = height / 1000;

    std::lock_guard<std::mutex> lock(file_mutex_);
    FILE* file = const_cast<BlockStore*>(this)->openUndoFile(file_num, true);
    if (!file) {
        return false;
    }

    // Scan for the height
    fseek(file, 0, SEEK_SET);
    while (!feof(file)) {
        uint32_t h, size;
        if (fread(&h, 4, 1, file) != 1) break;
        if (fread(&size, 4, 1, file) != 1) break;

        if (static_cast<int32_t>(h) == height) {
            undo_data.resize(size);
            if (fread(undo_data.data(), 1, size, file) == size) {
                return true;
            }
            return false;
        }

        // Skip this entry
        fseek(file, size, SEEK_CUR);
    }

    return false;
}

bool BlockStore::writeTxIndex(const crypto::Hash256& txid, const TxPos& pos) {
    if (!opened_) {
        return false;
    }

    std::string value;
    value += encodeFixed64(pos.block_pos.file_number);
    value += encodeFixed64(pos.block_pos.offset);
    value += encodeFixed64(pos.block_pos.size);
    value += encodeFixed32(pos.tx_index);
    value += encodeFixed32(pos.tx_offset);

    WriteOptions opts;
    Status s = index_db_->put(opts, txIndexKey(txid), value);
    return s.ok();
}

bool BlockStore::readTxIndex(const crypto::Hash256& txid, TxPos& pos) const {
    if (!opened_) {
        return false;
    }

    std::string value;
    ReadOptions opts;
    Status s = index_db_->get(opts, txIndexKey(txid), &value);
    if (!s.ok() || value.size() < 32) {
        return false;
    }

    const char* p = value.data();
    pos.block_pos.file_number = decodeFixed64(p); p += 8;
    pos.block_pos.offset = decodeFixed64(p); p += 8;
    pos.block_pos.size = decodeFixed64(p); p += 8;
    pos.tx_index = decodeFixed32(p); p += 4;
    pos.tx_offset = decodeFixed32(p);

    return true;
}

bool BlockStore::hasTx(const crypto::Hash256& txid) const {
    if (!opened_) {
        return false;
    }

    std::string value;
    ReadOptions opts;
    Status s = index_db_->get(opts, txIndexKey(txid), &value);
    return s.ok();
}

std::optional<chain::Block> BlockStore::getBlock(const crypto::Hash256& hash) const {
    BlockPos pos;
    int32_t height;
    crypto::Hash256 prev_hash;

    if (!readBlockIndex(hash, pos, height, prev_hash)) {
        return std::nullopt;
    }

    chain::Block block;
    if (!readBlock(pos, block)) {
        return std::nullopt;
    }

    return block;
}

std::optional<BlockPos> BlockStore::getBlockPos(const crypto::Hash256& hash) const {
    BlockPos pos;
    int32_t height;
    crypto::Hash256 prev_hash;

    if (!readBlockIndex(hash, pos, height, prev_hash)) {
        return std::nullopt;
    }

    return pos;
}

crypto::Hash256 BlockStore::getBestBlockHash() const {
    return best_block_hash_;
}

int32_t BlockStore::getBestHeight() const {
    return best_height_;
}

bool BlockStore::setBestBlock(const crypto::Hash256& hash, int32_t height) {
    if (!opened_) {
        return false;
    }

    best_block_hash_ = hash;
    best_height_ = height;

    WriteOptions opts;
    index_db_->put(opts, metaKey("best_hash"),
                  Slice(reinterpret_cast<const char*>(hash.data()), 32));
    index_db_->put(opts, metaKey("best_height"),
                  encodeFixed32(static_cast<uint32_t>(height)));

    return true;
}

void BlockStore::flush() {
    if (!opened_) {
        return;
    }

    std::lock_guard<std::mutex> lock(file_mutex_);
    for (auto& pair : block_files_) {
        if (pair.second) {
            fflush(pair.second);
        }
    }
    for (auto& pair : undo_files_) {
        if (pair.second) {
            fflush(pair.second);
        }
    }
}

uint64_t BlockStore::getTotalSize() const {
    return total_size_;
}

size_t BlockStore::getNumFiles() const {
    return file_info_.size();
}

void BlockStore::prune(uint64_t target_size) {
    // Remove old block files until we're under target_size
    if (!opened_ || !config_.prune) {
        return;
    }

    while (total_size_ > target_size && !file_info_.empty()) {
        auto it = file_info_.begin();
        uint64_t file_num = it->first;

        // Don't prune recent files
        if (file_num >= current_file_) {
            break;
        }

        // Remove file
        std::string path = blockFilePath(file_num);
        fs::remove(path);

        total_size_ -= it->second.size;
        file_info_.erase(it);
    }
}

void BlockStore::pruneToHeight(int32_t height) {
    // Remove blocks below given height
    if (!opened_ || !config_.prune) {
        return;
    }

    for (auto it = file_info_.begin(); it != file_info_.end();) {
        if (static_cast<int32_t>(it->second.height_last) < height) {
            std::string path = blockFilePath(it->first);
            fs::remove(path);

            total_size_ -= it->second.size;
            it = file_info_.erase(it);
        } else {
            ++it;
        }
    }
}

bool BlockStore::forEachBlock(std::function<bool(const crypto::Hash256& hash,
                                                 int32_t height,
                                                 const BlockPos& pos)> callback) const {
    if (!opened_) {
        return false;
    }

    // Create iterator over block index
    ReadOptions opts;
    auto it = index_db_->newIterator(opts);

    std::string prefix = "b";  // Block index prefix
    it->seek(Slice(prefix));

    while (it->valid()) {
        Slice key = it->key();
        if (key.size() < 33 || key.data()[0] != 'b') {
            break;
        }

        // Extract hash from key
        crypto::Hash256 hash;
        std::memcpy(hash.data(), key.data() + 1, 32);

        // Decode value
        Slice value = it->value();
        if (value.size() >= 60) {
            const char* p = value.data();
            BlockPos pos;
            pos.file_number = decodeFixed64(p); p += 8;
            pos.offset = decodeFixed64(p); p += 8;
            pos.size = decodeFixed64(p); p += 8;
            int32_t height = static_cast<int32_t>(decodeFixed32(p));

            if (!callback(hash, height, pos)) {
                return false;
            }
        }

        it->next();
    }

    return true;
}

std::string BlockStore::blockFilePath(uint64_t file_num) const {
    std::ostringstream oss;
    oss << config_.data_dir << "/blocks/blk"
        << std::setfill('0') << std::setw(5) << file_num << ".dat";
    return oss.str();
}

std::string BlockStore::undoFilePath(uint64_t file_num) const {
    std::ostringstream oss;
    oss << config_.data_dir << "/blocks/rev"
        << std::setfill('0') << std::setw(5) << file_num << ".dat";
    return oss.str();
}

FILE* BlockStore::openBlockFile(uint64_t file_num, bool read_only) {
    auto it = block_files_.find(file_num);
    if (it != block_files_.end() && it->second) {
        return it->second;
    }

    std::string path = blockFilePath(file_num);
    const char* mode = read_only ? "rb" : "r+b";

    FILE* file = fopen(path.c_str(), mode);
    if (!file && !read_only) {
        // Create new file
        file = fopen(path.c_str(), "w+b");
    }

    if (file) {
        block_files_[file_num] = file;
    }

    return file;
}

FILE* BlockStore::openUndoFile(uint64_t file_num, bool read_only) {
    auto it = undo_files_.find(file_num);
    if (it != undo_files_.end() && it->second) {
        return it->second;
    }

    std::string path = undoFilePath(file_num);
    const char* mode = read_only ? "rb" : "r+b";

    FILE* file = fopen(path.c_str(), mode);
    if (!file && !read_only) {
        file = fopen(path.c_str(), "w+b");
    }

    if (file) {
        undo_files_[file_num] = file;
    }

    return file;
}

bool BlockStore::allocateSpace(uint64_t size, BlockPos& pos) {
    // Check if current file has room
    uint64_t needed = 8 + size;  // magic + size + data

    if (current_pos_ + needed > config_.max_file_size) {
        // Start new file
        current_file_++;
        current_pos_ = 0;

        // Initialize file info
        BlockFileInfo info{};
        info.file_number = current_file_;
        file_info_[current_file_] = info;
    }

    pos.file_number = current_file_;
    pos.offset = current_pos_;
    pos.size = size;

    current_pos_ += needed;

    return true;
}

std::string BlockStore::blockIndexKey(const crypto::Hash256& hash) {
    std::string key = "b";
    key.append(reinterpret_cast<const char*>(hash.data()), 32);
    return key;
}

std::string BlockStore::txIndexKey(const crypto::Hash256& txid) {
    std::string key = "t";
    key.append(reinterpret_cast<const char*>(txid.data()), 32);
    return key;
}

std::string BlockStore::fileInfoKey(uint64_t file_num) {
    return "f" + encodeFixed64(file_num);
}

std::string BlockStore::metaKey(const std::string& name) {
    return "m" + name;
}

//-----------------------------------------------------------------------------
// BlockBatch implementation
//-----------------------------------------------------------------------------

BlockBatch::BlockBatch(BlockStore& store) : store_(store) {}

BlockBatch::~BlockBatch() {
    if (!committed_) {
        abort();
    }
}

void BlockBatch::addBlock(const chain::Block& block, int32_t height) {
    blocks_.emplace_back(block, height);
}

bool BlockBatch::commit() {
    if (committed_) {
        return false;
    }

    for (const auto& pair : blocks_) {
        const chain::Block& block = pair.first;
        int32_t height = pair.second;

        BlockPos pos;
        if (!store_.writeBlock(block, pos)) {
            return false;
        }

        crypto::Hash256 hash = block.getHash();
        if (!store_.writeBlockIndex(hash, pos, height, block.header.prev_hash)) {
            return false;
        }
    }

    committed_ = true;
    return true;
}

void BlockBatch::abort() {
    blocks_.clear();
}

//-----------------------------------------------------------------------------
// BlockReader implementation
//-----------------------------------------------------------------------------

BlockReader::BlockReader(const BlockStore& store) : store_(store) {}

BlockReader::~BlockReader() = default;

bool BlockReader::next(chain::Block& block, crypto::Hash256& hash, int32_t& height) {
    // Simple implementation: iterate through heights
    current_height_++;

    // Need to find block at this height
    // This would require a height->hash index for efficiency
    // For now, just mark as invalid
    valid_ = false;
    at_end_ = true;

    return false;
}

bool BlockReader::seek(int32_t height) {
    current_height_ = height - 1;  // Will be incremented by next()
    valid_ = true;
    at_end_ = false;
    return true;
}

bool BlockReader::seek(const crypto::Hash256& hash) {
    BlockPos pos;
    int32_t height;
    crypto::Hash256 prev;

    if (store_.readBlockIndex(hash, pos, height, prev)) {
        current_height_ = height - 1;
        current_hash_ = hash;
        valid_ = true;
        at_end_ = false;
        return true;
    }

    valid_ = false;
    return false;
}

//-----------------------------------------------------------------------------
// UTXOStore implementation
//-----------------------------------------------------------------------------

UTXOStore::UTXOStore(const std::string& path) : path_(path) {}

UTXOStore::~UTXOStore() {
    close();
}

bool UTXOStore::open() {
    Options options;
    options.create_if_missing = true;
    options.write_buffer_size = 64 * 1024 * 1024;  // 64 MB for UTXO set

    std::unique_ptr<Database> db;
    Status s = Database::open(options, path_, &db);
    if (!s.ok()) {
        return false;
    }

    db_ = std::move(db);
    return true;
}

void UTXOStore::close() {
    if (batch_) {
        abortBatch();
    }
    db_.reset();
}

static std::string encodeUTXOKey(const UTXOStore::UTXOKey& key) {
    std::string result;
    result.append(reinterpret_cast<const char*>(key.txid.data()), 32);
    result += encodeFixed32(key.vout);
    return result;
}

static std::string encodeUTXOValue(const UTXOStore::UTXOValue& value) {
    std::string result;
    result += encodeFixed64(value.amount);
    result += encodeVarint32(static_cast<uint32_t>(value.script.size()));
    result.append(reinterpret_cast<const char*>(value.script.data()), value.script.size());
    result += encodeFixed32(static_cast<uint32_t>(value.height));
    result += static_cast<char>(value.coinbase ? 1 : 0);
    return result;
}

static bool decodeUTXOValue(const std::string& data, UTXOStore::UTXOValue& value) {
    if (data.size() < 13) return false;

    const char* p = data.data();
    const char* end = p + data.size();

    value.amount = decodeFixed64(p); p += 8;

    uint32_t script_len;
    p = getVarint32(p, end, &script_len);
    if (!p || p + script_len > end) return false;

    value.script.assign(reinterpret_cast<const uint8_t*>(p),
                        reinterpret_cast<const uint8_t*>(p) + script_len);
    p += script_len;

    if (p + 5 > end) return false;
    value.height = static_cast<int32_t>(decodeFixed32(p)); p += 4;
    value.coinbase = (*p != 0);

    return true;
}

bool UTXOStore::addUTXO(const UTXOKey& key, const UTXOValue& value) {
    if (!db_) return false;

    WriteOptions opts;
    Status s = db_->put(opts, encodeUTXOKey(key), encodeUTXOValue(value));
    return s.ok();
}

bool UTXOStore::removeUTXO(const UTXOKey& key) {
    if (!db_) return false;

    WriteOptions opts;
    Status s = db_->del(opts, encodeUTXOKey(key));
    return s.ok();
}

bool UTXOStore::getUTXO(const UTXOKey& key, UTXOValue& value) const {
    if (!db_) return false;

    std::string data;
    ReadOptions opts;
    Status s = db_->get(opts, encodeUTXOKey(key), &data);
    if (!s.ok()) return false;

    return decodeUTXOValue(data, value);
}

bool UTXOStore::hasUTXO(const UTXOKey& key) const {
    if (!db_) return false;

    std::string data;
    ReadOptions opts;
    Status s = db_->get(opts, encodeUTXOKey(key), &data);
    return s.ok();
}

void UTXOStore::startBatch() {
    if (batch_active_) {
        abortBatch();
    }
    batch_ = std::make_unique<WriteBatch>();
    batch_active_ = true;
}

void UTXOStore::addToBatch(const UTXOKey& key, const UTXOValue& value) {
    if (!batch_active_ || !batch_) return;
    batch_->put(encodeUTXOKey(key), encodeUTXOValue(value));
}

void UTXOStore::removeFromBatch(const UTXOKey& key) {
    if (!batch_active_ || !batch_) return;
    batch_->del(encodeUTXOKey(key));
}

bool UTXOStore::commitBatch() {
    if (!batch_active_ || !batch_ || !db_) {
        return false;
    }

    WriteOptions opts;
    Status s = db_->write(opts, batch_.get());

    batch_.reset();
    batch_active_ = false;

    return s.ok();
}

void UTXOStore::abortBatch() {
    batch_.reset();
    batch_active_ = false;
}

uint64_t UTXOStore::size() const {
    if (!db_) return 0;

    // Count entries (inefficient but simple)
    uint64_t count = 0;
    ReadOptions opts;
    auto it = db_->newIterator(opts);
    for (it->seekToFirst(); it->valid(); it->next()) {
        count++;
    }
    return count;
}

uint64_t UTXOStore::totalAmount() const {
    if (!db_) return 0;

    uint64_t total = 0;
    ReadOptions opts;
    auto it = db_->newIterator(opts);
    for (it->seekToFirst(); it->valid(); it->next()) {
        UTXOValue value;
        if (decodeUTXOValue(it->value().toString(), value)) {
            total += value.amount;
        }
    }
    return total;
}

bool UTXOStore::forEach(std::function<bool(const UTXOKey&, const UTXOValue&)> callback) const {
    if (!db_) return false;

    ReadOptions opts;
    auto it = db_->newIterator(opts);

    for (it->seekToFirst(); it->valid(); it->next()) {
        Slice key_slice = it->key();
        if (key_slice.size() != 36) continue;  // 32 (txid) + 4 (vout)

        UTXOKey key;
        std::memcpy(key.txid.data(), key_slice.data(), 32);
        key.vout = decodeFixed32(key_slice.data() + 32);

        UTXOValue value;
        if (!decodeUTXOValue(it->value().toString(), value)) {
            continue;
        }

        if (!callback(key, value)) {
            return false;
        }
    }

    return true;
}

} // namespace storage
} // namespace ftc
