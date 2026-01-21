#include "storage/database.h"
#include <algorithm>
#include <cstring>
#include <sstream>
#include <filesystem>
#include <thread>
#include <condition_variable>

namespace fs = std::filesystem;

namespace ftc {
namespace storage {

//-----------------------------------------------------------------------------
// Slice implementation
//-----------------------------------------------------------------------------

int Slice::compare(const Slice& other) const {
    const size_t min_len = std::min(size_, other.size_);
    int r = std::memcmp(data_, other.data_, min_len);
    if (r == 0) {
        if (size_ < other.size_) r = -1;
        else if (size_ > other.size_) r = 1;
    }
    return r;
}

//-----------------------------------------------------------------------------
// Status implementation
//-----------------------------------------------------------------------------

std::string Status::toString() const {
    std::string result;
    switch (code_) {
        case Code::OK: result = "OK"; break;
        case Code::NOT_FOUND: result = "NotFound"; break;
        case Code::CORRUPTION: result = "Corruption"; break;
        case Code::IO_ERROR: result = "IOError"; break;
        case Code::INVALID_ARG: result = "InvalidArgument"; break;
    }
    if (!message_.empty()) {
        result += ": " + message_;
    }
    return result;
}

//-----------------------------------------------------------------------------
// WriteBatch implementation
//-----------------------------------------------------------------------------

void WriteBatch::put(const Slice& key, const Slice& value) {
    Operation op;
    op.type = Operation::PUT;
    op.key = key.toString();
    op.value = value.toString();
    operations_.push_back(std::move(op));
}

void WriteBatch::del(const Slice& key) {
    Operation op;
    op.type = Operation::DELETE;
    op.key = key.toString();
    operations_.push_back(std::move(op));
}

void WriteBatch::clear() {
    operations_.clear();
}

size_t WriteBatch::approximateSize() const {
    size_t size = 12;  // Header
    for (const auto& op : operations_) {
        size += 1 + 5 + op.key.size();  // type + key_len + key
        if (op.type == Operation::PUT) {
            size += 5 + op.value.size();  // value_len + value
        }
    }
    return size;
}

//-----------------------------------------------------------------------------
// BytewiseComparator implementation
//-----------------------------------------------------------------------------

void BytewiseComparator::findShortestSeparator(std::string* start, const Slice& limit) const {
    // Find common prefix length
    size_t min_len = std::min(start->size(), limit.size());
    size_t diff_index = 0;
    while (diff_index < min_len && (*start)[diff_index] == limit.data()[diff_index]) {
        diff_index++;
    }

    if (diff_index < min_len) {
        uint8_t diff_byte = static_cast<uint8_t>((*start)[diff_index]);
        if (diff_byte < 0xff && diff_byte + 1 < static_cast<uint8_t>(limit.data()[diff_index])) {
            (*start)[diff_index]++;
            start->resize(diff_index + 1);
        }
    }
}

void BytewiseComparator::findShortSuccessor(std::string* key) const {
    // Find first byte that can be incremented
    for (size_t i = 0; i < key->size(); i++) {
        uint8_t byte = static_cast<uint8_t>((*key)[i]);
        if (byte != 0xff) {
            (*key)[i] = byte + 1;
            key->resize(i + 1);
            return;
        }
    }
}

//-----------------------------------------------------------------------------
// BloomFilter implementation
//-----------------------------------------------------------------------------

BloomFilter::BloomFilter(int bits_per_key) : bits_per_key_(bits_per_key) {
    // Calculate optimal number of hash functions
    // k = (m/n) * ln(2) where m = bits, n = keys
    k_ = static_cast<size_t>(bits_per_key * 0.69);  // 0.69 ~= ln(2)
    if (k_ < 1) k_ = 1;
    if (k_ > 30) k_ = 30;
}

// Simple hash function
static uint32_t bloomHash(const Slice& key) {
    uint32_t h = 0;
    const char* data = key.data();
    for (size_t i = 0; i < key.size(); i++) {
        h = h * 31 + static_cast<uint8_t>(data[i]);
    }
    return h;
}

void BloomFilter::createFilter(const std::vector<Slice>& keys, std::string* dst) const {
    // Calculate filter size
    size_t bits = keys.size() * bits_per_key_;
    if (bits < 64) bits = 64;  // Minimum size

    size_t bytes = (bits + 7) / 8;
    bits = bytes * 8;  // Round up to byte boundary

    dst->resize(bytes + 1);  // +1 for storing k
    char* array = &(*dst)[0];
    std::memset(array, 0, bytes);
    (*dst)[bytes] = static_cast<char>(k_);  // Store k

    // Add each key
    for (const auto& key : keys) {
        uint32_t h = bloomHash(key);
        uint32_t delta = (h >> 17) | (h << 15);  // Rotate right 17 bits

        for (size_t j = 0; j < k_; j++) {
            uint32_t bitpos = h % bits;
            array[bitpos / 8] |= (1 << (bitpos % 8));
            h += delta;
        }
    }
}

bool BloomFilter::keyMayMatch(const Slice& key, const Slice& filter) const {
    if (filter.size() < 2) return true;  // No filter, assume match

    size_t len = filter.size();
    size_t k = static_cast<uint8_t>(filter.data()[len - 1]);
    if (k > 30) {
        return true;  // Reserved for future
    }

    size_t bits = (len - 1) * 8;
    const char* array = filter.data();

    uint32_t h = bloomHash(key);
    uint32_t delta = (h >> 17) | (h << 15);

    for (size_t j = 0; j < k; j++) {
        uint32_t bitpos = h % bits;
        if ((array[bitpos / 8] & (1 << (bitpos % 8))) == 0) {
            return false;  // Definitely not present
        }
        h += delta;
    }

    return true;  // May be present
}

//-----------------------------------------------------------------------------
// MemTable implementation
//-----------------------------------------------------------------------------

bool MemTable::EntryComparator::operator()(const Entry& a, const Entry& b) const {
    int cmp = user_cmp->compare(Slice(a.key), Slice(b.key));
    if (cmp != 0) return cmp < 0;
    // If keys are equal, newer sequence numbers come first
    return a.sequence > b.sequence;
}

MemTable::MemTable(const Comparator* cmp)
    : comparator_(cmp), table_(EntryComparator{cmp}) {}

MemTable::~MemTable() = default;

void MemTable::add(uint64_t seq, const Slice& key, const Slice& value) {
    std::lock_guard<std::mutex> lock(mutex_);

    Entry entry;
    entry.sequence = seq;
    entry.deletion = false;
    entry.key = key.toString();
    entry.value = value.toString();

    table_.insert(std::move(entry));
    approximate_memory_ += key.size() + value.size() + 16;
}

void MemTable::addDeletion(uint64_t seq, const Slice& key) {
    std::lock_guard<std::mutex> lock(mutex_);

    Entry entry;
    entry.sequence = seq;
    entry.deletion = true;
    entry.key = key.toString();

    table_.insert(std::move(entry));
    approximate_memory_ += key.size() + 16;
}

bool MemTable::get(const Slice& key, std::string* value, Status* s) const {
    std::lock_guard<std::mutex> lock(mutex_);

    Entry lookup;
    lookup.sequence = UINT64_MAX;
    lookup.key = key.toString();

    auto it = table_.lower_bound(lookup);

    // Find the first entry with matching key (highest sequence number)
    while (it != table_.end() && comparator_->compare(Slice(it->key), key) == 0) {
        if (it->deletion) {
            *s = Status::NotFound();
            return true;
        }
        *value = it->value;
        *s = Status::OK();
        return true;
    }

    return false;  // Key not found in memtable
}

// MemTable iterator
class MemTableIterator : public Iterator {
public:
    explicit MemTableIterator(const std::set<MemTable::Entry, MemTable::EntryComparator>* table)
        : table_(table) {}

    bool valid() const override { return valid_; }

    void seekToFirst() override {
        it_ = table_->begin();
        valid_ = it_ != table_->end();
    }

    void seekToLast() override {
        if (table_->empty()) {
            valid_ = false;
        } else {
            it_ = --table_->end();
            valid_ = true;
        }
    }

    void seek(const Slice& target) override {
        MemTable::Entry lookup;
        lookup.sequence = UINT64_MAX;
        lookup.key = target.toString();
        it_ = table_->lower_bound(lookup);
        valid_ = it_ != table_->end();
    }

    void next() override {
        ++it_;
        valid_ = it_ != table_->end();
    }

    void prev() override {
        if (it_ == table_->begin()) {
            valid_ = false;
        } else {
            --it_;
        }
    }

    Slice key() const override {
        return Slice(it_->key);
    }

    Slice value() const override {
        return Slice(it_->value);
    }

    Status status() const override {
        return Status::OK();
    }

private:
    const std::set<MemTable::Entry, MemTable::EntryComparator>* table_;
    std::set<MemTable::Entry, MemTable::EntryComparator>::const_iterator it_;
    bool valid_ = false;
};

std::unique_ptr<Iterator> MemTable::newIterator() const {
    return std::make_unique<MemTableIterator>(&table());
}

//-----------------------------------------------------------------------------
// WriteAheadLog implementation
//-----------------------------------------------------------------------------

WriteAheadLog::WriteAheadLog(const std::string& filename) : filename_(filename) {}

WriteAheadLog::~WriteAheadLog() {
    close();
}

Status WriteAheadLog::open() {
    file_.open(filename_, std::ios::binary | std::ios::app);
    if (!file_.is_open()) {
        return Status::IOError("Failed to open log file: " + filename_);
    }
    opened_ = true;
    return Status::OK();
}

Status WriteAheadLog::addRecord(const Slice& data) {
    if (!opened_) {
        return Status::IOError("Log not opened");
    }

    // Record format: [length (4 bytes)][checksum (4 bytes)][data]
    uint32_t length = static_cast<uint32_t>(data.size());
    uint32_t checksum = crc32c(data.data(), data.size());

    file_.write(reinterpret_cast<const char*>(&length), 4);
    file_.write(reinterpret_cast<const char*>(&checksum), 4);
    file_.write(data.data(), data.size());

    if (!file_.good()) {
        return Status::IOError("Failed to write to log");
    }

    return Status::OK();
}

Status WriteAheadLog::sync() {
    if (!opened_) {
        return Status::IOError("Log not opened");
    }
    file_.flush();
    return file_.good() ? Status::OK() : Status::IOError("Sync failed");
}

void WriteAheadLog::close() {
    if (opened_) {
        file_.close();
        opened_ = false;
    }
}

Status WriteAheadLog::readLog(const std::string& filename,
                              std::function<void(const Slice& record)> callback) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return Status::IOError("Failed to open log for reading: " + filename);
    }

    while (file.good()) {
        uint32_t length, checksum;
        file.read(reinterpret_cast<char*>(&length), 4);
        if (!file.good()) break;

        file.read(reinterpret_cast<char*>(&checksum), 4);
        if (!file.good()) break;

        std::vector<char> data(length);
        file.read(data.data(), length);
        if (!file.good() && !file.eof()) break;

        // Verify checksum
        uint32_t actual_crc = crc32c(data.data(), length);
        if (actual_crc != checksum) {
            return Status::Corruption("Log record checksum mismatch");
        }

        callback(Slice(data.data(), length));
    }

    return Status::OK();
}

//-----------------------------------------------------------------------------
// SSTableBuilder implementation
//-----------------------------------------------------------------------------

SSTableBuilder::SSTableBuilder(const Options& options, const std::string& filename)
    : options_(options), filename_(filename) {

    file_.open(filename, std::ios::binary);
    if (!file_.is_open()) {
        status_ = Status::IOError("Failed to create SSTable file");
    }

    if (options.bloom_bits_per_key > 0) {
        bloom_filter_ = std::make_unique<BloomFilter>(options.bloom_bits_per_key);
    }

    restarts_.push_back(0);
}

SSTableBuilder::~SSTableBuilder() {
    if (!closed_) {
        abandon();
    }
}

Status SSTableBuilder::add(const Slice& key, const Slice& value) {
    if (!status_.ok()) return status_;

    // Add to data block with prefix compression
    if (restart_counter_ < options_.block_restart_interval) {
        // Find shared prefix with last key
        size_t shared = 0;
        size_t min_len = std::min(last_key_.size(), key.size());
        while (shared < min_len && last_key_[shared] == key.data()[shared]) {
            shared++;
        }
        size_t non_shared = key.size() - shared;

        // Encode: shared_len | non_shared_len | value_len | key_delta | value
        data_block_ += encodeVarint32(static_cast<uint32_t>(shared));
        data_block_ += encodeVarint32(static_cast<uint32_t>(non_shared));
        data_block_ += encodeVarint32(static_cast<uint32_t>(value.size()));
        data_block_.append(key.data() + shared, non_shared);
        data_block_.append(value.data(), value.size());

        restart_counter_++;
    } else {
        // New restart point
        restarts_.push_back(static_cast<uint32_t>(data_block_.size()));

        // Full key (no prefix compression)
        data_block_ += encodeVarint32(0);  // shared = 0
        data_block_ += encodeVarint32(static_cast<uint32_t>(key.size()));
        data_block_ += encodeVarint32(static_cast<uint32_t>(value.size()));
        data_block_.append(key.data(), key.size());
        data_block_.append(value.data(), value.size());

        restart_counter_ = 1;
    }

    last_key_ = key.toString();
    num_entries_++;

    // Add key to bloom filter
    if (bloom_filter_) {
        filter_keys_.push_back(key.toString());
    }

    // Flush if block is large enough
    if (data_block_.size() >= options_.block_size) {
        flush();
    }

    return Status::OK();
}

void SSTableBuilder::flush() {
    if (data_block_.empty()) return;

    // Add restart array
    for (uint32_t restart : restarts_) {
        data_block_ += encodeFixed32(restart);
    }
    data_block_ += encodeFixed32(static_cast<uint32_t>(restarts_.size()));

    // Write data block
    uint64_t block_offset = offset_;
    writeBlock(data_block_, &offset_);

    // Add index entry for this block
    if (pending_index_entry_valid_) {
        index_block_ += pending_index_entry_;
    }

    pending_index_entry_.clear();
    pending_index_entry_ += encodeVarint32(static_cast<uint32_t>(last_key_.size()));
    pending_index_entry_ += last_key_;
    pending_index_entry_ += encodeFixed64(block_offset);
    pending_index_entry_ += encodeFixed64(data_block_.size());
    pending_index_entry_valid_ = true;

    // Reset data block
    data_block_.clear();
    restarts_.clear();
    restarts_.push_back(0);
    restart_counter_ = 0;
}

void SSTableBuilder::writeBlock(const std::string& data, uint64_t* offset) {
    // Block format: [data][checksum (4 bytes)][type (1 byte)]
    uint32_t checksum = crc32c(data.data(), data.size());
    uint8_t type = 0;  // No compression

    file_.write(data.data(), data.size());
    file_.write(reinterpret_cast<const char*>(&checksum), 4);
    file_.write(reinterpret_cast<const char*>(&type), 1);

    *offset += data.size() + 5;
}

Status SSTableBuilder::finish() {
    if (closed_) {
        return Status::IOError("Builder already closed");
    }

    // Flush any remaining data
    flush();

    // Write filter block (bloom filter)
    uint64_t filter_offset = 0;
    uint64_t filter_size = 0;
    if (bloom_filter_ && !filter_keys_.empty()) {
        std::vector<Slice> keys;
        for (const auto& k : filter_keys_) {
            keys.push_back(Slice(k));
        }
        bloom_filter_->createFilter(keys, &filter_data_);

        filter_offset = offset_;
        writeBlock(filter_data_, &offset_);
        filter_size = filter_data_.size() + 5;
    }

    // Write final index entry
    if (pending_index_entry_valid_) {
        index_block_ += pending_index_entry_;
    }

    // Write index block
    uint64_t index_offset = offset_;
    writeBlock(index_block_, &offset_);
    uint64_t index_size = index_block_.size() + 5;

    // Write footer
    // Footer format: [filter_offset (8)][filter_size (8)][index_offset (8)][index_size (8)][magic (8)]
    file_.write(reinterpret_cast<const char*>(&filter_offset), 8);
    file_.write(reinterpret_cast<const char*>(&filter_size), 8);
    file_.write(reinterpret_cast<const char*>(&index_offset), 8);
    file_.write(reinterpret_cast<const char*>(&index_size), 8);

    const uint64_t kTableMagic = 0x465443535374616BULL;  // "FTCSStab"
    file_.write(reinterpret_cast<const char*>(&kTableMagic), 8);

    offset_ += 40;  // Footer size

    file_.close();
    closed_ = true;

    return file_.good() ? Status::OK() : Status::IOError("Failed to finish SSTable");
}

void SSTableBuilder::abandon() {
    if (!closed_) {
        file_.close();
        fs::remove(filename_);
        closed_ = true;
    }
}

//-----------------------------------------------------------------------------
// SSTable implementation
//-----------------------------------------------------------------------------

Status SSTable::open(const std::string& filename, uint64_t file_size,
                     std::unique_ptr<SSTable>* table) {
    auto result = std::unique_ptr<SSTable>(new SSTable());
    result->filename_ = filename;
    result->file_size_ = file_size;

    result->file_.open(filename, std::ios::binary);
    if (!result->file_.is_open()) {
        return Status::IOError("Failed to open SSTable: " + filename);
    }

    // Read footer
    if (file_size < 40) {
        return Status::Corruption("SSTable too small");
    }

    result->file_.seekg(file_size - 40);
    uint64_t filter_offset, filter_size, index_offset, index_size, magic;
    result->file_.read(reinterpret_cast<char*>(&filter_offset), 8);
    result->file_.read(reinterpret_cast<char*>(&filter_size), 8);
    result->file_.read(reinterpret_cast<char*>(&index_offset), 8);
    result->file_.read(reinterpret_cast<char*>(&index_size), 8);
    result->file_.read(reinterpret_cast<char*>(&magic), 8);

    const uint64_t kTableMagic = 0x465443535374616BULL;  // "FTCSStab"
    if (magic != kTableMagic) {
        return Status::Corruption("Invalid SSTable magic number");
    }

    // Read index block
    if (index_size > 5) {
        result->index_block_ = std::make_unique<char[]>(index_size - 5);
        result->index_block_size_ = index_size - 5;
        result->file_.seekg(index_offset);
        result->file_.read(result->index_block_.get(), index_size - 5);
    }

    // Read filter block (bloom filter)
    if (filter_size > 5) {
        result->filter_data_.resize(filter_size - 5);
        result->file_.seekg(filter_offset);
        result->file_.read(&result->filter_data_[0], filter_size - 5);
        result->bloom_filter_ = std::make_unique<BloomFilter>(10);
    }

    *table = std::move(result);
    return Status::OK();
}

SSTable::~SSTable() {
    file_.close();
}

Status SSTable::get(const ReadOptions& options, const Slice& key, std::string* value) const {
    // Check bloom filter first
    if (bloom_filter_ && !filter_data_.empty()) {
        if (!bloom_filter_->keyMayMatch(key, Slice(filter_data_))) {
            return Status::NotFound();
        }
    }

    // Binary search in index to find the right data block
    // Then search within data block
    // Simplified implementation - in practice you'd do proper binary search

    auto it = newIterator(options);
    it->seek(key);

    if (it->valid() && it->key() == key) {
        *value = it->value().toString();
        return Status::OK();
    }

    return Status::NotFound();
}

uint64_t SSTable::approximateOffsetOf(const Slice& key) const {
    // Simplified - return 0 for now
    return 0;
}

// SSTable iterator (simplified)
class SSTableIterator : public Iterator {
public:
    SSTableIterator(const SSTable* table) : table_(table) {}

    bool valid() const override { return valid_; }
    void seekToFirst() override { valid_ = false; }  // Simplified
    void seekToLast() override { valid_ = false; }   // Simplified
    void seek(const Slice& target) override { valid_ = false; }  // Simplified
    void next() override { valid_ = false; }
    void prev() override { valid_ = false; }
    Slice key() const override { return Slice(current_key_); }
    Slice value() const override { return Slice(current_value_); }
    Status status() const override { return Status::OK(); }

private:
    const SSTable* table_;
    bool valid_ = false;
    std::string current_key_;
    std::string current_value_;
};

std::unique_ptr<Iterator> SSTable::newIterator(const ReadOptions& options) const {
    return std::make_unique<SSTableIterator>(this);
}

//-----------------------------------------------------------------------------
// Version implementation
//-----------------------------------------------------------------------------

Version::Version(VersionSet* vset) : vset_(vset) {}

Version::~Version() = default;

void Version::unref() {
    if (--refs_ <= 0) {
        delete this;
    }
}

Status Version::get(const ReadOptions& options, const Slice& key, std::string* value) const {
    // Search through all levels
    // Level 0: files may overlap, check all
    // Level 1+: files don't overlap, binary search

    for (int level = 0; level < 7; level++) {
        for (const auto& file : files_[level]) {
            // Check if key is in range
            if (key.compare(Slice(file.smallest_key)) >= 0 &&
                key.compare(Slice(file.largest_key)) <= 0) {
                // TODO: Read from file
            }
        }
    }

    return Status::NotFound();
}

std::unique_ptr<Iterator> Version::newIterator(const ReadOptions& options) const {
    // Would create a merging iterator over all levels
    return nullptr;
}

//-----------------------------------------------------------------------------
// VersionSet implementation
//-----------------------------------------------------------------------------

VersionSet::VersionSet(const std::string& dbname, const Options& options)
    : dbname_(dbname), options_(options) {

    current_ = new Version(this);
    current_->ref();
}

VersionSet::~VersionSet() {
    if (current_) {
        current_->unref();
    }
}

Status VersionSet::recover() {
    // Read CURRENT file to get manifest filename
    std::string current_path = dbname_ + "/CURRENT";
    std::ifstream current_file(current_path);
    if (!current_file.is_open()) {
        return Status::IOError("CURRENT file not found");
    }

    std::string manifest_name;
    std::getline(current_file, manifest_name);

    // Read manifest and recover state
    // Simplified - in practice would read version edits

    return Status::OK();
}

Status VersionSet::logAndApply(class VersionEdit* edit) {
    // Apply version edit and write to manifest
    return Status::OK();
}

bool VersionSet::needsCompaction() const {
    // Check if any level needs compaction
    return false;
}

void VersionSet::pickCompaction() {
    // Select files for compaction
}

//-----------------------------------------------------------------------------
// Database implementation
//-----------------------------------------------------------------------------

Database::Database(const Options& options, const std::string& dbname)
    : options_(options),
      dbname_(dbname),
      user_comparator_(BytewiseComparator::instance()) {

    snapshot_list_.prev = &snapshot_list_;
    snapshot_list_.next = &snapshot_list_;
}

Database::~Database() {
    shutting_down_ = true;

    // Wait for background compaction
    {
        std::unique_lock<std::mutex> lock(mutex_);
        while (bg_compaction_scheduled_) {
            bg_cv_.wait(lock);
        }
    }

    // Close log
    if (log_) {
        log_->close();
    }
}

Status Database::open(const Options& options, const std::string& name,
                      std::unique_ptr<Database>* dbptr) {
    auto db = std::unique_ptr<Database>(new Database(options, name));

    // Create directory if needed
    if (!fs::exists(name)) {
        if (options.create_if_missing) {
            fs::create_directories(name);
        } else {
            return Status::IOError("Database directory does not exist: " + name);
        }
    } else if (options.error_if_exists) {
        return Status::InvalidArgument("Database already exists: " + name);
    }

    // Recover existing database or create new one
    Status s = db->recover();
    if (!s.ok()) {
        if (s.isIOError() && options.create_if_missing) {
            s = db->newDB();
        }
        if (!s.ok()) {
            return s;
        }
    }

    *dbptr = std::move(db);
    return Status::OK();
}

Status Database::recover() {
    // Initialize version set
    versions_ = std::make_unique<VersionSet>(dbname_, options_);

    // Check for CURRENT file
    std::string current_path = dbname_ + "/CURRENT";
    if (!fs::exists(current_path)) {
        return Status::IOError("No database found");
    }

    Status s = versions_->recover();
    if (!s.ok()) {
        return s;
    }

    // Create new memtable
    mem_ = std::make_unique<MemTable>(user_comparator_);

    // Open new log
    logfile_number_ = versions_->newFileNumber();
    log_ = std::make_unique<WriteAheadLog>(logFileName(logfile_number_));
    s = log_->open();

    return s;
}

Status Database::newDB() {
    // Create new database

    // Initialize version set
    versions_ = std::make_unique<VersionSet>(dbname_, options_);

    // Write CURRENT file
    std::string current_path = dbname_ + "/CURRENT";
    std::ofstream current_file(current_path);
    if (!current_file.is_open()) {
        return Status::IOError("Failed to create CURRENT file");
    }
    current_file << "MANIFEST-000001" << std::endl;
    current_file.close();

    // Create manifest
    std::string manifest_path = dbname_ + "/MANIFEST-000001";
    std::ofstream manifest(manifest_path, std::ios::binary);
    manifest.close();

    // Create new memtable
    mem_ = std::make_unique<MemTable>(user_comparator_);

    // Open new log
    logfile_number_ = versions_->newFileNumber();
    log_ = std::make_unique<WriteAheadLog>(logFileName(logfile_number_));
    Status s = log_->open();

    return s;
}

Status Database::put(const WriteOptions& options, const Slice& key, const Slice& value) {
    WriteBatch batch;
    batch.put(key, value);
    return write(options, &batch);
}

Status Database::del(const WriteOptions& options, const Slice& key) {
    WriteBatch batch;
    batch.del(key);
    return write(options, &batch);
}

Status Database::write(const WriteOptions& options, WriteBatch* batch) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Make room for write
    Status s = makeRoomForWrite(false);
    if (!s.ok()) {
        return s;
    }

    // Get sequence number
    uint64_t seq = versions_->lastSequence() + 1;

    // Write to log
    std::string record;
    record += encodeFixed64(seq);
    record += encodeFixed32(static_cast<uint32_t>(batch->count()));
    for (const auto& op : batch->operations()) {
        if (op.type == WriteBatch::Operation::PUT) {
            record += '\x01';  // Put type
            record += encodeVarint32(static_cast<uint32_t>(op.key.size()));
            record += op.key;
            record += encodeVarint32(static_cast<uint32_t>(op.value.size()));
            record += op.value;
        } else {
            record += '\x00';  // Delete type
            record += encodeVarint32(static_cast<uint32_t>(op.key.size()));
            record += op.key;
        }
    }

    s = log_->addRecord(Slice(record));
    if (!s.ok()) {
        return s;
    }

    if (options.sync) {
        s = log_->sync();
        if (!s.ok()) {
            return s;
        }
    }

    // Apply to memtable
    for (const auto& op : batch->operations()) {
        if (op.type == WriteBatch::Operation::PUT) {
            mem_->add(seq, Slice(op.key), Slice(op.value));
        } else {
            mem_->addDeletion(seq, Slice(op.key));
        }
        seq++;
    }

    versions_->setLastSequence(seq - 1);

    return Status::OK();
}

Status Database::get(const ReadOptions& options, const Slice& key, std::string* value) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Get snapshot sequence number
    uint64_t snapshot_seq = options.snapshot
        ? options.snapshot->sequenceNumber()
        : versions_->lastSequence();

    // Check memtable
    Status s;
    if (mem_->get(key, value, &s)) {
        return s;
    }

    // Check immutable memtable
    if (imm_ && imm_->get(key, value, &s)) {
        return s;
    }

    // Check disk files
    s = versions_->current()->get(options, key, value);

    return s;
}

std::unique_ptr<Iterator> Database::newIterator(const ReadOptions& options) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Would create a merging iterator over memtable and disk files
    return mem_->newIterator();
}

const Snapshot* Database::getSnapshot() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto snap = new SnapshotImpl();
    snap->sequence = versions_->lastSequence();

    // Insert into doubly-linked list
    snap->next = &snapshot_list_;
    snap->prev = snapshot_list_.prev;
    snapshot_list_.prev->next = snap;
    snapshot_list_.prev = snap;

    return snap;
}

void Database::releaseSnapshot(const Snapshot* snapshot) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto snap = const_cast<SnapshotImpl*>(static_cast<const SnapshotImpl*>(snapshot));
    snap->prev->next = snap->next;
    snap->next->prev = snap->prev;
    delete snap;
}

void Database::compactRange(const Slice* begin, const Slice* end) {
    // Trigger compaction for range
    maybeScheduleCompaction();
}

bool Database::getProperty(const Slice& property, std::string* value) {
    std::string prop = property.toString();

    if (prop == "ftc.num-files-at-level0") {
        *value = std::to_string(versions_->current()->files_[0].size());
        return true;
    }

    if (prop == "ftc.stats") {
        std::ostringstream oss;
        oss << "Level Files Size(MB)\n";
        for (int level = 0; level < 7; level++) {
            size_t total_size = 0;
            for (const auto& f : versions_->current()->files_[level]) {
                total_size += f.file_size;
            }
            oss << level << " " << versions_->current()->files_[level].size()
                << " " << (total_size / 1048576.0) << "\n";
        }
        *value = oss.str();
        return true;
    }

    return false;
}

void Database::getApproximateSizes(const Slice* start, const Slice* limit,
                                   int n, uint64_t* sizes) {
    for (int i = 0; i < n; i++) {
        sizes[i] = 0;  // Simplified
    }
}

Status Database::makeRoomForWrite(bool force) {
    while (true) {
        if (mem_->approximateMemoryUsage() < options_.write_buffer_size) {
            // Memtable has room
            return Status::OK();
        }

        if (imm_ != nullptr) {
            // Wait for compaction to complete
            // In practice, would wait on condition variable
            return Status::IOError("Memtable full, waiting for compaction");
        }

        // Switch memtable
        imm_ = std::move(mem_);
        mem_ = std::make_unique<MemTable>(user_comparator_);

        // Create new log
        log_->close();
        logfile_number_ = versions_->newFileNumber();
        log_ = std::make_unique<WriteAheadLog>(logFileName(logfile_number_));
        Status s = log_->open();
        if (!s.ok()) {
            return s;
        }

        // Schedule compaction
        maybeScheduleCompaction();

        return Status::OK();
    }
}

Status Database::writeLevel0Table(MemTable* mem) {
    // Write memtable to new SSTable file
    uint64_t file_number = versions_->newFileNumber();
    std::string filename = tableFileName(file_number);

    SSTableBuilder builder(options_, filename);

    auto it = mem->newIterator();
    for (it->seekToFirst(); it->valid(); it->next()) {
        Status s = builder.add(it->key(), it->value());
        if (!s.ok()) {
            return s;
        }
    }

    return builder.finish();
}

void Database::maybeScheduleCompaction() {
    if (bg_compaction_scheduled_) {
        return;
    }

    if (shutting_down_) {
        return;
    }

    if (imm_ == nullptr && !versions_->needsCompaction()) {
        return;
    }

    bg_compaction_scheduled_ = true;

    // In practice, would spawn background thread
    // For simplicity, do inline
    backgroundCompaction();
}

void Database::backgroundCompaction() {
    if (imm_ != nullptr) {
        compactMemTable();
    }

    // Level compaction
    doCompactionWork();

    bg_compaction_scheduled_ = false;
    bg_cv_.notify_all();
}

void Database::compactMemTable() {
    // Write immutable memtable to disk
    Status s = writeLevel0Table(imm_.get());
    if (s.ok()) {
        imm_.reset();
    }
}

void Database::doCompactionWork() {
    // Pick files for compaction and merge them
    // Simplified - no-op for now
}

std::string Database::logFileName(uint64_t number) const {
    std::ostringstream oss;
    oss << dbname_ << "/" << std::setfill('0') << std::setw(6) << number << ".log";
    return oss.str();
}

std::string Database::tableFileName(uint64_t number) const {
    std::ostringstream oss;
    oss << dbname_ << "/" << std::setfill('0') << std::setw(6) << number << ".sst";
    return oss.str();
}

std::string Database::manifestFileName(uint64_t number) const {
    std::ostringstream oss;
    oss << dbname_ << "/MANIFEST-" << std::setfill('0') << std::setw(6) << number;
    return oss.str();
}

std::string Database::currentFileName() const {
    return dbname_ + "/CURRENT";
}

//-----------------------------------------------------------------------------
// Helper function implementations
//-----------------------------------------------------------------------------

std::string encodeFixed32(uint32_t value) {
    char buf[4];
    buf[0] = value & 0xff;
    buf[1] = (value >> 8) & 0xff;
    buf[2] = (value >> 16) & 0xff;
    buf[3] = (value >> 24) & 0xff;
    return std::string(buf, 4);
}

std::string encodeFixed64(uint64_t value) {
    char buf[8];
    buf[0] = value & 0xff;
    buf[1] = (value >> 8) & 0xff;
    buf[2] = (value >> 16) & 0xff;
    buf[3] = (value >> 24) & 0xff;
    buf[4] = (value >> 32) & 0xff;
    buf[5] = (value >> 40) & 0xff;
    buf[6] = (value >> 48) & 0xff;
    buf[7] = (value >> 56) & 0xff;
    return std::string(buf, 8);
}

std::string encodeVarint32(uint32_t value) {
    std::string result;
    while (value >= 0x80) {
        result += static_cast<char>((value & 0x7f) | 0x80);
        value >>= 7;
    }
    result += static_cast<char>(value);
    return result;
}

std::string encodeVarint64(uint64_t value) {
    std::string result;
    while (value >= 0x80) {
        result += static_cast<char>((value & 0x7f) | 0x80);
        value >>= 7;
    }
    result += static_cast<char>(value);
    return result;
}

uint32_t decodeFixed32(const char* ptr) {
    return static_cast<uint32_t>(static_cast<uint8_t>(ptr[0])) |
           (static_cast<uint32_t>(static_cast<uint8_t>(ptr[1])) << 8) |
           (static_cast<uint32_t>(static_cast<uint8_t>(ptr[2])) << 16) |
           (static_cast<uint32_t>(static_cast<uint8_t>(ptr[3])) << 24);
}

uint64_t decodeFixed64(const char* ptr) {
    uint64_t lo = decodeFixed32(ptr);
    uint64_t hi = decodeFixed32(ptr + 4);
    return lo | (hi << 32);
}

const char* getVarint32(const char* p, const char* limit, uint32_t* value) {
    if (p >= limit) return nullptr;

    uint32_t result = 0;
    for (int shift = 0; shift <= 28 && p < limit; shift += 7) {
        uint32_t byte = static_cast<uint8_t>(*p++);
        if (byte & 0x80) {
            result |= (byte & 0x7f) << shift;
        } else {
            result |= byte << shift;
            *value = result;
            return p;
        }
    }
    return nullptr;  // Malformed
}

const char* getVarint64(const char* p, const char* limit, uint64_t* value) {
    if (p >= limit) return nullptr;

    uint64_t result = 0;
    for (int shift = 0; shift <= 63 && p < limit; shift += 7) {
        uint64_t byte = static_cast<uint8_t>(*p++);
        if (byte & 0x80) {
            result |= (byte & 0x7f) << shift;
        } else {
            result |= byte << shift;
            *value = result;
            return p;
        }
    }
    return nullptr;  // Malformed
}

// CRC32C implementation using lookup table
static uint32_t crc32c_table[256];
static bool crc32c_table_initialized = false;

static void initCrc32cTable() {
    if (crc32c_table_initialized) return;

    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0x82F63B78;  // CRC32C polynomial
            } else {
                crc >>= 1;
            }
        }
        crc32c_table[i] = crc;
    }
    crc32c_table_initialized = true;
}

uint32_t crc32c(const char* data, size_t length) {
    return crc32cExtend(0, data, length);
}

uint32_t crc32cExtend(uint32_t crc, const char* data, size_t length) {
    initCrc32cTable();

    crc = ~crc;
    for (size_t i = 0; i < length; i++) {
        crc = crc32c_table[(crc ^ static_cast<uint8_t>(data[i])) & 0xff] ^ (crc >> 8);
    }
    return ~crc;
}

} // namespace storage
} // namespace ftc
