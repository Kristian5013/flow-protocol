#ifndef FTC_STORAGE_DATABASE_H
#define FTC_STORAGE_DATABASE_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <optional>
#include <fstream>
#include <condition_variable>

namespace ftc {
namespace storage {

// Slice - a lightweight view into data
class Slice {
public:
    Slice() : data_(nullptr), size_(0) {}
    Slice(const char* data, size_t size) : data_(data), size_(size) {}
    Slice(const std::string& s) : data_(s.data()), size_(s.size()) {}
    Slice(const std::vector<uint8_t>& v)
        : data_(reinterpret_cast<const char*>(v.data())), size_(v.size()) {}

    const char* data() const { return data_; }
    size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }

    std::string toString() const { return std::string(data_, size_); }
    std::vector<uint8_t> toBytes() const {
        return std::vector<uint8_t>(data_, data_ + size_);
    }

    int compare(const Slice& other) const;

    bool operator==(const Slice& other) const { return compare(other) == 0; }
    bool operator!=(const Slice& other) const { return compare(other) != 0; }
    bool operator<(const Slice& other) const { return compare(other) < 0; }

private:
    const char* data_;
    size_t size_;
};

// Database status
class Status {
public:
    Status() : code_(Code::OK) {}

    static Status OK() { return Status(); }
    static Status NotFound(const std::string& msg = "") { return Status(Code::NOT_FOUND, msg); }
    static Status Corruption(const std::string& msg = "") { return Status(Code::CORRUPTION, msg); }
    static Status IOError(const std::string& msg = "") { return Status(Code::IO_ERROR, msg); }
    static Status InvalidArgument(const std::string& msg = "") { return Status(Code::INVALID_ARG, msg); }

    bool ok() const { return code_ == Code::OK; }
    bool isNotFound() const { return code_ == Code::NOT_FOUND; }
    bool isCorruption() const { return code_ == Code::CORRUPTION; }
    bool isIOError() const { return code_ == Code::IO_ERROR; }

    std::string toString() const;

private:
    enum class Code { OK, NOT_FOUND, CORRUPTION, IO_ERROR, INVALID_ARG };

    Status(Code code, const std::string& msg) : code_(code), message_(msg) {}

    Code code_;
    std::string message_;
};

// Write batch - atomic writes
class WriteBatch {
public:
    WriteBatch() = default;

    void put(const Slice& key, const Slice& value);
    void del(const Slice& key);
    void clear();

    size_t count() const { return operations_.size(); }
    size_t approximateSize() const;

    // Internal iteration
    struct Operation {
        enum Type { PUT, DELETE };
        Type type;
        std::string key;
        std::string value;
    };

    const std::vector<Operation>& operations() const { return operations_; }

private:
    std::vector<Operation> operations_;
};

// Iterator for database traversal
class Iterator {
public:
    virtual ~Iterator() = default;

    virtual bool valid() const = 0;
    virtual void seekToFirst() = 0;
    virtual void seekToLast() = 0;
    virtual void seek(const Slice& target) = 0;
    virtual void next() = 0;
    virtual void prev() = 0;
    virtual Slice key() const = 0;
    virtual Slice value() const = 0;
    virtual Status status() const = 0;
};

// Snapshot for consistent reads
class Snapshot {
public:
    virtual ~Snapshot() = default;
    virtual uint64_t sequenceNumber() const = 0;
};

// Read options
struct ReadOptions {
    bool verify_checksums = false;
    bool fill_cache = true;
    const Snapshot* snapshot = nullptr;
};

// Write options
struct WriteOptions {
    bool sync = false;  // Fsync after write
};

// Database options
struct Options {
    // Create database if missing
    bool create_if_missing = true;

    // Error if database exists
    bool error_if_exists = false;

    // Write buffer size (before flush to disk)
    size_t write_buffer_size = 4 * 1024 * 1024;  // 4 MB

    // Maximum number of open files
    int max_open_files = 1000;

    // Block size for storage
    size_t block_size = 4 * 1024;  // 4 KB

    // Block restart interval
    int block_restart_interval = 16;

    // Compression
    bool compression = true;

    // Bloom filter bits per key (0 = disabled)
    int bloom_bits_per_key = 10;

    // Maximum file size for level files
    size_t max_file_size = 2 * 1024 * 1024;  // 2 MB
};

// Comparator for keys
class Comparator {
public:
    virtual ~Comparator() = default;

    virtual int compare(const Slice& a, const Slice& b) const = 0;
    virtual const char* name() const = 0;

    // Find shortest separator between start and limit
    virtual void findShortestSeparator(std::string* start, const Slice& limit) const = 0;

    // Find short successor to key
    virtual void findShortSuccessor(std::string* key) const = 0;
};

// Default bytewise comparator
class BytewiseComparator : public Comparator {
public:
    int compare(const Slice& a, const Slice& b) const override {
        return a.compare(b);
    }

    const char* name() const override { return "ftc.BytewiseComparator"; }

    void findShortestSeparator(std::string* start, const Slice& limit) const override;
    void findShortSuccessor(std::string* key) const override;

    static const BytewiseComparator* instance() {
        static BytewiseComparator comp;
        return &comp;
    }
};

// Bloom filter for efficient negative lookups
class BloomFilter {
public:
    BloomFilter(int bits_per_key);

    void createFilter(const std::vector<Slice>& keys, std::string* dst) const;
    bool keyMayMatch(const Slice& key, const Slice& filter) const;

private:
    size_t bits_per_key_;
    size_t k_;  // Number of hash functions
};

// MemTable - in-memory sorted structure
class MemTable {
public:
    explicit MemTable(const Comparator* cmp);
    ~MemTable();

    // No copying
    MemTable(const MemTable&) = delete;
    MemTable& operator=(const MemTable&) = delete;

    void add(uint64_t seq, const Slice& key, const Slice& value);
    void addDeletion(uint64_t seq, const Slice& key);

    bool get(const Slice& key, std::string* value, Status* s) const;

    size_t approximateMemoryUsage() const { return approximate_memory_; }

    // Create iterator
    std::unique_ptr<Iterator> newIterator() const;

    // Entry structure for internal storage (public for iterator access)
    struct Entry {
        uint64_t sequence;
        bool deletion;
        std::string key;
        std::string value;
    };

    struct EntryComparator {
        const Comparator* user_cmp;
        bool operator()(const Entry& a, const Entry& b) const;
    };

    // Table accessor for iterators
    const std::set<Entry, EntryComparator>& table() const { return table_; }

private:
    const Comparator* comparator_;
    std::set<Entry, EntryComparator> table_;
    size_t approximate_memory_ = 0;
    mutable std::mutex mutex_;
};

// SSTable (Sorted String Table) - immutable on-disk structure
class SSTable {
public:
    static Status open(const std::string& filename,
                       uint64_t file_size,
                       std::unique_ptr<SSTable>* table);

    ~SSTable();

    // Create iterator for this table
    std::unique_ptr<Iterator> newIterator(const ReadOptions& options) const;

    // Point lookup with bloom filter
    Status get(const ReadOptions& options, const Slice& key, std::string* value) const;

    // Get approximate offset of key
    uint64_t approximateOffsetOf(const Slice& key) const;

    // Table properties
    uint64_t fileSize() const { return file_size_; }
    const std::string& filename() const { return filename_; }

private:
    SSTable() = default;

    std::string filename_;
    uint64_t file_size_ = 0;
    std::unique_ptr<char[]> index_block_;
    size_t index_block_size_ = 0;
    std::string filter_data_;
    std::unique_ptr<BloomFilter> bloom_filter_;

    // File handle
    mutable std::ifstream file_;
    mutable std::mutex file_mutex_;
};

// SSTable builder
class SSTableBuilder {
public:
    SSTableBuilder(const Options& options, const std::string& filename);
    ~SSTableBuilder();

    // Add key/value pair (keys must be added in order)
    Status add(const Slice& key, const Slice& value);

    // Finish building and close file
    Status finish();

    // Abandon building
    void abandon();

    // Current file size
    uint64_t fileSize() const { return offset_; }

    // Number of entries
    uint64_t numEntries() const { return num_entries_; }

private:
    void flush();
    void writeBlock(const std::string& data, uint64_t* offset);

    Options options_;
    std::string filename_;
    std::ofstream file_;
    uint64_t offset_ = 0;
    uint64_t num_entries_ = 0;

    // Current data block
    std::string data_block_;
    std::string last_key_;
    int restart_counter_ = 0;
    std::vector<uint32_t> restarts_;

    // Index block
    std::string index_block_;
    std::string pending_index_entry_;
    bool pending_index_entry_valid_ = false;

    // Filter block (bloom filter)
    std::vector<std::string> filter_keys_;
    std::string filter_data_;
    std::unique_ptr<BloomFilter> bloom_filter_;

    bool closed_ = false;
    Status status_;
};

// Write-ahead log (WAL)
class WriteAheadLog {
public:
    WriteAheadLog(const std::string& filename);
    ~WriteAheadLog();

    Status open();
    Status addRecord(const Slice& data);
    Status sync();
    void close();

    // Read all records from log
    static Status readLog(const std::string& filename,
                          std::function<void(const Slice& record)> callback);

private:
    std::string filename_;
    std::ofstream file_;
    bool opened_ = false;
};

// Version - represents a specific state of the database
struct FileMetaData {
    uint64_t number;
    uint64_t file_size;
    std::string smallest_key;
    std::string largest_key;
};

class Version {
public:
    explicit Version(class VersionSet* vset);
    ~Version();

    // Add reference
    void ref() { ++refs_; }
    void unref();

    // Get value for key
    Status get(const ReadOptions& options, const Slice& key,
               std::string* value) const;

    // Create iterator over all data
    std::unique_ptr<Iterator> newIterator(const ReadOptions& options) const;

    // Files at each level
    std::vector<FileMetaData> files_[7];  // 7 levels (0-6)

private:
    VersionSet* vset_;
    std::atomic<int> refs_{0};
    Version* next_ = nullptr;
    Version* prev_ = nullptr;

    friend class VersionSet;
};

// VersionSet - manages versions and compaction
class VersionSet {
public:
    VersionSet(const std::string& dbname, const Options& options);
    ~VersionSet();

    Status recover();
    Status logAndApply(class VersionEdit* edit);

    Version* current() const { return current_; }
    uint64_t lastSequence() const { return last_sequence_; }
    void setLastSequence(uint64_t seq) { last_sequence_ = seq; }

    uint64_t newFileNumber() { return next_file_number_++; }
    uint64_t logNumber() const { return log_number_; }

    // Compaction
    bool needsCompaction() const;
    void pickCompaction();

private:
    std::string dbname_;
    Options options_;
    Version* current_ = nullptr;
    uint64_t next_file_number_ = 1;
    uint64_t last_sequence_ = 0;
    uint64_t log_number_ = 0;
    uint64_t manifest_file_number_ = 0;

    std::unique_ptr<WriteAheadLog> manifest_log_;
    mutable std::mutex mutex_;
};

/**
 * Database - LevelDB-style key-value store
 *
 * Features:
 * - Log-structured merge tree (LSM)
 * - Write-ahead logging for durability
 * - Sorted string tables (SST) for efficient reads
 * - Bloom filters for fast negative lookups
 * - Compaction for space reclamation
 * - Snapshots for consistent reads
 */
class Database {
public:
    // Open database
    static Status open(const Options& options,
                       const std::string& name,
                       std::unique_ptr<Database>* dbptr);

    ~Database();

    // No copying
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    // Basic operations
    Status put(const WriteOptions& options, const Slice& key, const Slice& value);
    Status del(const WriteOptions& options, const Slice& key);
    Status get(const ReadOptions& options, const Slice& key, std::string* value);

    // Batch operations
    Status write(const WriteOptions& options, WriteBatch* batch);

    // Iteration
    std::unique_ptr<Iterator> newIterator(const ReadOptions& options);

    // Snapshots
    const Snapshot* getSnapshot();
    void releaseSnapshot(const Snapshot* snapshot);

    // Compaction
    void compactRange(const Slice* begin, const Slice* end);

    // Properties
    bool getProperty(const Slice& property, std::string* value);

    // Approximate sizes
    void getApproximateSizes(const Slice* start, const Slice* limit,
                             int n, uint64_t* sizes);

    // Database name
    const std::string& name() const { return dbname_; }

private:
    Database(const Options& options, const std::string& dbname);

    Status recover();
    Status newDB();

    // Write helpers
    Status makeRoomForWrite(bool force);
    Status writeLevel0Table(MemTable* mem);

    // Background compaction
    void maybeScheduleCompaction();
    void backgroundCompaction();
    void compactMemTable();
    void doCompactionWork();

    // File management
    std::string logFileName(uint64_t number) const;
    std::string tableFileName(uint64_t number) const;
    std::string manifestFileName(uint64_t number) const;
    std::string currentFileName() const;

    // Configuration
    Options options_;
    std::string dbname_;
    const Comparator* user_comparator_;

    // State
    std::unique_ptr<MemTable> mem_;
    std::unique_ptr<MemTable> imm_;  // Immutable memtable being compacted
    std::unique_ptr<WriteAheadLog> log_;
    uint64_t logfile_number_ = 0;

    // Versions
    std::unique_ptr<VersionSet> versions_;

    // Table cache
    std::map<uint64_t, std::unique_ptr<SSTable>> table_cache_;
    mutable std::mutex table_cache_mutex_;

    // Background compaction
    std::atomic<bool> bg_compaction_scheduled_{false};
    std::atomic<bool> shutting_down_{false};

    // Synchronization
    mutable std::mutex mutex_;
    std::condition_variable bg_cv_;

    // Snapshots
    struct SnapshotImpl : public Snapshot {
        uint64_t sequence;
        SnapshotImpl* prev = nullptr;
        SnapshotImpl* next = nullptr;

        uint64_t sequenceNumber() const override { return sequence; }
    };
    SnapshotImpl snapshot_list_;
};

// Helper functions
std::string encodeFixed32(uint32_t value);
std::string encodeFixed64(uint64_t value);
std::string encodeVarint32(uint32_t value);
std::string encodeVarint64(uint64_t value);

uint32_t decodeFixed32(const char* ptr);
uint64_t decodeFixed64(const char* ptr);
const char* getVarint32(const char* p, const char* limit, uint32_t* value);
const char* getVarint64(const char* p, const char* limit, uint64_t* value);

// CRC32C checksum
uint32_t crc32c(const char* data, size_t length);
uint32_t crc32cExtend(uint32_t crc, const char* data, size_t length);

} // namespace storage
} // namespace ftc

#endif // FTC_STORAGE_DATABASE_H
