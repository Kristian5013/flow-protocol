// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/walletdb.h"
#include "core/logging.h"

#include <algorithm>
#include <cstring>
#include <fstream>

namespace wallet {

// ---------------------------------------------------------------------------
// Helpers: little-endian I/O
// ---------------------------------------------------------------------------

namespace {

void write_le16(std::ostream& os, uint16_t v) {
    uint8_t buf[2] = {
        static_cast<uint8_t>(v & 0xFF),
        static_cast<uint8_t>((v >> 8) & 0xFF)
    };
    os.write(reinterpret_cast<const char*>(buf), 2);
}

void write_le32(std::ostream& os, uint32_t v) {
    uint8_t buf[4] = {
        static_cast<uint8_t>(v & 0xFF),
        static_cast<uint8_t>((v >> 8) & 0xFF),
        static_cast<uint8_t>((v >> 16) & 0xFF),
        static_cast<uint8_t>((v >> 24) & 0xFF)
    };
    os.write(reinterpret_cast<const char*>(buf), 4);
}

bool read_le16(std::istream& is, uint16_t& out) {
    uint8_t buf[2];
    if (!is.read(reinterpret_cast<char*>(buf), 2)) return false;
    out = static_cast<uint16_t>(buf[0]) |
          (static_cast<uint16_t>(buf[1]) << 8);
    return true;
}

bool read_le32(std::istream& is, uint32_t& out) {
    uint8_t buf[4];
    if (!is.read(reinterpret_cast<char*>(buf), 4)) return false;
    out = static_cast<uint32_t>(buf[0]) |
          (static_cast<uint32_t>(buf[1]) << 8) |
          (static_cast<uint32_t>(buf[2]) << 16) |
          (static_cast<uint32_t>(buf[3]) << 24);
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

WalletDB::~WalletDB() {
    if (is_open_) {
        close();
    }
}

core::Result<void> WalletDB::open(const std::filesystem::path& path) {
    std::lock_guard lock(mutex_);

    if (is_open_) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "WalletDB already open");
    }

    path_ = path;

    // Acquire exclusive file lock.
    auto lock_result = acquire_lock();
    if (!lock_result.ok()) {
        return lock_result;
    }

    // If the file exists, read it. Otherwise create a fresh database.
    if (std::filesystem::exists(path_)) {
        auto read_result = read_from_disk();
        if (!read_result.ok()) {
            release_lock();
            return read_result;
        }
    } else {
        // Create parent directories if needed.
        std::error_code ec;
        std::filesystem::create_directories(path_.parent_path(), ec);
        if (ec) {
            release_lock();
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                               "Cannot create directory: " + ec.message());
        }
        records_.clear();
        auto write_result = write_to_disk();
        if (!write_result.ok()) {
            release_lock();
            return write_result;
        }
    }

    is_open_ = true;
    LOG_INFO(core::LogCategory::WALLET,
             "WalletDB opened: " + path_.string());
    return core::Result<void>{};
}

void WalletDB::close() {
    std::lock_guard lock(mutex_);
    if (!is_open_) return;

    // Flush remaining data to disk.
    auto result = write_to_disk();
    if (!result.ok()) {
        LOG_ERROR(core::LogCategory::WALLET,
                  "WalletDB flush on close failed: " + result.error().message());
    }

    records_.clear();
    release_lock();
    is_open_ = false;

    LOG_INFO(core::LogCategory::WALLET,
             "WalletDB closed: " + path_.string());
}

bool WalletDB::is_open() const {
    std::lock_guard lock(mutex_);
    return is_open_;
}

// ---------------------------------------------------------------------------
// Read / write
// ---------------------------------------------------------------------------

core::Result<void> WalletDB::write(std::string_view key,
                                    std::span<const uint8_t> value) {
    std::lock_guard lock(mutex_);

    if (!is_open_) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "WalletDB not open");
    }

    if (key.empty()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "WalletDB key must not be empty");
    }

    if (key.size() > 65535) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "WalletDB key too long (max 65535 bytes)");
    }

    std::string key_str(key);
    records_[key_str] = std::vector<uint8_t>(value.begin(), value.end());

    // Persist immediately.
    return write_to_disk();
}

core::Result<std::vector<uint8_t>> WalletDB::read(std::string_view key) const {
    std::lock_guard lock(mutex_);

    if (!is_open_) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "WalletDB not open");
    }

    std::string key_str(key);
    auto it = records_.find(key_str);
    if (it == records_.end() || it->second.empty()) {
        return core::Error(core::ErrorCode::STORAGE_NOT_FOUND,
                           "Key not found: " + key_str);
    }

    return it->second;
}

core::Result<void> WalletDB::erase(std::string_view key) {
    std::lock_guard lock(mutex_);

    if (!is_open_) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "WalletDB not open");
    }

    std::string key_str(key);
    auto it = records_.find(key_str);
    if (it == records_.end()) {
        return core::Error(core::ErrorCode::STORAGE_NOT_FOUND,
                           "Key not found: " + key_str);
    }

    // Logical delete: set value to empty.
    it->second.clear();
    return write_to_disk();
}

bool WalletDB::exists(std::string_view key) const {
    std::lock_guard lock(mutex_);

    std::string key_str(key);
    auto it = records_.find(key_str);
    return it != records_.end() && !it->second.empty();
}

std::vector<std::string> WalletDB::list_by_prefix(
    std::string_view prefix) const {
    std::lock_guard lock(mutex_);

    std::vector<std::string> result;
    for (const auto& [k, v] : records_) {
        if (!v.empty() && k.size() >= prefix.size() &&
            k.compare(0, prefix.size(), prefix) == 0) {
            result.push_back(k);
        }
    }

    std::sort(result.begin(), result.end());
    return result;
}

std::vector<std::pair<std::string, std::vector<uint8_t>>>
WalletDB::read_by_prefix(std::string_view prefix) const {
    std::lock_guard lock(mutex_);

    std::vector<std::pair<std::string, std::vector<uint8_t>>> result;
    for (const auto& [k, v] : records_) {
        if (!v.empty() && k.size() >= prefix.size() &&
            k.compare(0, prefix.size(), prefix) == 0) {
            result.emplace_back(k, v);
        }
    }

    std::sort(result.begin(), result.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    return result;
}

// ---------------------------------------------------------------------------
// Maintenance
// ---------------------------------------------------------------------------

core::Result<void> WalletDB::flush() {
    std::lock_guard lock(mutex_);

    if (!is_open_) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "WalletDB not open");
    }

    return write_to_disk();
}

core::Result<void> WalletDB::compact() {
    std::lock_guard lock(mutex_);

    if (!is_open_) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "WalletDB not open");
    }

    // Remove logically deleted records from the in-memory map.
    for (auto it = records_.begin(); it != records_.end(); ) {
        if (it->second.empty()) {
            it = records_.erase(it);
        } else {
            ++it;
        }
    }

    // Rewrite the file without deleted records.
    auto result = write_to_disk();
    if (result.ok()) {
        LOG_INFO(core::LogCategory::WALLET,
                 "WalletDB compacted: " + std::to_string(records_.size()) +
                 " records");
    }
    return result;
}

size_t WalletDB::record_count() const {
    std::lock_guard lock(mutex_);

    size_t count = 0;
    for (const auto& [k, v] : records_) {
        if (!v.empty()) ++count;
    }
    return count;
}

// ---------------------------------------------------------------------------
// Internal: disk I/O
// ---------------------------------------------------------------------------

core::Result<void> WalletDB::write_to_disk() {
    // Write to a temp file, then atomically rename.
    auto temp_path = path_;
    temp_path += ".tmp";

    std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Cannot open temp file for writing: " +
                           temp_path.string());
    }

    // Header: magic + version + record count.
    out.write(MAGIC, 4);

    uint32_t active_count = 0;
    for (const auto& [k, v] : records_) {
        if (!v.empty()) ++active_count;
    }

    write_le32(out, CURRENT_VERSION);
    write_le32(out, active_count);

    // Collect and sort keys for deterministic output.
    std::vector<std::string> sorted_keys;
    sorted_keys.reserve(records_.size());
    for (const auto& [k, v] : records_) {
        if (!v.empty()) {
            sorted_keys.push_back(k);
        }
    }
    std::sort(sorted_keys.begin(), sorted_keys.end());

    // Write each record.
    for (const auto& key : sorted_keys) {
        const auto& value = records_.at(key);

        auto key_len = static_cast<uint16_t>(key.size());
        write_le16(out, key_len);
        out.write(key.data(), static_cast<std::streamsize>(key.size()));

        auto value_len = static_cast<uint32_t>(value.size());
        write_le32(out, value_len);
        if (!value.empty()) {
            out.write(reinterpret_cast<const char*>(value.data()),
                      static_cast<std::streamsize>(value.size()));
        }
    }

    out.flush();
    if (!out.good()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Error writing wallet database");
    }
    out.close();

    // Atomic rename (best effort on Windows where rename can fail if
    // target exists).
    std::error_code ec;
    std::filesystem::remove(path_, ec);  // Remove old file first (Windows).
    std::filesystem::rename(temp_path, path_, ec);
    if (ec) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Cannot rename temp file: " + ec.message());
    }

    return core::Result<void>{};
}

core::Result<void> WalletDB::read_from_disk() {
    std::ifstream in(path_, std::ios::binary);
    if (!in) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Cannot open wallet database: " + path_.string());
    }

    // Read and verify magic.
    char magic[4];
    if (!in.read(magic, 4) || std::memcmp(magic, MAGIC, 4) != 0) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Invalid wallet database magic");
    }

    // Read version.
    uint32_t version = 0;
    if (!read_le32(in, version)) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Cannot read wallet database version");
    }

    if (version > CURRENT_VERSION) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Unsupported wallet database version: " +
                           std::to_string(version));
    }

    // Read record count.
    uint32_t count = 0;
    if (!read_le32(in, count)) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Cannot read wallet database record count");
    }

    // Sanity limit: prevent absurd allocations on corrupt files.
    if (count > 10'000'000) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Wallet database record count too high: " +
                           std::to_string(count));
    }

    records_.clear();
    records_.reserve(count);

    for (uint32_t i = 0; i < count; ++i) {
        // Read key.
        uint16_t key_len = 0;
        if (!read_le16(in, key_len) || key_len == 0) {
            return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                               "Cannot read record key length at index " +
                               std::to_string(i));
        }

        std::string key(key_len, '\0');
        if (!in.read(key.data(), key_len)) {
            return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                               "Cannot read record key at index " +
                               std::to_string(i));
        }

        // Read value.
        uint32_t value_len = 0;
        if (!read_le32(in, value_len)) {
            return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                               "Cannot read record value length at index " +
                               std::to_string(i));
        }

        // Sanity check value size (max 64 MiB per record).
        if (value_len > 64 * 1024 * 1024) {
            return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                               "Record value too large at index " +
                               std::to_string(i));
        }

        std::vector<uint8_t> value(value_len);
        if (value_len > 0) {
            if (!in.read(reinterpret_cast<char*>(value.data()), value_len)) {
                return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                                   "Cannot read record value at index " +
                                   std::to_string(i));
            }
        }

        records_[std::move(key)] = std::move(value);
    }

    LOG_DEBUG(core::LogCategory::WALLET,
              "WalletDB loaded " + std::to_string(records_.size()) +
              " records from " + path_.string());
    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// File locking
// ---------------------------------------------------------------------------

core::Result<void> WalletDB::acquire_lock() {
    auto lock_path = path_;
    lock_path += ".lock";

    // Try to create the lock file exclusively. On most systems this is
    // sufficient to detect concurrent access. A production implementation
    // would use platform-specific advisory locking (flock / LockFileEx).
    if (std::filesystem::exists(lock_path)) {
        // Check if the lock file is stale (older than 60 seconds).
        std::error_code ec;
        auto last_write = std::filesystem::last_write_time(lock_path, ec);
        if (!ec) {
            auto age = std::filesystem::file_time_type::clock::now() - last_write;
            auto age_sec = std::chrono::duration_cast<std::chrono::seconds>(age);
            if (age_sec.count() < 60) {
                return core::Error(core::ErrorCode::STORAGE_ERROR,
                                   "Wallet database is locked by another process. "
                                   "Lock file: " + lock_path.string());
            }
            // Stale lock -- remove it and proceed.
            LOG_WARN(core::LogCategory::WALLET,
                     "Removing stale wallet lock file: " + lock_path.string());
        }
    }

    lock_file_.open(lock_path, std::ios::out | std::ios::trunc);
    if (!lock_file_) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Cannot create wallet lock file: " +
                           lock_path.string());
    }

    lock_file_ << "locked" << std::flush;
    return core::Result<void>{};
}

void WalletDB::release_lock() {
    if (lock_file_.is_open()) {
        lock_file_.close();
    }

    auto lock_path = path_;
    lock_path += ".lock";

    std::error_code ec;
    std::filesystem::remove(lock_path, ec);
}

} // namespace wallet
