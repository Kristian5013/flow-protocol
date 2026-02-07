#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <span>

namespace wallet {

// ---------------------------------------------------------------------------
// WalletDB -- persistent key-value storage using a flat binary file
// ---------------------------------------------------------------------------
// File format:
//   [magic: 4B "FTW!"][version: 4B LE][record_count: 4B LE]
//   Followed by N records, each:
//     [key_len: 2B LE][key: key_len bytes][value_len: 4B LE][value: value_len bytes]
//
// Record types are distinguished by key prefix:
//   "key:"   -- private key records
//   "addr:"  -- address-to-key mapping records
//   "tx:"    -- transaction records
//   "meta:"  -- metadata records
//
// Erased records are kept in-file but have a zero-length value. The compact()
// method rewrites the file without erased records.
// ---------------------------------------------------------------------------

class WalletDB {
public:
    /// Magic bytes identifying an FTC wallet file.
    static constexpr char MAGIC[4] = {'F', 'T', 'W', '!'};
    static constexpr uint32_t CURRENT_VERSION = 1;

    WalletDB() = default;
    ~WalletDB();

    WalletDB(const WalletDB&) = delete;
    WalletDB& operator=(const WalletDB&) = delete;

    // -- Lifecycle -----------------------------------------------------------

    /// Open (or create) a wallet database at the given path.
    /// Acquires an exclusive file lock to prevent concurrent access.
    core::Result<void> open(const std::filesystem::path& path);

    /// Close the database, releasing all resources and the file lock.
    void close();

    /// Returns true if the database file is currently open.
    [[nodiscard]] bool is_open() const;

    /// Returns the path of the currently open database file.
    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

    // -- Read / write --------------------------------------------------------

    /// Write (insert or overwrite) a key-value pair.
    core::Result<void> write(std::string_view key,
                             std::span<const uint8_t> value);

    /// Read the value associated with a key.
    /// Returns STORAGE_NOT_FOUND if the key does not exist.
    core::Result<std::vector<uint8_t>> read(std::string_view key) const;

    /// Erase a key-value pair. The record is logically deleted (value set
    /// to empty) but not physically removed until compact() is called.
    core::Result<void> erase(std::string_view key);

    /// Check if a key exists in the database.
    [[nodiscard]] bool exists(std::string_view key) const;

    /// Return all keys that begin with the given prefix.
    [[nodiscard]] std::vector<std::string> list_by_prefix(
        std::string_view prefix) const;

    /// Return all key-value pairs whose keys begin with the given prefix.
    [[nodiscard]] std::vector<std::pair<std::string, std::vector<uint8_t>>>
    read_by_prefix(std::string_view prefix) const;

    // -- Maintenance ---------------------------------------------------------

    /// Flush any buffered writes to disk. Rewrites the complete file header
    /// and all records atomically.
    core::Result<void> flush();

    /// Compact the database by rewriting the file without erased records.
    /// This defragments storage and reclaims disk space.
    core::Result<void> compact();

    /// Total number of active (non-erased) records.
    [[nodiscard]] size_t record_count() const;

private:
    mutable std::mutex mutex_;
    std::filesystem::path path_;
    bool is_open_ = false;

    /// In-memory cache of all records. Erased records have empty values.
    std::unordered_map<std::string, std::vector<uint8_t>> records_;

    /// File lock handle (platform-specific).
    std::fstream lock_file_;

    /// Write the complete database to disk atomically (write temp + rename).
    core::Result<void> write_to_disk();

    /// Read and parse the database file into the in-memory cache.
    core::Result<void> read_from_disk();

    /// Acquire a file lock to prevent concurrent access.
    core::Result<void> acquire_lock();

    /// Release the file lock.
    void release_lock();
};

} // namespace wallet
