#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <span>
#include <vector>

namespace chain { namespace storage {

// ---------------------------------------------------------------------------
// FlatFile -- low-level flat file abstraction for sequential and random I/O
// ---------------------------------------------------------------------------
// Provides append-only writes (returning the offset), random-access reads,
// and basic file management (flush, truncate).  Thread-safe via an internal
// mutex.  Uses std::fstream with binary mode for cross-platform portability.
// ---------------------------------------------------------------------------
class FlatFile {
public:
    explicit FlatFile(const std::filesystem::path& path);
    ~FlatFile();

    FlatFile(const FlatFile&) = delete;
    FlatFile& operator=(const FlatFile&) = delete;
    FlatFile(FlatFile&&) noexcept;
    FlatFile& operator=(FlatFile&&) noexcept;

    /// Open the file (creates if it does not exist).
    core::Result<void> open();

    /// Close the file.
    void close();

    /// Returns true if the file is currently open.
    [[nodiscard]] bool is_open() const;

    /// Append data to the end of the file.
    /// Returns the byte offset where the data was written.
    core::Result<int64_t> append(std::span<const uint8_t> data);

    /// Read `length` bytes starting at byte offset `offset`.
    core::Result<std::vector<uint8_t>> read_at(int64_t offset, size_t length);

    /// Return the current file size in bytes.
    core::Result<int64_t> size() const;

    /// Flush buffered data to the underlying storage device.
    core::Result<void> flush();

    /// Truncate the file to `new_size` bytes (for crash recovery).
    core::Result<void> truncate(int64_t new_size);

    /// Return the file path.
    [[nodiscard]] const std::filesystem::path& path() const;

private:
    std::filesystem::path path_;
    std::fstream file_;
    int64_t current_size_ = 0;
    mutable std::mutex mutex_;
};

}} // namespace chain::storage
