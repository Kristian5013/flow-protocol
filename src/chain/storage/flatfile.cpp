// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/storage/flatfile.h"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <utility>

namespace chain { namespace storage {

FlatFile::FlatFile(const std::filesystem::path& path)
    : path_(path) {}

FlatFile::~FlatFile() {
    close();
}

FlatFile::FlatFile(FlatFile&& other) noexcept
    : path_(std::move(other.path_)),
      file_(std::move(other.file_)),
      current_size_(other.current_size_) {
    other.current_size_ = 0;
}

FlatFile& FlatFile::operator=(FlatFile&& other) noexcept {
    if (this != &other) {
        close();
        path_ = std::move(other.path_);
        file_ = std::move(other.file_);
        current_size_ = other.current_size_;
        other.current_size_ = 0;
    }
    return *this;
}

core::Result<void> FlatFile::open() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (file_.is_open()) {
        return core::make_ok();
    }

    // Ensure the parent directory exists.
    std::error_code ec;
    auto parent = path_.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "Failed to create directory: " + parent.string() +
                " (" + ec.message() + ")");
        }
    }

    // If the file does not exist, create it first by opening in out mode,
    // then close and reopen for read+write.
    if (!std::filesystem::exists(path_, ec)) {
        std::ofstream creator(path_, std::ios::binary);
        if (!creator.is_open()) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "Failed to create file: " + path_.string());
        }
        creator.close();
    }

    // Open for both reading and writing in binary mode.
    file_.open(path_,
               std::ios::binary | std::ios::in | std::ios::out);
    if (!file_.is_open()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to open file: " + path_.string());
    }

    // Determine the current file size by seeking to the end.
    file_.seekg(0, std::ios::end);
    if (file_.fail()) {
        file_.close();
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to determine file size: " + path_.string());
    }
    current_size_ = static_cast<int64_t>(file_.tellg());

    return core::make_ok();
}

void FlatFile::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_.is_open()) {
        file_.close();
    }
    current_size_ = 0;
}

bool FlatFile::is_open() const {
    return file_.is_open();
}

core::Result<int64_t> FlatFile::append(std::span<const uint8_t> data) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!file_.is_open()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "File not open for append: " + path_.string());
    }

    // Seek to the end of the file.
    file_.seekp(0, std::ios::end);
    if (file_.fail()) {
        file_.clear();
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to seek to end of file: " + path_.string());
    }

    int64_t offset = static_cast<int64_t>(file_.tellp());

    // Write the data.
    file_.write(reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size()));
    if (file_.fail()) {
        file_.clear();
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to write to file: " + path_.string());
    }

    current_size_ = offset + static_cast<int64_t>(data.size());
    return offset;
}

core::Result<std::vector<uint8_t>> FlatFile::read_at(int64_t offset,
                                                      size_t length) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!file_.is_open()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "File not open for read: " + path_.string());
    }

    if (offset < 0) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Negative read offset");
    }

    if (offset + static_cast<int64_t>(length) > current_size_) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Read past end of file: offset=" + std::to_string(offset) +
            " length=" + std::to_string(length) +
            " file_size=" + std::to_string(current_size_));
    }

    // Seek to the requested position.
    file_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (file_.fail()) {
        file_.clear();
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to seek in file: " + path_.string());
    }

    // Read the requested bytes.
    std::vector<uint8_t> buffer(length);
    file_.read(reinterpret_cast<char*>(buffer.data()),
               static_cast<std::streamsize>(length));
    if (file_.fail()) {
        file_.clear();
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to read from file: " + path_.string());
    }

    return buffer;
}

core::Result<int64_t> FlatFile::size() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!file_.is_open()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "File not open: " + path_.string());
    }

    return current_size_;
}

core::Result<void> FlatFile::flush() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!file_.is_open()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "File not open for flush: " + path_.string());
    }

    file_.flush();
    if (file_.fail()) {
        file_.clear();
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to flush file: " + path_.string());
    }

    return core::make_ok();
}

core::Result<void> FlatFile::truncate(int64_t new_size) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!file_.is_open()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "File not open for truncate: " + path_.string());
    }

    if (new_size < 0) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Invalid truncate size: " + std::to_string(new_size));
    }

    // Flush pending writes before truncation.
    file_.flush();

    // Close the fstream; std::fstream has no truncate support.
    file_.close();

    // Use std::filesystem::resize_file for cross-platform truncation.
    std::error_code ec;
    std::filesystem::resize_file(path_,
                                 static_cast<std::uintmax_t>(new_size), ec);
    if (ec) {
        // Attempt to reopen before returning the error.
        file_.open(path_, std::ios::binary | std::ios::in | std::ios::out);
        if (file_.is_open()) {
            file_.seekg(0, std::ios::end);
            current_size_ = static_cast<int64_t>(file_.tellg());
        }
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to truncate file: " + path_.string() +
            " (" + ec.message() + ")");
    }

    // Reopen the file.
    file_.open(path_, std::ios::binary | std::ios::in | std::ios::out);
    if (!file_.is_open()) {
        current_size_ = 0;
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "Failed to reopen file after truncate: " + path_.string());
    }

    current_size_ = new_size;
    return core::make_ok();
}

const std::filesystem::path& FlatFile::path() const {
    return path_;
}

}} // namespace chain::storage
