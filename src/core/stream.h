#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace core {

// ---------------------------------------------------------------------------
// DataStream -- primary serialization stream backed by std::vector<uint8_t>
// ---------------------------------------------------------------------------
// Provides both write (append) and sequential read (via internal cursor)
// semantics.  Used as the default stream type throughout the serialization
// framework.
// ---------------------------------------------------------------------------
class DataStream {
public:
    // -- Construction -------------------------------------------------------

    DataStream() = default;

    explicit DataStream(std::vector<uint8_t> data)
        : buf_(std::move(data)) {}

    explicit DataStream(std::span<const uint8_t> data)
        : buf_(data.begin(), data.end()) {}

    // -- Write interface ----------------------------------------------------

    void write(std::span<const uint8_t> data) {
        buf_.insert(buf_.end(), data.begin(), data.end());
    }

    // -- Read interface -----------------------------------------------------

    void read(std::span<uint8_t> buf) {
        if (read_pos_ + buf.size() > buf_.size()) {
            throw std::runtime_error(
                "DataStream::read(): attempted read past end of stream");
        }
        std::memcpy(buf.data(), buf_.data() + read_pos_, buf.size());
        read_pos_ += buf.size();
    }

    // -- Size / position queries --------------------------------------------

    /// Total number of bytes in the underlying buffer.
    [[nodiscard]] size_t size() const noexcept { return buf_.size(); }

    /// Number of bytes remaining from the current read position to the end.
    [[nodiscard]] size_t remaining() const noexcept {
        return buf_.size() - read_pos_;
    }

    /// True when the buffer contains no data at all.
    [[nodiscard]] bool empty() const noexcept { return remaining() == 0; }

    /// True when the read cursor has reached the end of the buffer.
    [[nodiscard]] bool eof() const noexcept {
        return read_pos_ >= buf_.size();
    }

    // -- Cursor manipulation ------------------------------------------------

    void skip(size_t n) {
        if (read_pos_ + n > buf_.size()) {
            throw std::runtime_error(
                "DataStream::skip(): attempted skip past end of stream");
        }
        read_pos_ += n;
    }

    void seek(size_t pos) {
        if (pos > buf_.size()) {
            throw std::runtime_error(
                "DataStream::seek(): position past end of stream");
        }
        read_pos_ = pos;
    }

    [[nodiscard]] size_t tell() const noexcept { return read_pos_; }

    // -- Raw access ---------------------------------------------------------

    [[nodiscard]] const uint8_t* data() const noexcept {
        return buf_.data();
    }

    /// Return a view of the data from the current read position onward.
    [[nodiscard]] std::span<const uint8_t> view() const noexcept {
        return std::span<const uint8_t>(
            buf_.data() + read_pos_, buf_.size() - read_pos_);
    }

    /// Move the internal buffer out.  Resets the stream to empty state.
    [[nodiscard]] std::vector<uint8_t> release() {
        read_pos_ = 0;
        return std::move(buf_);
    }

    // -- Mutation ------------------------------------------------------------

    void clear() {
        buf_.clear();
        read_pos_ = 0;
    }

    void reserve(size_t n) { buf_.reserve(n); }

private:
    std::vector<uint8_t> buf_;
    size_t               read_pos_ = 0;
};

// ---------------------------------------------------------------------------
// VectorWriter -- write-only stream that appends to an external vector
// ---------------------------------------------------------------------------
// Does not own the vector; the caller must ensure the referenced vector
// outlives the writer.
// ---------------------------------------------------------------------------
class VectorWriter {
public:
    explicit VectorWriter(std::vector<uint8_t>& vec) : vec_(vec) {}

    void write(std::span<const uint8_t> data) {
        vec_.insert(vec_.end(), data.begin(), data.end());
    }

private:
    std::vector<uint8_t>& vec_;
};

// ---------------------------------------------------------------------------
// SpanReader -- read-only stream over an existing byte span (zero-copy)
// ---------------------------------------------------------------------------
class SpanReader {
public:
    explicit SpanReader(std::span<const uint8_t> data)
        : data_(data) {}

    void read(std::span<uint8_t> buf) {
        if (pos_ + buf.size() > data_.size()) {
            throw std::runtime_error(
                "SpanReader::read(): attempted read past end of span");
        }
        std::memcpy(buf.data(), data_.data() + pos_, buf.size());
        pos_ += buf.size();
    }

    [[nodiscard]] size_t remaining() const noexcept {
        return data_.size() - pos_;
    }

    [[nodiscard]] bool eof() const noexcept {
        return pos_ >= data_.size();
    }

private:
    std::span<const uint8_t> data_;
    size_t                   pos_ = 0;
};

}  // namespace core
