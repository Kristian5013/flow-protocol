// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/arena.h"

#include <algorithm>
#include <cstring>
#include <new>
#include <utility>

namespace core {

// ---------------------------------------------------------------------------
// Construction / destruction / move
// ---------------------------------------------------------------------------

Arena::Arena(size_t initial_size)
    : initial_size_(initial_size > 0 ? initial_size : DEFAULT_BLOCK_SIZE) {}

Arena::~Arena() {
    release();
}

Arena::Arena(Arena&& other) noexcept
    : blocks_(std::move(other.blocks_))
    , current_block_(other.current_block_)
    , initial_size_(other.initial_size_)
    , total_used_(other.total_used_) {
    other.current_block_ = 0;
    other.total_used_ = 0;
}

Arena& Arena::operator=(Arena&& other) noexcept {
    if (this != &other) {
        release();
        blocks_ = std::move(other.blocks_);
        current_block_ = other.current_block_;
        initial_size_ = other.initial_size_;
        total_used_ = other.total_used_;
        other.current_block_ = 0;
        other.total_used_ = 0;
    }
    return *this;
}

// ---------------------------------------------------------------------------
// allocate -- bump-pointer allocation with alignment
// ---------------------------------------------------------------------------

void* Arena::allocate(size_t size, size_t alignment) {
    if (size == 0) {
        size = 1;  // Always return a unique pointer.
    }

    ensure_space(size, alignment);

    Block& block = blocks_[current_block_];
    size_t aligned_offset = align_up(block.used, alignment);

    // The block may not have enough room after alignment padding.
    // ensure_space should have handled this, but verify.
    if (aligned_offset + size > block.capacity) {
        // Need a new block -- this can happen when alignment padding
        // consumed the headroom that ensure_space thought was enough.
        // Allocate a fresh block that definitely fits.
        size_t required = size + alignment;  // worst-case padding
        size_t block_size = next_block_size(required);
        Block new_block;
        new_block.data = std::make_unique<uint8_t[]>(block_size);
        new_block.capacity = block_size;
        new_block.used = 0;

        // Insert after current_block_ so that earlier blocks are not
        // disturbed (important for checkpoint/restore ordering).
        current_block_++;
        if (current_block_ < blocks_.size()) {
            // There is a recycled block here; replace it.
            blocks_[current_block_] = std::move(new_block);
        } else {
            blocks_.push_back(std::move(new_block));
        }

        Block& fresh = blocks_[current_block_];
        aligned_offset = align_up(fresh.used, alignment);

        void* ptr = fresh.data.get() + aligned_offset;
        fresh.used = aligned_offset + size;
        total_used_ += aligned_offset + size;
        return ptr;
    }

    void* ptr = block.data.get() + aligned_offset;
    size_t consumed = (aligned_offset + size) - block.used;
    block.used = aligned_offset + size;
    total_used_ += consumed;
    return ptr;
}

// ---------------------------------------------------------------------------
// reset / release
// ---------------------------------------------------------------------------

void Arena::reset() {
    for (auto& block : blocks_) {
        block.used = 0;
    }
    current_block_ = 0;
    total_used_ = 0;
}

void Arena::release() {
    blocks_.clear();
    current_block_ = 0;
    total_used_ = 0;
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

size_t Arena::bytes_allocated() const noexcept {
    size_t total = 0;
    for (const auto& block : blocks_) {
        total += block.capacity;
    }
    return total;
}

size_t Arena::bytes_used() const noexcept {
    return total_used_;
}

// ---------------------------------------------------------------------------
// Checkpoint / restore
// ---------------------------------------------------------------------------

Arena::Checkpoint Arena::checkpoint() const noexcept {
    Checkpoint cp;
    cp.block_index = current_block_;
    cp.offset = blocks_.empty() ? 0 : blocks_[current_block_].used;
    cp.total_used = total_used_;
    return cp;
}

void Arena::restore(const Checkpoint& cp) noexcept {
    if (blocks_.empty()) return;

    // Reset blocks after the checkpoint's block.
    for (size_t i = cp.block_index + 1; i <= current_block_; ++i) {
        if (i < blocks_.size()) {
            blocks_[i].used = 0;
        }
    }

    // Restore the checkpoint block's offset.
    if (cp.block_index < blocks_.size()) {
        blocks_[cp.block_index].used = cp.offset;
    }

    current_block_ = cp.block_index;
    total_used_ = cp.total_used;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

void Arena::ensure_space(size_t size, size_t alignment) {
    // If there are no blocks yet, allocate the first one.
    if (blocks_.empty()) {
        size_t block_size = std::max(initial_size_, size + alignment);
        Block block;
        block.data = std::make_unique<uint8_t[]>(block_size);
        block.capacity = block_size;
        block.used = 0;
        blocks_.push_back(std::move(block));
        current_block_ = 0;
        return;
    }

    // Check if the current block has enough room.
    Block& cur = blocks_[current_block_];
    size_t aligned_offset = align_up(cur.used, alignment);
    if (aligned_offset + size <= cur.capacity) {
        return;  // Fits in current block.
    }

    // Try to reuse the next existing block (from a previous reset cycle).
    if (current_block_ + 1 < blocks_.size()) {
        Block& next = blocks_[current_block_ + 1];
        size_t next_aligned = align_up(next.used, alignment);
        if (next_aligned + size <= next.capacity) {
            current_block_++;
            return;
        }
        // The recycled block is too small.  Replace it.
        size_t required = size + alignment;
        size_t block_size = next_block_size(required);
        next.data = std::make_unique<uint8_t[]>(block_size);
        next.capacity = block_size;
        next.used = 0;
        current_block_++;
        return;
    }

    // Need a brand-new block.
    size_t required = size + alignment;
    size_t block_size = next_block_size(required);
    Block block;
    block.data = std::make_unique<uint8_t[]>(block_size);
    block.capacity = block_size;
    block.used = 0;
    blocks_.push_back(std::move(block));
    current_block_ = blocks_.size() - 1;
}

size_t Arena::next_block_size(size_t required) const {
    // Doubling strategy: the next block is at least twice the previous,
    // but also at least `required` bytes and at least `initial_size_`.
    size_t prev_cap = blocks_.empty()
                          ? initial_size_
                          : blocks_.back().capacity;
    size_t doubled = prev_cap * 2;
    return std::max({doubled, required, initial_size_});
}

}  // namespace core
