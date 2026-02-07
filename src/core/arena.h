#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

namespace core {

// ---------------------------------------------------------------------------
// Arena -- bump (region) allocator for batch / per-frame operations
// ---------------------------------------------------------------------------
// Allocations are O(1) pointer bumps.  Individual deallocations are not
// supported -- call `reset()` to reclaim all memory at once (blocks are
// kept for reuse) or `release()` to free every block back to the OS.
//
// NOT thread-safe.  Use one Arena per thread, or protect externally.
// ---------------------------------------------------------------------------
class Arena {
public:
    /// Default initial block size: 64 KiB.
    static constexpr size_t DEFAULT_BLOCK_SIZE = 64 * 1024;

    explicit Arena(size_t initial_size = DEFAULT_BLOCK_SIZE);
    ~Arena();

    Arena(const Arena&)            = delete;
    Arena& operator=(const Arena&) = delete;
    Arena(Arena&&) noexcept;
    Arena& operator=(Arena&&) noexcept;

    // -- Allocation ----------------------------------------------------------

    /// Allocate `size` bytes with the given alignment.
    /// @throws std::bad_alloc on failure.
    void* allocate(size_t size,
                   size_t alignment = alignof(std::max_align_t));

    /// Allocate and construct a single object of type T.
    /// The object is NOT destroyed when the arena is reset/released;
    /// use only for trivially-destructible types or types whose
    /// destruction can be safely skipped.
    template<typename T, typename... Args>
    T* create(Args&&... args) {
        void* mem = allocate(sizeof(T), alignof(T));
        return ::new (mem) T(std::forward<Args>(args)...);
    }

    /// Allocate a contiguous array of `count` default-initialised T's.
    /// Elements are default-constructed (zero for arithmetic types).
    template<typename T>
    std::span<T> allocate_array(size_t count) {
        if (count == 0) return {};
        void* mem = allocate(sizeof(T) * count, alignof(T));
        T* ptr = static_cast<T*>(mem);
        if constexpr (std::is_trivially_default_constructible_v<T>) {
            std::memset(mem, 0, sizeof(T) * count);
        } else {
            for (size_t i = 0; i < count; ++i) {
                ::new (ptr + i) T();
            }
        }
        return {ptr, count};
    }

    // -- Lifetime ------------------------------------------------------------

    /// Reset all allocations.  Memory blocks are kept for reuse so that
    /// subsequent allocation bursts do not hit the OS allocator.
    void reset();

    /// Free every memory block back to the system.  The arena returns to
    /// its just-constructed state (no allocated blocks).
    void release();

    // -- Statistics -----------------------------------------------------------

    /// Total bytes allocated from the OS (sum of all block capacities).
    [[nodiscard]] size_t bytes_allocated() const noexcept;

    /// Bytes actually handed out to callers via allocate().
    [[nodiscard]] size_t bytes_used() const noexcept;

    // -- Snapshot (for ScopedArena) ------------------------------------------

    /// Opaque snapshot of the arena's current allocation state.
    struct Checkpoint {
        size_t block_index;     ///< Index of the current block.
        size_t offset;          ///< Offset within that block.
        size_t total_used;      ///< bytes_used at snapshot time.
    };

    /// Capture the current state.
    [[nodiscard]] Checkpoint checkpoint() const noexcept;

    /// Restore to a previously captured state.  Any memory allocated
    /// after the checkpoint is conceptually freed (pointers become
    /// invalid).  Blocks beyond the checkpoint's block are not released
    /// -- they remain available for future allocations.
    void restore(const Checkpoint& cp) noexcept;

private:
    /// A single contiguous memory block.
    struct Block {
        std::unique_ptr<uint8_t[]> data;
        size_t capacity;
        size_t used;
    };

    /// Ensure there is room for at least `size` bytes (after alignment
    /// adjustment) in the current block, or allocate a new one.
    void ensure_space(size_t size, size_t alignment);

    /// Compute the next block size (doubling strategy).
    size_t next_block_size(size_t required) const;

    /// Align `offset` up to `alignment`.
    static size_t align_up(size_t offset, size_t alignment) noexcept {
        return (offset + alignment - 1) & ~(alignment - 1);
    }

    std::vector<Block> blocks_;
    size_t current_block_{0};       ///< Index of the active block.
    size_t initial_size_;           ///< Configured initial block size.
    size_t total_used_{0};          ///< Running total of bytes_used.
};

// ---------------------------------------------------------------------------
// ArenaAllocator<T> -- STL-compatible allocator backed by an Arena
// ---------------------------------------------------------------------------
// Allows use with std::vector<T, ArenaAllocator<T>>, std::string, etc.
// `deallocate` is a no-op; memory is reclaimed when the arena is
// reset/released.
// ---------------------------------------------------------------------------
template<typename T>
class ArenaAllocator {
public:
    using value_type = T;

    /// Construct from an arena reference.  The arena must outlive all
    /// containers that use this allocator.
    explicit ArenaAllocator(Arena& arena) noexcept : arena_(&arena) {}

    template<typename U>
    ArenaAllocator(const ArenaAllocator<U>& other) noexcept  // NOLINT
        : arena_(other.arena_) {}

    T* allocate(size_t n) {
        return static_cast<T*>(
            arena_->allocate(n * sizeof(T), alignof(T)));
    }

    void deallocate(T* /*ptr*/, size_t /*n*/) noexcept {
        // No-op.  Arena memory is freed in bulk.
    }

    template<typename U>
    bool operator==(const ArenaAllocator<U>& other) const noexcept {
        return arena_ == other.arena_;
    }

    template<typename U>
    bool operator!=(const ArenaAllocator<U>& other) const noexcept {
        return arena_ != other.arena_;
    }

private:
    Arena* arena_;

    template<typename U>
    friend class ArenaAllocator;
};

// ---------------------------------------------------------------------------
// ScopedArena -- RAII guard that restores arena state on scope exit
// ---------------------------------------------------------------------------
// Captures a checkpoint on construction and restores it on destruction.
// Useful for temporary per-operation allocations:
//
//   void process(Arena& arena) {
//       ScopedArena scope(arena);
//       auto* buf = arena.create<Buffer>(1024);
//       ...
//   }  // arena reverts to pre-scope state
// ---------------------------------------------------------------------------
class ScopedArena {
public:
    explicit ScopedArena(Arena& arena) noexcept
        : arena_(arena)
        , checkpoint_(arena.checkpoint()) {}

    ~ScopedArena() {
        arena_.restore(checkpoint_);
    }

    ScopedArena(const ScopedArena&)            = delete;
    ScopedArena& operator=(const ScopedArena&) = delete;
    ScopedArena(ScopedArena&&)                 = delete;
    ScopedArena& operator=(ScopedArena&&)      = delete;

private:
    Arena&            arena_;
    Arena::Checkpoint checkpoint_;
};

}  // namespace core
