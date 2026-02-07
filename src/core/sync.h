#pragma once

// Copyright (c) FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <atomic>
#include <cstdint>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>

#ifndef NDEBUG
#include <vector>
#endif

namespace core {

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------

class Mutex;
class SharedMutex;

// ---------------------------------------------------------------------------
// Deadlock detection (debug builds only)
// ---------------------------------------------------------------------------

#ifndef NDEBUG

/// Called internally when a potential deadlock (lock-order violation) is
/// detected.  Logs the offending mutex names to stderr.
void potential_deadlock_detected(
    const std::string& held_name, uint64_t held_order,
    const std::string& requested_name, uint64_t requested_order);

/// Push a mutex onto the current thread's held-lock stack and verify that
/// lock ordering is not violated.
void debug_lock_push(const Mutex* mtx);

/// Remove a mutex from the current thread's held-lock stack.
void debug_lock_pop(const Mutex* mtx);

/// Generate a globally unique, monotonically increasing order ID.
uint64_t next_mutex_order_id();

#endif  // !NDEBUG

// ---------------------------------------------------------------------------
// Mutex
// ---------------------------------------------------------------------------

/// Drop-in wrapper around std::mutex that participates in deadlock detection
/// in debug builds.  Each Mutex has a human-readable name and a unique order
/// ID; the debug layer enforces that locks are always acquired in increasing
/// order ID on any given thread.
class Mutex {
public:
    explicit Mutex(std::string_view name = "")
        : name_(name)
#ifndef NDEBUG
        , order_(next_mutex_order_id())
#endif
    {
    }

    ~Mutex() = default;

    Mutex(const Mutex&) = delete;
    Mutex& operator=(const Mutex&) = delete;

    void lock()
    {
#ifndef NDEBUG
        debug_lock_push(this);
#endif
        mutex_.lock();
    }

    void unlock()
    {
        mutex_.unlock();
#ifndef NDEBUG
        debug_lock_pop(this);
#endif
    }

    bool try_lock()
    {
        bool acquired = mutex_.try_lock();
#ifndef NDEBUG
        if (acquired) {
            debug_lock_push(this);
        }
#endif
        return acquired;
    }

    const std::string& name() const noexcept { return name_; }

#ifndef NDEBUG
    uint64_t order() const noexcept { return order_; }
#endif

private:
    std::mutex mutex_;
    std::string name_;
#ifndef NDEBUG
    uint64_t order_;
#endif
};

// ---------------------------------------------------------------------------
// SharedMutex
// ---------------------------------------------------------------------------

/// Drop-in wrapper around std::shared_mutex.  In debug builds the exclusive
/// lock/unlock paths participate in deadlock detection.  Shared (reader)
/// paths do not enforce ordering because readers do not block each other.
class SharedMutex {
public:
    explicit SharedMutex(std::string_view name = "")
        : name_(name)
#ifndef NDEBUG
        , order_(next_mutex_order_id())
#endif
    {
    }

    ~SharedMutex() = default;

    SharedMutex(const SharedMutex&) = delete;
    SharedMutex& operator=(const SharedMutex&) = delete;

    // Exclusive (writer) operations ------------------------------------

    void lock()
    {
#ifndef NDEBUG
        debug_lock_push(reinterpret_cast<const Mutex*>(this));
#endif
        mutex_.lock();
    }

    void unlock()
    {
        mutex_.unlock();
#ifndef NDEBUG
        debug_lock_pop(reinterpret_cast<const Mutex*>(this));
#endif
    }

    bool try_lock()
    {
        bool acquired = mutex_.try_lock();
#ifndef NDEBUG
        if (acquired) {
            debug_lock_push(reinterpret_cast<const Mutex*>(this));
        }
#endif
        return acquired;
    }

    // Shared (reader) operations ---------------------------------------

    void lock_shared()
    {
        mutex_.lock_shared();
    }

    void unlock_shared()
    {
        mutex_.unlock_shared();
    }

    bool try_lock_shared()
    {
        return mutex_.try_lock_shared();
    }

    const std::string& name() const noexcept { return name_; }

#ifndef NDEBUG
    uint64_t order() const noexcept { return order_; }
#endif

private:
    std::shared_mutex mutex_;
    std::string name_;
#ifndef NDEBUG
    uint64_t order_;
#endif
};

// ---------------------------------------------------------------------------
// UniqueLock  (works with core::Mutex)
// ---------------------------------------------------------------------------

/// RAII lock guard for core::Mutex, analogous to std::unique_lock.
/// Supports deferred locking and try-to-lock semantics.
class UniqueLock {
public:
    /// Immediately lock the mutex.
    explicit UniqueLock(Mutex& mtx)
        : mutex_(&mtx), owns_(false)
    {
        mutex_->lock();
        owns_ = true;
    }

    /// Try-to-lock construction (same tag as std::try_to_lock).
    UniqueLock(Mutex& mtx, std::try_to_lock_t)
        : mutex_(&mtx), owns_(false)
    {
        owns_ = mutex_->try_lock();
    }

    /// Deferred construction -- mutex is associated but not locked.
    UniqueLock(Mutex& mtx, std::defer_lock_t) noexcept
        : mutex_(&mtx), owns_(false)
    {
    }

    ~UniqueLock()
    {
        if (owns_) {
            mutex_->unlock();
        }
    }

    UniqueLock(const UniqueLock&) = delete;
    UniqueLock& operator=(const UniqueLock&) = delete;

    UniqueLock(UniqueLock&& other) noexcept
        : mutex_(other.mutex_), owns_(other.owns_)
    {
        other.mutex_ = nullptr;
        other.owns_ = false;
    }

    UniqueLock& operator=(UniqueLock&& other) noexcept
    {
        if (this != &other) {
            if (owns_) {
                mutex_->unlock();
            }
            mutex_ = other.mutex_;
            owns_ = other.owns_;
            other.mutex_ = nullptr;
            other.owns_ = false;
        }
        return *this;
    }

    void lock()
    {
        mutex_->lock();
        owns_ = true;
    }

    bool try_lock()
    {
        owns_ = mutex_->try_lock();
        return owns_;
    }

    void unlock()
    {
        mutex_->unlock();
        owns_ = false;
    }

    bool owns_lock() const noexcept { return owns_; }
    explicit operator bool() const noexcept { return owns_; }
    Mutex* mutex() const noexcept { return mutex_; }

private:
    Mutex* mutex_;
    bool owns_;
};

// ---------------------------------------------------------------------------
// SharedLock  (works with core::SharedMutex)
// ---------------------------------------------------------------------------

/// RAII shared (reader) lock guard for core::SharedMutex.
class SharedLock {
public:
    explicit SharedLock(SharedMutex& mtx)
        : mutex_(&mtx), owns_(false)
    {
        mutex_->lock_shared();
        owns_ = true;
    }

    SharedLock(SharedMutex& mtx, std::try_to_lock_t)
        : mutex_(&mtx), owns_(false)
    {
        owns_ = mutex_->try_lock_shared();
    }

    SharedLock(SharedMutex& mtx, std::defer_lock_t) noexcept
        : mutex_(&mtx), owns_(false)
    {
    }

    ~SharedLock()
    {
        if (owns_) {
            mutex_->unlock_shared();
        }
    }

    SharedLock(const SharedLock&) = delete;
    SharedLock& operator=(const SharedLock&) = delete;

    SharedLock(SharedLock&& other) noexcept
        : mutex_(other.mutex_), owns_(other.owns_)
    {
        other.mutex_ = nullptr;
        other.owns_ = false;
    }

    SharedLock& operator=(SharedLock&& other) noexcept
    {
        if (this != &other) {
            if (owns_) {
                mutex_->unlock_shared();
            }
            mutex_ = other.mutex_;
            owns_ = other.owns_;
            other.mutex_ = nullptr;
            other.owns_ = false;
        }
        return *this;
    }

    void lock()
    {
        mutex_->lock_shared();
        owns_ = true;
    }

    bool try_lock()
    {
        owns_ = mutex_->try_lock_shared();
        return owns_;
    }

    void unlock()
    {
        mutex_->unlock_shared();
        owns_ = false;
    }

    bool owns_lock() const noexcept { return owns_; }
    explicit operator bool() const noexcept { return owns_; }
    SharedMutex* mutex() const noexcept { return mutex_; }

private:
    SharedMutex* mutex_;
    bool owns_;
};

// ---------------------------------------------------------------------------
// Convenience macros
// ---------------------------------------------------------------------------

/// Helper to produce a unique variable name per source line.
#define CORE_SYNC_CAT_(a, b)  a##b
#define CORE_SYNC_CAT(a, b)   CORE_SYNC_CAT_(a, b)

/// Acquire an exclusive lock on @p cs, scoped to the enclosing block.
/// The variable is named deterministically so two LOCK()s on distinct lines
/// in the same scope will not collide.
#define LOCK(cs) \
    core::UniqueLock CORE_SYNC_CAT(lock_, __LINE__)(cs)

/// Acquire exclusive locks on two mutexes in a globally consistent order
/// (by raw address) to avoid ABBA deadlocks.
#define LOCK2(cs1, cs2)                                                   \
    core::UniqueLock CORE_SYNC_CAT(lock1_, __LINE__)(                     \
        (&(cs1) < &(cs2)) ? (cs1) : (cs2));                              \
    core::UniqueLock CORE_SYNC_CAT(lock2_, __LINE__)(                     \
        (&(cs1) < &(cs2)) ? (cs2) : (cs1))

/// Try to acquire @p cs; the resulting UniqueLock is named @p name.
/// Use `if (name)` to check whether the lock was obtained.
#define TRY_LOCK(cs, name) \
    core::UniqueLock name(cs, std::try_to_lock)

}  // namespace core
