// Copyright (c) FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sync.h"

#ifndef NDEBUG

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <vector>

namespace core {

// ---------------------------------------------------------------------------
// Global monotonic order-ID generator
// ---------------------------------------------------------------------------

/// Every Mutex and SharedMutex receives a unique, monotonically increasing
/// order ID at construction time.  The deadlock detector uses these IDs to
/// enforce that threads always acquire locks in the same relative order.
static std::atomic<uint64_t> g_next_order_id{1};

uint64_t next_mutex_order_id()
{
    return g_next_order_id.fetch_add(1, std::memory_order_relaxed);
}

// ---------------------------------------------------------------------------
// Per-thread held-lock stack
// ---------------------------------------------------------------------------

/// Thread-local stack of pointers to mutexes currently held by this thread,
/// ordered from earliest acquired (front) to most recently acquired (back).
/// We treat Mutex* as an opaque identifier; SharedMutex is reinterpret_cast
/// to Mutex* in the header so it uses the same tracking path.
static thread_local std::vector<const Mutex*> held_locks;

// ---------------------------------------------------------------------------
// Deadlock warning
// ---------------------------------------------------------------------------

void potential_deadlock_detected(
    const std::string& held_name, uint64_t held_order,
    const std::string& requested_name, uint64_t requested_order)
{
    std::fprintf(stderr,
        "ftc: potential deadlock detected!\n"
        "  Thread already holds mutex '%s' (order %llu)\n"
        "  but is trying to acquire mutex '%s' (order %llu)\n"
        "  Locks must be acquired in increasing order ID to prevent "
        "deadlocks.\n",
        held_name.c_str(),
        static_cast<unsigned long long>(held_order),
        requested_name.c_str(),
        static_cast<unsigned long long>(requested_order));
}

// ---------------------------------------------------------------------------
// Debug push / pop
// ---------------------------------------------------------------------------

void debug_lock_push(const Mutex* mtx)
{
    // Check that every mutex we already hold has a strictly lower order ID
    // than the one we are about to acquire.  If not, flag a potential
    // deadlock: some other thread could acquire these two mutexes in the
    // opposite order, leading to a classic ABBA situation.
    const uint64_t new_order = mtx->order();
    const std::string& new_name = mtx->name();

    for (const Mutex* held : held_locks) {
        if (held->order() >= new_order) {
            potential_deadlock_detected(
                held->name(), held->order(),
                new_name, new_order);
            break;  // one warning is sufficient
        }
    }

    held_locks.push_back(mtx);
}

void debug_lock_pop(const Mutex* mtx)
{
    // Remove the mutex from the held-lock stack.  Locks are not always
    // released in strict LIFO order (e.g. when two UniqueLocks go out of
    // scope in an unspecified order), so we search from the back and erase
    // the first match.
    for (auto it = held_locks.rbegin(); it != held_locks.rend(); ++it) {
        if (*it == mtx) {
            // Convert reverse iterator to a regular iterator for erase.
            held_locks.erase(std::next(it).base());
            return;
        }
    }
    // If we get here the mutex was not in the stack -- this would indicate a
    // bug in our tracking, but we silently tolerate it rather than crashing.
}

}  // namespace core

#endif  // !NDEBUG
