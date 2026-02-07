#pragma once

// Copyright (c) FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace core {

// ---------------------------------------------------------------------------
// Thread naming
// ---------------------------------------------------------------------------

/// Set the name of the calling thread (visible in debuggers and OS tools).
/// On Windows uses SetThreadDescription; on POSIX uses pthread_setname_np.
void set_thread_name(std::string_view name);

/// Retrieve the name previously set for the calling thread.
/// Returns an empty string if no name was set or if the OS query fails.
std::string get_thread_name();

// ---------------------------------------------------------------------------
// CPU topology
// ---------------------------------------------------------------------------

/// Return the number of logical CPU cores.  Falls back to 1 when the
/// hardware concurrency value is unavailable.
int get_num_cores();

// ---------------------------------------------------------------------------
// Thread-local singleton helper
// ---------------------------------------------------------------------------

/// Return a reference to a thread-local default-constructed instance of T.
/// Each thread gets its own independent copy.
template<typename T>
T& thread_local_instance()
{
    thread_local T instance;
    return instance;
}

// ---------------------------------------------------------------------------
// ThreadGroup
// ---------------------------------------------------------------------------

/// Manages a collection of named threads with cooperative interruption.
///
/// Threads spawned through a ThreadGroup share a single atomic flag that
/// can be raised via `interrupt_all()`.  Individual thread functions are
/// expected to poll an external condition (or use the flag exposed by the
/// group) to honour the request.
class ThreadGroup {
public:
    ThreadGroup() = default;
    ~ThreadGroup();

    ThreadGroup(const ThreadGroup&) = delete;
    ThreadGroup& operator=(const ThreadGroup&) = delete;

    /// Spawn a new thread, assign it the given name, then invoke @p func.
    void create_thread(std::string name, std::function<void()> func);

    /// Block until every managed thread has completed.
    void join_all();

    /// Return the number of threads currently managed by the group.
    size_t size() const;

    /// Raise the shared interruption flag.  Threads must cooperatively
    /// check `is_interrupted()` and exit their work loop.
    void interrupt_all();

    /// Query whether `interrupt_all()` has been called.
    bool is_interrupted() const noexcept
    {
        return interrupted_.load(std::memory_order_acquire);
    }

private:
    mutable std::mutex mutex_;
    std::vector<std::thread> threads_;
    std::atomic<bool> interrupted_{false};
};

// ---------------------------------------------------------------------------
// TraceThread
// ---------------------------------------------------------------------------

/// RAII wrapper that starts a named thread with automatic start/end logging.
///
/// The thread name is set via `set_thread_name` and diagnostic messages are
/// emitted when the thread begins and terminates (including on exception).
/// TraceThread is move-only; the destructor joins the thread if joinable.
class TraceThread {
public:
    /// Construct and immediately start the thread.
    /// @param name  Human-readable name for logging and OS-level thread name.
    /// @param func  Callable to execute on the new thread.
    TraceThread(std::string name, std::function<void()> func);

    ~TraceThread();

    TraceThread(TraceThread&& other) noexcept;
    TraceThread& operator=(TraceThread&& other) noexcept;

    TraceThread(const TraceThread&) = delete;
    TraceThread& operator=(const TraceThread&) = delete;

    /// Block until the thread completes.
    void join();

    /// Return true if the thread object is associated with an active thread.
    bool joinable() const noexcept;

private:
    std::string name_;
    std::thread thread_;
};

}  // namespace core
