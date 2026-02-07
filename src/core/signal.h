#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>

namespace core {

// ---------------------------------------------------------------------------
// Global shutdown signalling
// ---------------------------------------------------------------------------

/// Atomic flag indicating that a shutdown has been requested.
/// Written by OS signal handlers and request_shutdown(); read lock-free
/// by any thread via shutdown_requested().
inline std::atomic<bool> g_shutdown_requested{false};

/// Condition variable used by wait_for_shutdown() to sleep until
/// a shutdown signal arrives.
inline std::condition_variable g_shutdown_cv;

/// Mutex protecting g_shutdown_cv.
inline std::mutex g_shutdown_mutex;

/// Install OS-level signal handlers for graceful shutdown.
/// On POSIX: SIGINT, SIGTERM, SIGHUP.
/// On Windows: SetConsoleCtrlHandler for CTRL_C_EVENT, CTRL_BREAK_EVENT,
///             CTRL_CLOSE_EVENT.
/// Safe to call more than once (subsequent calls are no-ops).
void init_signal_handlers();

/// Returns true if a shutdown has been requested via an OS signal or
/// a call to request_shutdown().
[[nodiscard]] bool shutdown_requested() noexcept;

/// Programmatically request a shutdown (wakes any wait_for_shutdown()
/// callers).
void request_shutdown();

/// Block the calling thread until shutdown_requested() becomes true.
void wait_for_shutdown();

/// Reset the shutdown flag and condition variable.  Intended for use
/// in unit tests only.
void reset_shutdown();

// ---------------------------------------------------------------------------
// SignalSet  --  generic (non-OS) event / notification primitive
// ---------------------------------------------------------------------------
class SignalSet {
public:
    SignalSet() = default;

    // Non-copyable, non-movable (contains mutex + cv).
    SignalSet(const SignalSet&) = delete;
    SignalSet& operator=(const SignalSet&) = delete;
    SignalSet(SignalSet&&) = delete;
    SignalSet& operator=(SignalSet&&) = delete;

    /// Wake one thread blocked in wait() or wait_for().
    void notify_one();

    /// Wake all threads blocked in wait() or wait_for().
    void notify_all();

    /// Block until notified.
    void wait();

    /// Block until notified or @p timeout expires.
    /// @return true if notified, false on timeout.
    bool wait_for(std::chrono::milliseconds timeout);

    /// Reset to the un-notified state so that subsequent wait()
    /// calls will block again.
    void reset();

private:
    std::mutex              mutex_;
    std::condition_variable cv_;
    bool                    notified_{false};
};

} // namespace core
