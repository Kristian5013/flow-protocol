#include "core/signal.h"
#include "core/logging.h"

#ifdef _WIN32
#   ifndef WIN32_LEAN_AND_MEAN
#       define WIN32_LEAN_AND_MEAN
#   endif
#   include <windows.h>
#else
#   include <csignal>
#   include <cstdlib>  // _exit
#   include <cstring>  // std::memset
#   include <unistd.h> // write, STDERR_FILENO
#endif

namespace core {

// ---------------------------------------------------------------------------
// Global shutdown helpers
// ---------------------------------------------------------------------------

bool shutdown_requested() noexcept {
    return g_shutdown_requested.load(std::memory_order_acquire);
}

void request_shutdown() {
    bool expected = false;
    if (g_shutdown_requested.compare_exchange_strong(
            expected, true, std::memory_order_release,
            std::memory_order_relaxed)) {
        LOG_INFO(core::LogCategory::NONE, "Shutdown requested");
        std::lock_guard<std::mutex> lock(g_shutdown_mutex);
        g_shutdown_cv.notify_all();
    }
}

void wait_for_shutdown() {
    std::unique_lock<std::mutex> lock(g_shutdown_mutex);
    g_shutdown_cv.wait(lock, [] {
        return g_shutdown_requested.load(std::memory_order_acquire);
    });
}

void reset_shutdown() {
    g_shutdown_requested.store(false, std::memory_order_release);
}

// ---------------------------------------------------------------------------
// Platform-specific OS signal handler installation
// ---------------------------------------------------------------------------

#ifdef _WIN32

// ---- Windows implementation -----------------------------------------------

static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    switch (ctrl_type) {
        case CTRL_C_EVENT:
            LOG_INFO(core::LogCategory::NONE, "Received CTRL+C");
            request_shutdown();
            return TRUE;
        case CTRL_BREAK_EVENT:
            LOG_INFO(core::LogCategory::NONE, "Received CTRL+BREAK");
            request_shutdown();
            return TRUE;
        case CTRL_CLOSE_EVENT:
            LOG_INFO(core::LogCategory::NONE, "Received console close event");
            request_shutdown();
            return TRUE;
        case CTRL_LOGOFF_EVENT:
            // Ignore logoff when running as a service.
            return FALSE;
        case CTRL_SHUTDOWN_EVENT:
            LOG_INFO(core::LogCategory::NONE, "Received system shutdown event");
            request_shutdown();
            return TRUE;
        default:
            return FALSE;
    }
}

void init_signal_handlers() {
    static std::once_flag flag;
    std::call_once(flag, [] {
        if (!SetConsoleCtrlHandler(console_ctrl_handler, TRUE)) {
            LOG_ERROR(core::LogCategory::NONE,
                      "Failed to set console control handler");
        }
    });
}

#else

// ---- POSIX implementation -------------------------------------------------

static void posix_signal_handler(int signum) {
    // Signal handlers must be async-signal-safe.  We must NOT call
    // LOG_INFO, lock mutexes, or do anything that could deadlock
    // (e.g. if the main thread holds the logger mutex when the signal
    // arrives, calling LOG_INFO here would deadlock).
    //
    // First Ctrl+C: set the atomic flag to request graceful shutdown.
    // Second Ctrl+C: force immediate exit (shutdown may be stuck).
    if (g_shutdown_requested.load(std::memory_order_relaxed)) {
        // Already shutting down — force exit on second signal.
        const char msg[] = "\nForced shutdown (second signal received)\n";
        (void)!write(STDERR_FILENO, msg, sizeof(msg) - 1);
        _exit(1);
    }

    // Set the flag — async-signal-safe (atomic store).
    g_shutdown_requested.store(true, std::memory_order_release);

    // Wake wait_for_shutdown().  mutex lock + cv notify are technically
    // not async-signal-safe, but in practice work on Linux/glibc and
    // are the standard pattern for this shutdown mechanism.
    {
        std::lock_guard<std::mutex> lock(g_shutdown_mutex);
        g_shutdown_cv.notify_all();
    }

    (void)signum;
}

void init_signal_handlers() {
    static std::once_flag flag;
    std::call_once(flag, [] {
        struct sigaction sa;
        std::memset(&sa, 0, sizeof(sa));
        sa.sa_handler = posix_signal_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;

        if (sigaction(SIGINT, &sa, nullptr) != 0) {
            LOG_ERROR(core::LogCategory::NONE, "Failed to install SIGINT handler");
        }
        if (sigaction(SIGTERM, &sa, nullptr) != 0) {
            LOG_ERROR(core::LogCategory::NONE, "Failed to install SIGTERM handler");
        }
        if (sigaction(SIGHUP, &sa, nullptr) != 0) {
            LOG_ERROR(core::LogCategory::NONE, "Failed to install SIGHUP handler");
        }
    });
}

#endif  // _WIN32

// ---------------------------------------------------------------------------
// SignalSet implementation
// ---------------------------------------------------------------------------

void SignalSet::notify_one() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        notified_ = true;
    }
    cv_.notify_one();
}

void SignalSet::notify_all() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        notified_ = true;
    }
    cv_.notify_all();
}

void SignalSet::wait() {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this] { return notified_; });
}

bool SignalSet::wait_for(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    return cv_.wait_for(lock, timeout, [this] { return notified_; });
}

void SignalSet::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    notified_ = false;
}

} // namespace core
