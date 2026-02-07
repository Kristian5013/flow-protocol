// Copyright (c) FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "thread.h"

#include <algorithm>
#include <cstdio>
#include <exception>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <pthread.h>
#endif

namespace core {

// ---------------------------------------------------------------------------
// Thread naming -- platform-specific
// ---------------------------------------------------------------------------

void set_thread_name(std::string_view name)
{
#ifdef _WIN32
    // SetThreadDescription is available since Windows 10 1607.
    // Convert UTF-8 name to a wide string.
    if (name.empty()) return;

    int wide_len = MultiByteToWideChar(
        CP_UTF8, 0, name.data(), static_cast<int>(name.size()), nullptr, 0);
    if (wide_len <= 0) return;

    std::wstring wide_name(static_cast<size_t>(wide_len), L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0, name.data(), static_cast<int>(name.size()),
        wide_name.data(), wide_len);

    ::SetThreadDescription(::GetCurrentThread(), wide_name.c_str());
#else
    // pthread_setname_np on Linux accepts at most 15 characters + NUL.
    // macOS allows longer names, but we truncate uniformly for portability.
    constexpr size_t MAX_PTHREAD_NAME = 15;
    std::string truncated{name.substr(0, MAX_PTHREAD_NAME)};

#ifdef __APPLE__
    // macOS: pthread_setname_np takes only a const char*.
    pthread_setname_np(truncated.c_str());
#else
    // Linux / FreeBSD: pthread_setname_np(pthread_t, const char*).
    pthread_setname_np(pthread_self(), truncated.c_str());
#endif
#endif  // _WIN32
}

std::string get_thread_name()
{
#ifdef _WIN32
    PWSTR wide_name = nullptr;
    HRESULT hr = ::GetThreadDescription(::GetCurrentThread(), &wide_name);
    if (FAILED(hr) || wide_name == nullptr) return {};

    int utf8_len = WideCharToMultiByte(
        CP_UTF8, 0, wide_name, -1, nullptr, 0, nullptr, nullptr);
    if (utf8_len <= 0) {
        ::LocalFree(wide_name);
        return {};
    }

    std::string result(static_cast<size_t>(utf8_len - 1), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, wide_name, -1,
        result.data(), utf8_len, nullptr, nullptr);

    ::LocalFree(wide_name);
    return result;
#else
    char buf[64]{};

#ifdef __APPLE__
    if (pthread_getname_np(pthread_self(), buf, sizeof(buf)) != 0) return {};
#else
    if (pthread_getname_np(pthread_self(), buf, sizeof(buf)) != 0) return {};
#endif

    return std::string(buf);
#endif  // _WIN32
}

// ---------------------------------------------------------------------------
// CPU topology
// ---------------------------------------------------------------------------

int get_num_cores()
{
    unsigned n = std::thread::hardware_concurrency();
    return (n > 0) ? static_cast<int>(n) : 1;
}

// ---------------------------------------------------------------------------
// ThreadGroup
// ---------------------------------------------------------------------------

ThreadGroup::~ThreadGroup()
{
    join_all();
}

void ThreadGroup::create_thread(std::string name, std::function<void()> func)
{
    std::lock_guard<std::mutex> guard(mutex_);
    threads_.emplace_back(
        [n = std::move(name), f = std::move(func)]() {
            set_thread_name(n);
            try {
                f();
            } catch (const std::exception& e) {
                std::fprintf(stderr,
                    "ftc: exception in thread '%s': %s\n",
                    n.c_str(), e.what());
            } catch (...) {
                std::fprintf(stderr,
                    "ftc: unknown exception in thread '%s'\n",
                    n.c_str());
            }
        });
}

void ThreadGroup::join_all()
{
    // Move threads out while holding the lock, then join without the lock
    // so that join_all() does not block other operations on the mutex for
    // the entire duration.
    std::vector<std::thread> local;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        local.swap(threads_);
    }
    for (auto& t : local) {
        if (t.joinable()) {
            t.join();
        }
    }
}

size_t ThreadGroup::size() const
{
    std::lock_guard<std::mutex> guard(mutex_);
    return threads_.size();
}

void ThreadGroup::interrupt_all()
{
    interrupted_.store(true, std::memory_order_release);
}

// ---------------------------------------------------------------------------
// TraceThread
// ---------------------------------------------------------------------------

TraceThread::TraceThread(std::string name, std::function<void()> func)
    : name_(std::move(name))
{
    thread_ = std::thread(
        [n = name_, f = std::move(func)]() {
            set_thread_name(n);
            std::fprintf(stdout,
                "ftc: thread '%s' started\n", n.c_str());
            try {
                f();
            } catch (const std::exception& e) {
                std::fprintf(stderr,
                    "ftc: exception in thread '%s': %s\n",
                    n.c_str(), e.what());
            } catch (...) {
                std::fprintf(stderr,
                    "ftc: unknown exception in thread '%s'\n",
                    n.c_str());
            }
            std::fprintf(stdout,
                "ftc: thread '%s' exiting\n", n.c_str());
        });
}

TraceThread::~TraceThread()
{
    if (thread_.joinable()) {
        thread_.join();
    }
}

TraceThread::TraceThread(TraceThread&& other) noexcept
    : name_(std::move(other.name_))
    , thread_(std::move(other.thread_))
{
}

TraceThread& TraceThread::operator=(TraceThread&& other) noexcept
{
    if (this != &other) {
        if (thread_.joinable()) {
            thread_.join();
        }
        name_ = std::move(other.name_);
        thread_ = std::move(other.thread_);
    }
    return *this;
}

void TraceThread::join()
{
    if (thread_.joinable()) {
        thread_.join();
    }
}

bool TraceThread::joinable() const noexcept
{
    return thread_.joinable();
}

}  // namespace core
