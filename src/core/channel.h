#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <utility>

namespace core {

// ---------------------------------------------------------------------------
// ChannelClosedError -- thrown when receiving from a closed, empty channel
// ---------------------------------------------------------------------------

class ChannelClosedError : public std::runtime_error {
public:
    ChannelClosedError();
    explicit ChannelClosedError(const std::string& message);
};

// ---------------------------------------------------------------------------
// Channel<T> -- Multi-Producer Single-Consumer (MPSC) channel
// ---------------------------------------------------------------------------
// A mutex + condition-variable channel designed for the actor model.
// Messages between components flow through channels rather than through
// shared mutable state.  The API mirrors Rust's std::sync::mpsc::channel.
//
// When capacity == 0 the channel is unbounded (limited only by memory).
// When capacity > 0 the channel is bounded; `send()` blocks when the
// buffer is full and `try_send()` returns false immediately.
// ---------------------------------------------------------------------------
template<typename T>
class Channel {
public:
    /// Construct a channel.
    /// @param capacity  Maximum number of buffered items (0 = unbounded).
    explicit Channel(size_t capacity = 0)
        : capacity_(capacity) {}

    ~Channel() = default;

    Channel(const Channel&)            = delete;
    Channel& operator=(const Channel&) = delete;
    Channel(Channel&&)                 = delete;
    Channel& operator=(Channel&&)      = delete;

    // -- Send interface -----------------------------------------------------

    /// Enqueue an item.  Blocks if the channel is bounded and full.
    /// Does nothing (silently drops) if the channel is already closed.
    void send(T item) {
        std::unique_lock lock(mutex_);
        if (closed_) return;
        if (capacity_ > 0) {
            not_full_.wait(lock, [this] {
                return closed_ || queue_.size() < capacity_;
            });
            if (closed_) return;
        }
        queue_.push_back(std::move(item));
        not_empty_.notify_one();
    }

    /// Non-blocking enqueue.
    /// @return true if the item was enqueued, false if the channel is
    ///         closed or bounded-and-full.
    bool try_send(T item) {
        std::lock_guard lock(mutex_);
        if (closed_) return false;
        if (capacity_ > 0 && queue_.size() >= capacity_) return false;
        queue_.push_back(std::move(item));
        not_empty_.notify_one();
        return true;
    }

    /// Enqueue with timeout.
    /// @return true if the item was enqueued before the deadline.
    bool try_send_for(T item, std::chrono::milliseconds timeout) {
        std::unique_lock lock(mutex_);
        if (closed_) return false;
        if (capacity_ > 0) {
            bool ok = not_full_.wait_for(lock, timeout, [this] {
                return closed_ || queue_.size() < capacity_;
            });
            if (!ok || closed_) return false;
        }
        queue_.push_back(std::move(item));
        not_empty_.notify_one();
        return true;
    }

    // -- Receive interface --------------------------------------------------

    /// Dequeue an item.  Blocks until an item is available.
    /// @throws ChannelClosedError if the channel is closed and empty.
    T receive() {
        std::unique_lock lock(mutex_);
        not_empty_.wait(lock, [this] {
            return !queue_.empty() || closed_;
        });
        if (queue_.empty()) {
            throw ChannelClosedError();
        }
        T item = std::move(queue_.front());
        queue_.pop_front();
        if (capacity_ > 0) {
            not_full_.notify_one();
        }
        return item;
    }

    /// Non-blocking dequeue.
    /// @return The front item, or std::nullopt if empty (or closed+empty).
    std::optional<T> try_receive() {
        std::lock_guard lock(mutex_);
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop_front();
        if (capacity_ > 0) {
            not_full_.notify_one();
        }
        return item;
    }

    /// Dequeue with timeout.
    /// @return The front item, or std::nullopt if the timeout expired.
    std::optional<T> try_receive_for(std::chrono::milliseconds timeout) {
        std::unique_lock lock(mutex_);
        bool ok = not_empty_.wait_for(lock, timeout, [this] {
            return !queue_.empty() || closed_;
        });
        if (!ok || queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop_front();
        if (capacity_ > 0) {
            not_full_.notify_one();
        }
        return item;
    }

    // -- Lifecycle -----------------------------------------------------------

    /// Signal that no more items will be sent.  Wakes all blocked waiters.
    void close() {
        std::lock_guard lock(mutex_);
        closed_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    /// Query whether the channel has been closed.
    [[nodiscard]] bool is_closed() const {
        std::lock_guard lock(mutex_);
        return closed_;
    }

    /// Approximate number of items currently buffered.
    [[nodiscard]] size_t size() const {
        std::lock_guard lock(mutex_);
        return queue_.size();
    }

    /// True when the buffer contains no items.
    [[nodiscard]] bool empty() const {
        std::lock_guard lock(mutex_);
        return queue_.empty();
    }

private:
    mutable std::mutex      mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    std::deque<T>           queue_;
    size_t                  capacity_{0};
    bool                    closed_{false};
};

// ---------------------------------------------------------------------------
// MpmcChannel<T> -- Multi-Producer Multi-Consumer channel
// ---------------------------------------------------------------------------
// Same semantics as Channel<T> but safe for multiple consumers.
// The implementation is identical (mutex + cvs already support multiple
// consumers).  The separate type exists to make the intent explicit in
// code and to allow future optimisation of the MPSC variant.
// ---------------------------------------------------------------------------
template<typename T>
class MpmcChannel {
public:
    explicit MpmcChannel(size_t capacity = 0)
        : capacity_(capacity) {}

    ~MpmcChannel() = default;

    MpmcChannel(const MpmcChannel&)            = delete;
    MpmcChannel& operator=(const MpmcChannel&) = delete;
    MpmcChannel(MpmcChannel&&)                 = delete;
    MpmcChannel& operator=(MpmcChannel&&)      = delete;

    // -- Send interface -----------------------------------------------------

    void send(T item) {
        std::unique_lock lock(mutex_);
        if (closed_) return;
        if (capacity_ > 0) {
            not_full_.wait(lock, [this] {
                return closed_ || queue_.size() < capacity_;
            });
            if (closed_) return;
        }
        queue_.push_back(std::move(item));
        not_empty_.notify_one();
    }

    bool try_send(T item) {
        std::lock_guard lock(mutex_);
        if (closed_) return false;
        if (capacity_ > 0 && queue_.size() >= capacity_) return false;
        queue_.push_back(std::move(item));
        not_empty_.notify_one();
        return true;
    }

    bool try_send_for(T item, std::chrono::milliseconds timeout) {
        std::unique_lock lock(mutex_);
        if (closed_) return false;
        if (capacity_ > 0) {
            bool ok = not_full_.wait_for(lock, timeout, [this] {
                return closed_ || queue_.size() < capacity_;
            });
            if (!ok || closed_) return false;
        }
        queue_.push_back(std::move(item));
        not_empty_.notify_one();
        return true;
    }

    // -- Receive interface --------------------------------------------------

    T receive() {
        std::unique_lock lock(mutex_);
        not_empty_.wait(lock, [this] {
            return !queue_.empty() || closed_;
        });
        if (queue_.empty()) {
            throw ChannelClosedError();
        }
        T item = std::move(queue_.front());
        queue_.pop_front();
        if (capacity_ > 0) {
            not_full_.notify_one();
        }
        return item;
    }

    std::optional<T> try_receive() {
        std::lock_guard lock(mutex_);
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop_front();
        if (capacity_ > 0) {
            not_full_.notify_one();
        }
        return item;
    }

    std::optional<T> try_receive_for(std::chrono::milliseconds timeout) {
        std::unique_lock lock(mutex_);
        bool ok = not_empty_.wait_for(lock, timeout, [this] {
            return !queue_.empty() || closed_;
        });
        if (!ok || queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop_front();
        if (capacity_ > 0) {
            not_full_.notify_one();
        }
        return item;
    }

    // -- Lifecycle -----------------------------------------------------------

    void close() {
        std::lock_guard lock(mutex_);
        closed_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    [[nodiscard]] bool is_closed() const {
        std::lock_guard lock(mutex_);
        return closed_;
    }

    [[nodiscard]] size_t size() const {
        std::lock_guard lock(mutex_);
        return queue_.size();
    }

    [[nodiscard]] bool empty() const {
        std::lock_guard lock(mutex_);
        return queue_.empty();
    }

private:
    mutable std::mutex      mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    std::deque<T>           queue_;
    size_t                  capacity_{0};
    bool                    closed_{false};
};

// ---------------------------------------------------------------------------
// select -- simplified select-like operation across multiple channels
// ---------------------------------------------------------------------------
// Polls the supplied channels in round-robin order and returns the
// zero-based index of the first channel that has data available.
// If none of the channels have data, sleeps briefly and retries.
// Returns SIZE_MAX if all channels are closed and empty.
//
// This is a simplified implementation.  A production system might use
// a shared condition variable that all channels notify, but that would
// require channels to hold a reference to an external CV.
// ---------------------------------------------------------------------------
namespace detail {

/// Check whether a channel-like object has data.
template<typename Ch>
bool channel_has_data(Ch& ch) {
    return !ch.empty();
}

/// Check whether a channel-like object is closed and empty.
template<typename Ch>
bool channel_is_done(Ch& ch) {
    return ch.is_closed() && ch.empty();
}

/// Attempt a single poll across all channels.
/// Returns the index of the first channel with data, or SIZE_MAX if none.
/// Channels are checked in index order 0..N-1.  True round-robin with a
/// rotating start would require a runtime-to-compile-time dispatch that
/// is not worth the complexity for a polling select.
template<typename Tuple, size_t... Is>
size_t try_poll(Tuple& channels, [[maybe_unused]] size_t start_idx,
                std::index_sequence<Is...>) {
    size_t result = SIZE_MAX;

    auto check = [&]<size_t I>() {
        if (result != SIZE_MAX) return;
        if (channel_has_data(std::get<I>(channels))) {
            result = I;
        }
    };

    (check.template operator()<Is>(), ...);

    return result;
}

template<typename Tuple, size_t... Is>
bool all_done(Tuple& channels, std::index_sequence<Is...>) {
    return (channel_is_done(std::get<Is>(channels)) && ...);
}

}  // namespace detail

/// Poll multiple channels and return the index of the first one with data.
/// Channels can be heterogeneous (different T types).
/// Returns SIZE_MAX if all channels are closed and empty.
///
/// Usage:
///   Channel<int> ch1;
///   Channel<std::string> ch2;
///   size_t idx = select(ch1, ch2);
///   if (idx == 0) { auto val = ch1.try_receive(); ... }
///   else if (idx == 1) { auto val = ch2.try_receive(); ... }
template<typename... Channels>
size_t select(Channels&... channels) {
    static_assert(sizeof...(Channels) > 0,
                  "select() requires at least one channel");

    constexpr size_t N = sizeof...(Channels);
    auto channel_tuple = std::tie(channels...);
    constexpr auto indices = std::make_index_sequence<N>{};

    // Spin with exponential back-off up to a cap.
    constexpr int MAX_SPIN_ITERS = 4;
    constexpr auto POLL_INTERVAL_MIN = std::chrono::microseconds(50);
    constexpr auto POLL_INTERVAL_MAX = std::chrono::milliseconds(10);

    auto sleep_duration = POLL_INTERVAL_MIN;

    for (;;) {
        // Quick spin phase -- try a few times without sleeping.
        for (int spin = 0; spin < MAX_SPIN_ITERS; ++spin) {
            size_t idx = detail::try_poll(
                channel_tuple, 0, indices);
            if (idx != SIZE_MAX) return idx;

            if (detail::all_done(channel_tuple, indices)) {
                return SIZE_MAX;
            }
        }

        // Backoff sleep.
        std::this_thread::sleep_for(sleep_duration);
        sleep_duration = std::min(
            std::chrono::duration_cast<std::chrono::microseconds>(
                sleep_duration * 2),
            std::chrono::duration_cast<std::chrono::microseconds>(
                POLL_INTERVAL_MAX));

        size_t idx = detail::try_poll(channel_tuple, 0, indices);
        if (idx != SIZE_MAX) return idx;

        if (detail::all_done(channel_tuple, indices)) {
            return SIZE_MAX;
        }
    }
}

}  // namespace core
