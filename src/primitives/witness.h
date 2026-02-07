#pragma once

#include <cstdint>
#include <stdexcept>
#include <vector>

#include "core/serialize.h"

namespace primitives {

/// Segregated-witness data for a single transaction input.
///
/// The witness is an ordered stack of byte-vectors that is consumed by the
/// script interpreter when verifying a SegWit spend.  Witness data is
/// serialized separately from the base transaction and does not contribute
/// to the legacy transaction hash.
class Witness {
    std::vector<std::vector<uint8_t>> stack_;

    /// Return the byte-length of a Bitcoin compact-size encoding of n.
    static size_t compact_size_len(size_t n);

public:
    Witness() = default;

    /// Construct directly from a pre-built stack.
    explicit Witness(std::vector<std::vector<uint8_t>> stack);

    /// Returns true when the witness stack contains no items.
    [[nodiscard]] bool empty() const { return stack_.empty(); }

    /// Number of items on the witness stack.
    [[nodiscard]] size_t size() const { return stack_.size(); }

    /// Access a stack item by index (0 = bottom).
    /// Throws std::out_of_range if the index is invalid.
    [[nodiscard]] const std::vector<uint8_t>& operator[](size_t i) const;

    /// Push a new item onto the top of the witness stack.
    void push(std::vector<uint8_t> item);

    /// Remove all items from the witness stack.
    void clear();

    /// Read-only reference to the underlying stack.
    [[nodiscard]] const std::vector<std::vector<uint8_t>>& stack() const {
        return stack_;
    }

    /// Compute the total number of bytes this witness would occupy when
    /// serialized (compact-size prefix for the item count, plus for each
    /// item a compact-size length prefix followed by its bytes).
    [[nodiscard]] size_t serialized_size() const;

    /// Serialize the witness stack.
    ///
    /// Wire format:
    ///   compact_size(num_items)
    ///   for each item:
    ///     compact_size(item_len) | item_bytes
    template<typename Stream>
    void serialize(Stream& s) const {
        core::ser_write_compact_size(s, stack_.size());
        for (const auto& item : stack_) {
            core::ser_write_compact_size(s, item.size());
            if (!item.empty()) {
                core::ser_write_bytes(
                    s,
                    std::span<const uint8_t>(item.data(), item.size()));
            }
        }
    }

    /// Deserialize a witness stack from the stream.
    template<typename Stream>
    static Witness deserialize(Stream& s) {
        uint64_t count = core::ser_read_compact_size(s);
        std::vector<std::vector<uint8_t>> stack;
        stack.reserve(static_cast<size_t>(count));

        for (uint64_t i = 0; i < count; ++i) {
            uint64_t item_len = core::ser_read_compact_size(s);
            std::vector<uint8_t> item(static_cast<size_t>(item_len));
            if (item_len > 0) {
                core::ser_read_bytes(
                    s,
                    std::span<uint8_t>(item.data(), item.size()));
            }
            stack.push_back(std::move(item));
        }

        return Witness(std::move(stack));
    }
};

} // namespace primitives
