#include "primitives/witness.h"

namespace primitives {

Witness::Witness(std::vector<std::vector<uint8_t>> stack)
    : stack_(std::move(stack)) {}

const std::vector<uint8_t>& Witness::operator[](size_t i) const {
    if (i >= stack_.size()) {
        throw std::out_of_range(
            "Witness::operator[]: index " + std::to_string(i) +
            " out of range (size=" + std::to_string(stack_.size()) + ")");
    }
    return stack_[i];
}

void Witness::push(std::vector<uint8_t> item) {
    stack_.push_back(std::move(item));
}

void Witness::clear() {
    stack_.clear();
}

size_t Witness::serialized_size() const {
    size_t total = 0;

    // Leading compact-size encoding of the number of stack items.
    // compact_size uses:  1 byte for values < 253,
    //                     3 bytes for values < 0x10000,
    //                     5 bytes for values < 0x100000000,
    //                     9 bytes otherwise.
    total += compact_size_len(stack_.size());

    for (const auto& item : stack_) {
        total += compact_size_len(item.size());
        total += item.size();
    }

    return total;
}

// ---- private helper (file-local) ----

/// Return the number of bytes required to encode `n` as a Bitcoin-style
/// compact size integer.
size_t Witness::compact_size_len(size_t n) {
    if (n < 253) return 1;
    if (n <= 0xFFFF) return 3;
    if (n <= 0xFFFFFFFF) return 5;
    return 9;
}

} // namespace primitives
