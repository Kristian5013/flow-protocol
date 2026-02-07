#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "core/serialize.h"
#include "core/types.h"

namespace primitives {

/// Identifies a particular output of a previous transaction by its hash and
/// index within that transaction's output list.
struct OutPoint {
    /// Hash of the referenced transaction.
    core::uint256 txid;

    /// Zero-based index into the referenced transaction's outputs.
    /// The sentinel value 0xFFFFFFFF indicates a null outpoint (e.g. for
    /// coinbase inputs).
    uint32_t n = 0xFFFFFFFF;

    OutPoint() = default;
    OutPoint(const core::uint256& txid_in, uint32_t n_in)
        : txid(txid_in), n(n_in) {}

    /// Returns true when this outpoint refers to no real output (zero hash,
    /// maximum index).
    [[nodiscard]] bool is_null() const {
        return txid.is_zero() && n == 0xFFFFFFFF;
    }

    bool operator==(const OutPoint&) const = default;
    auto operator<=>(const OutPoint&) const = default;

    /// Human-readable representation: "<txid_hex>:<index>".
    [[nodiscard]] std::string to_string() const;

    /// Serialize: 32-byte txid followed by a 32-bit little-endian index.
    template<typename Stream>
    void serialize(Stream& s) const {
        core::ser_write_bytes(
            s, std::span<const uint8_t>(txid.data(), txid.size()));
        core::ser_write_u32(s, n);
    }

    /// Deserialize: read 32-byte txid then 32-bit little-endian index.
    template<typename Stream>
    static OutPoint deserialize(Stream& s) {
        OutPoint op;
        core::ser_read_bytes(
            s, std::span<uint8_t>(op.txid.data(), op.txid.size()));
        op.n = core::ser_read_u32(s);
        return op;
    }
};

} // namespace primitives

/// Specialization of std::hash for OutPoint so it can be used as a key in
/// unordered containers.
template<>
struct std::hash<primitives::OutPoint> {
    std::size_t operator()(const primitives::OutPoint& op) const noexcept {
        // FNV-1a inspired combination of the txid bytes and the index.
        std::size_t h = 14695981039346656037ULL;
        const uint8_t* p = op.txid.data();
        for (std::size_t i = 0; i < op.txid.size(); ++i) {
            h ^= static_cast<std::size_t>(p[i]);
            h *= 1099511628211ULL;
        }
        h ^= static_cast<std::size_t>(op.n);
        h *= 1099511628211ULL;
        return h;
    }
};
