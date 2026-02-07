#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "core/types.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace net::protocol {

// ---------------------------------------------------------------------------
// Inventory item types used in INV, GETDATA, and NOTFOUND messages
// ---------------------------------------------------------------------------
// These type codes identify the kind of object referenced by an inventory
// vector.  The witness variants (0x40000000 flag) indicate that the requester
// wants the witness-serialized form of the object.
// ---------------------------------------------------------------------------
enum class InvType : uint32_t {
    /// Standard (non-witness) transaction.
    TX             = 1,

    /// Block.
    BLOCK          = 2,

    /// Filtered (Bloom) block (BIP37).
    FILTERED_BLOCK = 3,

    /// Compact block (BIP152).
    CMPCT_BLOCK    = 4,

    /// Witness transaction (BIP144).  Set the witness flag on TX.
    WITNESS_TX     = 0x40000001,

    /// Witness block (BIP144).  Set the witness flag on BLOCK.
    WITNESS_BLOCK  = 0x40000002,
};

/// Bitmask for the witness service flag in inventory type codes.
inline constexpr uint32_t INV_WITNESS_FLAG = 0x40000000;

/// Maximum number of inventory items per message.
/// Consensus-derived limit matching Bitcoin Core behavior.
inline constexpr size_t MAX_INV_ITEMS = 50000;

/// Return a human-readable string for an InvType value.
[[nodiscard]] const char* inv_type_name(InvType type) noexcept;

/// Strip the witness flag from an InvType to get the base type.
[[nodiscard]] inline InvType inv_base_type(InvType type) noexcept {
    return static_cast<InvType>(
        static_cast<uint32_t>(type) & ~INV_WITNESS_FLAG);
}

/// Check whether the witness flag is set on an InvType.
[[nodiscard]] inline bool inv_is_witness(InvType type) noexcept {
    return (static_cast<uint32_t>(type) & INV_WITNESS_FLAG) != 0;
}

// ---------------------------------------------------------------------------
// InvItem -- a single inventory vector (type + hash)
// ---------------------------------------------------------------------------
// Each inventory item identifies an object on the network by its type and
// hash.  For transactions the hash is the txid; for blocks it is the block
// header hash.
// ---------------------------------------------------------------------------
struct InvItem {
    InvType       type = InvType::TX;
    core::uint256 hash;

    [[nodiscard]] bool operator==(const InvItem& other) const;
    [[nodiscard]] bool operator!=(const InvItem& other) const;

    /// Serialize a single inventory item to a stream.
    template <typename Stream>
    void serialize_to(Stream& s) const;

    /// Deserialize a single inventory item from a stream.
    template <typename Stream>
    static InvItem deserialize_from(Stream& s);

    /// Return a human-readable representation: "TYPE(hash_hex)".
    [[nodiscard]] std::string to_string() const;
};

// ---------------------------------------------------------------------------
// InvMessage -- carries a vector of inventory items (INV command)
// ---------------------------------------------------------------------------
// Transmits one or more inventory vectors to announce the availability of
// objects.  A node sends inv messages to notify connected peers about
// transactions or blocks it has accepted into its local data store.
// ---------------------------------------------------------------------------
struct InvMessage {
    std::vector<InvItem> items;

    /// Serialize the complete inv message payload.
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize an inv message from raw bytes.
    [[nodiscard]] static core::Result<InvMessage> deserialize(
        std::span<const uint8_t> data);

    /// Validate the message (item count, type ranges, etc.).
    [[nodiscard]] core::Result<void> validate() const;
};

// ---------------------------------------------------------------------------
// GetDataMessage -- request objects by inventory (same wire format as INV)
// ---------------------------------------------------------------------------
// When a node receives an inv, it responds with getdata to request the
// actual objects it does not yet have.
// ---------------------------------------------------------------------------
using GetDataMessage = InvMessage;

// ---------------------------------------------------------------------------
// NotFoundMessage -- signal that requested objects were not found
// ---------------------------------------------------------------------------
// Sent in response to getdata when the requested object is not available.
// ---------------------------------------------------------------------------
using NotFoundMessage = InvMessage;

} // namespace net::protocol
