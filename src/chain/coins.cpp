// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/coins.h"

#include "core/error.h"
#include "core/serialize.h"
#include "core/stream.h"
#include "core/types.h"
#include "primitives/amount.h"
#include "primitives/txout.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace chain {

// ---------------------------------------------------------------------------
// Coin constructor
// ---------------------------------------------------------------------------
Coin::Coin(primitives::TxOutput out_in, int height_in, bool coinbase)
    : out(std::move(out_in))
    , height(height_in)
    , is_coinbase(coinbase) {}

// ---------------------------------------------------------------------------
// is_spent
// ---------------------------------------------------------------------------
bool Coin::is_spent() const {
    return out.amount.value() == -1;
}

// ---------------------------------------------------------------------------
// serialize
// ---------------------------------------------------------------------------
// Layout:
//   [0..3]   height       -- 4 bytes, signed 32-bit little-endian
//   [4]      is_coinbase  -- 1 byte (0x00 or 0x01)
//   [5..12]  amount       -- 8 bytes, signed 64-bit little-endian
//   [13..]   script_pubkey length (compact size) + script_pubkey bytes
// ---------------------------------------------------------------------------
std::vector<uint8_t> Coin::serialize() const {
    core::DataStream stream;

    // Height (4 bytes LE).
    core::ser_write_i32(stream, static_cast<int32_t>(height));

    // Coinbase flag (1 byte).
    core::ser_write_bool(stream, is_coinbase);

    // The output (amount + script).
    out.serialize(stream);

    return stream.release();
}

// ---------------------------------------------------------------------------
// deserialize
// ---------------------------------------------------------------------------
core::Result<Coin> Coin::deserialize(std::span<const uint8_t> data) {
    // Minimum size: 4 (height) + 1 (coinbase) + 8 (amount) + 1 (compact size 0)
    //             = 14 bytes.
    if (data.size() < 14) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
                           "Coin::deserialize: data too short");
    }

    try {
        core::SpanReader reader(data);

        // Height.
        int32_t h = core::ser_read_i32(reader);

        // Coinbase flag.
        bool coinbase = core::ser_read_bool(reader);

        // Output (amount + script).
        primitives::TxOutput output = primitives::TxOutput::deserialize(reader);

        // Verify we consumed all the data.
        if (!reader.eof()) {
            return core::Error(core::ErrorCode::PARSE_ERROR,
                               "Coin::deserialize: trailing data");
        }

        Coin coin;
        coin.out = std::move(output);
        coin.height = static_cast<int>(h);
        coin.is_coinbase = coinbase;
        return coin;
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
                           std::string("Coin::deserialize: ") + e.what());
    }
}

// ---------------------------------------------------------------------------
// dynamic_memory_usage
// ---------------------------------------------------------------------------
size_t Coin::dynamic_memory_usage() const {
    // The Coin struct itself is stored inline in whatever container holds it.
    // The only heap allocation is the script_pubkey vector.
    // We report the capacity (not size) because that is the actual allocation.
    return out.script_pubkey.capacity() * sizeof(uint8_t);
}

} // namespace chain
