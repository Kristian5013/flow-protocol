// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/utxo/db.h"

#include "chain/coins.h"
#include "chain/utxo/cache.h"
#include "core/error.h"
#include "core/serialize.h"
#include "core/stream.h"
#include "core/types.h"
#include "primitives/amount.h"
#include "primitives/outpoint.h"
#include "primitives/txout.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

namespace chain::utxo {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

UtxoDB::UtxoDB(const std::filesystem::path& path)
    : path_(path) {}

// ---------------------------------------------------------------------------
// save_snapshot
// ---------------------------------------------------------------------------

core::Result<void> UtxoDB::save_snapshot(const UtxoCache& cache) {
    // Build the snapshot into a DataStream first, then write atomically.
    core::DataStream ds;

    // Header: magic, version, best block hash.
    core::ser_write_u32(ds, SNAPSHOT_MAGIC);
    core::ser_write_u32(ds, SNAPSHOT_VERSION);

    core::uint256 best = cache.get_best_block();
    core::ser_write_bytes(ds, std::span<const uint8_t>(best.data(), best.size()));

    // Collect all outpoints while holding the shared lock via the public API.
    auto outpoints = cache.get_all_outpoints();
    uint64_t count = static_cast<uint64_t>(outpoints.size());
    core::ser_write_u64(ds, count);

    // Serialize each coin.
    for (const auto& op : outpoints) {
        const Coin* coin = cache.get_coin(op);
        if (!coin) {
            // Should not happen -- the outpoint was just returned by the cache.
            continue;
        }

        // txid (32 bytes)
        core::ser_write_bytes(ds,
            std::span<const uint8_t>(op.txid.data(), op.txid.size()));

        // output index (4 bytes)
        core::ser_write_u32(ds, op.n);

        // height (4 bytes)
        core::ser_write_i32(ds, coin->height);

        // is_coinbase (1 byte)
        core::ser_write_u8(ds, coin->is_coinbase ? 1 : 0);

        // amount (8 bytes)
        core::ser_write_i64(ds, coin->out.amount.value());

        // script_pubkey length (4 bytes) + script bytes
        auto script_len = static_cast<uint32_t>(coin->out.script_pubkey.size());
        core::ser_write_u32(ds, script_len);
        if (script_len > 0) {
            core::ser_write_bytes(ds,
                std::span<const uint8_t>(
                    coin->out.script_pubkey.data(), script_len));
        }
    }

    // Write to a temporary file, then rename for atomicity.
    auto tmp_path = path_;
    tmp_path += ".tmp";

    {
        std::ofstream ofs(tmp_path, std::ios::binary | std::ios::trunc);
        if (!ofs) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "failed to open snapshot temp file for writing: " +
                tmp_path.string());
        }

        const auto* buf = reinterpret_cast<const char*>(ds.data());
        ofs.write(buf, static_cast<std::streamsize>(ds.size()));
        if (!ofs) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "failed to write snapshot data");
        }
        ofs.flush();
        if (!ofs) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                "failed to flush snapshot file");
        }
    }

    // Atomic rename.
    std::error_code ec;
    std::filesystem::rename(tmp_path, path_, ec);
    if (ec) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "failed to rename snapshot file: " + ec.message());
    }

    return core::make_ok();
}

// ---------------------------------------------------------------------------
// load_snapshot
// ---------------------------------------------------------------------------

core::Result<void> UtxoDB::load_snapshot(UtxoCache& cache) {
    // Read the entire file into memory.
    std::ifstream ifs(path_, std::ios::binary | std::ios::ate);
    if (!ifs) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "failed to open snapshot file: " + path_.string());
    }

    auto file_size = static_cast<size_t>(ifs.tellg());
    if (file_size < 48) { // magic(4) + version(4) + hash(32) + count(8) = 48
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
            "snapshot file too small");
    }

    ifs.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(file_size);
    ifs.read(reinterpret_cast<char*>(buf.data()),
             static_cast<std::streamsize>(file_size));
    if (!ifs) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "failed to read snapshot file");
    }
    ifs.close();

    core::DataStream ds(std::move(buf));

    // Validate header.
    uint32_t magic = core::ser_read_u32(ds);
    if (magic != SNAPSHOT_MAGIC) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
            "invalid snapshot magic");
    }

    uint32_t version = core::ser_read_u32(ds);
    if (version != SNAPSHOT_VERSION) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
            "unsupported snapshot version");
    }

    // Read best block hash (32 bytes).
    core::uint256 best_block;
    core::ser_read_bytes(ds,
        std::span<uint8_t>(best_block.data(), best_block.size()));

    uint64_t count = core::ser_read_u64(ds);

    // Clear the cache and load coins.
    cache.clear();
    cache.set_best_block(best_block);

    for (uint64_t i = 0; i < count; ++i) {
        // txid
        core::uint256 txid;
        core::ser_read_bytes(ds,
            std::span<uint8_t>(txid.data(), txid.size()));

        // output index
        uint32_t out_index = core::ser_read_u32(ds);

        // height
        int32_t height = core::ser_read_i32(ds);

        // is_coinbase
        uint8_t cb_byte = core::ser_read_u8(ds);
        bool is_coinbase = (cb_byte != 0);

        // amount
        int64_t amount_val = core::ser_read_i64(ds);

        // script_pubkey
        uint32_t script_len = core::ser_read_u32(ds);
        std::vector<uint8_t> script(script_len);
        if (script_len > 0) {
            core::ser_read_bytes(ds,
                std::span<uint8_t>(script.data(), script_len));
        }

        primitives::OutPoint outpoint(txid, out_index);
        primitives::TxOutput txout(primitives::Amount(amount_val),
                                   std::move(script));
        Coin coin(std::move(txout), height, is_coinbase);

        cache.add_coin(outpoint, std::move(coin));
    }

    return core::make_ok();
}

// ---------------------------------------------------------------------------
// has_snapshot
// ---------------------------------------------------------------------------

bool UtxoDB::has_snapshot() const {
    return std::filesystem::exists(path_) &&
           std::filesystem::is_regular_file(path_);
}

// ---------------------------------------------------------------------------
// get_snapshot_hash
// ---------------------------------------------------------------------------

core::Result<core::uint256> UtxoDB::get_snapshot_hash() const {
    std::ifstream ifs(path_, std::ios::binary);
    if (!ifs) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
            "failed to open snapshot file: " + path_.string());
    }

    // We only need the first 40 bytes: magic(4) + version(4) + hash(32).
    constexpr size_t header_size = 4 + 4 + 32;
    std::vector<uint8_t> buf(header_size);
    ifs.read(reinterpret_cast<char*>(buf.data()),
             static_cast<std::streamsize>(header_size));
    if (!ifs) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
            "snapshot file header too short");
    }
    ifs.close();

    core::DataStream ds(std::move(buf));

    uint32_t magic = core::ser_read_u32(ds);
    if (magic != SNAPSHOT_MAGIC) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
            "invalid snapshot magic");
    }

    uint32_t version = core::ser_read_u32(ds);
    if (version != SNAPSHOT_VERSION) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
            "unsupported snapshot version");
    }

    core::uint256 best_block;
    core::ser_read_bytes(ds,
        std::span<uint8_t>(best_block.data(), best_block.size()));

    return best_block;
}

} // namespace chain::utxo
