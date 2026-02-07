// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/transaction.h"

#include "core/error.h"
#include "core/serialize.h"
#include "core/stream.h"
#include "core/types.h"
#include "crypto/keccak.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

namespace primitives {

// =========================================================================
// Construction
// =========================================================================

Transaction::Transaction(std::vector<TxInput> vin,
                         std::vector<TxOutput> vout,
                         int32_t version,
                         uint32_t locktime)
    : version_(version)
    , vin_(std::move(vin))
    , vout_(std::move(vout))
    , locktime_(locktime) {}

// =========================================================================
// Cache management
// =========================================================================

void Transaction::invalidate_cache() {
    txid_cached_ = false;
    wtxid_cached_ = false;
}

void Transaction::compute_txid() const {
    auto data = serialize_no_witness();
    txid_cache_ = crypto::keccak256d(
        std::span<const uint8_t>(data.data(), data.size()));
    txid_cached_ = true;
}

void Transaction::compute_wtxid() const {
    if (!has_witness()) {
        // When there is no witness data, wtxid == txid.
        if (!txid_cached_) {
            compute_txid();
        }
        wtxid_cache_ = txid_cache_;
    } else {
        auto data = serialize();
        wtxid_cache_ = crypto::keccak256d(
            std::span<const uint8_t>(data.data(), data.size()));
    }
    wtxid_cached_ = true;
}

const core::uint256& Transaction::txid() const {
    if (!txid_cached_) {
        compute_txid();
    }
    return txid_cache_;
}

const core::uint256& Transaction::wtxid() const {
    if (!wtxid_cached_) {
        compute_wtxid();
    }
    return wtxid_cache_;
}

// =========================================================================
// Properties
// =========================================================================

bool Transaction::is_coinbase() const {
    if (vin_.size() != 1) {
        return false;
    }
    const auto& prevout = vin_[0].prevout;
    return prevout.txid.is_zero() && prevout.n == 0xFFFFFFFF;
}

bool Transaction::has_witness() const {
    for (const auto& input : vin_) {
        if (!input.witness.empty()) {
            return true;
        }
    }
    return false;
}

// =========================================================================
// Sizes
// =========================================================================

size_t Transaction::base_size() const {
    core::DataStream s;
    serialize_no_witness_to(s);
    return s.size();
}

size_t Transaction::total_size() const {
    core::DataStream s;
    serialize_to(s);
    return s.size();
}

size_t Transaction::weight() const {
    return base_size() * 3 + total_size();
}

size_t Transaction::vsize() const {
    return (weight() + 3) / 4;
}

// =========================================================================
// Serialization
// =========================================================================

std::vector<uint8_t> Transaction::serialize() const {
    core::DataStream s;
    serialize_to(s);
    return s.release();
}

std::vector<uint8_t> Transaction::serialize_no_witness() const {
    core::DataStream s;
    serialize_no_witness_to(s);
    return s.release();
}

core::Result<Transaction> Transaction::deserialize(core::DataStream& s) {
    try {
        Transaction tx;

        // Read version.
        tx.version_ = core::ser_read_i32(s);

        // Peek at the next byte to detect the BIP144 segwit marker.
        // If marker == 0x00, the next byte should be the flag (0x01).
        bool has_witness_data = false;

        // Save position to potentially rewind.
        size_t pos_before_marker = s.tell();
        uint8_t marker = core::ser_read_u8(s);

        if (marker == 0x00) {
            // BIP144 segwit format: marker=0x00, flag=0x01.
            uint8_t flag = core::ser_read_u8(s);
            if (flag != 0x01) {
                return core::Error(
                    core::ErrorCode::PARSE_BAD_FORMAT,
                    "Transaction::deserialize: invalid segwit flag");
            }
            has_witness_data = true;
        } else {
            // Non-segwit format: the byte we read is actually the first
            // byte of the input count (compact size). Rewind.
            s.seek(pos_before_marker);
        }

        // Read inputs.
        uint64_t vin_count = core::ser_read_compact_size(s);
        if (vin_count > core::MAX_VECTOR_SIZE) {
            return core::Error(
                core::ErrorCode::PARSE_OVERFLOW,
                "Transaction::deserialize: too many inputs");
        }
        tx.vin_.reserve(static_cast<size_t>(vin_count));
        for (uint64_t i = 0; i < vin_count; ++i) {
            tx.vin_.push_back(TxInput::deserialize(s));
        }

        // Read outputs.
        uint64_t vout_count = core::ser_read_compact_size(s);
        if (vout_count > core::MAX_VECTOR_SIZE) {
            return core::Error(
                core::ErrorCode::PARSE_OVERFLOW,
                "Transaction::deserialize: too many outputs");
        }
        tx.vout_.reserve(static_cast<size_t>(vout_count));
        for (uint64_t i = 0; i < vout_count; ++i) {
            tx.vout_.push_back(TxOutput::deserialize(s));
        }

        // Read witness data if present.
        if (has_witness_data) {
            for (size_t i = 0; i < tx.vin_.size(); ++i) {
                uint64_t stack_count = core::ser_read_compact_size(s);
                if (stack_count > core::MAX_VECTOR_SIZE) {
                    return core::Error(
                        core::ErrorCode::PARSE_OVERFLOW,
                        "Transaction::deserialize: "
                        "too many witness items");
                }
                tx.vin_[i].witness.reserve(
                    static_cast<size_t>(stack_count));
                for (uint64_t j = 0; j < stack_count; ++j) {
                    tx.vin_[i].witness.push_back(
                        core::ser_read_vector(s));
                }
            }
        }

        // Read locktime.
        tx.locktime_ = core::ser_read_u32(s);

        return tx;

    } catch (const std::exception& e) {
        return core::Error(
            core::ErrorCode::PARSE_ERROR,
            std::string("Transaction::deserialize: ") + e.what());
    }
}

// =========================================================================
// BIP143 Signature Hash
// =========================================================================

core::uint256 Transaction::signature_hash(
    size_t input_index,
    const std::vector<uint8_t>& script_code,
    Amount amount,
    int hash_type) const
{
    int base_type = hash_type & 0x1F;
    bool anyone_can_pay = (hash_type & SIGHASH_ANYONECANPAY) != 0;

    // -- hashPrevouts ---------------------------------------------------
    core::uint256 hash_prevouts;
    if (!anyone_can_pay) {
        core::DataStream ss;
        for (const auto& input : vin_) {
            core::ser_write_uint256(ss, input.prevout.txid);
            core::ser_write_u32(ss, input.prevout.n);
        }
        auto buf = ss.release();
        hash_prevouts = crypto::keccak256d(
            std::span<const uint8_t>(buf.data(), buf.size()));
    }
    // else: hash_prevouts remains zero-initialized

    // -- hashSequence ---------------------------------------------------
    core::uint256 hash_sequence;
    if (!anyone_can_pay
        && base_type != SIGHASH_SINGLE
        && base_type != SIGHASH_NONE)
    {
        core::DataStream ss;
        for (const auto& input : vin_) {
            core::ser_write_u32(ss, input.sequence);
        }
        auto buf = ss.release();
        hash_sequence = crypto::keccak256d(
            std::span<const uint8_t>(buf.data(), buf.size()));
    }
    // else: hash_sequence remains zero-initialized

    // -- hashOutputs ----------------------------------------------------
    core::uint256 hash_outputs;
    if (base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE) {
        core::DataStream ss;
        for (const auto& output : vout_) {
            output.serialize(ss);
        }
        auto buf = ss.release();
        hash_outputs = crypto::keccak256d(
            std::span<const uint8_t>(buf.data(), buf.size()));
    } else if (base_type == SIGHASH_SINGLE
               && input_index < vout_.size())
    {
        core::DataStream ss;
        vout_[input_index].serialize(ss);
        auto buf = ss.release();
        hash_outputs = crypto::keccak256d(
            std::span<const uint8_t>(buf.data(), buf.size()));
    }
    // else: hash_outputs remains zero-initialized

    // -- Build the preimage ---------------------------------------------
    core::DataStream preimage;

    // nVersion (4 bytes LE)
    core::ser_write_i32(preimage, version_);

    // hashPrevouts (32 bytes)
    core::ser_write_uint256(preimage, hash_prevouts);

    // hashSequence (32 bytes)
    core::ser_write_uint256(preimage, hash_sequence);

    // outpoint being spent (32 + 4 bytes)
    const auto& spent_input = vin_[input_index];
    core::ser_write_uint256(preimage, spent_input.prevout.txid);
    core::ser_write_u32(preimage, spent_input.prevout.n);

    // scriptCode (varint length + data)
    core::ser_write_compact_size(preimage, script_code.size());
    if (!script_code.empty()) {
        core::ser_write_bytes(preimage,
            std::span<const uint8_t>(script_code.data(),
                                     script_code.size()));
    }

    // amount (8 bytes LE)
    amount.serialize(preimage);

    // nSequence of the input being signed (4 bytes LE)
    core::ser_write_u32(preimage, spent_input.sequence);

    // hashOutputs (32 bytes)
    core::ser_write_uint256(preimage, hash_outputs);

    // nLockTime (4 bytes LE)
    core::ser_write_u32(preimage, locktime_);

    // sighash type (4 bytes LE)
    core::ser_write_u32(preimage,
                        static_cast<uint32_t>(hash_type));

    // Double-hash the preimage.
    auto buf = preimage.release();
    return crypto::keccak256d(
        std::span<const uint8_t>(buf.data(), buf.size()));
}

} // namespace primitives
