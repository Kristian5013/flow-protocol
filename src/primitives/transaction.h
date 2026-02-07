#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "core/serialize.h"
#include "core/stream.h"
#include "core/types.h"
#include "primitives/amount.h"
#include "primitives/outpoint.h"
#include "primitives/txin.h"
#include "primitives/txout.h"
#include "primitives/witness.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace primitives {

// ---------------------------------------------------------------------------
// Transaction -- immutable-ish transaction with cached hashes
// ---------------------------------------------------------------------------
// Supports BIP144 (segregated witness) serialization format.
// Hash computation uses Keccak-256d (double Keccak-256).
// ---------------------------------------------------------------------------
class Transaction {
public:
    // -- Construction -------------------------------------------------------

    Transaction() = default;

    Transaction(std::vector<TxInput> vin, std::vector<TxOutput> vout,
                int32_t version = 2, uint32_t locktime = 0);

    // -- Const accessors ----------------------------------------------------

    [[nodiscard]] int32_t version() const { return version_; }
    [[nodiscard]] const std::vector<TxInput>& vin() const { return vin_; }
    [[nodiscard]] const std::vector<TxOutput>& vout() const { return vout_; }
    [[nodiscard]] uint32_t locktime() const { return locktime_; }

    // -- Mutable access for construction ------------------------------------

    std::vector<TxInput>& vin() { return vin_; }
    std::vector<TxOutput>& vout() { return vout_; }
    void set_version(int32_t v) { version_ = v; invalidate_cache(); }
    void set_locktime(uint32_t lt) { locktime_ = lt; invalidate_cache(); }

    // -- Hashes (cached, lazily computed) ------------------------------------

    /// Transaction ID: keccak256d of the non-witness serialization.
    [[nodiscard]] const core::uint256& txid() const;

    /// Witness transaction ID: keccak256d of the full segwit serialization.
    /// Returns the same value as txid() when there is no witness data.
    [[nodiscard]] const core::uint256& wtxid() const;

    // -- Properties ---------------------------------------------------------

    /// True if this is a coinbase transaction (exactly one input whose
    /// prevout is null -- txid all zeros, index 0xFFFFFFFF).
    [[nodiscard]] bool is_coinbase() const;

    /// True if any input carries witness data.
    [[nodiscard]] bool has_witness() const;

    // -- Sizes --------------------------------------------------------------

    /// Size of the non-witness serialization in bytes.
    [[nodiscard]] size_t base_size() const;

    /// Size of the full serialization (including witness) in bytes.
    [[nodiscard]] size_t total_size() const;

    /// Segwit weight: base_size * 3 + total_size.
    [[nodiscard]] size_t weight() const;

    /// Virtual size: (weight + 3) / 4 (rounded up).
    [[nodiscard]] size_t vsize() const;

    // -- Serialization (BIP144 segwit format) --------------------------------

    /// Serialize to a byte vector (uses segwit format if witness present).
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Serialize without witness data to a byte vector.
    [[nodiscard]] std::vector<uint8_t> serialize_no_witness() const;

    /// Serialize to an arbitrary stream (segwit format if witness present).
    template <typename Stream>
    void serialize_to(Stream& s) const;

    /// Serialize without witness data to an arbitrary stream.
    template <typename Stream>
    void serialize_no_witness_to(Stream& s) const;

    /// Deserialize a transaction from a DataStream.
    [[nodiscard]] static core::Result<Transaction> deserialize(
        core::DataStream& s);

    // -- Signature hash (BIP143 segwit v0) ----------------------------------

    /// Compute the signature hash for a given input index using the
    /// BIP143 algorithm (segwit v0).
    [[nodiscard]] core::uint256 signature_hash(
        size_t input_index,
        const std::vector<uint8_t>& script_code,
        Amount amount,
        int hash_type) const;

    // -- SIGHASH type constants ---------------------------------------------

    static constexpr int SIGHASH_ALL          = 1;
    static constexpr int SIGHASH_NONE         = 2;
    static constexpr int SIGHASH_SINGLE       = 3;
    static constexpr int SIGHASH_ANYONECANPAY = 0x80;

private:
    int32_t version_ = 2;
    std::vector<TxInput> vin_;
    std::vector<TxOutput> vout_;
    uint32_t locktime_ = 0;

    // Lazily-computed hash caches.
    mutable core::uint256 txid_cache_;
    mutable core::uint256 wtxid_cache_;
    mutable bool txid_cached_ = false;
    mutable bool wtxid_cached_ = false;

    void invalidate_cache();
    void compute_txid() const;
    void compute_wtxid() const;
};

// =========================================================================
// Template implementations
// =========================================================================

template <typename Stream>
void Transaction::serialize_to(Stream& s) const {
    bool use_witness = has_witness();

    // version
    core::ser_write_i32(s, version_);

    if (use_witness) {
        // BIP144 marker + flag
        core::ser_write_u8(s, 0x00);
        core::ser_write_u8(s, 0x01);
    }

    // inputs
    core::ser_write_compact_size(s, vin_.size());
    for (const auto& input : vin_) {
        input.serialize(s);
    }

    // outputs
    core::ser_write_compact_size(s, vout_.size());
    for (const auto& output : vout_) {
        output.serialize(s);
    }

    // witness data (one witness stack per input)
    if (use_witness) {
        for (const auto& input : vin_) {
            const auto& wit = input.witness;
            core::ser_write_compact_size(s, wit.size());
            for (const auto& item : wit) {
                core::ser_write_vector(s, item);
            }
        }
    }

    // locktime
    core::ser_write_u32(s, locktime_);
}

template <typename Stream>
void Transaction::serialize_no_witness_to(Stream& s) const {
    // version
    core::ser_write_i32(s, version_);

    // inputs
    core::ser_write_compact_size(s, vin_.size());
    for (const auto& input : vin_) {
        input.serialize(s);
    }

    // outputs
    core::ser_write_compact_size(s, vout_.size());
    for (const auto& output : vout_) {
        output.serialize(s);
    }

    // locktime
    core::ser_write_u32(s, locktime_);
}

} // namespace primitives
