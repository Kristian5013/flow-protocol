#pragma once

#include "primitives/script/opcodes.h"
#include "core/types.h"
#include "core/serialize.h"
#include "core/stream.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace primitives::script {

/// Maximum number of bytes pushable to the stack.
static constexpr size_t MAX_SCRIPT_ELEMENT_SIZE = 520;

/// Maximum number of bytes in a serialised script.
static constexpr size_t MAX_SCRIPT_SIZE = 10'000;

/// Maximum number of public keys per multisig.
static constexpr int MAX_PUBKEYS_PER_MULTISIG = 20;

/// Maximum number of non-push operations per script.
static constexpr int MAX_OPS_PER_SCRIPT = 201;

// -----------------------------------------------------------------------
// Script  --  bytecode container for FTC transaction scripts
// -----------------------------------------------------------------------

class Script {
    std::vector<uint8_t> data_;

public:
    // -------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------

    Script() = default;

    explicit Script(std::vector<uint8_t> data)
        : data_(std::move(data)) {}

    explicit Script(std::span<const uint8_t> data)
        : data_(data.begin(), data.end()) {}

    // -------------------------------------------------------------------
    // Standard script template constructors
    // -------------------------------------------------------------------

    /// P2PKH: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
    static Script p2pkh(const core::uint160& pubkey_hash);

    /// P2SH: OP_HASH160 <20-byte hash> OP_EQUAL
    static Script p2sh(const core::uint160& script_hash);

    /// P2WPKH: OP_0 <20-byte hash>
    static Script p2wpkh(const core::uint160& pubkey_hash);

    /// P2WSH: OP_0 <32-byte hash>
    static Script p2wsh(const core::uint256& script_hash);

    /// P2TR (Taproot): OP_1 <32-byte output key>
    static Script p2tr(const core::uint256& output_key);

    /// OP_RETURN followed by a single data push.
    static Script op_return(std::span<const uint8_t> payload);

    /// Bare multisig: OP_M <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG
    /// Throws std::invalid_argument if parameters are out of range.
    static Script multisig(
        int required,
        const std::vector<std::vector<uint8_t>>& pubkeys);

    // -------------------------------------------------------------------
    // Script type detection
    // -------------------------------------------------------------------

    bool is_p2pkh() const;
    bool is_p2sh() const;
    bool is_p2wpkh() const;
    bool is_p2wsh() const;
    bool is_p2tr() const;
    bool is_op_return() const;
    bool is_multisig() const;
    bool is_unspendable() const;

    /// True for any valid witness program (version 0-16, program 2-40 bytes).
    bool is_witness_program() const;

    /// If this is a witness program, return (version, program).
    std::optional<std::pair<int, std::vector<uint8_t>>>
    witness_program() const;

    // -------------------------------------------------------------------
    // Extract hashes from standard scripts
    // -------------------------------------------------------------------

    std::optional<core::uint160> get_p2pkh_hash() const;
    std::optional<core::uint160> get_p2sh_hash() const;
    std::optional<core::uint160> get_p2wpkh_hash() const;
    std::optional<core::uint256> get_p2wsh_hash() const;
    std::optional<core::uint256> get_p2tr_key() const;

    // -------------------------------------------------------------------
    // Raw access
    // -------------------------------------------------------------------

    const std::vector<uint8_t>& data() const { return data_; }
    std::vector<uint8_t>&       data()       { return data_; }
    const uint8_t* bytes() const { return data_.data(); }
    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }

    bool operator==(const Script& other) const = default;

    // -------------------------------------------------------------------
    // Script builder helpers
    // -------------------------------------------------------------------

    /// Append a single opcode byte.
    Script& push_opcode(Opcode op);

    /// Append a data push with the shortest valid encoding.
    /// Selects among OP_PUSHBYTES_N, OP_PUSHDATA1/2/4 automatically.
    Script& push_data(std::span<const uint8_t> payload);

    /// Push a CScriptNum-encoded integer.
    Script& push_int(int64_t n);

    // -------------------------------------------------------------------
    // Script element iteration
    // -------------------------------------------------------------------

    /// A single decoded script element: an opcode and optional push data.
    struct Element {
        Opcode opcode;
        std::span<const uint8_t> data;  // non-empty only for push ops
    };

    /// Forward-only iterator that decodes script elements one at a time.
    /// Returns std::nullopt when the script is exhausted or malformed.
    class Iterator {
        const uint8_t* ptr_;
        const uint8_t* end_;

    public:
        Iterator(const uint8_t* begin, const uint8_t* end);

        /// Decode and return the next element, advancing the cursor.
        /// Returns std::nullopt on end-of-script or parse error.
        std::optional<Element> next();

        /// True if the cursor has not reached the end.
        bool has_more() const { return ptr_ < end_; }
    };

    /// Obtain a forward iterator over this script's elements.
    Iterator begin_iter() const;

    // -------------------------------------------------------------------
    // Serialization (compact-size prefixed byte vector)
    // -------------------------------------------------------------------

    template <typename Stream>
    void serialize(Stream& s) const {
        ser_write_compact_size(s, static_cast<uint64_t>(data_.size()));
        ser_write_bytes(s, std::span<const uint8_t>(data_));
    }

    template <typename Stream>
    static Script deserialize(Stream& s) {
        auto len = ser_read_compact_size(s);
        if (len > MAX_SCRIPT_SIZE) {
            throw std::runtime_error(
                "Script::deserialize: script too large");
        }
        std::vector<uint8_t> buf(static_cast<size_t>(len));
        s.read(buf.data(), buf.size());
        return Script(std::move(buf));
    }

    // -------------------------------------------------------------------
    // Hashing helpers
    // -------------------------------------------------------------------

    /// HASH160 of the serialised script bytes (for P2SH address derivation).
    /// Defined as: first 20 bytes of Keccak256(Keccak256(script)).
    core::uint160 script_hash() const;

    /// Keccak256 of the serialised script bytes (for P2WSH witness hash).
    core::uint256 witness_script_hash() const;
};

} // namespace primitives::script
