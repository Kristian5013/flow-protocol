#include "primitives/script/script.h"
#include "crypto/keccak.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <stdexcept>

namespace primitives::script {

// ===================================================================
// Internal helpers
// ===================================================================

namespace {

/// Write a push-data prefix + payload into a byte vector using the
/// shortest valid encoding (Bitcoin consensus rules).
void append_push_data(std::vector<uint8_t>& out,
                      std::span<const uint8_t> payload) {
    auto len = payload.size();

    if (len == 0) {
        // Empty push encodes as OP_0.
        out.push_back(static_cast<uint8_t>(Opcode::OP_0));
    } else if (len == 1 && payload[0] == 0) {
        // Canonical encoding for zero is OP_0.
        out.push_back(static_cast<uint8_t>(Opcode::OP_0));
    } else if (len == 1 && payload[0] <= 16) {
        // Small integers get their own opcodes (OP_1..OP_16).
        out.push_back(
            static_cast<uint8_t>(encode_small_int(payload[0])));
    } else if (len == 1 && payload[0] == 0x81) {
        // -1 is encoded as OP_1NEGATE.
        out.push_back(static_cast<uint8_t>(Opcode::OP_1NEGATE));
    } else if (len <= 75) {
        // OP_PUSHBYTES_N: the length byte IS the opcode.
        out.push_back(static_cast<uint8_t>(len));
        out.insert(out.end(), payload.begin(), payload.end());
    } else if (len <= 0xFF) {
        out.push_back(static_cast<uint8_t>(Opcode::OP_PUSHDATA1));
        out.push_back(static_cast<uint8_t>(len));
        out.insert(out.end(), payload.begin(), payload.end());
    } else if (len <= 0xFFFF) {
        out.push_back(static_cast<uint8_t>(Opcode::OP_PUSHDATA2));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        out.insert(out.end(), payload.begin(), payload.end());
    } else {
        out.push_back(static_cast<uint8_t>(Opcode::OP_PUSHDATA4));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
        out.insert(out.end(), payload.begin(), payload.end());
    }
}

/// Append raw bytes of a core::uint160 (20 bytes) as a push operation.
void append_push_hash160(std::vector<uint8_t>& out,
                         const core::uint160& h) {
    const auto* p = reinterpret_cast<const uint8_t*>(h.data());
    out.push_back(20);  // OP_PUSHBYTES_20
    out.insert(out.end(), p, p + 20);
}

/// Append raw bytes of a core::uint256 (32 bytes) as a push operation.
void append_push_hash256(std::vector<uint8_t>& out,
                         const core::uint256& h) {
    const auto* p = reinterpret_cast<const uint8_t*>(h.data());
    out.push_back(32);  // OP_PUSHBYTES_32
    out.insert(out.end(), p, p + 32);
}

/// Encode a signed 64-bit integer as a CScriptNum byte sequence.
/// The encoding is little-endian magnitude with a sign bit in the
/// MSB of the last byte.
std::vector<uint8_t> encode_script_num(int64_t n) {
    if (n == 0) {
        return {};
    }

    std::vector<uint8_t> result;
    bool negative = (n < 0);
    uint64_t abs_val = negative
        ? (n == std::numeric_limits<int64_t>::min()
            ? static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1
            : static_cast<uint64_t>(-n))
        : static_cast<uint64_t>(n);

    while (abs_val > 0) {
        result.push_back(static_cast<uint8_t>(abs_val & 0xFF));
        abs_val >>= 8;
    }

    // If the most significant byte has its high bit set, we need an
    // extra byte to hold the sign bit.
    if (result.back() & 0x80) {
        result.push_back(negative ? 0x80 : 0x00);
    } else if (negative) {
        result.back() |= 0x80;
    }

    return result;
}

} // anonymous namespace

// ===================================================================
// Standard script template constructors
// ===================================================================

Script Script::p2pkh(const core::uint160& pubkey_hash) {
    // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    std::vector<uint8_t> out;
    out.reserve(25);
    out.push_back(static_cast<uint8_t>(Opcode::OP_DUP));
    out.push_back(static_cast<uint8_t>(Opcode::OP_HASH160));
    append_push_hash160(out, pubkey_hash);
    out.push_back(static_cast<uint8_t>(Opcode::OP_EQUALVERIFY));
    out.push_back(static_cast<uint8_t>(Opcode::OP_CHECKSIG));
    return Script(std::move(out));
}

Script Script::p2sh(const core::uint160& script_hash) {
    // OP_HASH160 <20 bytes> OP_EQUAL
    std::vector<uint8_t> out;
    out.reserve(23);
    out.push_back(static_cast<uint8_t>(Opcode::OP_HASH160));
    append_push_hash160(out, script_hash);
    out.push_back(static_cast<uint8_t>(Opcode::OP_EQUAL));
    return Script(std::move(out));
}

Script Script::p2wpkh(const core::uint160& pubkey_hash) {
    // OP_0 <20 bytes>
    std::vector<uint8_t> out;
    out.reserve(22);
    out.push_back(static_cast<uint8_t>(Opcode::OP_0));
    append_push_hash160(out, pubkey_hash);
    return Script(std::move(out));
}

Script Script::p2wsh(const core::uint256& script_hash) {
    // OP_0 <32 bytes>
    std::vector<uint8_t> out;
    out.reserve(34);
    out.push_back(static_cast<uint8_t>(Opcode::OP_0));
    append_push_hash256(out, script_hash);
    return Script(std::move(out));
}

Script Script::p2tr(const core::uint256& output_key) {
    // OP_1 <32 bytes>
    std::vector<uint8_t> out;
    out.reserve(34);
    out.push_back(static_cast<uint8_t>(Opcode::OP_1));
    append_push_hash256(out, output_key);
    return Script(std::move(out));
}

Script Script::op_return(std::span<const uint8_t> payload) {
    std::vector<uint8_t> out;
    out.reserve(1 + 1 + payload.size());
    out.push_back(static_cast<uint8_t>(Opcode::OP_RETURN));
    // Push the payload using standard encoding.
    append_push_data(out, payload);
    return Script(std::move(out));
}

Script Script::multisig(
    int required,
    const std::vector<std::vector<uint8_t>>& pubkeys) {
    auto n = static_cast<int>(pubkeys.size());
    if (required < 1 || required > n) {
        throw std::invalid_argument(
            "Script::multisig: required out of range");
    }
    if (n > MAX_PUBKEYS_PER_MULTISIG) {
        throw std::invalid_argument(
            "Script::multisig: too many pubkeys");
    }

    std::vector<uint8_t> out;
    // OP_M
    out.push_back(static_cast<uint8_t>(encode_small_int(required)));
    // <pubkey1> ... <pubkeyN>
    for (const auto& pk : pubkeys) {
        append_push_data(out, std::span<const uint8_t>(pk));
    }
    // OP_N OP_CHECKMULTISIG
    out.push_back(static_cast<uint8_t>(encode_small_int(n)));
    out.push_back(static_cast<uint8_t>(Opcode::OP_CHECKMULTISIG));
    return Script(std::move(out));
}

// ===================================================================
// Script type detection
// ===================================================================

bool Script::is_p2pkh() const {
    // 25 bytes: OP_DUP OP_HASH160 0x14 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    return data_.size() == 25
        && data_[0]  == static_cast<uint8_t>(Opcode::OP_DUP)
        && data_[1]  == static_cast<uint8_t>(Opcode::OP_HASH160)
        && data_[2]  == 20  // OP_PUSHBYTES_20
        && data_[23] == static_cast<uint8_t>(Opcode::OP_EQUALVERIFY)
        && data_[24] == static_cast<uint8_t>(Opcode::OP_CHECKSIG);
}

bool Script::is_p2sh() const {
    // 23 bytes: OP_HASH160 0x14 <20 bytes> OP_EQUAL
    return data_.size() == 23
        && data_[0]  == static_cast<uint8_t>(Opcode::OP_HASH160)
        && data_[1]  == 20
        && data_[22] == static_cast<uint8_t>(Opcode::OP_EQUAL);
}

bool Script::is_p2wpkh() const {
    // 22 bytes: OP_0 0x14 <20 bytes>
    return data_.size() == 22
        && data_[0] == static_cast<uint8_t>(Opcode::OP_0)
        && data_[1] == 20;
}

bool Script::is_p2wsh() const {
    // 34 bytes: OP_0 0x20 <32 bytes>
    return data_.size() == 34
        && data_[0] == static_cast<uint8_t>(Opcode::OP_0)
        && data_[1] == 32;
}

bool Script::is_p2tr() const {
    // 34 bytes: OP_1 0x20 <32 bytes>
    return data_.size() == 34
        && data_[0] == static_cast<uint8_t>(Opcode::OP_1)
        && data_[1] == 32;
}

bool Script::is_op_return() const {
    return !data_.empty()
        && data_[0] == static_cast<uint8_t>(Opcode::OP_RETURN);
}

bool Script::is_multisig() const {
    if (data_.size() < 3) {
        return false;
    }

    // Last byte must be OP_CHECKMULTISIG.
    if (data_.back() !=
        static_cast<uint8_t>(Opcode::OP_CHECKMULTISIG)) {
        return false;
    }

    // Second-to-last decoded element must be OP_N (the total count).
    // First byte must be OP_M (the required count).
    auto op_m = static_cast<Opcode>(data_[0]);
    auto op_n = static_cast<Opcode>(data_[data_.size() - 2]);

    auto m = decode_small_int(op_m);
    auto n = decode_small_int(op_n);

    if (!m || !n || *m < 1 || *n < 1 || *m > *n) {
        return false;
    }
    if (*n > MAX_PUBKEYS_PER_MULTISIG) {
        return false;
    }

    // Walk the pubkey pushes to verify structure.
    Iterator it(data_.data() + 1,
                data_.data() + data_.size() - 2);
    int count = 0;
    while (auto elem = it.next()) {
        // Each element must be a data push (pubkey).
        if (elem->data.empty()) {
            return false;
        }
        ++count;
    }

    return count == *n;
}

bool Script::is_unspendable() const {
    // A script is provably unspendable if it starts with OP_RETURN
    // or exceeds the maximum script size.
    if (data_.size() > MAX_SCRIPT_SIZE) {
        return true;
    }
    return is_op_return();
}

bool Script::is_witness_program() const {
    // BIP141: A scriptPubKey that consists of a 1-byte push opcode
    // (OP_0 for version 0, OP_1..OP_16 for versions 1-16) followed
    // by a data push of 2 to 40 bytes.
    if (data_.size() < 4 || data_.size() > 42) {
        return false;
    }

    auto version_byte = data_[0];
    // OP_0 = 0x00, OP_1..OP_16 = 0x51..0x60
    if (version_byte != 0x00 &&
        (version_byte < 0x51 || version_byte > 0x60)) {
        return false;
    }

    // The second byte is the push length; the rest is the program.
    auto program_len = data_[1];
    if (program_len < 2 || program_len > 40) {
        return false;
    }

    return data_.size() == static_cast<size_t>(2 + program_len);
}

std::optional<std::pair<int, std::vector<uint8_t>>>
Script::witness_program() const {
    if (!is_witness_program()) {
        return std::nullopt;
    }

    int version = 0;
    auto version_byte = data_[0];
    if (version_byte == 0x00) {
        version = 0;
    } else {
        // OP_1..OP_16 => version 1..16
        version = version_byte - 0x50;
    }

    auto program_len = static_cast<size_t>(data_[1]);
    std::vector<uint8_t> program(
        data_.begin() + 2,
        data_.begin() + 2 + static_cast<ptrdiff_t>(program_len));

    return std::make_pair(version, std::move(program));
}

// ===================================================================
// Hash extraction
// ===================================================================

std::optional<core::uint160> Script::get_p2pkh_hash() const {
    if (!is_p2pkh()) {
        return std::nullopt;
    }
    core::uint160 hash;
    std::memcpy(hash.data(), data_.data() + 3, 20);
    return hash;
}

std::optional<core::uint160> Script::get_p2sh_hash() const {
    if (!is_p2sh()) {
        return std::nullopt;
    }
    core::uint160 hash;
    std::memcpy(hash.data(), data_.data() + 2, 20);
    return hash;
}

std::optional<core::uint160> Script::get_p2wpkh_hash() const {
    if (!is_p2wpkh()) {
        return std::nullopt;
    }
    core::uint160 hash;
    std::memcpy(hash.data(), data_.data() + 2, 20);
    return hash;
}

std::optional<core::uint256> Script::get_p2wsh_hash() const {
    if (!is_p2wsh()) {
        return std::nullopt;
    }
    core::uint256 hash;
    std::memcpy(hash.data(), data_.data() + 2, 32);
    return hash;
}

std::optional<core::uint256> Script::get_p2tr_key() const {
    if (!is_p2tr()) {
        return std::nullopt;
    }
    core::uint256 key;
    std::memcpy(key.data(), data_.data() + 2, 32);
    return key;
}

// ===================================================================
// Builder helpers
// ===================================================================

Script& Script::push_opcode(Opcode op) {
    data_.push_back(static_cast<uint8_t>(op));
    return *this;
}

Script& Script::push_data(std::span<const uint8_t> payload) {
    append_push_data(data_, payload);
    return *this;
}

Script& Script::push_int(int64_t n) {
    if (n == -1) {
        return push_opcode(Opcode::OP_1NEGATE);
    }
    if (n == 0) {
        return push_opcode(Opcode::OP_0);
    }
    if (n >= 1 && n <= 16) {
        return push_opcode(encode_small_int(static_cast<int>(n)));
    }

    // General case: CScriptNum encoding.
    auto encoded = encode_script_num(n);
    append_push_data(data_,
        std::span<const uint8_t>(encoded.data(), encoded.size()));
    return *this;
}

// ===================================================================
// Iterator
// ===================================================================

Script::Iterator::Iterator(const uint8_t* begin, const uint8_t* end)
    : ptr_(begin), end_(end) {}

std::optional<Script::Element> Script::Iterator::next() {
    if (ptr_ >= end_) {
        return std::nullopt;
    }

    auto raw = *ptr_++;
    auto op = static_cast<Opcode>(raw);

    // Implicit push-bytes: opcode value IS the byte count (1-75).
    if (raw >= 0x01 && raw <= 0x4b) {
        size_t count = raw;
        if (static_cast<size_t>(end_ - ptr_) < count) {
            // Truncated script -- signal error.
            ptr_ = end_;
            return std::nullopt;
        }
        Element elem{op, std::span<const uint8_t>(ptr_, count)};
        ptr_ += count;
        return elem;
    }

    // OP_PUSHDATA1: next 1 byte is the length.
    if (op == Opcode::OP_PUSHDATA1) {
        if (ptr_ >= end_) {
            ptr_ = end_;
            return std::nullopt;
        }
        size_t count = *ptr_++;
        if (static_cast<size_t>(end_ - ptr_) < count) {
            ptr_ = end_;
            return std::nullopt;
        }
        Element elem{op, std::span<const uint8_t>(ptr_, count)};
        ptr_ += count;
        return elem;
    }

    // OP_PUSHDATA2: next 2 bytes (LE) are the length.
    if (op == Opcode::OP_PUSHDATA2) {
        if (static_cast<size_t>(end_ - ptr_) < 2) {
            ptr_ = end_;
            return std::nullopt;
        }
        size_t count = static_cast<size_t>(ptr_[0])
                     | (static_cast<size_t>(ptr_[1]) << 8);
        ptr_ += 2;
        if (static_cast<size_t>(end_ - ptr_) < count) {
            ptr_ = end_;
            return std::nullopt;
        }
        Element elem{op, std::span<const uint8_t>(ptr_, count)};
        ptr_ += count;
        return elem;
    }

    // OP_PUSHDATA4: next 4 bytes (LE) are the length.
    if (op == Opcode::OP_PUSHDATA4) {
        if (static_cast<size_t>(end_ - ptr_) < 4) {
            ptr_ = end_;
            return std::nullopt;
        }
        size_t count = static_cast<size_t>(ptr_[0])
                     | (static_cast<size_t>(ptr_[1]) << 8)
                     | (static_cast<size_t>(ptr_[2]) << 16)
                     | (static_cast<size_t>(ptr_[3]) << 24);
        ptr_ += 4;
        if (static_cast<size_t>(end_ - ptr_) < count) {
            ptr_ = end_;
            return std::nullopt;
        }
        Element elem{op, std::span<const uint8_t>(ptr_, count)};
        ptr_ += count;
        return elem;
    }

    // All other opcodes carry no inline data.
    return Element{op, {}};
}

Script::Iterator Script::begin_iter() const {
    return Iterator(data_.data(), data_.data() + data_.size());
}

// ===================================================================
// Hashing
// ===================================================================

core::uint160 Script::script_hash() const {
    // FTC HASH160 = first 20 bytes of Keccak256(Keccak256(data))
    auto first = crypto::keccak256(data_.data(), data_.size());
    auto second = crypto::keccak256(
        reinterpret_cast<const uint8_t*>(first.data()), 32);

    core::uint160 result;
    std::memcpy(result.data(),
                reinterpret_cast<const uint8_t*>(second.data()), 20);
    return result;
}

core::uint256 Script::witness_script_hash() const {
    // P2WSH uses a single Keccak256.
    return crypto::keccak256(data_.data(), data_.size());
}

} // namespace primitives::script
