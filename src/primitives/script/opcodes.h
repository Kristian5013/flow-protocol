#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace primitives::script {

/// Complete Bitcoin-compatible opcode set, modified for FTC (Flow Token Chain).
/// Opcodes 0x00-0x4b are implicit push-N-bytes instructions.
/// FTC replaces SHA256 with Keccak256 in the crypto opcode range.
enum class Opcode : uint8_t {
    // -----------------------------------------------------------------------
    // Push value
    // -----------------------------------------------------------------------
    OP_0                = 0x00,
    OP_FALSE            = 0x00,

    // OP_PUSHBYTES_1 through OP_PUSHBYTES_75 (0x01-0x4b)
    // These are not enumerated individually; any byte in [0x01, 0x4b]
    // means "push the next N bytes onto the stack".

    OP_PUSHDATA1        = 0x4c,  // next 1 byte is data length
    OP_PUSHDATA2        = 0x4d,  // next 2 bytes are data length (LE)
    OP_PUSHDATA4        = 0x4e,  // next 4 bytes are data length (LE)
    OP_1NEGATE          = 0x4f,

    OP_RESERVED         = 0x50,

    OP_1                = 0x51,
    OP_TRUE             = 0x51,
    OP_2                = 0x52,
    OP_3                = 0x53,
    OP_4                = 0x54,
    OP_5                = 0x55,
    OP_6                = 0x56,
    OP_7                = 0x57,
    OP_8                = 0x58,
    OP_9                = 0x59,
    OP_10               = 0x5a,
    OP_11               = 0x5b,
    OP_12               = 0x5c,
    OP_13               = 0x5d,
    OP_14               = 0x5e,
    OP_15               = 0x5f,
    OP_16               = 0x60,

    // -----------------------------------------------------------------------
    // Flow control
    // -----------------------------------------------------------------------
    OP_NOP              = 0x61,
    OP_VER              = 0x62,
    OP_IF               = 0x63,
    OP_NOTIF            = 0x64,
    OP_VERIF            = 0x65,
    OP_VERNOTIF         = 0x66,
    OP_ELSE             = 0x67,
    OP_ENDIF            = 0x68,
    OP_VERIFY           = 0x69,
    OP_RETURN           = 0x6a,

    // -----------------------------------------------------------------------
    // Stack
    // -----------------------------------------------------------------------
    OP_TOALTSTACK       = 0x6b,
    OP_FROMALTSTACK     = 0x6c,
    OP_2DROP            = 0x6d,
    OP_2DUP             = 0x6e,
    OP_3DUP             = 0x6f,
    OP_2OVER            = 0x70,
    OP_2ROT             = 0x71,
    OP_2SWAP            = 0x72,
    OP_IFDUP            = 0x73,
    OP_DEPTH            = 0x74,
    OP_DROP             = 0x75,
    OP_DUP              = 0x76,
    OP_NIP              = 0x77,
    OP_OVER             = 0x78,
    OP_PICK             = 0x79,
    OP_ROLL             = 0x7a,
    OP_ROT              = 0x7b,
    OP_SWAP             = 0x7c,
    OP_TUCK             = 0x7d,

    // -----------------------------------------------------------------------
    // Splice (disabled in consensus)
    // -----------------------------------------------------------------------
    OP_CAT              = 0x7e,
    OP_SUBSTR           = 0x7f,
    OP_LEFT             = 0x80,
    OP_RIGHT            = 0x81,
    OP_SIZE             = 0x82,

    // -----------------------------------------------------------------------
    // Bitwise logic
    // -----------------------------------------------------------------------
    OP_INVERT           = 0x83,
    OP_AND              = 0x84,
    OP_OR               = 0x85,
    OP_XOR              = 0x86,
    OP_EQUAL            = 0x87,
    OP_EQUALVERIFY      = 0x88,
    OP_RESERVED1        = 0x89,
    OP_RESERVED2        = 0x8a,

    // -----------------------------------------------------------------------
    // Arithmetic
    // -----------------------------------------------------------------------
    OP_1ADD             = 0x8b,
    OP_1SUB             = 0x8c,
    OP_2MUL             = 0x8d,
    OP_2DIV             = 0x8e,
    OP_NEGATE           = 0x8f,
    OP_ABS              = 0x90,
    OP_NOT              = 0x91,
    OP_0NOTEQUAL        = 0x92,
    OP_ADD              = 0x93,
    OP_SUB              = 0x94,
    OP_MUL              = 0x95,
    OP_DIV              = 0x96,
    OP_MOD              = 0x97,
    OP_LSHIFT           = 0x98,
    OP_RSHIFT           = 0x99,
    OP_BOOLAND          = 0x9a,
    OP_BOOLOR           = 0x9b,
    OP_NUMEQUAL         = 0x9c,
    OP_NUMEQUALVERIFY   = 0x9d,
    OP_NUMNOTEQUAL      = 0x9e,
    OP_LESSTHAN         = 0x9f,
    OP_GREATERTHAN      = 0xa0,
    OP_LESSTHANOREQUAL  = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN              = 0xa3,
    OP_MAX              = 0xa4,
    OP_WITHIN           = 0xa5,

    // -----------------------------------------------------------------------
    // Crypto  (FTC modifications noted)
    // -----------------------------------------------------------------------
    OP_RIPEMD160        = 0xa6,
    OP_SHA1             = 0xa7,
    OP_KECCAK256        = 0xa8,  // FTC: replaces OP_SHA256
    OP_HASH160          = 0xa9,  // FTC: Keccak256(Keccak256(x))[0..20]
    OP_HASH256          = 0xaa,  // FTC: Keccak256d (double Keccak256)
    OP_CODESEPARATOR    = 0xab,
    OP_CHECKSIG         = 0xac,
    OP_CHECKSIGVERIFY   = 0xad,
    OP_CHECKMULTISIG    = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // -----------------------------------------------------------------------
    // Expansion / locktime
    // -----------------------------------------------------------------------
    OP_NOP1             = 0xb0,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_NOP2             = 0xb1,
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    OP_NOP3             = 0xb2,
    OP_NOP4             = 0xb3,
    OP_NOP5             = 0xb4,
    OP_NOP6             = 0xb5,
    OP_NOP7             = 0xb6,
    OP_NOP8             = 0xb7,
    OP_NOP9             = 0xb8,
    OP_NOP10            = 0xb9,

    // -----------------------------------------------------------------------
    // Taproot
    // -----------------------------------------------------------------------
    OP_CHECKSIGADD      = 0xba,

    // -----------------------------------------------------------------------
    // Invalid
    // -----------------------------------------------------------------------
    OP_INVALIDOPCODE    = 0xff,
};

// ---------------------------------------------------------------------------
// String conversion
// ---------------------------------------------------------------------------

/// Return the canonical display name for an opcode (e.g. "OP_DUP").
/// For push-bytes opcodes in [0x01, 0x4b], returns "OP_PUSHBYTES_N".
/// For unknown opcodes returns "OP_UNKNOWN_XX".
std::string_view opcode_name(Opcode op);

/// Look up an opcode by its canonical name (case-sensitive).
/// Returns std::nullopt for unrecognised names.
std::optional<Opcode> opcode_from_name(std::string_view name);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// True for any opcode whose raw byte value is in [0x00, 0x60],
/// i.e. all push-value opcodes including OP_0, OP_PUSHBYTES_*,
/// OP_PUSHDATA1/2/4, OP_1NEGATE, OP_RESERVED, and OP_1..OP_16.
constexpr bool is_push_opcode(Opcode op) noexcept {
    return static_cast<uint8_t>(op) <= 0x60;
}

/// Decode OP_0 -> 0, OP_1..OP_16 -> 1..16.
/// Returns std::nullopt for any other opcode.
constexpr std::optional<int> decode_small_int(Opcode op) noexcept {
    if (op == Opcode::OP_0) {
        return 0;
    }
    auto raw = static_cast<uint8_t>(op);
    if (raw >= static_cast<uint8_t>(Opcode::OP_1) &&
        raw <= static_cast<uint8_t>(Opcode::OP_16)) {
        return static_cast<int>(raw) - 0x50;
    }
    return std::nullopt;
}

/// Encode an integer in [0, 16] to the corresponding small-integer opcode.
/// Precondition: 0 <= n <= 16.  Behaviour is undefined otherwise.
constexpr Opcode encode_small_int(int n) noexcept {
    if (n == 0) {
        return Opcode::OP_0;
    }
    return static_cast<Opcode>(static_cast<uint8_t>(Opcode::OP_1) + n - 1);
}

} // namespace primitives::script
