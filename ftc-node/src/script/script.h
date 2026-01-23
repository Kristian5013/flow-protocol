#ifndef FTC_SCRIPT_SCRIPT_H
#define FTC_SCRIPT_SCRIPT_H

#include <cstdint>
#include <vector>
#include <string>

namespace ftc {
namespace script {

/**
 * Script opcodes - Bitcoin-compatible
 *
 * FTC uses the same script system as Bitcoin for maximum compatibility.
 * Scripts are executed on a stack machine.
 */
enum class Opcode : uint8_t {
    // Push value
    OP_0 = 0x00,
    OP_FALSE = OP_0,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_TRUE = OP_1,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // Control flow
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // Stack operations
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,

    // Splice operations (disabled in Bitcoin, we keep them disabled)
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,

    // Bitwise logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    // Numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,
    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,
    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,
    OP_WITHIN = 0xa5,

    // Crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // Expansion
    OP_NOP1 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,

    // SegWit
    OP_CHECKSIGADD = 0xba,

    OP_INVALIDOPCODE = 0xff,
};

// Script verification flags
enum ScriptFlags : uint32_t {
    SCRIPT_VERIFY_NONE = 0,

    // Evaluate P2SH subscripts
    SCRIPT_VERIFY_P2SH = (1U << 0),

    // Passing a non-strict-DER signature is an error
    SCRIPT_VERIFY_STRICTENC = (1U << 1),

    // Passing a non-strict-DER signature or pubkey is an error
    SCRIPT_VERIFY_DERSIG = (1U << 2),

    // Require strict encoding of signatures
    SCRIPT_VERIFY_LOW_S = (1U << 3),

    // Verify dummy stack elements are null
    SCRIPT_VERIFY_NULLDUMMY = (1U << 4),

    // Using non-push operators in scriptSig is an error
    SCRIPT_VERIFY_SIGPUSHONLY = (1U << 5),

    // Require minimal encodings for data pushes
    SCRIPT_VERIFY_MINIMALDATA = (1U << 6),

    // Discourage NOPs
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1U << 7),

    // Require that CLEANSTACK is used
    SCRIPT_VERIFY_CLEANSTACK = (1U << 8),

    // Verify CHECKLOCKTIMEVERIFY
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),

    // Verify CHECKSEQUENCEVERIFY
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10),

    // Support segregated witness
    SCRIPT_VERIFY_WITNESS = (1U << 11),

    // Require minimal IF/NOTIF arguments
    SCRIPT_VERIFY_MINIMALIF = (1U << 12),

    // Signature must be empty if failed CHECKSIG
    SCRIPT_VERIFY_NULLFAIL = (1U << 13),

    // Public keys must be compressed
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = (1U << 14),

    // Const scriptcode for tapscript
    SCRIPT_VERIFY_CONST_SCRIPTCODE = (1U << 15),

    // Taproot/Tapscript
    SCRIPT_VERIFY_TAPROOT = (1U << 16),

    // Discourage checksigadd
    SCRIPT_VERIFY_DISCOURAGE_CHECKSIGADD = (1U << 17),

    // Discourage upgradable pubkey type
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = (1U << 18),

    // Standard flags
    SCRIPT_STANDARD_FLAGS = SCRIPT_VERIFY_P2SH |
                            SCRIPT_VERIFY_DERSIG |
                            SCRIPT_VERIFY_STRICTENC |
                            SCRIPT_VERIFY_MINIMALDATA |
                            SCRIPT_VERIFY_NULLDUMMY |
                            SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
                            SCRIPT_VERIFY_CLEANSTACK |
                            SCRIPT_VERIFY_MINIMALIF |
                            SCRIPT_VERIFY_NULLFAIL |
                            SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                            SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                            SCRIPT_VERIFY_LOW_S |
                            SCRIPT_VERIFY_WITNESS |
                            SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
};

// Script error codes
enum class ScriptError {
    OK = 0,
    UNKNOWN_ERROR,
    EVAL_FALSE,
    OP_RETURN,

    // Stack errors
    SCRIPT_SIZE,
    PUSH_SIZE,
    OP_COUNT,
    STACK_SIZE,
    SIG_COUNT,
    PUBKEY_COUNT,

    // Validation errors
    INVALID_OPCODE,
    DISABLED_OPCODE,
    INVALID_STACK_OPERATION,
    INVALID_ALTSTACK_OPERATION,
    UNBALANCED_CONDITIONAL,

    // OP_CHECKLOCKTIMEVERIFY errors
    NEGATIVE_LOCKTIME,
    UNSATISFIED_LOCKTIME,

    // OP_CHECKSEQUENCEVERIFY errors
    UNSATISFIED_SEQUENCE,

    // Signature errors
    SIG_HASHTYPE,
    SIG_DER,
    MINIMALDATA,
    SIG_PUSHONLY,
    SIG_HIGH_S,
    SIG_NULLDUMMY,
    PUBKEYTYPE,
    CLEANSTACK,
    MINIMALIF,
    SIG_NULLFAIL,

    // Signature verification
    SIG_VERIFY,
    MULTISIG_VERIFY,

    // Witness errors
    WITNESS_PROGRAM_WRONG_LENGTH,
    WITNESS_PROGRAM_WITNESS_EMPTY,
    WITNESS_PROGRAM_MISMATCH,
    WITNESS_MALLEATED,
    WITNESS_MALLEATED_P2SH,
    WITNESS_UNEXPECTED,
    WITNESS_PUBKEYTYPE,

    // Taproot errors
    TAPROOT_WRONG_CONTROL_SIZE,
    TAPROOT_ANNEX_UNSUPPORTED,
    TAPROOT_INVALID_INTERNAL_KEY,
    TAPROOT_INVALID_PARITY,
    TAPROOT_INVALID_MERKLE_ROOT,
    TAPSCRIPT_VALIDATION_WEIGHT,
    TAPSCRIPT_CHECKMULTISIG,
    TAPSCRIPT_MINIMALIF,

    // Constant errors
    OP_CODESEPARATOR,
    SIG_FINDANDDELETE,

    ERROR_COUNT
};

// Get error message
const char* ScriptErrorString(ScriptError error);

/**
 * Script - represents a Bitcoin-style script
 */
class Script {
public:
    Script() = default;
    explicit Script(const std::vector<uint8_t>& data) : data_(data) {}
    Script(const uint8_t* data, size_t len) : data_(data, data + len) {}

    // Access
    const std::vector<uint8_t>& data() const { return data_; }
    std::vector<uint8_t>& data() { return data_; }
    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }
    const uint8_t* begin() const { return data_.data(); }
    const uint8_t* end() const { return data_.data() + data_.size(); }

    // Operators
    Script& operator<<(Opcode opcode);
    Script& operator<<(const std::vector<uint8_t>& data);
    Script& operator<<(int64_t n);

    // Script type detection
    bool isPayToPublicKeyHash() const;     // P2PKH
    bool isPayToScriptHash() const;        // P2SH
    bool isPayToWitnessKeyHash() const;    // P2WPKH (native segwit)
    bool isPayToWitnessScriptHash() const; // P2WSH
    bool isPayToTaproot() const;           // P2TR
    bool isWitnessProgram(int& version, std::vector<uint8_t>& program) const;
    bool isPushOnly() const;
    bool isUnspendable() const;            // OP_RETURN or invalid

    // Standard script creation
    static Script createP2PKH(const std::vector<uint8_t>& pubkey_hash);
    static Script createP2SH(const std::vector<uint8_t>& script_hash);
    static Script createP2WPKH(const std::vector<uint8_t>& pubkey_hash);
    static Script createP2WSH(const std::vector<uint8_t>& script_hash);
    static Script createP2TR(const std::vector<uint8_t>& output_key);
    static Script createOpReturn(const std::vector<uint8_t>& data);
    static Script createMultisig(int required, const std::vector<std::vector<uint8_t>>& pubkeys);

    // Serialization
    std::string toHex() const;
    std::string toAsm() const;
    static Script fromHex(const std::string& hex);

    // Extract data
    bool extractPubKeyHash(std::vector<uint8_t>& hash) const;
    bool extractScriptHash(std::vector<uint8_t>& hash) const;

private:
    std::vector<uint8_t> data_;
};

// Stack element (can be up to 520 bytes)
using StackElement = std::vector<uint8_t>;

// Convert stack element to/from integer
int64_t stackElementToInt(const StackElement& elem, bool require_minimal, size_t max_len = 4);
StackElement intToStackElement(int64_t value);
bool stackElementIsTrue(const StackElement& elem);

// Signature hash types
enum SigHashType : uint8_t {
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,
};

// Get opcode name
const char* getOpcodeName(Opcode opcode);

// Check if opcode is disabled
bool isOpcodeDisabled(Opcode opcode);

// Check if opcode is push-only
bool isPushOpcode(uint8_t opcode);

// Calculate script number encoding size
size_t getScriptNumSize(int64_t value);

} // namespace script
} // namespace ftc

#endif // FTC_SCRIPT_SCRIPT_H
