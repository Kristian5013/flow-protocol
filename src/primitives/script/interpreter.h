#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "primitives/script/opcodes.h"
#include "primitives/script/script.h"
#include "primitives/transaction.h"

namespace primitives::script {

// ---------------------------------------------------------------------------
// Script verification flags
// ---------------------------------------------------------------------------
enum class ScriptFlags : uint32_t {
    NONE                                  = 0,
    P2SH                                  = (1u << 0),
    STRICTENC                             = (1u << 1),
    DERSIG                                = (1u << 2),
    LOW_S                                 = (1u << 3),
    NULLDUMMY                             = (1u << 4),
    SIGPUSHONLY                            = (1u << 5),
    MINIMALDATA                           = (1u << 6),
    DISCOURAGE_UPGRADABLE_NOPS            = (1u << 7),
    CLEANSTACK                            = (1u << 8),
    CHECKLOCKTIMEVERIFY                   = (1u << 9),
    CHECKSEQUENCEVERIFY                   = (1u << 10),
    WITNESS                               = (1u << 11),
    DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = (1u << 12),
    MINIMALIF                             = (1u << 13),
    NULLFAIL                              = (1u << 14),
    WITNESS_PUBKEYTYPE                    = (1u << 15),
    TAPROOT                               = (1u << 17),

    STANDARD = P2SH | STRICTENC | DERSIG | LOW_S | NULLDUMMY |
               SIGPUSHONLY | MINIMALDATA | DISCOURAGE_UPGRADABLE_NOPS |
               CLEANSTACK | CHECKLOCKTIMEVERIFY | CHECKSEQUENCEVERIFY |
               WITNESS | DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
               MINIMALIF | NULLFAIL | WITNESS_PUBKEYTYPE,

    MANDATORY = P2SH | STRICTENC | DERSIG | LOW_S,
};

inline ScriptFlags operator|(ScriptFlags a, ScriptFlags b) {
    return static_cast<ScriptFlags>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline ScriptFlags operator&(ScriptFlags a, ScriptFlags b) {
    return static_cast<ScriptFlags>(
        static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}
inline ScriptFlags& operator|=(ScriptFlags& a, ScriptFlags b) {
    a = a | b;
    return a;
}
inline bool has_flag(ScriptFlags flags, ScriptFlags test) {
    return (static_cast<uint32_t>(flags) &
            static_cast<uint32_t>(test)) != 0;
}

// ---------------------------------------------------------------------------
// Signature checker interface
// ---------------------------------------------------------------------------
class BaseSignatureChecker {
public:
    virtual ~BaseSignatureChecker() = default;

    virtual bool check_sig(std::span<const uint8_t> sig,
                           std::span<const uint8_t> pubkey,
                           const Script& script_code,
                           int hash_type) const = 0;

    virtual bool check_lock_time(int64_t lock_time) const {
        return false;
    }
    virtual bool check_sequence(int64_t sequence) const {
        return false;
    }
};

// ---------------------------------------------------------------------------
// Transaction-aware signature checker
// ---------------------------------------------------------------------------
class TransactionSignatureChecker : public BaseSignatureChecker {
public:
    TransactionSignatureChecker(const Transaction* tx,
                                size_t idx,
                                Amount amount)
        : tx_(tx), input_index_(idx), amount_(amount) {}

    bool check_sig(std::span<const uint8_t> sig,
                   std::span<const uint8_t> pubkey,
                   const Script& script_code,
                   int hash_type) const override;

    bool check_lock_time(int64_t lock_time) const override;
    bool check_sequence(int64_t sequence) const override;

private:
    const Transaction* tx_;
    size_t input_index_;
    Amount amount_;
};

// ---------------------------------------------------------------------------
// Script execution error codes
// ---------------------------------------------------------------------------
enum class ScriptError {
    OK = 0,
    UNKNOWN,
    EVAL_FALSE,
    OP_RETURN,

    // Size limits
    SCRIPT_SIZE,
    PUSH_SIZE,
    OP_COUNT,
    STACK_SIZE,

    // Disabled opcodes
    DISABLED_OPCODE,

    // Flow control
    UNBALANCED_CONDITIONAL,

    // Stack errors
    INVALID_STACK_OPERATION,
    INVALID_ALTSTACK_OPERATION,

    // Numeric
    NUM_OVERFLOW,

    // Signature
    SIG_COUNT,
    PUBKEY_COUNT,
    MULTISIG_VERIFY,
    SIG_NULLDUMMY,
    SIG_DER,
    SIG_HIGH_S,
    SIG_HASHTYPE,
    SIG_NULLFAIL,

    // Crypto
    VERIFY,
    EQUALVERIFY,
    CHECKMULTISIGVERIFY,
    CHECKSIGVERIFY,

    // Locktime
    NEGATIVE_LOCKTIME,
    UNSATISFIED_LOCKTIME,

    // Witness
    WITNESS_PROGRAM_WRONG_LENGTH,
    WITNESS_PROGRAM_WITNESS_EMPTY,
    WITNESS_PROGRAM_MISMATCH,
    WITNESS_MALLEATED,
    WITNESS_MALLEATED_P2SH,
    WITNESS_UNEXPECTED,
    WITNESS_PUBKEYTYPE,

    // Cleanstack
    CLEANSTACK,

    // Minimaldata
    MINIMALDATA,
    MINIMALIF,

    // Policy
    DISCOURAGE_UPGRADABLE_NOPS,
    DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    SIGPUSHONLY,
};

/// Human-readable string for a script error code.
std::string_view script_error_string(ScriptError err);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Full script verification: scriptSig + scriptPubKey (+ witness / P2SH).
bool verify_script(const Script& script_sig,
                   const Script& script_pubkey,
                   const std::vector<std::vector<uint8_t>>& witness,
                   ScriptFlags flags,
                   const BaseSignatureChecker& checker,
                   ScriptError* error_out = nullptr);

/// Execute a single script program against the provided stack.
bool eval_script(std::vector<std::vector<uint8_t>>& stack,
                 const Script& script,
                 ScriptFlags flags,
                 const BaseSignatureChecker& checker,
                 ScriptError* error_out = nullptr);

}  // namespace primitives::script
