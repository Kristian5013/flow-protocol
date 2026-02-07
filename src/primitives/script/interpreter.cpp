#include "primitives/script/interpreter.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <limits>
#include <optional>
#include <stdexcept>
#include <vector>

#include "crypto/keccak.h"
#include "crypto/secp256k1.h"

namespace primitives::script {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
static constexpr size_t MAX_STACK_SIZE         = 1000;
static constexpr size_t MAX_PUSH_SIZE          = 520;
static constexpr size_t MAX_SCRIPT_NUM_LENGTH  = 4;

// Sighash mask (lower 5 bits of hash_type carry the base type).
static constexpr int SIGHASH_ALL          = 1;
static constexpr int SIGHASH_NONE         = 2;
static constexpr int SIGHASH_SINGLE       = 3;
static constexpr int SIGHASH_ANYONECANPAY = 0x80;

// SEQUENCE_LOCKTIME flag used by OP_CHECKSEQUENCEVERIFY.
static constexpr uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1u << 31);
static constexpr uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG    = (1u << 22);
static constexpr uint32_t SEQUENCE_LOCKTIME_MASK         = 0x0000ffff;

// ---------------------------------------------------------------------------
// Helpers: error reporting
// ---------------------------------------------------------------------------
static inline bool set_error(ScriptError* out, ScriptError err) {
    if (out) *out = err;
    return false;
}

static inline bool set_success(ScriptError* out) {
    if (out) *out = ScriptError::OK;
    return true;
}

// ---------------------------------------------------------------------------
// ScriptNum -- variable-length little-endian integer with sign bit
// ---------------------------------------------------------------------------
class ScriptNum {
public:
    explicit ScriptNum(int64_t value) : value_(value) {}

    /// Decode from stack element. max_length is typically 4.
    static std::optional<ScriptNum> from_bytes(
            std::span<const uint8_t> data,
            size_t max_length = MAX_SCRIPT_NUM_LENGTH,
            bool require_minimal = false) {
        if (data.size() > max_length) return std::nullopt;
        if (data.empty()) return ScriptNum{0};

        // Minimal encoding check: the most significant byte (excluding the
        // sign bit) must be non-zero, unless the byte is needed solely for
        // the sign bit.
        if (require_minimal) {
            if ((data.back() & 0x7f) == 0) {
                if (data.size() <= 1 || (data[data.size() - 2] & 0x80) == 0) {
                    return std::nullopt;
                }
            }
        }

        int64_t result = 0;
        for (size_t i = 0; i < data.size(); ++i) {
            result |= static_cast<int64_t>(data[i]) << (8 * i);
        }

        // Sign bit is the MSB of the last byte.
        if (data.back() & 0x80) {
            result &= ~(static_cast<int64_t>(0x80) << (8 * (data.size() - 1)));
            result = -result;
        }
        return ScriptNum{result};
    }

    /// Encode to minimal byte representation.
    std::vector<uint8_t> to_bytes() const {
        if (value_ == 0) return {};

        std::vector<uint8_t> result;
        const bool negative = value_ < 0;
        uint64_t abs_val = negative
            ? (value_ == std::numeric_limits<int64_t>::min()
                   ? static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1
                   : static_cast<uint64_t>(-value_))
            : static_cast<uint64_t>(value_);

        while (abs_val > 0) {
            result.push_back(static_cast<uint8_t>(abs_val & 0xff));
            abs_val >>= 8;
        }

        // If the high bit is set, add an extra byte for the sign.
        if (result.back() & 0x80) {
            result.push_back(negative ? 0x80 : 0x00);
        } else if (negative) {
            result.back() |= 0x80;
        }
        return result;
    }

    int64_t value() const { return value_; }
    int     to_int() const {
        if (value_ > std::numeric_limits<int>::max())
            return std::numeric_limits<int>::max();
        if (value_ < std::numeric_limits<int>::min())
            return std::numeric_limits<int>::min();
        return static_cast<int>(value_);
    }

private:
    int64_t value_;
};

// ---------------------------------------------------------------------------
// Stack helpers
// ---------------------------------------------------------------------------
using Stack = std::vector<std::vector<uint8_t>>;

static inline bool cast_to_bool(const std::vector<uint8_t>& v) {
    for (size_t i = 0; i < v.size(); ++i) {
        if (v[i] != 0) {
            // Negative zero: the last byte can be 0x80.
            if (i == v.size() - 1 && v[i] == 0x80)
                return false;
            return true;
        }
    }
    return false;
}

/// Reference to the n-th element from the top of the stack (0 = top).
static inline std::vector<uint8_t>& stacktop(Stack& stack, int idx) {
    return stack[stack.size() + idx];
}
static inline const std::vector<uint8_t>& stacktop(
        const Stack& stack, int idx) {
    return stack[stack.size() + idx];
}

// ---------------------------------------------------------------------------
// Signature encoding helpers
// ---------------------------------------------------------------------------

/// Check if the hash_type byte is valid.
static bool is_valid_signature_encoding(std::span<const uint8_t> sig) {
    // A valid DER-encoded signature is at least 9 bytes:
    // 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    if (sig.size() < 9) return false;
    if (sig.size() > 73) return false;
    if (sig[0] != 0x30) return false;
    if (sig[1] != sig.size() - 3) return false;
    size_t len_r = sig[3];
    if (5 + len_r >= sig.size()) return false;
    size_t len_s = sig[5 + len_r];
    if (len_r + len_s + 7 != sig.size()) return false;
    if (sig[2] != 0x02) return false;
    if (len_r == 0) return false;
    if (sig[4] & 0x80) return false;
    if (len_r > 1 && sig[4] == 0x00 && !(sig[5] & 0x80)) return false;
    if (sig[4 + len_r] != 0x02) return false;
    if (len_s == 0) return false;
    if (sig[6 + len_r] & 0x80) return false;
    if (len_s > 1 && sig[6 + len_r] == 0x00 &&
            !(sig[7 + len_r] & 0x80)) return false;
    return true;
}

static bool is_low_der_signature(std::span<const uint8_t> sig) {
    if (!is_valid_signature_encoding(sig)) return false;
    // S value must be <= order/2.  secp256k1 order/2 is:
    // 0x7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 5D576E73 57A4501D DFE92F46 681B20A0
    static constexpr uint8_t kHalfOrder[32] = {
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
        0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
    };
    size_t len_r = sig[3];
    size_t len_s = sig[5 + len_r];
    const uint8_t* s_ptr = sig.data() + 6 + len_r;

    // Left-pad S to 32 bytes for comparison.
    if (len_s > 32) return false;
    uint8_t s_padded[32] = {};
    std::memcpy(s_padded + (32 - len_s), s_ptr, len_s);
    for (int i = 0; i < 32; ++i) {
        if (s_padded[i] < kHalfOrder[i]) return true;
        if (s_padded[i] > kHalfOrder[i]) return false;
    }
    return true;  // Equal is fine.
}

static bool is_defined_hashtype_sig(std::span<const uint8_t> sig) {
    if (sig.empty()) return false;
    uint8_t ht = sig.back() & (~SIGHASH_ANYONECANPAY);
    if (ht < SIGHASH_ALL || ht > SIGHASH_SINGLE) return false;
    return true;
}

static bool check_signature_encoding(std::span<const uint8_t> sig,
                                     ScriptFlags flags,
                                     ScriptError* err) {
    if (sig.empty()) return true;
    if (has_flag(flags, ScriptFlags::STRICTENC) &&
            !is_valid_signature_encoding(sig)) {
        return set_error(err, ScriptError::SIG_DER);
    }
    if (has_flag(flags, ScriptFlags::DERSIG) &&
            !is_valid_signature_encoding(sig)) {
        return set_error(err, ScriptError::SIG_DER);
    }
    if (has_flag(flags, ScriptFlags::LOW_S) &&
            !is_low_der_signature(sig)) {
        return set_error(err, ScriptError::SIG_HIGH_S);
    }
    if (has_flag(flags, ScriptFlags::STRICTENC) &&
            !is_defined_hashtype_sig(sig)) {
        return set_error(err, ScriptError::SIG_HASHTYPE);
    }
    return true;
}

static bool check_pubkey_encoding(std::span<const uint8_t> pubkey,
                                  ScriptFlags flags,
                                  ScriptError* err) {
    if (has_flag(flags, ScriptFlags::STRICTENC)) {
        if (pubkey.size() == 33) {
            if (pubkey[0] != 0x02 && pubkey[0] != 0x03)
                return set_error(err, ScriptError::WITNESS_PUBKEYTYPE);
        } else if (pubkey.size() == 65) {
            if (pubkey[0] != 0x04)
                return set_error(err, ScriptError::WITNESS_PUBKEYTYPE);
        } else {
            return set_error(err, ScriptError::WITNESS_PUBKEYTYPE);
        }
    }
    if (has_flag(flags, ScriptFlags::WITNESS_PUBKEYTYPE)) {
        if (pubkey.size() != 33 ||
                (pubkey[0] != 0x02 && pubkey[0] != 0x03)) {
            return set_error(err, ScriptError::WITNESS_PUBKEYTYPE);
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// P2SH / Witness detection helpers
// ---------------------------------------------------------------------------

/// Returns true if script is exactly: OP_HASH160 <20 bytes> OP_EQUAL
static bool is_p2sh(const Script& script) {
    const auto& d = script.data();
    return d.size() == 23 &&
           d[0]  == static_cast<uint8_t>(Opcode::OP_HASH160) &&
           d[1]  == 0x14 &&
           d[22] == static_cast<uint8_t>(Opcode::OP_EQUAL);
}

/// Detect witness program: OP_n <2..40 bytes>. Returns version (-1 if
/// not a witness program) and writes the program bytes into `program`.
static int witness_version(const Script& script,
                           std::vector<uint8_t>& program) {
    const auto& d = script.data();
    if (d.size() < 4 || d.size() > 42) return -1;

    uint8_t first = d[0];
    int version = -1;
    if (first == static_cast<uint8_t>(Opcode::OP_0)) {
        version = 0;
    } else if (first >= static_cast<uint8_t>(Opcode::OP_1) &&
               first <= static_cast<uint8_t>(Opcode::OP_16)) {
        version = first - static_cast<uint8_t>(Opcode::OP_1) + 1;
    } else {
        return -1;
    }

    uint8_t push_len = d[1];
    if (push_len < 2 || push_len > 40) return -1;
    if (static_cast<size_t>(push_len + 2) != d.size()) return -1;

    program.assign(d.begin() + 2, d.end());
    return version;
}

// ---------------------------------------------------------------------------
// Script element: push-only check
// ---------------------------------------------------------------------------
static bool is_push_only(const Script& script) {
    auto it = script.begin_iter();
    while (auto elem = it.next()) {
        if (static_cast<uint8_t>(elem->opcode) >
                static_cast<uint8_t>(Opcode::OP_16)) {
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// script_error_string
// ---------------------------------------------------------------------------
std::string_view script_error_string(ScriptError err) {
    switch (err) {
        case ScriptError::OK:                           return "OK";
        case ScriptError::UNKNOWN:                      return "UNKNOWN";
        case ScriptError::EVAL_FALSE:                   return "EVAL_FALSE";
        case ScriptError::OP_RETURN:                    return "OP_RETURN";
        case ScriptError::SCRIPT_SIZE:                  return "SCRIPT_SIZE";
        case ScriptError::PUSH_SIZE:                    return "PUSH_SIZE";
        case ScriptError::OP_COUNT:                     return "OP_COUNT";
        case ScriptError::STACK_SIZE:                   return "STACK_SIZE";
        case ScriptError::DISABLED_OPCODE:              return "DISABLED_OPCODE";
        case ScriptError::UNBALANCED_CONDITIONAL:
            return "UNBALANCED_CONDITIONAL";
        case ScriptError::INVALID_STACK_OPERATION:
            return "INVALID_STACK_OPERATION";
        case ScriptError::INVALID_ALTSTACK_OPERATION:
            return "INVALID_ALTSTACK_OPERATION";
        case ScriptError::NUM_OVERFLOW:                 return "NUM_OVERFLOW";
        case ScriptError::SIG_COUNT:                    return "SIG_COUNT";
        case ScriptError::PUBKEY_COUNT:                 return "PUBKEY_COUNT";
        case ScriptError::MULTISIG_VERIFY:
            return "MULTISIG_VERIFY";
        case ScriptError::SIG_NULLDUMMY:                return "SIG_NULLDUMMY";
        case ScriptError::SIG_DER:                      return "SIG_DER";
        case ScriptError::SIG_HIGH_S:                   return "SIG_HIGH_S";
        case ScriptError::SIG_HASHTYPE:                 return "SIG_HASHTYPE";
        case ScriptError::SIG_NULLFAIL:                 return "SIG_NULLFAIL";
        case ScriptError::VERIFY:                       return "VERIFY";
        case ScriptError::EQUALVERIFY:                  return "EQUALVERIFY";
        case ScriptError::CHECKMULTISIGVERIFY:
            return "CHECKMULTISIGVERIFY";
        case ScriptError::CHECKSIGVERIFY:               return "CHECKSIGVERIFY";
        case ScriptError::NEGATIVE_LOCKTIME:
            return "NEGATIVE_LOCKTIME";
        case ScriptError::UNSATISFIED_LOCKTIME:
            return "UNSATISFIED_LOCKTIME";
        case ScriptError::WITNESS_PROGRAM_WRONG_LENGTH:
            return "WITNESS_PROGRAM_WRONG_LENGTH";
        case ScriptError::WITNESS_PROGRAM_WITNESS_EMPTY:
            return "WITNESS_PROGRAM_WITNESS_EMPTY";
        case ScriptError::WITNESS_PROGRAM_MISMATCH:
            return "WITNESS_PROGRAM_MISMATCH";
        case ScriptError::WITNESS_MALLEATED:
            return "WITNESS_MALLEATED";
        case ScriptError::WITNESS_MALLEATED_P2SH:
            return "WITNESS_MALLEATED_P2SH";
        case ScriptError::WITNESS_UNEXPECTED:
            return "WITNESS_UNEXPECTED";
        case ScriptError::WITNESS_PUBKEYTYPE:
            return "WITNESS_PUBKEYTYPE";
        case ScriptError::CLEANSTACK:                   return "CLEANSTACK";
        case ScriptError::MINIMALDATA:                  return "MINIMALDATA";
        case ScriptError::MINIMALIF:                    return "MINIMALIF";
        case ScriptError::DISCOURAGE_UPGRADABLE_NOPS:
            return "DISCOURAGE_UPGRADABLE_NOPS";
        case ScriptError::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM:
            return "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM";
        case ScriptError::SIGPUSHONLY:                  return "SIGPUSHONLY";
    }
    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// TransactionSignatureChecker
// ---------------------------------------------------------------------------
bool TransactionSignatureChecker::check_sig(
        std::span<const uint8_t> sig_span,
        std::span<const uint8_t> pubkey,
        const Script& script_code,
        int hash_type) const {
    if (!tx_) return false;

    // Compute the signature hash via the transaction.
    core::uint256 sighash = tx_->signature_hash(
        input_index_,
        script_code.data(),
        amount_,
        hash_type);

    return crypto::ECKey::verify(pubkey, sighash, sig_span);
}

bool TransactionSignatureChecker::check_lock_time(
        int64_t lock_time) const {
    // lock_time must be non-negative.
    if (lock_time < 0) return false;
    if (!tx_) return false;

    // The nLockTime field of the transaction must be the same type
    // (block height vs. timestamp) as the argument.
    int64_t tx_locktime = static_cast<int64_t>(tx_->locktime());
    if ((tx_locktime < 500000000 && lock_time >= 500000000) ||
        (tx_locktime >= 500000000 && lock_time < 500000000)) {
        return false;
    }

    // The lock_time argument must not exceed the tx lock time.
    if (lock_time > tx_locktime) return false;

    // The input's nSequence must not be 0xffffffff (final).
    if (tx_->vin()[input_index_].sequence == 0xffffffff) return false;

    return true;
}

bool TransactionSignatureChecker::check_sequence(
        int64_t sequence) const {
    if (sequence < 0) return false;
    if (!tx_) return false;

    uint32_t tx_seq = tx_->vin()[input_index_].sequence;

    // Disable flag set means sequence lock is not applied.
    if (tx_->version() < 2) return false;
    if (tx_seq & SEQUENCE_LOCKTIME_DISABLE_FLAG) return false;

    uint32_t lock_time_mask = SEQUENCE_LOCKTIME_TYPE_FLAG |
                              SEQUENCE_LOCKTIME_MASK;
    int64_t masked_seq  = static_cast<int64_t>(tx_seq & lock_time_mask);
    int64_t masked_arg  = sequence & static_cast<int64_t>(lock_time_mask);

    // Type mismatch check.
    if ((masked_seq & SEQUENCE_LOCKTIME_TYPE_FLAG) !=
        (masked_arg & SEQUENCE_LOCKTIME_TYPE_FLAG)) {
        return false;
    }

    if (masked_arg > masked_seq) return false;

    return true;
}

// ---------------------------------------------------------------------------
// eval_script -- the core interpreter loop
// ---------------------------------------------------------------------------
bool eval_script(Stack& stack,
                 const Script& script,
                 ScriptFlags flags,
                 const BaseSignatureChecker& checker,
                 ScriptError* error_out) {
    if (script.size() > MAX_SCRIPT_SIZE)
        return set_error(error_out, ScriptError::SCRIPT_SIZE);

    const bool require_minimal =
        has_flag(flags, ScriptFlags::MINIMALDATA);

    Stack altstack;
    // vfExec tracks the nested conditional execution state.
    std::vector<bool> vf_exec;
    int op_count = 0;

    auto it = script.begin_iter();

    // Are we currently in an executing branch?
    auto executing = [&]() -> bool {
        for (bool v : vf_exec) {
            if (!v) return false;
        }
        return true;
    };

    while (auto elem = it.next()) {
        Opcode opcode = elem->opcode;
        uint8_t raw = static_cast<uint8_t>(opcode);
        bool is_exec = executing();

        // -----------------------------------------------------------------
        // Push data
        // -----------------------------------------------------------------
        if (raw <= static_cast<uint8_t>(Opcode::OP_PUSHDATA4)) {
            // Data push: elem->data contains the bytes to push.
            if (elem->data.size() > MAX_PUSH_SIZE)
                return set_error(error_out, ScriptError::PUSH_SIZE);

            if (require_minimal) {
                size_t sz = elem->data.size();
                if (sz == 0) {
                    if (opcode != Opcode::OP_0)
                        return set_error(error_out,
                                         ScriptError::MINIMALDATA);
                } else if (sz == 1 && elem->data[0] >= 1 &&
                           elem->data[0] <= 16) {
                    // Should have used OP_1..OP_16.
                    return set_error(error_out, ScriptError::MINIMALDATA);
                } else if (sz == 1 && elem->data[0] == 0x81) {
                    // Should have used OP_1NEGATE.
                    return set_error(error_out, ScriptError::MINIMALDATA);
                } else if (sz <= 75 &&
                           opcode == Opcode::OP_PUSHDATA1) {
                    return set_error(error_out, ScriptError::MINIMALDATA);
                } else if (sz <= 255 &&
                           opcode == Opcode::OP_PUSHDATA2) {
                    return set_error(error_out, ScriptError::MINIMALDATA);
                } else if (sz <= 65535 &&
                           opcode == Opcode::OP_PUSHDATA4) {
                    return set_error(error_out, ScriptError::MINIMALDATA);
                }
            }

            if (is_exec) {
                stack.emplace_back(elem->data.begin(),
                                   elem->data.end());
            }
            continue;
        }

        // Count non-push opcodes.
        if (raw > static_cast<uint8_t>(Opcode::OP_16)) {
            ++op_count;
            if (op_count > MAX_OPS_PER_SCRIPT)
                return set_error(error_out, ScriptError::OP_COUNT);
        }

        // -----------------------------------------------------------------
        // Conditional opcodes are always processed (for nesting).
        // -----------------------------------------------------------------
        if (opcode == Opcode::OP_IF ||
            opcode == static_cast<Opcode>(0x64) /* OP_NOTIF */) {
            bool value = false;
            if (is_exec) {
                if (stack.empty())
                    return set_error(error_out,
                                     ScriptError::UNBALANCED_CONDITIONAL);
                auto& top = stacktop(stack, -1);
                if (has_flag(flags, ScriptFlags::MINIMALIF)) {
                    if (top.size() > 1)
                        return set_error(error_out,
                                         ScriptError::MINIMALIF);
                    if (top.size() == 1 &&
                            top[0] != 0 && top[0] != 1)
                        return set_error(error_out,
                                         ScriptError::MINIMALIF);
                }
                value = cast_to_bool(top);
                if (opcode == static_cast<Opcode>(0x64)) // OP_NOTIF
                    value = !value;
                stack.pop_back();
            }
            vf_exec.push_back(value);
            continue;
        }

        if (opcode == Opcode::OP_ELSE) {
            if (vf_exec.empty())
                return set_error(error_out,
                                 ScriptError::UNBALANCED_CONDITIONAL);
            vf_exec.back() = !vf_exec.back();
            continue;
        }

        if (opcode == Opcode::OP_ENDIF) {
            if (vf_exec.empty())
                return set_error(error_out,
                                 ScriptError::UNBALANCED_CONDITIONAL);
            vf_exec.pop_back();
            continue;
        }

        // If we're in a non-executing branch skip everything else.
        if (!is_exec) continue;

        // =================================================================
        // From here: all opcodes run only when executing.
        // =================================================================
        switch (opcode) {

        // ----- Constants -------------------------------------------------
        case Opcode::OP_0: {
            stack.emplace_back();
            break;
        }
        // OP_1NEGATE = 0x4f
        case static_cast<Opcode>(0x4f): {
            ScriptNum sn(-1);
            stack.push_back(sn.to_bytes());
            break;
        }
        // OP_1 .. OP_16
        case Opcode::OP_1:  case static_cast<Opcode>(0x52):
        case static_cast<Opcode>(0x53): case static_cast<Opcode>(0x54):
        case static_cast<Opcode>(0x55): case static_cast<Opcode>(0x56):
        case static_cast<Opcode>(0x57): case static_cast<Opcode>(0x58):
        case static_cast<Opcode>(0x59): case static_cast<Opcode>(0x5a):
        case static_cast<Opcode>(0x5b): case static_cast<Opcode>(0x5c):
        case static_cast<Opcode>(0x5d): case static_cast<Opcode>(0x5e):
        case static_cast<Opcode>(0x5f): case Opcode::OP_16: {
            int num = raw - static_cast<uint8_t>(Opcode::OP_1) + 1;
            ScriptNum sn(num);
            stack.push_back(sn.to_bytes());
            break;
        }

        // ----- NOP / OP_NOP1..OP_NOP10 ----------------------------------
        case static_cast<Opcode>(0x61): // OP_NOP
        case static_cast<Opcode>(0xb0): // OP_NOP1
        case static_cast<Opcode>(0xb3): // OP_NOP4
        case static_cast<Opcode>(0xb4): // OP_NOP5
        case static_cast<Opcode>(0xb5): // OP_NOP6
        case static_cast<Opcode>(0xb6): // OP_NOP7
        case static_cast<Opcode>(0xb7): // OP_NOP8
        case static_cast<Opcode>(0xb8): // OP_NOP9
        case static_cast<Opcode>(0xb9): // OP_NOP10
        {
            if (has_flag(flags,
                         ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS) &&
                opcode != static_cast<Opcode>(0x61)) {
                return set_error(error_out,
                                 ScriptError::DISCOURAGE_UPGRADABLE_NOPS);
            }
            break;
        }

        // ----- OP_VERIFY ------------------------------------------------
        case Opcode::OP_VERIFY: {
            if (stack.empty())
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            if (!cast_to_bool(stacktop(stack, -1)))
                return set_error(error_out, ScriptError::VERIFY);
            stack.pop_back();
            break;
        }

        // ----- OP_RETURN -------------------------------------------------
        case Opcode::OP_RETURN: {
            return set_error(error_out, ScriptError::OP_RETURN);
        }

        // =================================================================
        // Stack manipulation
        // =================================================================

        // OP_TOALTSTACK (0x6b)
        case static_cast<Opcode>(0x6b): {
            if (stack.empty())
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            altstack.push_back(std::move(stacktop(stack, -1)));
            stack.pop_back();
            break;
        }

        // OP_FROMALTSTACK (0x6c)
        case static_cast<Opcode>(0x6c): {
            if (altstack.empty())
                return set_error(error_out,
                                 ScriptError::INVALID_ALTSTACK_OPERATION);
            stack.push_back(std::move(altstack.back()));
            altstack.pop_back();
            break;
        }

        // OP_2DROP (0x6d)
        case static_cast<Opcode>(0x6d): {
            if (stack.size() < 2)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            stack.pop_back();
            stack.pop_back();
            break;
        }

        // OP_2DUP (0x6e)
        case static_cast<Opcode>(0x6e): {
            if (stack.size() < 2)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto v1 = stacktop(stack, -2);
            auto v2 = stacktop(stack, -1);
            stack.push_back(v1);
            stack.push_back(v2);
            break;
        }

        // OP_3DUP (0x6f)
        case static_cast<Opcode>(0x6f): {
            if (stack.size() < 3)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto v1 = stacktop(stack, -3);
            auto v2 = stacktop(stack, -2);
            auto v3 = stacktop(stack, -1);
            stack.push_back(v1);
            stack.push_back(v2);
            stack.push_back(v3);
            break;
        }

        // OP_2OVER (0x70)
        case static_cast<Opcode>(0x70): {
            if (stack.size() < 4)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto v1 = stacktop(stack, -4);
            auto v2 = stacktop(stack, -3);
            stack.push_back(v1);
            stack.push_back(v2);
            break;
        }

        // OP_2ROT (0x71)
        case static_cast<Opcode>(0x71): {
            if (stack.size() < 6)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto v1 = stacktop(stack, -6);
            auto v2 = stacktop(stack, -5);
            stack.erase(stack.end() - 6, stack.end() - 4);
            stack.push_back(v1);
            stack.push_back(v2);
            break;
        }

        // OP_2SWAP (0x72)
        case static_cast<Opcode>(0x72): {
            if (stack.size() < 4)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            std::swap(stacktop(stack, -4), stacktop(stack, -2));
            std::swap(stacktop(stack, -3), stacktop(stack, -1));
            break;
        }

        // OP_IFDUP (0x73)
        case static_cast<Opcode>(0x73): {
            if (stack.empty())
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            if (cast_to_bool(stacktop(stack, -1)))
                stack.push_back(stacktop(stack, -1));
            break;
        }

        // OP_DEPTH (0x74)
        case static_cast<Opcode>(0x74): {
            ScriptNum sn(static_cast<int64_t>(stack.size()));
            stack.push_back(sn.to_bytes());
            break;
        }

        // OP_DROP (0x75)
        case static_cast<Opcode>(0x75): {
            if (stack.empty())
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            stack.pop_back();
            break;
        }

        // OP_DUP (0x76)
        case Opcode::OP_DUP: {
            if (stack.empty())
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            stack.push_back(stacktop(stack, -1));
            break;
        }

        // OP_NIP (0x77)
        case static_cast<Opcode>(0x77): {
            if (stack.size() < 2)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            stack.erase(stack.end() - 2);
            break;
        }

        // OP_OVER (0x78)
        case static_cast<Opcode>(0x78): {
            if (stack.size() < 2)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            stack.push_back(stacktop(stack, -2));
            break;
        }

        // OP_PICK (0x79)
        case static_cast<Opcode>(0x79): {
            if (stack.empty())
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto n_opt = ScriptNum::from_bytes(stacktop(stack, -1),
                                               MAX_SCRIPT_NUM_LENGTH,
                                               require_minimal);
            if (!n_opt)
                return set_error(error_out, ScriptError::NUM_OVERFLOW);
            stack.pop_back();
            int n = n_opt->to_int();
            if (n < 0 || static_cast<size_t>(n) >= stack.size())
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            stack.push_back(stacktop(stack, -n - 1));
            break;
        }

        // OP_ROLL (0x7a)
        case static_cast<Opcode>(0x7a): {
            if (stack.empty())
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto n_opt = ScriptNum::from_bytes(stacktop(stack, -1),
                                               MAX_SCRIPT_NUM_LENGTH,
                                               require_minimal);
            if (!n_opt)
                return set_error(error_out, ScriptError::NUM_OVERFLOW);
            stack.pop_back();
            int n = n_opt->to_int();
            if (n < 0 || static_cast<size_t>(n) >= stack.size())
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto val = stacktop(stack, -n - 1);
            stack.erase(stack.end() - n - 1);
            stack.push_back(std::move(val));
            break;
        }

        // OP_ROT (0x7b)
        case static_cast<Opcode>(0x7b): {
            if (stack.size() < 3)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            std::swap(stacktop(stack, -3), stacktop(stack, -2));
            std::swap(stacktop(stack, -2), stacktop(stack, -1));
            break;
        }

        // OP_SWAP (0x7c)
        case static_cast<Opcode>(0x7c): {
            if (stack.size() < 2)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            std::swap(stacktop(stack, -2), stacktop(stack, -1));
            break;
        }

        // OP_TUCK (0x7d)
        case static_cast<Opcode>(0x7d): {
            if (stack.size() < 2)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto top = stacktop(stack, -1);
            stack.insert(stack.end() - 2, top);
            break;
        }

        // OP_SIZE (0x82)
        case static_cast<Opcode>(0x82): {
            if (stack.empty())
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            ScriptNum sn(static_cast<int64_t>(
                stacktop(stack, -1).size()));
            stack.push_back(sn.to_bytes());
            break;
        }

        // =================================================================
        // Bitwise / equality
        // =================================================================

        // OP_EQUAL (0x87)
        case Opcode::OP_EQUAL:
        // OP_EQUALVERIFY (0x88)
        case Opcode::OP_EQUALVERIFY: {
            if (stack.size() < 2)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            bool eq = (stacktop(stack, -2) == stacktop(stack, -1));
            stack.pop_back();
            stack.pop_back();
            stack.push_back(eq ? std::vector<uint8_t>{1}
                               : std::vector<uint8_t>{});
            if (opcode == Opcode::OP_EQUALVERIFY) {
                if (eq) {
                    stack.pop_back();
                } else {
                    return set_error(error_out,
                                     ScriptError::EQUALVERIFY);
                }
            }
            break;
        }

        // =================================================================
        // Arithmetic
        // =================================================================
        // OP_1ADD(0x8b) OP_1SUB(0x8c) OP_NEGATE(0x8f) OP_ABS(0x90)
        // OP_NOT(0x91) OP_0NOTEQUAL(0x92)
        case static_cast<Opcode>(0x8b):
        case static_cast<Opcode>(0x8c):
        case static_cast<Opcode>(0x8f):
        case static_cast<Opcode>(0x90):
        case static_cast<Opcode>(0x91):
        case static_cast<Opcode>(0x92): {
            if (stack.empty())
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto bn_opt = ScriptNum::from_bytes(stacktop(stack, -1),
                                                MAX_SCRIPT_NUM_LENGTH,
                                                require_minimal);
            if (!bn_opt)
                return set_error(error_out, ScriptError::NUM_OVERFLOW);
            int64_t n = bn_opt->value();
            switch (raw) {
                case 0x8b: n = n + 1; break; // OP_1ADD
                case 0x8c: n = n - 1; break; // OP_1SUB
                case 0x8f: n = -n;    break; // OP_NEGATE
                case 0x90: n = (n < 0) ? -n : n; break; // OP_ABS
                case 0x91: n = (n == 0) ? 1 : 0; break; // OP_NOT
                case 0x92: n = (n != 0) ? 1 : 0; break; // OP_0NOTEQUAL
                default: break;
            }
            stack.pop_back();
            stack.push_back(ScriptNum(n).to_bytes());
            break;
        }

        // Binary arithmetic:
        // OP_ADD(0x93) OP_SUB(0x94) OP_BOOLAND(0x9a) OP_BOOLOR(0x9b)
        // OP_NUMEQUAL(0x9c) OP_NUMEQUALVERIFY(0x9d)
        // OP_NUMNOTEQUAL(0x9e)
        // OP_LESSTHAN(0x9f) OP_GREATERTHAN(0xa0)
        // OP_LESSTHANOREQUAL(0xa1) OP_GREATERTHANOREQUAL(0xa2)
        // OP_MIN(0xa3) OP_MAX(0xa4)
        case static_cast<Opcode>(0x93):
        case static_cast<Opcode>(0x94):
        case static_cast<Opcode>(0x9a):
        case static_cast<Opcode>(0x9b):
        case static_cast<Opcode>(0x9c):
        case static_cast<Opcode>(0x9d):
        case static_cast<Opcode>(0x9e):
        case static_cast<Opcode>(0x9f):
        case static_cast<Opcode>(0xa0):
        case static_cast<Opcode>(0xa1):
        case static_cast<Opcode>(0xa2):
        case static_cast<Opcode>(0xa3):
        case static_cast<Opcode>(0xa4): {
            if (stack.size() < 2)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto bn1 = ScriptNum::from_bytes(stacktop(stack, -2),
                                             MAX_SCRIPT_NUM_LENGTH,
                                             require_minimal);
            auto bn2 = ScriptNum::from_bytes(stacktop(stack, -1),
                                             MAX_SCRIPT_NUM_LENGTH,
                                             require_minimal);
            if (!bn1 || !bn2)
                return set_error(error_out, ScriptError::NUM_OVERFLOW);
            int64_t a = bn1->value();
            int64_t b = bn2->value();
            int64_t result = 0;
            switch (raw) {
                case 0x93: result = a + b; break;       // OP_ADD
                case 0x94: result = a - b; break;       // OP_SUB
                case 0x9a: result = (a != 0 && b != 0) ? 1 : 0; break;
                case 0x9b: result = (a != 0 || b != 0) ? 1 : 0; break;
                case 0x9c: result = (a == b) ? 1 : 0; break;
                case 0x9d: result = (a == b) ? 1 : 0; break;
                case 0x9e: result = (a != b) ? 1 : 0; break;
                case 0x9f: result = (a < b)  ? 1 : 0; break;
                case 0xa0: result = (a > b)  ? 1 : 0; break;
                case 0xa1: result = (a <= b) ? 1 : 0; break;
                case 0xa2: result = (a >= b) ? 1 : 0; break;
                case 0xa3: result = std::min(a, b); break;
                case 0xa4: result = std::max(a, b); break;
                default: break;
            }
            stack.pop_back();
            stack.pop_back();
            stack.push_back(ScriptNum(result).to_bytes());

            // OP_NUMEQUALVERIFY
            if (raw == 0x9d) {
                if (cast_to_bool(stacktop(stack, -1))) {
                    stack.pop_back();
                } else {
                    return set_error(error_out, ScriptError::VERIFY);
                }
            }
            break;
        }

        // OP_WITHIN (0xa5): a is within [b, c)
        case static_cast<Opcode>(0xa5): {
            if (stack.size() < 3)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto bn1 = ScriptNum::from_bytes(stacktop(stack, -3),
                                             MAX_SCRIPT_NUM_LENGTH,
                                             require_minimal);
            auto bn2 = ScriptNum::from_bytes(stacktop(stack, -2),
                                             MAX_SCRIPT_NUM_LENGTH,
                                             require_minimal);
            auto bn3 = ScriptNum::from_bytes(stacktop(stack, -1),
                                             MAX_SCRIPT_NUM_LENGTH,
                                             require_minimal);
            if (!bn1 || !bn2 || !bn3)
                return set_error(error_out, ScriptError::NUM_OVERFLOW);
            bool within = (bn2->value() <= bn1->value() &&
                           bn1->value() < bn3->value());
            stack.pop_back();
            stack.pop_back();
            stack.pop_back();
            stack.push_back(within ? ScriptNum(1).to_bytes()
                                   : ScriptNum(0).to_bytes());
            break;
        }

        // =================================================================
        // Crypto -- using Keccak-256 instead of SHA-256
        // =================================================================

        // OP_RIPEMD160(0xa6) -- not commonly used, treat as disabled
        // OP_SHA1(0xa7) -- disabled
        case static_cast<Opcode>(0xa6):
        case static_cast<Opcode>(0xa7): {
            return set_error(error_out, ScriptError::DISABLED_OPCODE);
        }

        // OP_KECCAK256 (0xa8) -- replaces OP_SHA256
        case Opcode::OP_KECCAK256: {
            if (stack.empty())
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto& top = stacktop(stack, -1);
            core::uint256 hash = crypto::keccak256(
                std::span<const uint8_t>(top.data(), top.size()));
            top.assign(hash.data(), hash.data() + hash.size());
            break;
        }

        // OP_HASH160 (0xa9) -- Keccak-256 then RIPEMD-160
        case Opcode::OP_HASH160: {
            if (stack.empty())
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto& top = stacktop(stack, -1);
            core::uint160 hash = crypto::hash160(
                std::span<const uint8_t>(top.data(), top.size()));
            top.assign(hash.data(), hash.data() + hash.size());
            break;
        }

        // OP_HASH256 (0xaa) -- double Keccak-256
        case Opcode::OP_HASH256: {
            if (stack.empty())
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto& top = stacktop(stack, -1);
            core::uint256 hash = crypto::keccak256d(
                std::span<const uint8_t>(top.data(), top.size()));
            top.assign(hash.data(), hash.data() + hash.size());
            break;
        }

        // OP_CHECKSIG (0xac)
        case Opcode::OP_CHECKSIG:
        // OP_CHECKSIGVERIFY (0xad)
        case static_cast<Opcode>(0xad): {
            if (stack.size() < 2)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto& sig    = stacktop(stack, -2);
            auto& pubkey = stacktop(stack, -1);

            if (!check_signature_encoding(sig, flags, error_out))
                return false;
            if (!check_pubkey_encoding(pubkey, flags, error_out))
                return false;

            bool success = false;
            if (!sig.empty()) {
                // Last byte is hash_type.
                int hash_type = sig.back();
                std::span<const uint8_t> sig_data(
                    sig.data(), sig.size() - 1);
                success = checker.check_sig(
                    sig_data, pubkey, script, hash_type);
            }

            if (!success && has_flag(flags, ScriptFlags::NULLFAIL) &&
                    !sig.empty()) {
                return set_error(error_out, ScriptError::SIG_NULLFAIL);
            }

            stack.pop_back();
            stack.pop_back();
            stack.push_back(success ? std::vector<uint8_t>{1}
                                    : std::vector<uint8_t>{});

            if (opcode == static_cast<Opcode>(0xad)) { // CHECKSIGVERIFY
                if (success) {
                    stack.pop_back();
                } else {
                    return set_error(error_out,
                                     ScriptError::CHECKSIGVERIFY);
                }
            }
            break;
        }

        // OP_CHECKMULTISIG (0xae) / OP_CHECKMULTISIGVERIFY (0xaf)
        case Opcode::OP_CHECKMULTISIG:
        case static_cast<Opcode>(0xaf): {
            // --- Parse n (number of public keys) ---
            size_t i = 1;
            if (stack.size() < i)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto nkeys_opt = ScriptNum::from_bytes(
                stacktop(stack, -static_cast<int>(i)),
                MAX_SCRIPT_NUM_LENGTH, require_minimal);
            if (!nkeys_opt)
                return set_error(error_out, ScriptError::NUM_OVERFLOW);
            int nkeys = nkeys_opt->to_int();
            if (nkeys < 0 || nkeys > MAX_PUBKEYS_PER_MULTISIG)
                return set_error(error_out, ScriptError::PUBKEY_COUNT);
            op_count += nkeys;
            if (op_count > MAX_OPS_PER_SCRIPT)
                return set_error(error_out, ScriptError::OP_COUNT);

            size_t ikey = ++i;
            // ikey is index of first pubkey from the top.
            i += static_cast<size_t>(nkeys);

            // --- Parse m (number of signatures) ---
            if (stack.size() < i)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto nsigs_opt = ScriptNum::from_bytes(
                stacktop(stack, -static_cast<int>(i)),
                MAX_SCRIPT_NUM_LENGTH, require_minimal);
            if (!nsigs_opt)
                return set_error(error_out, ScriptError::NUM_OVERFLOW);
            int nsigs = nsigs_opt->to_int();
            if (nsigs < 0 || nsigs > nkeys)
                return set_error(error_out, ScriptError::SIG_COUNT);

            size_t isig = ++i;
            i += static_cast<size_t>(nsigs);

            // One extra dummy element (the off-by-one bug in Bitcoin).
            if (stack.size() < i)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);

            // NULLDUMMY enforcement: the dummy must be empty.
            if (has_flag(flags, ScriptFlags::NULLDUMMY) &&
                    !stacktop(stack, -static_cast<int>(i)).empty()) {
                return set_error(error_out,
                                 ScriptError::SIG_NULLDUMMY);
            }

            bool success = true;
            int keys_remaining   = nkeys;
            int sigs_remaining   = nsigs;
            // Track which sigs were non-empty for NULLFAIL.
            bool had_nonempty_sig = false;

            while (success && sigs_remaining > 0) {
                auto& sig    = stacktop(stack,
                    -static_cast<int>(isig));
                auto& pubkey = stacktop(stack,
                    -static_cast<int>(ikey));

                if (!sig.empty()) had_nonempty_sig = true;

                if (!check_signature_encoding(sig, flags, error_out))
                    return false;
                if (!check_pubkey_encoding(pubkey, flags, error_out))
                    return false;

                bool match = false;
                if (!sig.empty()) {
                    int hash_type = sig.back();
                    std::span<const uint8_t> sig_data(
                        sig.data(), sig.size() - 1);
                    match = checker.check_sig(
                        sig_data, pubkey, script, hash_type);
                }

                if (match) {
                    ++isig;
                    --sigs_remaining;
                }
                ++ikey;
                --keys_remaining;

                // If more sigs left than keys remaining, fail early.
                if (sigs_remaining > keys_remaining)
                    success = false;
            }

            if (!success && has_flag(flags, ScriptFlags::NULLFAIL) &&
                    had_nonempty_sig) {
                return set_error(error_out, ScriptError::SIG_NULLFAIL);
            }

            // Remove consumed elements: dummy + nsigs sigs + nkeys
            // pubkeys + 2 count values = 1 + nsigs + nkeys + 2
            // We pop i elements total.
            while (i > 0) {
                stack.pop_back();
                --i;
            }

            stack.push_back(success ? std::vector<uint8_t>{1}
                                    : std::vector<uint8_t>{});

            if (opcode == static_cast<Opcode>(0xaf)) {
                if (success) {
                    stack.pop_back();
                } else {
                    return set_error(error_out,
                                     ScriptError::CHECKMULTISIGVERIFY);
                }
            }
            break;
        }

        // OP_CHECKSIGADD (0xba) -- BIP 342 style: sig n pubkey -> n'
        case Opcode::OP_CHECKSIGADD: {
            if (stack.size() < 3)
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto& sig    = stacktop(stack, -3);
            auto& n_elem = stacktop(stack, -2);
            auto& pubkey = stacktop(stack, -1);

            auto n_opt = ScriptNum::from_bytes(n_elem,
                                               MAX_SCRIPT_NUM_LENGTH,
                                               require_minimal);
            if (!n_opt)
                return set_error(error_out, ScriptError::NUM_OVERFLOW);

            if (!check_signature_encoding(sig, flags, error_out))
                return false;
            if (!check_pubkey_encoding(pubkey, flags, error_out))
                return false;

            bool success = false;
            if (!sig.empty()) {
                int hash_type = sig.back();
                std::span<const uint8_t> sig_data(
                    sig.data(), sig.size() - 1);
                success = checker.check_sig(
                    sig_data, pubkey, script, hash_type);
            }

            if (!success && has_flag(flags, ScriptFlags::NULLFAIL) &&
                    !sig.empty()) {
                return set_error(error_out, ScriptError::SIG_NULLFAIL);
            }

            int64_t new_n = n_opt->value() + (success ? 1 : 0);
            stack.pop_back();
            stack.pop_back();
            stack.pop_back();
            stack.push_back(ScriptNum(new_n).to_bytes());
            break;
        }

        // =================================================================
        // Locktime
        // =================================================================

        // OP_CHECKLOCKTIMEVERIFY (0xb1) -- BIP 65
        case Opcode::OP_CHECKLOCKTIMEVERIFY: {
            if (!has_flag(flags, ScriptFlags::CHECKLOCKTIMEVERIFY)) {
                // Treat as NOP if the flag is not set.
                if (has_flag(flags,
                             ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS)) {
                    return set_error(
                        error_out,
                        ScriptError::DISCOURAGE_UPGRADABLE_NOPS);
                }
                break;
            }
            if (stack.empty())
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            // The stack top is interpreted as a 5-byte integer.
            auto lock_opt = ScriptNum::from_bytes(
                stacktop(stack, -1), 5, require_minimal);
            if (!lock_opt)
                return set_error(error_out, ScriptError::NUM_OVERFLOW);
            if (lock_opt->value() < 0)
                return set_error(error_out,
                                 ScriptError::NEGATIVE_LOCKTIME);
            if (!checker.check_lock_time(lock_opt->value()))
                return set_error(error_out,
                                 ScriptError::UNSATISFIED_LOCKTIME);
            // NOP -- do not pop the stack.
            break;
        }

        // OP_CHECKSEQUENCEVERIFY (0xb2) -- BIP 112
        case Opcode::OP_CHECKSEQUENCEVERIFY: {
            if (!has_flag(flags, ScriptFlags::CHECKSEQUENCEVERIFY)) {
                if (has_flag(flags,
                             ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS)) {
                    return set_error(
                        error_out,
                        ScriptError::DISCOURAGE_UPGRADABLE_NOPS);
                }
                break;
            }
            if (stack.empty())
                return set_error(error_out,
                                 ScriptError::INVALID_STACK_OPERATION);
            auto seq_opt = ScriptNum::from_bytes(
                stacktop(stack, -1), 5, require_minimal);
            if (!seq_opt)
                return set_error(error_out, ScriptError::NUM_OVERFLOW);
            if (seq_opt->value() < 0)
                return set_error(error_out,
                                 ScriptError::NEGATIVE_LOCKTIME);
            // If the disable flag is set the constraint is vacuously
            // satisfied.
            if (seq_opt->value() &
                    static_cast<int64_t>(
                        SEQUENCE_LOCKTIME_DISABLE_FLAG)) {
                break;
            }
            if (!checker.check_sequence(seq_opt->value()))
                return set_error(error_out,
                                 ScriptError::UNSATISFIED_LOCKTIME);
            break;
        }

        default: {
            return set_error(error_out, ScriptError::DISABLED_OPCODE);
        }

        }  // switch

        // Stack + altstack size check.
        if (stack.size() + altstack.size() > MAX_STACK_SIZE)
            return set_error(error_out, ScriptError::STACK_SIZE);
    }

    // All conditionals must be closed.
    if (!vf_exec.empty())
        return set_error(error_out, ScriptError::UNBALANCED_CONDITIONAL);

    return set_success(error_out);
}

// ---------------------------------------------------------------------------
// Witness program verification (v0)
// ---------------------------------------------------------------------------
static bool verify_witness_program(
        const std::vector<std::vector<uint8_t>>& witness,
        int witness_version,
        const std::vector<uint8_t>& witness_program,
        ScriptFlags flags,
        const BaseSignatureChecker& checker,
        ScriptError* error_out) {
    Stack stack;
    Script witness_script;

    if (witness_version == 0) {
        // P2WPKH: 20-byte program
        if (witness_program.size() == 20) {
            if (witness.size() != 2)
                return set_error(error_out,
                                 ScriptError::WITNESS_PROGRAM_MISMATCH);

            // Construct the equivalent P2PKH script:
            // OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
            std::vector<uint8_t> script_bytes;
            script_bytes.push_back(
                static_cast<uint8_t>(Opcode::OP_DUP));
            script_bytes.push_back(
                static_cast<uint8_t>(Opcode::OP_HASH160));
            script_bytes.push_back(0x14);  // push 20 bytes
            script_bytes.insert(script_bytes.end(),
                                witness_program.begin(),
                                witness_program.end());
            script_bytes.push_back(
                static_cast<uint8_t>(Opcode::OP_EQUALVERIFY));
            script_bytes.push_back(
                static_cast<uint8_t>(Opcode::OP_CHECKSIG));

            witness_script = Script(std::move(script_bytes));
            stack.assign(witness.begin(), witness.end());

        // P2WSH: 32-byte program
        } else if (witness_program.size() == 32) {
            if (witness.empty())
                return set_error(
                    error_out,
                    ScriptError::WITNESS_PROGRAM_WITNESS_EMPTY);

            // The last witness item is the serialised script.
            const auto& script_data = witness.back();
            // Verify: Keccak-256(script) must equal the 32-byte program.
            core::uint256 hash = crypto::keccak256(
                std::span<const uint8_t>(script_data.data(),
                                         script_data.size()));

            if (!std::equal(hash.data(), hash.data() + hash.size(),
                            witness_program.begin(),
                            witness_program.end())) {
                return set_error(error_out,
                                 ScriptError::WITNESS_PROGRAM_MISMATCH);
            }

            witness_script = Script(
                std::vector<uint8_t>(script_data.begin(),
                                     script_data.end()));
            stack.assign(witness.begin(), witness.end() - 1);

        } else {
            return set_error(error_out,
                             ScriptError::WITNESS_PROGRAM_WRONG_LENGTH);
        }

    } else if (has_flag(flags,
                        ScriptFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)) {
        return set_error(error_out,
                         ScriptError::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
    } else {
        // Future witness versions: treat as anyone-can-spend under
        // currently known rules.
        return set_success(error_out);
    }

    // Ensure no individual witness stack item exceeds the push limit.
    for (const auto& item : stack) {
        if (item.size() > MAX_PUSH_SIZE)
            return set_error(error_out, ScriptError::PUSH_SIZE);
    }

    // Execute the witness script.
    if (!eval_script(stack, witness_script, flags, checker, error_out))
        return false;

    // The stack must contain exactly one element that is true.
    if (stack.size() != 1)
        return set_error(error_out, ScriptError::CLEANSTACK);
    if (!cast_to_bool(stack.back()))
        return set_error(error_out, ScriptError::EVAL_FALSE);

    return set_success(error_out);
}

// ---------------------------------------------------------------------------
// verify_script -- the main entry point
// ---------------------------------------------------------------------------
bool verify_script(const Script& script_sig,
                   const Script& script_pubkey,
                   const std::vector<std::vector<uint8_t>>& witness,
                   ScriptFlags flags,
                   const BaseSignatureChecker& checker,
                   ScriptError* error_out) {
    set_error(error_out, ScriptError::UNKNOWN);

    // SIGPUSHONLY: scriptSig must consist of push operations only.
    if (has_flag(flags, ScriptFlags::SIGPUSHONLY) &&
            !is_push_only(script_sig)) {
        return set_error(error_out, ScriptError::SIGPUSHONLY);
    }

    // -------------------------------------------------------------------
    // Step 1: Evaluate scriptSig
    // -------------------------------------------------------------------
    Stack stack;
    if (!eval_script(stack, script_sig, flags, checker, error_out))
        return false;

    // Save a copy of the scriptSig stack for P2SH.
    Stack stack_copy;
    if (has_flag(flags, ScriptFlags::P2SH))
        stack_copy = stack;

    // -------------------------------------------------------------------
    // Step 2: Evaluate scriptPubKey
    // -------------------------------------------------------------------
    if (!eval_script(stack, script_pubkey, flags, checker, error_out))
        return false;

    if (stack.empty())
        return set_error(error_out, ScriptError::EVAL_FALSE);
    if (!cast_to_bool(stack.back()))
        return set_error(error_out, ScriptError::EVAL_FALSE);

    // -------------------------------------------------------------------
    // Step 3: P2SH evaluation
    // -------------------------------------------------------------------
    bool had_witness = false;
    if (has_flag(flags, ScriptFlags::P2SH) && is_p2sh(script_pubkey)) {
        // scriptSig must be push-only.
        if (!is_push_only(script_sig))
            return set_error(error_out, ScriptError::SIGPUSHONLY);

        // The serialized script is the last item pushed by scriptSig.
        if (stack_copy.empty())
            return set_error(error_out, ScriptError::EVAL_FALSE);

        const auto& serialized = stack_copy.back();
        Script redeem_script(
            std::vector<uint8_t>(serialized.begin(), serialized.end()));

        stack = stack_copy;
        // Pop the serialized script off and execute the redeemScript.
        stack.pop_back();

        if (!eval_script(stack, redeem_script, flags, checker, error_out))
            return false;

        if (stack.empty())
            return set_error(error_out, ScriptError::EVAL_FALSE);
        if (!cast_to_bool(stack.back()))
            return set_error(error_out, ScriptError::EVAL_FALSE);

        // Check for witness embedded in P2SH.
        if (has_flag(flags, ScriptFlags::WITNESS)) {
            std::vector<uint8_t> program;
            int wit_ver = witness_version(redeem_script, program);
            if (wit_ver != -1) {
                had_witness = true;
                // The scriptSig must be exactly a push of the
                // serialized redeem script.
                // Construct expected: <len> <serialized>
                std::vector<uint8_t> expected;
                if (serialized.size() <= 75) {
                    expected.push_back(
                        static_cast<uint8_t>(serialized.size()));
                } else if (serialized.size() <= 255) {
                    expected.push_back(
                        static_cast<uint8_t>(Opcode::OP_PUSHDATA1));
                    expected.push_back(
                        static_cast<uint8_t>(serialized.size()));
                } else {
                    expected.push_back(
                        static_cast<uint8_t>(Opcode::OP_PUSHDATA2));
                    expected.push_back(
                        static_cast<uint8_t>(serialized.size() & 0xff));
                    expected.push_back(
                        static_cast<uint8_t>(
                            (serialized.size() >> 8) & 0xff));
                }
                expected.insert(expected.end(),
                                serialized.begin(), serialized.end());

                if (script_sig.data() !=
                        std::vector<uint8_t>(expected.begin(),
                                             expected.end())) {
                    return set_error(error_out,
                                     ScriptError::WITNESS_MALLEATED_P2SH);
                }

                if (!verify_witness_program(
                        witness, wit_ver, program, flags,
                        checker, error_out)) {
                    return false;
                }

                // Witness handled cleanstack; clear our stack to one
                // true element.
                stack.clear();
                stack.push_back({1});
            }
        }
    }

    // -------------------------------------------------------------------
    // Step 4: Native witness programs (not P2SH-wrapped)
    // -------------------------------------------------------------------
    if (has_flag(flags, ScriptFlags::WITNESS) && !had_witness) {
        std::vector<uint8_t> program;
        int wit_ver = witness_version(script_pubkey, program);
        if (wit_ver != -1) {
            had_witness = true;

            // For native witness, scriptSig must be empty.
            if (!script_sig.data().empty())
                return set_error(error_out,
                                 ScriptError::WITNESS_MALLEATED);

            if (!verify_witness_program(
                    witness, wit_ver, program, flags,
                    checker, error_out)) {
                return false;
            }

            // Witness handled cleanstack; set a single true element.
            stack.clear();
            stack.push_back({1});
        }
    }

    // -------------------------------------------------------------------
    // Step 5: Cleanstack check
    // -------------------------------------------------------------------
    if (has_flag(flags, ScriptFlags::CLEANSTACK)) {
        // P2SH and WITNESS are required alongside CLEANSTACK.
        if (stack.size() != 1)
            return set_error(error_out, ScriptError::CLEANSTACK);
    }

    // -------------------------------------------------------------------
    // Step 6: Unexpected witness check
    // -------------------------------------------------------------------
    if (has_flag(flags, ScriptFlags::WITNESS) && !had_witness &&
            !witness.empty()) {
        return set_error(error_out, ScriptError::WITNESS_UNEXPECTED);
    }

    return set_success(error_out);
}

}  // namespace primitives::script
