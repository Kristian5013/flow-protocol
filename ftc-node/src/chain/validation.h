#ifndef FTC_CHAIN_VALIDATION_H
#define FTC_CHAIN_VALIDATION_H

#include <string>

// Undefine Windows ERROR macro to avoid conflict
#ifdef ERROR
#undef ERROR
#endif

namespace ftc {
namespace chain {

/**
 * Block/Transaction validation result codes
 */
enum class ValidationResult {
    VALID,
    INVALID,
    INVALID_BLOCK_HEADER,
    INVALID_POW,
    INVALID_TIMESTAMP,
    INVALID_MERKLE_ROOT,
    INVALID_COINBASE,
    INVALID_BLOCK_SIZE,
    INVALID_TX,
    DUPLICATE_TX,
    BAD_TX_INPUTS,
    BAD_TX_OUTPUTS,
    MISSING_INPUTS,
    PREMATURE_SPEND,
    BAD_CB_AMOUNT,
    SCRIPT_FAILED,
    BLOCK_MISSING_PREV,
    BLOCK_TOO_OLD,
    BLOCK_TOO_NEW,
    BLOCK_WEIGHT_TOO_HIGH,
    ORPHAN,
    CHECKPOINT_MISMATCH,
    ERROR  // General error
};

/**
 * Validation state - carries result and error details
 */
struct ValidationState {
    ValidationResult result = ValidationResult::VALID;
    std::string reason;
    std::string debug_message;
    bool corruption_possible = false;

    bool isValid() const { return result == ValidationResult::VALID; }
    bool isInvalid() const { return result != ValidationResult::VALID; }

    void invalid(ValidationResult r, const std::string& msg, const std::string& debug = "") {
        result = r;
        reason = msg;
        debug_message = debug;
    }

    std::string toString() const;
};

} // namespace chain
} // namespace ftc

#endif // FTC_CHAIN_VALIDATION_H
