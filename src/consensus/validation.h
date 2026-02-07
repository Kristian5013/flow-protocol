#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// ValidationState -- high-level validation outcome tracking
// ---------------------------------------------------------------------------
// Provides a lightweight state object that records whether a transaction or
// block passed consensus validation, and if not, the reason for rejection.
// The typed wrappers BlockValidationState and TxValidationState prevent
// accidentally mixing block-level and transaction-level validation states.
// ---------------------------------------------------------------------------

#include <string>

namespace consensus {

// ---------------------------------------------------------------------------
// ValidationResult -- enumerated outcomes
// ---------------------------------------------------------------------------

enum class ValidationResult {
    VALID,

    // Transaction-level rejection reasons
    TX_MISSING_INPUTS,
    TX_PREMATURE_SPEND,
    TX_DUPLICATE,
    TX_CONSENSUS,
    TX_RECENT_CONFLICT,
    TX_NOT_STANDARD,
    TX_MEMPOOL_POLICY,

    // Block-level rejection reasons
    BLOCK_CONSENSUS,
    BLOCK_CACHED_INVALID,
    BLOCK_HEADER_LOW_POW,
    BLOCK_MUTATED,
    BLOCK_MISSING_PREV,
    BLOCK_INVALID_PREV,
    BLOCK_TIME_FUTURE,

    // Internal / catch-all
    INTERNAL_ERROR,
};

// ---------------------------------------------------------------------------
// ValidationState -- tracks the outcome of a validation check
// ---------------------------------------------------------------------------

class ValidationState {
public:
    /// Default-construct in the VALID state.
    ValidationState() = default;

    /// Returns true when validation passed (no error has been recorded).
    [[nodiscard]] bool is_valid() const noexcept { return is_valid_; }

    /// Returns true when validation failed (an error has been recorded).
    [[nodiscard]] bool is_invalid() const noexcept { return !is_valid_; }

    /// The specific rejection result (VALID when no failure recorded).
    [[nodiscard]] ValidationResult get_result() const noexcept { return result_; }

    /// Short machine-readable reason string (e.g. "bad-txns-vin-empty").
    [[nodiscard]] const std::string& get_reject_reason() const noexcept {
        return reject_reason_;
    }

    /// Longer human-readable debug message (may be empty).
    [[nodiscard]] const std::string& get_debug_message() const noexcept {
        return debug_message_;
    }

    /// Record a validation failure.
    void invalid(ValidationResult result,
                 const std::string& reject_reason,
                 const std::string& debug_message = "");

    /// Record an internal error (sets result to INTERNAL_ERROR).
    void error(const std::string& reject_reason);

    /// Return a combined human-readable description of the rejection.
    [[nodiscard]] std::string to_string() const;

private:
    ValidationResult result_ = ValidationResult::VALID;
    std::string reject_reason_;
    std::string debug_message_;
    bool is_valid_ = true;
};

// ---------------------------------------------------------------------------
// Type-safe wrappers
// ---------------------------------------------------------------------------

/// Block-specific validation state (prevents mixing with TxValidationState).
class BlockValidationState : public ValidationState {};

/// Transaction-specific validation state (prevents mixing with
/// BlockValidationState).
class TxValidationState : public ValidationState {};

} // namespace consensus
