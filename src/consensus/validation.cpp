// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/validation.h"

namespace consensus {

void ValidationState::invalid(ValidationResult result,
                              const std::string& reject_reason,
                              const std::string& debug_message) {
    result_ = result;
    reject_reason_ = reject_reason;
    debug_message_ = debug_message;
    is_valid_ = false;
}

void ValidationState::error(const std::string& reject_reason) {
    result_ = ValidationResult::INTERNAL_ERROR;
    reject_reason_ = reject_reason;
    debug_message_.clear();
    is_valid_ = false;
}

std::string ValidationState::to_string() const {
    if (is_valid_) {
        return "valid";
    }
    std::string s = reject_reason_;
    if (!debug_message_.empty()) {
        s += " (";
        s += debug_message_;
        s += ')';
    }
    return s;
}

} // namespace consensus
