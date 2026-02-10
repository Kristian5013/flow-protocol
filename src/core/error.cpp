// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"

#include <sstream>

namespace core {

// ---------------------------------------------------------------------------
// error_code_name: human-readable label for every ErrorCode variant
// ---------------------------------------------------------------------------
std::string_view error_code_name(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::NONE:              return "NONE";

        // Parsing
        case ErrorCode::PARSE_ERROR:       return "PARSE_ERROR";
        case ErrorCode::PARSE_OVERFLOW:    return "PARSE_OVERFLOW";
        case ErrorCode::PARSE_UNDERFLOW:   return "PARSE_UNDERFLOW";
        case ErrorCode::PARSE_BAD_FORMAT:  return "PARSE_BAD_FORMAT";

        // Validation
        case ErrorCode::VALIDATION_ERROR:  return "VALIDATION_ERROR";
        case ErrorCode::VALIDATION_RANGE:  return "VALIDATION_RANGE";
        case ErrorCode::VALIDATION_SCRIPT: return "VALIDATION_SCRIPT";
        case ErrorCode::VALIDATION_SIG:    return "VALIDATION_SIG";
        case ErrorCode::VALIDATION_ORPHAN: return "VALIDATION_ORPHAN";

        // Network
        case ErrorCode::NETWORK_ERROR:     return "NETWORK_ERROR";
        case ErrorCode::NETWORK_TIMEOUT:   return "NETWORK_TIMEOUT";
        case ErrorCode::NETWORK_REFUSED:   return "NETWORK_REFUSED";
        case ErrorCode::NETWORK_CLOSED:    return "NETWORK_CLOSED";

        // Cryptography
        case ErrorCode::CRYPTO_ERROR:      return "CRYPTO_ERROR";
        case ErrorCode::CRYPTO_HASH_FAIL:  return "CRYPTO_HASH_FAIL";
        case ErrorCode::CRYPTO_SIG_FAIL:   return "CRYPTO_SIG_FAIL";
        case ErrorCode::CRYPTO_KEY_FAIL:   return "CRYPTO_KEY_FAIL";

        // Storage
        case ErrorCode::STORAGE_ERROR:     return "STORAGE_ERROR";
        case ErrorCode::STORAGE_NOT_FOUND: return "STORAGE_NOT_FOUND";
        case ErrorCode::STORAGE_CORRUPT:   return "STORAGE_CORRUPT";
        case ErrorCode::STORAGE_FULL:      return "STORAGE_FULL";

        // Wallet
        case ErrorCode::WALLET_ERROR:      return "WALLET_ERROR";
        case ErrorCode::WALLET_LOCKED:     return "WALLET_LOCKED";
        case ErrorCode::WALLET_NO_FUNDS:   return "WALLET_NO_FUNDS";
        case ErrorCode::WALLET_KEY_MISS:   return "WALLET_KEY_MISS";

        // RPC
        case ErrorCode::RPC_ERROR:         return "RPC_ERROR";
        case ErrorCode::RPC_INVALID_REQ:   return "RPC_INVALID_REQ";
        case ErrorCode::RPC_METHOD_MISS:   return "RPC_METHOD_MISS";
        case ErrorCode::RPC_FORBIDDEN:     return "RPC_FORBIDDEN";

        // Internal
        case ErrorCode::INTERNAL_ERROR:    return "INTERNAL_ERROR";
        case ErrorCode::NOT_IMPLEMENTED:   return "NOT_IMPLEMENTED";
        case ErrorCode::OUT_OF_MEMORY:     return "OUT_OF_MEMORY";
    }

    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// Error::format: build a diagnostic string including source location
// ---------------------------------------------------------------------------
std::string Error::format() const {
    if (code_ == ErrorCode::NONE) {
        return "no error";
    }

    std::ostringstream oss;
    oss << error_code_name(code_)
        << '(' << static_cast<uint16_t>(code_) << ')';

    if (!message_.empty()) {
        oss << ": " << message_;
    }

    // Append source location when available (file name is non-empty).
    const char* file = location_.file_name();
    if (file && file[0] != '\0') {
        oss << " [" << file
            << ':' << location_.line()
            << ':' << location_.column() << ']';
    }

    return oss.str();
}

} // namespace core
