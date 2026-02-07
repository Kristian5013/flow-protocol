// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "node/logging_init.h"
#include "node/context.h"

#include "core/fs.h"
#include "core/logging.h"
#include "core/time.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <sstream>
#include <string>
#include <string_view>

namespace node {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

namespace {

/// Case-insensitive equality.
bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

/// Trim leading and trailing whitespace.
std::string_view trim_ws(std::string_view sv) {
    while (!sv.empty() &&
           std::isspace(static_cast<unsigned char>(sv.front()))) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() &&
           std::isspace(static_cast<unsigned char>(sv.back()))) {
        sv.remove_suffix(1);
    }
    return sv;
}

/// Parse a single category name to a LogCategory bitmask value.
core::LogCategory parse_single_category(std::string_view name) {
    if (iequals(name, "net"))        return core::LogCategory::NET;
    if (iequals(name, "mempool"))    return core::LogCategory::MEMPOOL;
    if (iequals(name, "validation")) return core::LogCategory::VALIDATION;
    if (iequals(name, "mining"))     return core::LogCategory::MINING;
    if (iequals(name, "rpc"))        return core::LogCategory::RPC;
    if (iequals(name, "wallet"))     return core::LogCategory::WALLET;
    if (iequals(name, "chain"))      return core::LogCategory::CHAIN;
    if (iequals(name, "script"))     return core::LogCategory::SCRIPT;
    if (iequals(name, "lock"))       return core::LogCategory::LOCK;
    if (iequals(name, "p2p"))        return core::LogCategory::P2P;
    if (iequals(name, "bench"))      return core::LogCategory::BENCH;
    if (iequals(name, "all"))        return core::LogCategory::ALL;
    if (iequals(name, "none"))       return core::LogCategory::NONE;
    return core::LogCategory::NONE;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// init_logging
// ---------------------------------------------------------------------------

core::Result<void> init_logging(const NodeConfig& config) {
    auto& logger = core::Logger::instance();

    // Step 1: Set the log level.
    logger.set_level(config.log_level);

    // Step 2: Configure categories.  If the bitmask is the default (ALL),
    // leave everything enabled.  Otherwise, apply the bitmask.
    if (config.log_categories !=
        static_cast<uint32_t>(core::LogCategory::ALL)) {
        set_log_categories(config.log_categories);
    }

    // Step 3: Resolve the log file path.
    std::filesystem::path log_path = config.log_file_path();

    // Ensure the parent directory exists.
    if (log_path.has_parent_path()) {
        core::fs::ensure_directory(log_path.parent_path());
    }

    // Step 4: Rotate the log file if it is too large.
    rotate_log_file(log_path, MAX_LOG_FILE_SIZE);

    // Step 5: Open the log file.
    logger.set_log_file(log_path);
    logger.set_print_to_file(true);

    // Step 6: Print the startup banner.
    std::string banner = get_startup_banner(config);
    LOG_INFO(core::LogCategory::NONE, banner);

    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// init_console_logging / disable_console_logging
// ---------------------------------------------------------------------------

void init_console_logging() {
    core::Logger::instance().set_print_to_console(true);
}

void disable_console_logging() {
    core::Logger::instance().set_print_to_console(false);
}

// ---------------------------------------------------------------------------
// rotate_log_file
// ---------------------------------------------------------------------------

bool rotate_log_file(const std::filesystem::path& log_path,
                     uint64_t max_size) {
    // Check if the log file exists and exceeds the size threshold.
    auto size_opt = core::fs::file_size(log_path);
    if (!size_opt.has_value()) {
        // File does not exist or cannot be queried -- nothing to rotate.
        return false;
    }

    if (*size_opt < max_size) {
        // File is within limits -- no rotation needed.
        return false;
    }

    // Build the rotated file path: debug.log -> debug.log.1
    std::filesystem::path rotated_path =
        log_path.parent_path() / (log_path.filename().string() + ".1");

    // Remove the old rotated file if it exists.
    std::error_code ec;
    if (std::filesystem::exists(rotated_path, ec)) {
        std::filesystem::remove(rotated_path, ec);
        if (ec) {
            // Non-fatal: we can still try the rename.
            LOG_WARN(core::LogCategory::NONE,
                     "Failed to remove old rotated log: " +
                     rotated_path.string());
        }
    }

    // Rename the current log file to the rotated name.
    if (!core::fs::rename_safe(log_path, rotated_path)) {
        LOG_WARN(core::LogCategory::NONE,
                 "Failed to rotate log file: " + log_path.string());
        return false;
    }

    LOG_INFO(core::LogCategory::NONE,
             "Rotated log file: " + log_path.string() +
             " -> " + rotated_path.string() +
             " (was " + std::to_string(*size_opt / (1024 * 1024)) + " MB)");

    return true;
}

// ---------------------------------------------------------------------------
// get_startup_banner (with config)
// ---------------------------------------------------------------------------

std::string get_startup_banner(const NodeConfig& config) {
    std::ostringstream ss;

    ss << "\n"
       << "============================================================\n"
       << "  " << get_client_name() << "\n"
       << "  Build: " << __DATE__ << " " << __TIME__ << "\n"
       << "  Compiler: "
#if defined(__clang__)
       << "Clang " << __clang_major__ << "." << __clang_minor__
#elif defined(_MSC_VER)
       << "MSVC " << _MSC_VER
#elif defined(__GNUC__)
       << "GCC " << __GNUC__ << "." << __GNUC_MINOR__
#else
       << "Unknown"
#endif
       << " | C++ " << __cplusplus << "\n"
       << "  Network: " << config.network_name() << "\n"
       << "  Data directory: " << config.resolved_datadir().string() << "\n"
       << "  P2P port: " << config.p2p_port << "\n"
       << "  RPC: " << (config.rpc_enabled ? "enabled" : "disabled");

    if (config.rpc_enabled) {
        ss << " (port " << config.rpc_port
           << ", bind " << config.rpc_bind << ")";
    }
    ss << "\n";

    ss << "  Wallet: " << (config.wallet_enabled ? "enabled" : "disabled")
       << "\n"
       << "  Mining: " << (config.mine ? "enabled" : "disabled");
    if (config.mine) {
        ss << " (" << config.mine_threads << " threads)";
    }
    ss << "\n";

    ss << "  Log level: "
       << core::log_level_string(config.log_level) << "\n";

    // Current timestamp.
    int64_t now = core::get_time();
    ss << "  Started: " << core::format_iso8601(now) << "\n"
       << "============================================================\n";

    return ss.str();
}

// ---------------------------------------------------------------------------
// get_startup_banner (no config)
// ---------------------------------------------------------------------------

std::string get_startup_banner() {
    std::ostringstream ss;

    ss << "\n"
       << "============================================================\n"
       << "  " << get_client_name() << "\n"
       << "  Build: " << __DATE__ << " " << __TIME__ << "\n"
       << "  Started: " << core::format_iso8601(core::get_time()) << "\n"
       << "============================================================\n";

    return ss.str();
}

// ---------------------------------------------------------------------------
// enable_log_categories
// ---------------------------------------------------------------------------

void enable_log_categories(uint32_t categories) {
    auto& logger = core::Logger::instance();

    // Enable each bit that is set.
    if (categories & static_cast<uint32_t>(core::LogCategory::NET))
        logger.enable_category(core::LogCategory::NET);
    if (categories & static_cast<uint32_t>(core::LogCategory::MEMPOOL))
        logger.enable_category(core::LogCategory::MEMPOOL);
    if (categories & static_cast<uint32_t>(core::LogCategory::VALIDATION))
        logger.enable_category(core::LogCategory::VALIDATION);
    if (categories & static_cast<uint32_t>(core::LogCategory::MINING))
        logger.enable_category(core::LogCategory::MINING);
    if (categories & static_cast<uint32_t>(core::LogCategory::RPC))
        logger.enable_category(core::LogCategory::RPC);
    if (categories & static_cast<uint32_t>(core::LogCategory::WALLET))
        logger.enable_category(core::LogCategory::WALLET);
    if (categories & static_cast<uint32_t>(core::LogCategory::CHAIN))
        logger.enable_category(core::LogCategory::CHAIN);
    if (categories & static_cast<uint32_t>(core::LogCategory::SCRIPT))
        logger.enable_category(core::LogCategory::SCRIPT);
    if (categories & static_cast<uint32_t>(core::LogCategory::LOCK))
        logger.enable_category(core::LogCategory::LOCK);
    if (categories & static_cast<uint32_t>(core::LogCategory::P2P))
        logger.enable_category(core::LogCategory::P2P);
    if (categories & static_cast<uint32_t>(core::LogCategory::BENCH))
        logger.enable_category(core::LogCategory::BENCH);
}

// ---------------------------------------------------------------------------
// set_log_categories
// ---------------------------------------------------------------------------

void set_log_categories(uint32_t categories) {
    auto& logger = core::Logger::instance();

    // Disable all categories first, then enable only the requested ones.
    // We do this by disabling ALL, then enabling the specified bitmask.
    logger.disable_category(core::LogCategory::ALL);
    enable_log_categories(categories);
}

// ---------------------------------------------------------------------------
// parse_log_categories
// ---------------------------------------------------------------------------

uint32_t parse_log_categories(std::string_view category_str) {
    if (category_str.empty()) {
        return static_cast<uint32_t>(core::LogCategory::ALL);
    }

    uint32_t result = 0;

    // Split by comma.
    size_t start = 0;
    while (start < category_str.size()) {
        size_t comma = category_str.find(',', start);
        if (comma == std::string_view::npos) {
            comma = category_str.size();
        }

        std::string_view token = trim_ws(category_str.substr(start, comma - start));
        if (!token.empty()) {
            auto cat = parse_single_category(token);
            result |= static_cast<uint32_t>(cat);
        }

        start = comma + 1;
    }

    // If the result is 0 (no valid categories), enable ALL as a safe default.
    if (result == 0) {
        result = static_cast<uint32_t>(core::LogCategory::ALL);
    }

    return result;
}

} // namespace node
