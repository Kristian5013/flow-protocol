// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "node/config.h"
#include "node/context.h"

#include "core/error.h"
#include "core/fs.h"
#include "core/logging.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>

namespace node {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

namespace {

/// Trim leading and trailing whitespace from a string_view.
std::string_view trim(std::string_view sv) {
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

/// Convert a string to lowercase (returns a new string).
std::string to_lower(std::string_view sv) {
    std::string result;
    result.reserve(sv.size());
    for (char ch : sv) {
        result.push_back(
            static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return result;
}

/// Case-insensitive equality check.
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

/// Parse a boolean string value.
bool parse_bool_value(std::string_view sv, bool default_val) {
    if (sv.empty()) return default_val;
    if (iequals(sv, "1") || iequals(sv, "true") ||
        iequals(sv, "yes") || iequals(sv, "on")) {
        return true;
    }
    if (iequals(sv, "0") || iequals(sv, "false") ||
        iequals(sv, "no") || iequals(sv, "off")) {
        return false;
    }
    return default_val;
}

/// Parse an integer from a string.
int parse_int_value(std::string_view sv, int default_val) {
    int result = default_val;
    auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), result);
    if (ec != std::errc{}) {
        return default_val;
    }
    return result;
}

/// Parse a uint16_t port number.
uint16_t parse_port(std::string_view sv, uint16_t default_val) {
    int val = parse_int_value(sv, static_cast<int>(default_val));
    if (val < 0 || val > 65535) return default_val;
    return static_cast<uint16_t>(val);
}

/// Parse a LogLevel from a string.
core::LogLevel parse_log_level_value(std::string_view sv) {
    if (iequals(sv, "trace"))   return core::LogLevel::TRACE;
    if (iequals(sv, "debug"))   return core::LogLevel::DEBUG;
    if (iequals(sv, "info"))    return core::LogLevel::INFO;
    if (iequals(sv, "warn") || iequals(sv, "warning"))
                                return core::LogLevel::WARN;
    if (iequals(sv, "error") || iequals(sv, "err"))
                                return core::LogLevel::ERR;
    if (iequals(sv, "fatal"))   return core::LogLevel::FATAL;
    if (iequals(sv, "off") || iequals(sv, "none"))
                                return core::LogLevel::OFF;
    return core::LogLevel::INFO;
}

/// Apply a single key-value pair to a NodeConfig.  The key is expected
/// to be lowercase already.
void apply_single(const std::string& key, const std::string& value,
                  NodeConfig& config) {
    if (key == "datadir") {
        config.datadir = value;
    } else if (key == "listen") {
        config.listen = parse_bool_value(value, config.listen);
    } else if (key == "port") {
        config.p2p_port = parse_port(value, config.p2p_port);
    } else if (key == "rpcport") {
        config.rpc_port = parse_port(value, config.rpc_port);
    } else if (key == "rpcuser") {
        config.rpc_user = value;
    } else if (key == "rpcpassword") {
        config.rpc_password = value;
    } else if (key == "rpcbind") {
        config.rpc_bind = value;
    } else if (key == "norpc") {
        config.rpc_enabled = false;
    } else if (key == "rpc") {
        config.rpc_enabled = parse_bool_value(value, config.rpc_enabled);
    } else if (key == "nowallet") {
        config.wallet_enabled = false;
    } else if (key == "wallet") {
        config.wallet_enabled = parse_bool_value(value, config.wallet_enabled);
    } else if (key == "walletfile") {
        config.wallet_file = value;
    } else if (key == "mine") {
        config.mine = parse_bool_value(value, true);
    } else if (key == "minethreads") {
        config.mine_threads = parse_int_value(value, config.mine_threads);
    } else if (key == "mineaddress") {
        config.mine_address = value;
    } else if (key == "testnet") {
        config.testnet = parse_bool_value(value, true);
    } else if (key == "regtest") {
        config.regtest = parse_bool_value(value, true);
    } else if (key == "loglevel") {
        config.log_level = parse_log_level_value(value);
    } else if (key == "logfile") {
        config.log_file = value;
    } else if (key == "maxoutbound") {
        config.max_outbound = parse_int_value(value, config.max_outbound);
    } else if (key == "maxinbound") {
        config.max_inbound = parse_int_value(value, config.max_inbound);
    } else if (key == "dnsseed") {
        config.dns_seed = parse_bool_value(value, config.dns_seed);
    } else if (key == "connect") {
        // Multi-value keys are handled specially in the multi-map overload.
        // For single-map, we just set the first value.
        if (!value.empty()) {
            config.connect_nodes.push_back(value);
        }
    } else if (key == "addnode") {
        if (!value.empty()) {
            config.add_nodes.push_back(value);
        }
    } else {
        LOG_DEBUG(core::LogCategory::NONE,
                  "Unknown config key: " + key + " = " + value);
    }
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// ConfigParser::parse_line
// ---------------------------------------------------------------------------

bool ConfigParser::parse_line(std::string_view line, int line_num,
                              std::string& key, std::string& value) {
    std::string_view trimmed = trim(line);

    // Skip empty lines and comments.
    if (trimmed.empty() || trimmed.front() == '#') {
        return false;
    }

    // Find the '=' separator.
    auto eq_pos = trimmed.find('=');
    if (eq_pos == std::string_view::npos) {
        // Treat bare words as boolean flags (value = "1").
        key = to_lower(trimmed);
        value = "1";
        return true;
    }

    std::string_view raw_key = trim(trimmed.substr(0, eq_pos));
    std::string_view raw_val = trim(trimmed.substr(eq_pos + 1));

    if (raw_key.empty()) {
        LOG_WARN(core::LogCategory::NONE,
                 "Config: empty key on line " + std::to_string(line_num));
        return false;
    }

    key = to_lower(raw_key);
    value = std::string{raw_val};
    return true;
}

// ---------------------------------------------------------------------------
// ConfigParser::parse
// ---------------------------------------------------------------------------

core::Result<std::map<std::string, std::string>>
ConfigParser::parse(const std::filesystem::path& path) const {
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        return core::Error(
            core::ErrorCode::STORAGE_NOT_FOUND,
            "Cannot open config file: " + path.string());
    }

    std::map<std::string, std::string> result;
    std::string line;
    int line_num = 0;

    while (std::getline(ifs, line)) {
        ++line_num;
        std::string key, value;
        if (parse_line(line, line_num, key, value)) {
            // Last value wins for duplicate keys in single-map mode.
            result[key] = std::move(value);
        }
    }

    LOG_DEBUG(core::LogCategory::NONE,
              "Parsed " + std::to_string(result.size()) +
              " config entries from " + path.string());

    return result;
}

// ---------------------------------------------------------------------------
// ConfigParser::parse_multi
// ---------------------------------------------------------------------------

core::Result<std::multimap<std::string, std::string>>
ConfigParser::parse_multi(const std::filesystem::path& path) const {
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        return core::Error(
            core::ErrorCode::STORAGE_NOT_FOUND,
            "Cannot open config file: " + path.string());
    }

    std::multimap<std::string, std::string> result;
    std::string line;
    int line_num = 0;

    while (std::getline(ifs, line)) {
        ++line_num;
        std::string key, value;
        if (parse_line(line, line_num, key, value)) {
            result.emplace(std::move(key), std::move(value));
        }
    }

    LOG_DEBUG(core::LogCategory::NONE,
              "Parsed " + std::to_string(result.size()) +
              " config entries (multi) from " + path.string());

    return result;
}

// ---------------------------------------------------------------------------
// ConfigParser::apply_config (single-map)
// ---------------------------------------------------------------------------

void ConfigParser::apply_config(
    const std::map<std::string, std::string>& values,
    NodeConfig& config) {
    for (const auto& [key, value] : values) {
        apply_single(key, value, config);
    }
}

// ---------------------------------------------------------------------------
// ConfigParser::apply_config (multi-map)
// ---------------------------------------------------------------------------

void ConfigParser::apply_config(
    const std::multimap<std::string, std::string>& values,
    NodeConfig& config) {
    for (const auto& [key, value] : values) {
        apply_single(key, value, config);
    }
}

// ---------------------------------------------------------------------------
// get_default_datadir
// ---------------------------------------------------------------------------

std::filesystem::path get_default_datadir() {
    return core::fs::get_default_data_dir();
}

// ---------------------------------------------------------------------------
// ensure_datadir_exists
// ---------------------------------------------------------------------------

core::Result<void>
ensure_datadir_exists(const std::filesystem::path& datadir) {
    // Create the root data directory.
    if (!core::fs::ensure_directory(datadir)) {
        return core::Error(
            core::ErrorCode::STORAGE_ERROR,
            "Failed to create data directory: " + datadir.string());
    }

    // Create standard subdirectories.
    static constexpr const char* SUBDIRS[] = {
        "blocks",
        "chainstate",
        "wallet",
    };

    for (const char* subdir : SUBDIRS) {
        std::filesystem::path sub_path = datadir / subdir;
        if (!core::fs::ensure_directory(sub_path)) {
            return core::Error(
                core::ErrorCode::STORAGE_ERROR,
                "Failed to create directory: " + sub_path.string());
        }
    }

    LOG_INFO(core::LogCategory::NONE,
             "Data directory initialized: " + datadir.string());

    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// validate_datadir
// ---------------------------------------------------------------------------

core::Result<void>
validate_datadir(const std::filesystem::path& datadir) {
    // Check that the path is not empty.
    if (datadir.empty()) {
        return core::Error(
            core::ErrorCode::VALIDATION_ERROR,
            "Data directory path is empty");
    }

    // If the directory exists, check that it is actually a directory.
    std::error_code ec;
    if (std::filesystem::exists(datadir, ec)) {
        if (!std::filesystem::is_directory(datadir, ec)) {
            return core::Error(
                core::ErrorCode::VALIDATION_ERROR,
                "Data directory path exists but is not a directory: " +
                datadir.string());
        }
    }

    // Try to create the directory (no-op if already exists) to verify
    // that we have write permissions to the parent.
    if (!core::fs::ensure_directory(datadir)) {
        return core::Error(
            core::ErrorCode::STORAGE_ERROR,
            "Cannot create data directory (permission denied?): " +
            datadir.string());
    }

    // Verify write access by creating a temporary file.
    std::filesystem::path test_file = datadir / ".ftc_test_write";
    {
        std::ofstream ofs(test_file, std::ios::trunc);
        if (!ofs.is_open()) {
            return core::Error(
                core::ErrorCode::STORAGE_ERROR,
                "Data directory is not writable: " + datadir.string());
        }
        ofs << "ftc";
        ofs.close();
    }

    // Clean up the test file.
    std::filesystem::remove(test_file, ec);

    return core::Result<void>{};
}

} // namespace node
