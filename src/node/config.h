#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// ConfigParser -- parse .conf configuration files for the FTC node.
//
// File format:
//   - One key=value pair per line.
//   - Lines starting with '#' are comments.
//   - Blank lines and leading/trailing whitespace are ignored.
//   - Keys are case-insensitive during lookup.
//   - Multi-value keys (e.g. connect=addr1 repeated) accumulate.
//
// This module also provides platform-specific default data directory
// detection and directory creation utilities.
// ---------------------------------------------------------------------------

#ifndef FTC_NODE_CONFIG_H
#define FTC_NODE_CONFIG_H

#include "core/error.h"

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

// Forward declaration.
namespace node {
struct NodeConfig;
} // namespace node

namespace node {

// ---------------------------------------------------------------------------
// ConfigParser
// ---------------------------------------------------------------------------

class ConfigParser {
public:
    ConfigParser() = default;
    ~ConfigParser() = default;

    // Non-copyable but movable.
    ConfigParser(const ConfigParser&) = delete;
    ConfigParser& operator=(const ConfigParser&) = delete;
    ConfigParser(ConfigParser&&) = default;
    ConfigParser& operator=(ConfigParser&&) = default;

    /// Parse a .conf file.
    ///
    /// Returns the parsed key-value map on success, or an error if the
    /// file cannot be opened or contains syntax errors that prevent
    /// meaningful parsing.
    ///
    /// @param path  Path to the configuration file.
    /// @returns A map of key -> value on success.
    [[nodiscard]] core::Result<std::map<std::string, std::string>>
    parse(const std::filesystem::path& path) const;

    /// Parse a .conf file and return a multi-value map (keys can repeat).
    ///
    /// @param path  Path to the configuration file.
    /// @returns A multimap of key -> values.
    [[nodiscard]]
    core::Result<std::multimap<std::string, std::string>>
    parse_multi(const std::filesystem::path& path) const;

    /// Apply a parsed key-value map to a NodeConfig struct.
    ///
    /// Known keys are mapped to their corresponding NodeConfig fields.
    /// Unknown keys are silently ignored (a warning is logged).
    ///
    /// @param values  The parsed configuration values.
    /// @param config  The NodeConfig to update.
    static void apply_config(
        const std::map<std::string, std::string>& values,
        NodeConfig& config);

    /// Apply a parsed multi-value map to a NodeConfig struct.
    ///
    /// @param values  The parsed configuration values (multi-value).
    /// @param config  The NodeConfig to update.
    static void apply_config(
        const std::multimap<std::string, std::string>& values,
        NodeConfig& config);

private:
    /// Parse a single line from a .conf file.
    ///
    /// @param line     The raw line text.
    /// @param line_num The 1-based line number (for error messages).
    /// @param key      [out] The parsed key.
    /// @param value    [out] The parsed value.
    /// @returns true if a key-value pair was extracted, false if the line
    ///          should be skipped (blank, comment).
    [[nodiscard]] static bool parse_line(
        std::string_view line,
        int line_num,
        std::string& key,
        std::string& value);
};

// ---------------------------------------------------------------------------
// Data directory utilities
// ---------------------------------------------------------------------------

/// Returns the platform-specific default data directory for FTC.
///
///   Windows : %APPDATA%/FTC/
///   macOS   : ~/Library/Application Support/FTC/
///   Linux   : ~/.ftc/
///
/// This delegates to core::fs::get_default_data_dir() but is provided here
/// as a convenience for the node module.
[[nodiscard]] std::filesystem::path get_default_datadir();

/// Ensure that the specified data directory and its standard subdirectories
/// exist.  Creates them if they are missing.
///
/// Standard subdirectory layout:
///   datadir/blocks/       -- blockchain.dat, undo files
///   datadir/chainstate/   -- UTXO snapshot, block index
///   datadir/wallet/       -- wallet.dat
///
/// @param datadir  The root data directory path.
/// @returns core::make_ok() on success, or an error.
[[nodiscard]] core::Result<void>
ensure_datadir_exists(const std::filesystem::path& datadir);

/// Validate a data directory path: check that it is writable and not
/// already locked by another process.
///
/// @param datadir  The data directory to validate.
/// @returns core::make_ok() if valid, or an error.
[[nodiscard]] core::Result<void>
validate_datadir(const std::filesystem::path& datadir);

} // namespace node

#endif // FTC_NODE_CONFIG_H
