#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Logging system initialization for the FTC node.
//
// Configures the global Logger singleton based on NodeConfig settings:
//   - Sets the log level threshold.
//   - Enables/disables log categories from the config bitmask.
//   - Opens the log file at datadir/debug.log with optional rotation.
//   - Optionally enables console (stderr) logging.
//   - Prints a startup banner with version and build information.
// ---------------------------------------------------------------------------

#ifndef FTC_NODE_LOGGING_INIT_H
#define FTC_NODE_LOGGING_INIT_H

#include "core/error.h"

#include <filesystem>
#include <string>

// Forward declaration.
namespace node {
struct NodeConfig;
} // namespace node

namespace node {

// ---------------------------------------------------------------------------
// Logging initialization
// ---------------------------------------------------------------------------

/// Initialize the logging subsystem based on the node configuration.
///
/// Performs the following steps in order:
///   1. Set the log level from config.log_level.
///   2. Configure enabled log categories from config.log_categories.
///   3. Rotate the existing log file if it exceeds MAX_LOG_FILE_SIZE.
///   4. Open the log file at config.log_file_path() in append mode.
///   5. Enable file logging.
///   6. Print the startup banner to the log.
///
/// @param config  The node configuration.
/// @returns core::make_ok() on success, or an error if the log file
///          cannot be opened.
[[nodiscard]] core::Result<void> init_logging(const NodeConfig& config);

/// Enable console (stderr) logging in addition to file logging.
///
/// This is typically called when the node is running in the foreground
/// (not as a daemon).
void init_console_logging();

/// Disable console logging (e.g. when daemonizing).
void disable_console_logging();

// ---------------------------------------------------------------------------
// Log file rotation
// ---------------------------------------------------------------------------

/// Maximum log file size before rotation, in bytes.
/// When the log file exceeds this size, it is renamed to debug.log.1
/// and a new debug.log is started.
inline constexpr uint64_t MAX_LOG_FILE_SIZE = 50 * 1024 * 1024;  // 50 MB

/// Rotate the log file at the given path if it exceeds max_size bytes.
///
/// The rotation scheme is simple:
///   - If debug.log.1 exists, it is deleted.
///   - debug.log is renamed to debug.log.1.
///   - A new debug.log will be created when the logger opens it.
///
/// @param log_path  Path to the log file.
/// @param max_size  Maximum file size in bytes before rotation triggers.
/// @returns true if rotation was performed, false if not needed or on error.
bool rotate_log_file(const std::filesystem::path& log_path,
                     uint64_t max_size = MAX_LOG_FILE_SIZE);

// ---------------------------------------------------------------------------
// Startup banner
// ---------------------------------------------------------------------------

/// Generate the startup banner string.
///
/// Contains:
///   - FTC version and client name
///   - Build date and compiler info
///   - Active network (main/testnet/regtest)
///   - Data directory path
///   - Current date and time
///
/// @param config  The node configuration (for network/datadir info).
/// @returns The formatted banner string.
[[nodiscard]] std::string get_startup_banner(const NodeConfig& config);

/// Generate a shorter version-only banner (no config-dependent info).
[[nodiscard]] std::string get_startup_banner();

// ---------------------------------------------------------------------------
// Category helpers
// ---------------------------------------------------------------------------

/// Enable a set of log categories from a bitmask.
///
/// @param categories  Bitmask of LogCategory values to enable.
void enable_log_categories(uint32_t categories);

/// Disable all log categories except those in the given bitmask.
///
/// @param categories  Bitmask of LogCategory values to keep enabled.
void set_log_categories(uint32_t categories);

/// Parse a comma-separated list of category names into a bitmask.
///
/// Recognised names (case-insensitive):
///   net, mempool, validation, mining, rpc, wallet, chain, script,
///   lock, p2p, bench, all, none
///
/// @param category_str  Comma-separated category names.
/// @returns The combined bitmask.
[[nodiscard]] uint32_t parse_log_categories(std::string_view category_str);

} // namespace node

#endif // FTC_NODE_LOGGING_INIT_H
