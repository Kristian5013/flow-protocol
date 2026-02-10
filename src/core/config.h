#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace core {

// ---------------------------------------------------------------------------
// Common configuration key constants
// ---------------------------------------------------------------------------
inline constexpr const char* CONF_DATADIR        = "datadir";
inline constexpr const char* CONF_NETWORK        = "network";
inline constexpr const char* CONF_TESTNET        = "testnet";
inline constexpr const char* CONF_REGTEST        = "regtest";
inline constexpr const char* CONF_PORT           = "port";
inline constexpr const char* CONF_RPCPORT        = "rpcport";
inline constexpr const char* CONF_RPCUSER        = "rpcuser";
inline constexpr const char* CONF_RPCPASSWORD    = "rpcpassword";
inline constexpr const char* CONF_MAXCONNECTIONS = "maxconnections";
inline constexpr const char* CONF_DBCACHE        = "dbcache";
inline constexpr const char* CONF_MINE           = "mine";
inline constexpr const char* CONF_MINETHREADS    = "minethreads";
inline constexpr const char* CONF_LOGLEVEL       = "loglevel";
inline constexpr const char* CONF_RPCALLOWIP     = "rpcallowip";
inline constexpr const char* CONF_CONNECT        = "connect";
inline constexpr const char* CONF_ADDNODE        = "addnode";

// ---------------------------------------------------------------------------
// Config  --  hierarchical configuration with multiple sources
//
// Priority order: command-line args  >  config file  >  programmatic defaults
// Multi-value keys (e.g. -connect=a -connect=b) are accumulated into a
// vector accessible via get_list().
// ---------------------------------------------------------------------------
class Config {
public:
    Config() = default;

    // -- source loading -----------------------------------------------------

    /// Parse command-line arguments.
    /// Accepted formats:
    ///   -key=value   --key=value   (key/value pair)
    ///   -key         --key         (boolean flag, value = "1")
    void parse_args(int argc, char* argv[]);

    /// Parse an INI-style configuration file.
    /// Format per line:  key=value
    /// Lines starting with '#' and blank lines are ignored.
    /// Leading/trailing whitespace around key and value is trimmed.
    void parse_file(const std::filesystem::path& path);

    // -- setters / getters --------------------------------------------------

    /// Set a key to a single value (replaces any previous values).
    void set(std::string_view key, std::string value);

    /// Return the first value for @p key, or std::nullopt if absent.
    [[nodiscard]] std::optional<std::string> get(std::string_view key) const;

    /// Return the first value for @p key, or @p default_val if absent.
    [[nodiscard]] std::string get_or(std::string_view key,
                                     std::string_view default_val) const;

    /// Return the value for @p key parsed as int64, or @p default_val.
    [[nodiscard]] int64_t get_int(std::string_view key,
                                  int64_t default_val = 0) const;

    /// Return the value for @p key parsed as bool, or @p default_val.
    /// Truthy: "1", "true", "yes", "on" (case-insensitive).
    [[nodiscard]] bool get_bool(std::string_view key,
                                bool default_val = false) const;

    /// Return the value for @p key parsed as double, or @p default_val.
    [[nodiscard]] double get_double(std::string_view key,
                                    double default_val = 0.0) const;

    /// Return all values associated with @p key (multi-value support).
    [[nodiscard]] std::vector<std::string> get_list(
        std::string_view key) const;

    /// Check whether @p key exists in any source.
    [[nodiscard]] bool has(std::string_view key) const;

    // -- convenience accessors ----------------------------------------------

    /// Resolved data directory.  Uses the "datadir" key if set, otherwise
    /// falls back to core::fs::get_default_data_dir().  For testnet/regtest
    /// a subdirectory is appended automatically.
    [[nodiscard]] std::filesystem::path data_dir() const;

    /// Active network name: "main", "testnet", or "regtest".
    [[nodiscard]] std::string network() const;

private:
    // Two separate maps so that CLI args always override file values.
    // Lookup checks cli_values_ first, then file_values_.
    using ValueMap =
        std::unordered_map<std::string, std::vector<std::string>>;

    ValueMap cli_values_;
    ValueMap file_values_;

    // Internal helpers
    void insert(ValueMap& target, std::string_view key, std::string value);
    [[nodiscard]] const std::vector<std::string>* lookup(
        std::string_view key) const;
};

} // namespace core
