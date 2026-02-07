#include "core/config.h"
#include "core/fs.h"
#include "core/logging.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <sstream>
#include <string>

namespace core {

// ---------------------------------------------------------------------------
// Helpers (anonymous namespace)
// ---------------------------------------------------------------------------
namespace {

/// Trim leading and trailing whitespace from a string_view.
std::string_view trim(std::string_view sv) {
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front())))
        sv.remove_prefix(1);
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back())))
        sv.remove_suffix(1);
    return sv;
}

/// Strip leading dashes from an argument key (one or two).
std::string_view strip_dashes(std::string_view sv) {
    if (sv.starts_with("--")) return sv.substr(2);
    if (sv.starts_with("-"))  return sv.substr(1);
    return sv;
}

/// Case-insensitive equality check.
bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

/// Parse a string as a boolean.
/// Truthy values: "1", "true", "yes", "on" (case-insensitive).
/// Everything else (including empty) is false.
bool parse_bool(std::string_view sv, bool default_val) {
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

} // anonymous namespace

// ---------------------------------------------------------------------------
// Config -- internal helpers
// ---------------------------------------------------------------------------

void Config::insert(ValueMap& target, std::string_view key,
                    std::string value) {
    std::string k{key};
    target[k].push_back(std::move(value));
}

const std::vector<std::string>* Config::lookup(std::string_view key) const {
    std::string k{key};

    // CLI values take priority.
    if (auto it = cli_values_.find(k); it != cli_values_.end()) {
        return &it->second;
    }
    if (auto it = file_values_.find(k); it != file_values_.end()) {
        return &it->second;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Config -- source loading
// ---------------------------------------------------------------------------

void Config::parse_args(int argc, char* argv[]) {
    // argv[0] is the program name -- skip it.
    for (int i = 1; i < argc; ++i) {
        std::string_view arg{argv[i]};
        if (arg.empty()) continue;

        // Must start with '-' to be considered an option.
        if (!arg.starts_with("-")) {
            LOG_ERROR(core::LogCategory::NONE,
                      "Config: ignoring positional argument '" +
                      std::string{arg} + "'");
            continue;
        }

        std::string_view stripped = strip_dashes(arg);

        // Look for '=' separator.
        auto eq_pos = stripped.find('=');
        if (eq_pos != std::string_view::npos) {
            std::string_view key = stripped.substr(0, eq_pos);
            std::string_view val = stripped.substr(eq_pos + 1);
            insert(cli_values_, trim(key), std::string{trim(val)});
        } else {
            // Boolean flag -- no '=' present.
            insert(cli_values_, trim(stripped), "1");
        }
    }
}

void Config::parse_file(const std::filesystem::path& path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        LOG_ERROR(core::LogCategory::NONE,
                  "Config: unable to open config file '" +
                  path.string() + "'");
        return;
    }

    LOG_INFO(core::LogCategory::NONE,
             "Config: loading configuration from '" + path.string() + "'");

    std::string line;
    int line_num = 0;
    while (std::getline(ifs, line)) {
        ++line_num;
        std::string_view sv = trim(std::string_view{line});

        // Skip empty lines and comments.
        if (sv.empty() || sv.front() == '#') continue;

        auto eq_pos = sv.find('=');
        if (eq_pos == std::string_view::npos) {
            // Treat bare words as boolean flags (same as CLI).
            insert(file_values_, sv, "1");
            continue;
        }

        std::string_view key = trim(sv.substr(0, eq_pos));
        std::string_view val = trim(sv.substr(eq_pos + 1));

        if (key.empty()) {
            LOG_ERROR(core::LogCategory::NONE,
                      "Config: empty key on line " +
                      std::to_string(line_num) + " of '" +
                      path.string() + "'");
            continue;
        }

        insert(file_values_, key, std::string{val});
    }
}

// ---------------------------------------------------------------------------
// Config -- setters / getters
// ---------------------------------------------------------------------------

void Config::set(std::string_view key, std::string value) {
    std::string k{key};
    // Programmatic set goes into file_values_ (lower priority than CLI).
    // Replace any previous values so that set() acts as an override.
    file_values_[k] = {std::move(value)};
}

std::optional<std::string> Config::get(std::string_view key) const {
    const auto* vals = lookup(key);
    if (!vals || vals->empty()) return std::nullopt;
    return vals->front();
}

std::string Config::get_or(std::string_view key,
                           std::string_view default_val) const {
    auto val = get(key);
    return val.has_value() ? *val : std::string{default_val};
}

int64_t Config::get_int(std::string_view key, int64_t default_val) const {
    auto val = get(key);
    if (!val.has_value()) return default_val;

    int64_t result = default_val;
    const auto& s = *val;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), result);
    if (ec != std::errc{}) {
        LOG_ERROR(core::LogCategory::NONE,
                  "Config: cannot parse '" + s +
                  "' as integer for key '" + std::string{key} + "'");
        return default_val;
    }
    return result;
}

bool Config::get_bool(std::string_view key, bool default_val) const {
    auto val = get(key);
    if (!val.has_value()) return default_val;
    return parse_bool(*val, default_val);
}

double Config::get_double(std::string_view key, double default_val) const {
    auto val = get(key);
    if (!val.has_value()) return default_val;

    // std::from_chars for double is not universally available on all
    // compilers yet; fall back to std::stod for portability.
    try {
        std::size_t pos = 0;
        double result = std::stod(*val, &pos);
        if (pos == 0) return default_val;
        return result;
    } catch (...) {
        LOG_ERROR(core::LogCategory::NONE,
                  "Config: cannot parse '" + *val +
                  "' as double for key '" + std::string{key} + "'");
        return default_val;
    }
}

std::vector<std::string> Config::get_list(std::string_view key) const {
    // Merge both sources: CLI values first (higher priority), then file.
    std::string k{key};
    std::vector<std::string> result;

    if (auto it = cli_values_.find(k); it != cli_values_.end()) {
        result.insert(result.end(),
                      it->second.begin(), it->second.end());
    }
    if (auto it = file_values_.find(k); it != file_values_.end()) {
        result.insert(result.end(),
                      it->second.begin(), it->second.end());
    }
    return result;
}

bool Config::has(std::string_view key) const {
    return lookup(key) != nullptr;
}

// ---------------------------------------------------------------------------
// Config -- convenience accessors
// ---------------------------------------------------------------------------

std::filesystem::path Config::data_dir() const {
    std::filesystem::path base;

    auto custom = get(CONF_DATADIR);
    if (custom.has_value() && !custom->empty()) {
        base = std::filesystem::path{*custom};
    } else {
        base = core::fs::get_default_data_dir();
    }

    // Append a network-specific subdirectory for non-mainnet networks.
    std::string net = network();
    if (net == "testnet") {
        base /= "testnet";
    } else if (net == "regtest") {
        base /= "regtest";
    }
    // "main" uses the base directory with no suffix.

    return base;
}

std::string Config::network() const {
    // Explicit --network=<name> takes priority.
    auto net = get(CONF_NETWORK);
    if (net.has_value() && !net->empty()) {
        return *net;
    }

    // Shorthand boolean flags.
    if (get_bool(CONF_REGTEST, false)) return "regtest";
    if (get_bool(CONF_TESTNET, false)) return "testnet";

    return "main";
}

} // namespace core
