// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/control.h"
#include "rpc/util.h"

#include "core/logging.h"
#include "core/time.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <psapi.h>
    // Link psapi via CMake; pragma comment not supported on MinGW
#else
    #include <sys/resource.h>
    #include <unistd.h>
    #include <fstream>
#endif

namespace rpc {

// ===========================================================================
// stop
// ===========================================================================

RpcResponse rpc_stop(const RpcRequest& req, NodeContext& ctx) {
    LOG_INFO(core::LogCategory::RPC, "RPC stop requested");

    if (ctx.request_shutdown) {
        ctx.request_shutdown();
    }

    return make_result(JsonValue("FTC server stopping"), req.id);
}

// ===========================================================================
// uptime
// ===========================================================================

RpcResponse rpc_uptime(const RpcRequest& req, const NodeContext& ctx) {
    int64_t now = core::get_time();
    int64_t uptime = now - ctx.startup_time;
    if (uptime < 0) uptime = 0;

    return make_result(JsonValue(uptime), req.id);
}

// ===========================================================================
// help
// ===========================================================================

RpcResponse rpc_help(const RpcRequest& req, RpcServer& server) {
    // If a command name is given, show help for that command
    if (param_exists(req.params, 0) && !param_value(req.params, 0).is_null()) {
        std::string command = param_string(req.params, 0);
        std::string text = help_text(command);
        if (text.empty()) {
            return make_error(RpcError::METHOD_NOT_FOUND,
                              "help: unknown command: " + command, req.id);
        }
        return make_result(JsonValue(text), req.id);
    }

    // No command given: list all commands grouped by category
    auto all_names = get_all_method_names();

    // Group by category
    std::map<std::string, std::vector<std::string>> categories;
    for (const auto& name : all_names) {
        // Extract category from help text first line or use "misc"
        std::string text = help_text(name);
        categories[""].push_back(name);
    }

    // Build a simple listing
    std::string listing;
    listing.reserve(all_names.size() * 30);

    for (const auto& name : all_names) {
        std::string text = help_text(name);
        // Show the first line of help text
        size_t nl = text.find('\n');
        if (nl != std::string::npos) {
            listing += text.substr(0, nl);
        } else {
            listing += text;
        }
        listing += '\n';
    }

    if (listing.empty()) {
        listing = "No commands registered.\n";
    }

    return make_result(JsonValue(listing), req.id);
}

// ===========================================================================
// getmemoryinfo
// ===========================================================================

namespace {

struct MemoryInfo {
    int64_t used       = 0;  // bytes of memory used by the process
    int64_t free       = 0;  // estimated free memory
    int64_t total      = 0;  // total system memory
    int64_t locked     = 0;  // locked/pinned memory
    int64_t peak_used  = 0;  // peak RSS
};

MemoryInfo get_process_memory() {
    MemoryInfo info;

#ifdef _WIN32
    // Windows: use PROCESS_MEMORY_COUNTERS
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(),
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
        info.used      = static_cast<int64_t>(pmc.WorkingSetSize);
        info.peak_used = static_cast<int64_t>(pmc.PeakWorkingSetSize);
    }

    // System total memory
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        info.total = static_cast<int64_t>(memStatus.ullTotalPhys);
        info.free  = static_cast<int64_t>(memStatus.ullAvailPhys);
    }
#else
    // Linux: read /proc/self/status for VmRSS and VmPeak
    std::ifstream status_file("/proc/self/status");
    if (status_file.is_open()) {
        std::string line;
        while (std::getline(status_file, line)) {
            if (line.compare(0, 6, "VmRSS:") == 0) {
                info.used = std::stoll(line.substr(6)) * 1024; // kB to B
            } else if (line.compare(0, 7, "VmPeak:") == 0) {
                info.peak_used = std::stoll(line.substr(7)) * 1024;
            } else if (line.compare(0, 6, "VmLck:") == 0) {
                info.locked = std::stoll(line.substr(6)) * 1024;
            }
        }
    }

    // Total system memory from sysconf
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    if (pages > 0 && page_size > 0) {
        info.total = static_cast<int64_t>(pages) * page_size;
    }
    long avail_pages = sysconf(_SC_AVPHYS_PAGES);
    if (avail_pages > 0 && page_size > 0) {
        info.free = static_cast<int64_t>(avail_pages) * page_size;
    }
#endif

    return info;
}

// Map of category name -> LogCategory bitmask
struct LogCategoryInfo {
    const char* name;
    core::LogCategory category;
};

static constexpr LogCategoryInfo LOG_CATEGORIES[] = {
    {"net",        core::LogCategory::NET},
    {"mempool",    core::LogCategory::MEMPOOL},
    {"validation", core::LogCategory::VALIDATION},
    {"mining",     core::LogCategory::MINING},
    {"rpc",        core::LogCategory::RPC},
    {"wallet",     core::LogCategory::WALLET},
    {"chain",      core::LogCategory::CHAIN},
    {"script",     core::LogCategory::SCRIPT},
    {"lock",       core::LogCategory::LOCK},
    {"p2p",        core::LogCategory::P2P},
    {"bench",      core::LogCategory::BENCH},
};

static constexpr size_t NUM_LOG_CATEGORIES =
    sizeof(LOG_CATEGORIES) / sizeof(LOG_CATEGORIES[0]);

core::LogCategory parse_log_category(const std::string& name) {
    if (name == "all" || name == "1") return core::LogCategory::ALL;
    if (name == "none" || name == "0") return core::LogCategory::NONE;
    for (size_t i = 0; i < NUM_LOG_CATEGORIES; ++i) {
        if (name == LOG_CATEGORIES[i].name) {
            return LOG_CATEGORIES[i].category;
        }
    }
    return core::LogCategory::NONE;
}

} // anonymous namespace

RpcResponse rpc_getmemoryinfo(const RpcRequest& req) {
    std::string mode = param_string(req.params, 0, "stats");

    if (mode == "mallocinfo") {
        // Return malloc info as a string (platform-specific)
        return make_result(JsonValue("malloc info not available on this platform"),
                           req.id);
    }

    // Default mode: "stats"
    MemoryInfo mem = get_process_memory();

    JsonValue result(JsonValue::Object{});

    JsonValue locked(JsonValue::Object{});
    locked["used"]       = JsonValue(mem.used);
    locked["free"]       = JsonValue(mem.free);
    locked["total"]      = JsonValue(mem.total);
    locked["locked"]     = JsonValue(mem.locked);
    locked["chunks_used"]= JsonValue(static_cast<int64_t>(0));
    locked["chunks_free"]= JsonValue(static_cast<int64_t>(0));
    result["locked"]     = std::move(locked);

    // Additional process info
    JsonValue process(JsonValue::Object{});
    process["resident_set_size"] = JsonValue(mem.used);
    process["peak_rss"]          = JsonValue(mem.peak_used);
    process["system_total"]      = JsonValue(mem.total);
    process["system_free"]       = JsonValue(mem.free);
    result["process"]            = std::move(process);

    return make_result(std::move(result), req.id);
}

// ===========================================================================
// logging
// ===========================================================================

RpcResponse rpc_logging(const RpcRequest& req) {
    auto& logger = core::Logger::instance();

    // If parameters provided, modify logging categories
    if (param_count(req.params) > 0) {
        // params[0] = include categories (array of strings)
        // params[1] = exclude categories (array of strings)

        if (param_exists(req.params, 0) &&
            param_value(req.params, 0).is_array()) {
            for (const auto& cat_val : param_value(req.params, 0).get_array()) {
                if (cat_val.is_string()) {
                    auto cat = parse_log_category(cat_val.get_string());
                    if (cat != core::LogCategory::NONE) {
                        logger.enable_category(cat);
                    }
                }
            }
        }

        if (param_exists(req.params, 1) &&
            param_value(req.params, 1).is_array()) {
            for (const auto& cat_val : param_value(req.params, 1).get_array()) {
                if (cat_val.is_string()) {
                    auto cat = parse_log_category(cat_val.get_string());
                    if (cat != core::LogCategory::NONE) {
                        logger.disable_category(cat);
                    }
                }
            }
        }
    }

    // Return current logging state
    JsonValue result(JsonValue::Object{});
    auto enabled = logger.enabled_categories();

    for (size_t i = 0; i < NUM_LOG_CATEGORIES; ++i) {
        bool is_enabled = (enabled & LOG_CATEGORIES[i].category) !=
                          core::LogCategory::NONE;
        result[LOG_CATEGORIES[i].name] = JsonValue(is_enabled);
    }

    return make_result(std::move(result), req.id);
}

// ===========================================================================
// Registration
// ===========================================================================

void register_control_rpcs(RpcServer& server, NodeContext& ctx) {
    server.register_commands({
        {"stop",
         [&](const RpcRequest& r) { return rpc_stop(r, ctx); },
         "stop\n"
         "Request a graceful shutdown of the FTC server.",
         "control"},

        {"uptime",
         [&](const RpcRequest& r) { return rpc_uptime(r, ctx); },
         "uptime\n"
         "Returns the total uptime of the server in seconds.",
         "control"},

        {"help",
         [&](const RpcRequest& r) { return rpc_help(r, server); },
         "help ( \"command\" )\n"
         "List all commands, or get help for a specified command.\n"
         "\nArguments:\n"
         "1. command    (string, optional) The command to get help on.\n"
         "\nResult:\n"
         "\"text\"       (string) The help text.",
         "control"},

        {"getmemoryinfo",
         [](const RpcRequest& r) { return rpc_getmemoryinfo(r); },
         "getmemoryinfo ( \"mode\" )\n"
         "Returns an object containing information about memory usage.\n"
         "\nArguments:\n"
         "1. mode    (string, optional, default=\"stats\") \"stats\" or \"mallocinfo\".\n"
         "\nResult (for mode = \"stats\"):\n"
         "{\n"
         "  \"locked\" : {\n"
         "    \"used\" : n,       (numeric) Number of bytes used\n"
         "    \"free\" : n,       (numeric) Number of bytes available\n"
         "    \"total\" : n,      (numeric) Total number of bytes managed\n"
         "    \"locked\" : n      (numeric) Amount of bytes locked\n"
         "  }\n"
         "}",
         "control"},

        {"logging",
         [](const RpcRequest& r) { return rpc_logging(r); },
         "logging ( [\"include_category\",...] [\"exclude_category\",...] )\n"
         "Gets and sets the logging configuration.\n"
         "When called without arguments, returns the list of categories\n"
         "with their current status (true/false).\n"
         "\nArguments:\n"
         "1. include    (array, optional) Categories to enable.\n"
         "2. exclude    (array, optional) Categories to disable.\n"
         "\nAvailable categories:\n"
         "  net, mempool, validation, mining, rpc, wallet, chain,\n"
         "  script, lock, p2p, bench, all, none",
         "control"},
    });
}

} // namespace rpc
