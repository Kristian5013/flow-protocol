// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/dns_seeds.h"
#include "core/logging.h"

#include <algorithm>
#include <cstring>
#include <unordered_set>

// ---------------------------------------------------------------------------
// Platform-specific includes for DNS resolution
// ---------------------------------------------------------------------------
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <netdb.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif

namespace net {

// ---------------------------------------------------------------------------
// DNS seed hostnames
// ---------------------------------------------------------------------------
// Each hostname is a DNS seeder operated by a community member.  The seeder
// crawls the FTC network and populates its DNS zone with A/AAAA records
// pointing to nodes it has recently verified as reachable.
//
// Naming convention: seed-<operator>.ftc-chain.org
// ---------------------------------------------------------------------------

const std::vector<std::string>& get_dns_seeds() {
    static const std::vector<std::string> seeds = {
        "seed.flowcoin.org",
        "seed.flowprotocol.net",
    };
    return seeds;
}

// ---------------------------------------------------------------------------
// Hardcoded seed nodes (fallback)
// ---------------------------------------------------------------------------
// These are well-known, long-running nodes that serve as a last resort
// when DNS resolution fails or returns no results.  Each entry is in
// "ip:port" format.
//
// Maintenance: this list should be refreshed periodically by running a
// crawler against the live network and selecting nodes that have been
// continuously reachable for at least 30 days.
//
// Last updated: 2026-01-15
// ---------------------------------------------------------------------------

const std::vector<std::string>& get_seed_nodes() {
    static const std::vector<std::string> nodes = {
        // Seoul seed (seed.flowprotocol.net)
        "3.35.208.160:9333",
        // Virginia seed (seed.flowcoin.org)
        "44.221.81.40:9333",
    };
    return nodes;
}

// ---------------------------------------------------------------------------
// DNS resolution implementation
// ---------------------------------------------------------------------------

/// Initialize Winsock on Windows (called once via static init).
#ifdef _WIN32
namespace {

struct WinsockInit {
    WinsockInit() {
        WSADATA wsa_data;
        int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
        if (result != 0) {
            LOG_ERROR(core::LogCategory::NET,
                      "WSAStartup failed with error: " + std::to_string(result));
        }
    }
    ~WinsockInit() {
        WSACleanup();
    }
};

// Ensure Winsock is initialized before any DNS calls.
static WinsockInit s_winsock_init;

} // anonymous namespace
#endif

std::vector<std::string> resolve_dns_seed(const std::string& hostname) {
    std::vector<std::string> results;

    if (hostname.empty()) {
        return results;
    }

    LOG_DEBUG(core::LogCategory::NET,
              "Resolving DNS seed: " + hostname);

    // Set up hints for getaddrinfo: we want both IPv4 and IPv6 TCP addresses.
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;      // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;  // TCP
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_ADDRCONFIG;   // Only return addresses that the host
                                       // can actually reach

    struct addrinfo* result_list = nullptr;
    int rc = getaddrinfo(hostname.c_str(), nullptr, &hints, &result_list);

    if (rc != 0) {
        // Log the failure but do not treat it as fatal -- the caller will
        // try the next seed or fall back to hardcoded nodes.
#ifdef _WIN32
        LOG_WARN(core::LogCategory::NET,
                 "DNS resolution failed for " + hostname +
                 ": error " + std::to_string(rc));
#else
        LOG_WARN(core::LogCategory::NET,
                 "DNS resolution failed for " + hostname +
                 ": " + std::string(gai_strerror(rc)));
#endif
        return results;
    }

    // Walk the linked list of address results.
    for (struct addrinfo* rp = result_list; rp != nullptr; rp = rp->ai_next) {
        char addr_str[INET6_ADDRSTRLEN] = {};

        if (rp->ai_family == AF_INET) {
            // IPv4
            auto* sin = reinterpret_cast<struct sockaddr_in*>(rp->ai_addr);
            if (inet_ntop(AF_INET, &sin->sin_addr,
                          addr_str, sizeof(addr_str)) != nullptr) {
                results.emplace_back(addr_str);
            }
        } else if (rp->ai_family == AF_INET6) {
            // IPv6
            auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr);
            if (inet_ntop(AF_INET6, &sin6->sin6_addr,
                          addr_str, sizeof(addr_str)) != nullptr) {
                results.emplace_back(addr_str);
            }
        }
        // Skip any other address families (e.g. AF_UNIX).
    }

    freeaddrinfo(result_list);

    // Remove duplicates (some DNS servers return the same address multiple
    // times across different socket types).
    std::sort(results.begin(), results.end());
    results.erase(std::unique(results.begin(), results.end()), results.end());

    LOG_DEBUG(core::LogCategory::NET,
             "Resolved " + std::to_string(results.size()) +
             " addresses from DNS seed " + hostname);

    return results;
}

std::vector<std::string> resolve_all_dns_seeds() {
    std::unordered_set<std::string> seen;
    std::vector<std::string> all_addresses;

    const auto& seeds = get_dns_seeds();

    LOG_DEBUG(core::LogCategory::NET,
             "Resolving " + std::to_string(seeds.size()) + " DNS seeds");

    for (const auto& seed : seeds) {
        auto addresses = resolve_dns_seed(seed);

        for (auto& addr : addresses) {
            if (seen.insert(addr).second) {
                all_addresses.push_back(std::move(addr));
            }
        }
    }

    LOG_DEBUG(core::LogCategory::NET,
             "DNS seed resolution complete: " +
             std::to_string(all_addresses.size()) +
             " unique addresses from " +
             std::to_string(seeds.size()) + " seeds");

    return all_addresses;
}

} // namespace net
