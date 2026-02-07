#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// DNS seed hostnames and hardcoded seed nodes for initial peer discovery.
//
// When the node starts with an empty address manager it uses DNS seed
// lookups to bootstrap its set of known peers.  If DNS resolution fails
// (e.g. behind a restrictive firewall) the hardcoded seed list provides a
// fallback set of well-known node IP addresses.
//
// The DNS seeds are operated by community members and return A/AAAA records
// that point to currently-reachable FTC nodes.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <string>
#include <vector>

namespace net {

// ---------------------------------------------------------------------------
// DNS seed hostnames
// ---------------------------------------------------------------------------

/// Returns the list of DNS seed hostnames.  Each hostname, when resolved
/// via DNS A/AAAA queries, should yield IP addresses of currently active
/// FTC full nodes listening on the default P2P port (9333).
///
/// The returned reference is to a static vector; it is valid for the
/// lifetime of the process.
const std::vector<std::string>& get_dns_seeds();

// ---------------------------------------------------------------------------
// DNS resolution
// ---------------------------------------------------------------------------

/// Resolve a single DNS seed hostname to a list of IPv4 and IPv6 address
/// strings.  Uses getaddrinfo() under the hood.
///
/// On failure (hostname not found, network down, etc.) returns an empty
/// vector -- the caller should try the next seed or fall back to the
/// hardcoded seed list.
///
/// @param hostname  The DNS seed hostname to resolve.
/// @returns A vector of IP address strings (e.g. "1.2.3.4", "::1").
std::vector<std::string> resolve_dns_seed(const std::string& hostname);

/// Resolve all DNS seeds and return a deduplicated list of IP addresses.
/// Calls resolve_dns_seed() for each seed in get_dns_seeds().
///
/// @returns A vector of unique IP address strings from all seeds.
std::vector<std::string> resolve_all_dns_seeds();

// ---------------------------------------------------------------------------
// Hardcoded seed nodes (fallback)
// ---------------------------------------------------------------------------

/// Returns a list of hardcoded seed node addresses in "ip:port" format.
/// These are well-known nodes that have historically been reliable and
/// are used as a last-resort fallback when DNS seeds fail.
///
/// The returned reference is to a static vector; it is valid for the
/// lifetime of the process.
const std::vector<std::string>& get_seed_nodes();

/// Default P2P port used when a seed entry does not specify one.
inline constexpr uint16_t DNS_SEED_DEFAULT_PORT = 9333;

} // namespace net
