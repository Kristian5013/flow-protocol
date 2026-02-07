// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/peer/peer_info.h"

#include <cstdio>
#include <string>

namespace net {

// ===========================================================================
// PeerInfo -- service flag queries
// ===========================================================================

bool PeerInfo::is_full_node() const noexcept
{
    return (services & SERVICE_NODE_NETWORK) != 0;
}

bool PeerInfo::has_witness() const noexcept
{
    return (services & SERVICE_NODE_WITNESS) != 0;
}

bool PeerInfo::is_version_acceptable() const noexcept
{
    return version >= MIN_PEER_PROTO_VERSION;
}

bool PeerInfo::supports_send_headers() const noexcept
{
    return version >= SENDHEADERS_VERSION;
}

bool PeerInfo::supports_compact_blocks() const noexcept
{
    return version >= COMPACT_BLOCKS_VERSION;
}

bool PeerInfo::supports_fee_filter() const noexcept
{
    return version >= FEEFILTER_VERSION;
}

// ===========================================================================
// PeerInfo::to_string
// ===========================================================================

std::string PeerInfo::to_string() const
{
    // Compact single-line format suitable for log output.
    //
    // Example:
    //   peer#42 1.2.3.4:9333 (inbound) v70020 /FTC:1.0.0/ height=840000
    //     services=0x0000000d relay=1 sendheaders=1 cmpct=0/0 fee=1000

    char buf[512];

    // Line 1: core identity
    int n = std::snprintf(buf, sizeof(buf),
        "peer#%llu %s (%s) v%d %s height=%d",
        static_cast<unsigned long long>(id),
        address.c_str(),
        inbound ? "inbound" : "outbound",
        static_cast<int>(version),
        user_agent.c_str(),
        static_cast<int>(start_height));

    if (n < 0 || static_cast<size_t>(n) >= sizeof(buf)) {
        return std::string(buf, sizeof(buf) - 1);
    }

    // Line 2: capabilities (appended on the same line for log grep-ability)
    std::snprintf(buf + n, sizeof(buf) - static_cast<size_t>(n),
        " services=0x%016llx relay=%d sendheaders=%d cmpct=%d/%d fee=%lld",
        static_cast<unsigned long long>(services),
        relay ? 1 : 0,
        send_headers ? 1 : 0,
        compact_blocks ? 1 : 0,
        compact_high_bw ? 1 : 0,
        static_cast<long long>(fee_filter));

    return std::string(buf);
}

} // namespace net
