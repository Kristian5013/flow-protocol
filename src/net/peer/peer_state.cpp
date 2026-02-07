// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/peer/peer_state.h"

#include <cstdio>
#include <string>

namespace net {

// ===========================================================================
// PeerState helpers
// ===========================================================================

std::string_view peer_state_name(PeerState state) noexcept
{
    switch (state) {
    case PeerState::CONNECTING:    return "CONNECTING";
    case PeerState::CONNECTED:     return "CONNECTED";
    case PeerState::VERSION_SENT:  return "VERSION_SENT";
    case PeerState::HANDSHAKE_DONE:return "HANDSHAKE_DONE";
    case PeerState::ACTIVE:        return "ACTIVE";
    case PeerState::DISCONNECTING: return "DISCONNECTING";
    case PeerState::DISCONNECTED:  return "DISCONNECTED";
    }
    return "UNKNOWN";
}

bool peer_state_is_operational(PeerState state) noexcept
{
    return state == PeerState::HANDSHAKE_DONE ||
           state == PeerState::ACTIVE;
}

bool peer_state_is_terminal(PeerState state) noexcept
{
    return state == PeerState::DISCONNECTED;
}

bool peer_state_transition_valid(PeerState from, PeerState to) noexcept
{
    // State machine validation:
    //
    //   CONNECTING     -> CONNECTED | DISCONNECTING | DISCONNECTED
    //   CONNECTED      -> VERSION_SENT | DISCONNECTING | DISCONNECTED
    //   VERSION_SENT   -> HANDSHAKE_DONE | DISCONNECTING | DISCONNECTED
    //   HANDSHAKE_DONE -> ACTIVE | DISCONNECTING | DISCONNECTED
    //   ACTIVE         -> DISCONNECTING | DISCONNECTED
    //   DISCONNECTING  -> DISCONNECTED
    //   DISCONNECTED   -> (none -- terminal)
    //
    // Any state may jump directly to DISCONNECTING or DISCONNECTED to
    // handle abrupt connection loss or forced shutdown.

    if (from == to) {
        return false; // no self-transitions
    }

    // Terminal state: no outgoing transitions.
    if (from == PeerState::DISCONNECTED) {
        return false;
    }

    // Any non-terminal state may move to DISCONNECTING or DISCONNECTED.
    if (to == PeerState::DISCONNECTING || to == PeerState::DISCONNECTED) {
        return true;
    }

    // Forward-only state advancement.
    switch (from) {
    case PeerState::CONNECTING:
        return to == PeerState::CONNECTED;

    case PeerState::CONNECTED:
        return to == PeerState::VERSION_SENT;

    case PeerState::VERSION_SENT:
        return to == PeerState::HANDSHAKE_DONE;

    case PeerState::HANDSHAKE_DONE:
        return to == PeerState::ACTIVE;

    case PeerState::ACTIVE:
        // ACTIVE only transitions to disconnect states (handled above).
        return false;

    case PeerState::DISCONNECTING:
        // DISCONNECTING only transitions to DISCONNECTED (handled above).
        return false;

    case PeerState::DISCONNECTED:
        return false; // already handled
    }

    return false;
}

// ===========================================================================
// PeerStats
// ===========================================================================

void PeerStats::reset() noexcept
{
    connected_time     = 0;
    last_send          = 0;
    last_recv          = 0;
    bytes_sent         = 0;
    bytes_recv         = 0;
    msgs_sent          = 0;
    msgs_recv          = 0;
    ping_time          = -1;
    pending_ping_nonce = 0;
    ping_sent_time     = 0;
    misbehavior_score  = 0;
}

std::string PeerStats::to_string() const
{
    // Format: "sent=123B/4msg recv=456B/5msg ping=12ms misbehavior=0"
    char buf[256];
    std::snprintf(buf, sizeof(buf),
        "sent=%lluB/%llumsg recv=%lluB/%llumsg ping=%lldms misbehavior=%d",
        static_cast<unsigned long long>(bytes_sent),
        static_cast<unsigned long long>(msgs_sent),
        static_cast<unsigned long long>(bytes_recv),
        static_cast<unsigned long long>(msgs_recv),
        static_cast<long long>(ping_time),
        static_cast<int>(misbehavior_score));
    return std::string(buf);
}

// ===========================================================================
// DisconnectReason
// ===========================================================================

std::string_view disconnect_reason_name(DisconnectReason reason) noexcept
{
    switch (reason) {
    case DisconnectReason::NONE:                 return "NONE";
    case DisconnectReason::TIMEOUT:              return "TIMEOUT";
    case DisconnectReason::PROTOCOL_ERROR:       return "PROTOCOL_ERROR";
    case DisconnectReason::MISBEHAVIOR:          return "MISBEHAVIOR";
    case DisconnectReason::TOO_MANY_CONNECTIONS: return "TOO_MANY_CONNECTIONS";
    case DisconnectReason::DUPLICATE:            return "DUPLICATE";
    case DisconnectReason::BANNED:               return "BANNED";
    case DisconnectReason::USER_REQUESTED:       return "USER_REQUESTED";
    }
    return "UNKNOWN";
}

} // namespace net
