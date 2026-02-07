#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Aggregating header for the net/peer/ subsystem.
//
// The actual Peer struct and PeerEvent are defined in
// net/manager/conn_manager.h, which owns the peer lifecycle.
// This header re-exports the peer metadata and state types used
// by the rest of the networking layer.
// ---------------------------------------------------------------------------

#include "net/peer/peer_info.h"
#include "net/peer/peer_state.h"
