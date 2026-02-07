// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/channel.h"

namespace core {

// ---------------------------------------------------------------------------
// ChannelClosedError
// ---------------------------------------------------------------------------

ChannelClosedError::ChannelClosedError()
    : std::runtime_error("receive on closed channel") {}

ChannelClosedError::ChannelClosedError(const std::string& message)
    : std::runtime_error(message) {}

}  // namespace core
