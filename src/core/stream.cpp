// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/stream.h"

// ---------------------------------------------------------------------------
// All DataStream, VectorWriter, and SpanReader methods are defined inline in
// the header.  This translation unit exists so that the build system can
// compile it (the CMakeLists.txt already references stream.cpp) and to
// provide a single place where out-of-line definitions can be added in the
// future without touching the header's ABI.
// ---------------------------------------------------------------------------

namespace core {

// Intentionally empty -- every method is currently header-inline.
// If profiling shows that particular methods should be out-of-line (e.g.
// the throwing read/skip/seek paths), they can be moved here.

}  // namespace core
