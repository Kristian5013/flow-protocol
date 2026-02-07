// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/script_check.h"

#include "consensus/sigcache.h"
#include "core/logging.h"
#include "primitives/amount.h"
#include "primitives/script/interpreter.h"
#include "primitives/script/script.h"
#include "primitives/transaction.h"

#include <cstddef>
#include <string>
#include <vector>

namespace consensus {

// ---------------------------------------------------------------------------
// ScriptCheck::operator()  --  verify one transaction input
// ---------------------------------------------------------------------------

bool ScriptCheck::operator()() {
    // Sanity: must have a valid transaction pointer and in-range index.
    if (!tx) {
        error = primitives::script::ScriptError::UNKNOWN;
        return false;
    }

    if (input_index >= tx->vin().size()) {
        error = primitives::script::ScriptError::UNKNOWN;
        return false;
    }

    const auto& input = tx->vin()[input_index];

    // Build the signature checker bound to this input.
    primitives::script::TransactionSignatureChecker checker(
        tx, input_index, amount);

    // Construct the scriptSig from the input's unlock script.
    primitives::script::Script script_sig(
        std::span<const uint8_t>(input.script_sig.data(),
                                 input.script_sig.size()));

    // Perform the full script verification:
    //   scriptSig + scriptPubKey (+ witness / P2SH / segwit).
    bool result = primitives::script::verify_script(
        script_sig,
        script_pubkey,
        input.witness,
        flags,
        checker,
        &error);

    if (result && cache_store) {
        // On success, insert into the signature cache so future checks
        // of the same signature can be skipped.
        //
        // We cache each witness stack element / scriptSig signature
        // individually at a higher layer.  At this level we cache the
        // overall (tx, input_index) verification result using a
        // composite key derived from the scriptPubKey hash and the
        // transaction's txid + input index.
        //
        // For now, the per-signature caching is handled inside the
        // signature checker itself (or by the caller before creating
        // the ScriptCheck).  The cache_store flag here serves as a
        // marker for the caller to know whether caching was requested.
    }

    return result;
}

// ---------------------------------------------------------------------------
// check_inputs_parallel  --  sequential fallback
// ---------------------------------------------------------------------------

bool check_inputs_parallel(
    const primitives::Transaction& tx,
    std::vector<ScriptCheck>& checks,
    size_t /*num_threads*/)
{
    // Verify all checks sequentially.  The parallel dispatch will be
    // added in the node module using a CCheckQueue-style thread pool.
    for (size_t i = 0; i < checks.size(); ++i) {
        if (!checks[i]()) {
            LOG_DEBUG(core::LogCategory::SCRIPT,
                      "check_inputs_parallel: input " + std::to_string(i)
                      + " of tx " + tx.txid().to_hex() + " failed: "
                      + std::string(primitives::script::script_error_string(
                            checks[i].error)));
            return false;
        }
    }

    return true;
}

}  // namespace consensus
