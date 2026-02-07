#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Script verification tasks for parallel input checking
// ---------------------------------------------------------------------------
// ScriptCheck encapsulates all the data needed to verify a single transaction
// input's script.  It is designed to be callable as a functor so it can be
// dispatched to a thread pool for parallel verification.
//
// check_inputs_parallel() orchestrates the verification of all inputs in a
// transaction.  The current implementation is sequential; the thread-pool
// integration will be wired up in the node module.
// ---------------------------------------------------------------------------

#include "consensus/sigcache.h"
#include "primitives/amount.h"
#include "primitives/script/interpreter.h"
#include "primitives/script/script.h"
#include "primitives/transaction.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace consensus {

/// Captures all data needed to verify one transaction input's script.
///
/// Designed as a callable (functor): invoking operator()() performs the
/// full script verification and returns true on success.  On failure the
/// @c error member is set to the specific ScriptError code.
struct ScriptCheck {
    // -- Input data (set by the caller before invocation) --------------------

    /// Pointer to the transaction being verified.  Must remain valid for
    /// the lifetime of the ScriptCheck.
    const primitives::Transaction* tx = nullptr;

    /// Index into tx->vin() identifying the input to verify.
    size_t input_index = 0;

    /// Value of the output being spent (required for segwit sighash).
    primitives::Amount amount{};

    /// The scriptPubKey of the output being spent.
    primitives::script::Script script_pubkey{};

    /// Script verification flags to apply.
    primitives::script::ScriptFlags flags = primitives::script::ScriptFlags::NONE;

    /// Whether to store a successful verification result in the signature
    /// cache (and check the cache before verifying).
    bool cache_store = false;

    // -- Output data (set by operator()()) -----------------------------------

    /// On failure, contains the specific error code describing what went
    /// wrong.  Set to ScriptError::OK on success.
    primitives::script::ScriptError error = primitives::script::ScriptError::OK;

    // -- Execution -----------------------------------------------------------

    /// Perform the script verification.
    ///
    /// Creates a TransactionSignatureChecker for the input and calls
    /// verify_script() with the scriptSig from the transaction input and
    /// the stored script_pubkey.
    ///
    /// If @c cache_store is true and a SigCache is available, the cache is
    /// consulted before performing the full verification.  On success the
    /// result is inserted into the cache.
    ///
    /// @returns true if the script passes verification; false otherwise
    ///          (with @c error set to the appropriate ScriptError).
    bool operator()();
};

/// Verify all input scripts for a transaction.
///
/// @param tx          The transaction whose inputs are to be verified.
/// @param checks      A vector of pre-populated ScriptCheck objects, one per
///                    input.  Each check's operator()() is invoked.
/// @param num_threads Hint for the number of worker threads to use.
///                    Currently unused; all checks run sequentially.
/// @returns true if every input passes script verification; false on the
///          first failure.
///
/// NOTE: The parallel dispatch (thread pool) will be wired up in the node
/// module.  This function provides the sequential fallback that is correct
/// and sufficient for initial integration and testing.
[[nodiscard]] bool check_inputs_parallel(
    const primitives::Transaction& tx,
    std::vector<ScriptCheck>& checks,
    size_t num_threads = 1);

}  // namespace consensus
