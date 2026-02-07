#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "primitives/amount.h"
#include "primitives/script/script.h"
#include "primitives/script/sign.h"
#include "primitives/transaction.h"
#include "wallet/coins.h"
#include "wallet/keys.h"

#include <cstddef>
#include <string>
#include <vector>

namespace wallet {

// ---------------------------------------------------------------------------
// Transaction signing
// ---------------------------------------------------------------------------
// Signs all inputs of a transaction using the wallet's key manager.
// Supports P2PKH, P2WPKH, and P2SH-P2WPKH input types.
// ---------------------------------------------------------------------------

/// Information about each input needed for signing.
struct InputSigningInfo {
    primitives::Amount amount;
    primitives::script::Script script_pubkey;
};

/// Sign a transaction using the wallet's key manager.
///
/// @param tx            The transaction to sign (modified in place).
/// @param keys          The key manager to retrieve signing keys from.
/// @param input_info    Per-input signing information (amounts and scripts).
/// @param sighash_type  The sighash type to use (default SIGHASH_ALL).
/// @returns The signed transaction, or an error if signing fails.
core::Result<primitives::Transaction> sign_transaction(
    primitives::Transaction tx,
    const KeyManager& keys,
    const std::vector<InputSigningInfo>& input_info,
    int sighash_type = primitives::Transaction::SIGHASH_ALL);

/// Sign a transaction using a generic signing provider.
core::Result<primitives::Transaction> sign_transaction(
    primitives::Transaction tx,
    const primitives::script::SigningProvider& provider,
    const std::vector<InputSigningInfo>& input_info,
    int sighash_type = primitives::Transaction::SIGHASH_ALL);

/// Check if a transaction is fully signed (all inputs have valid signatures).
/// This does a quick structural check, not full script evaluation.
bool is_fully_signed(const primitives::Transaction& tx);

/// Check if a specific input is signed.
bool is_input_signed(const primitives::Transaction& tx, size_t input_index);

/// Count the number of signed inputs in a transaction.
size_t count_signed_inputs(const primitives::Transaction& tx);

// ---------------------------------------------------------------------------
// WalletSigningProvider -- bridges KeyManager to SigningProvider interface
// ---------------------------------------------------------------------------

class WalletSigningProvider : public primitives::script::SigningProvider {
public:
    explicit WalletSigningProvider(const KeyManager& keys);

    bool get_key(const core::uint160& pubkey_hash,
                 crypto::ECKey& key_out) const override;

    bool get_pubkey(const core::uint160& pubkey_hash,
                    std::vector<uint8_t>& pubkey_out) const override;

    bool get_script(const core::uint160& script_hash,
                    primitives::script::Script& script_out) const override;

private:
    const KeyManager& keys_;

    /// Cache of P2SH-P2WPKH redeem scripts indexed by their script hash.
    mutable std::unordered_map<core::uint160, primitives::script::Script>
        script_cache_;
};

} // namespace wallet
