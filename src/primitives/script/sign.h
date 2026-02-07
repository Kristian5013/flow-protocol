#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/types.h"
#include "crypto/secp256k1.h"
#include "primitives/amount.h"
#include "primitives/script/script.h"
#include "primitives/transaction.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

namespace primitives::script {

// ---------------------------------------------------------------------------
// Signing provider interface
// ---------------------------------------------------------------------------

/// Abstract interface for looking up keys and scripts required to produce
/// transaction signatures.  Implementations may back onto an in-memory map,
/// a hardware wallet, or a wallet database.
class SigningProvider {
public:
    virtual ~SigningProvider() = default;

    /// Retrieve the private key whose compressed public key hashes to
    /// @p pubkey_hash.  On success, writes the key into @p key_out and
    /// returns true.
    virtual bool get_key(const core::uint160& pubkey_hash,
                         crypto::ECKey& key_out) const = 0;

    /// Retrieve the compressed public key whose HASH160 is @p pubkey_hash.
    virtual bool get_pubkey(const core::uint160& pubkey_hash,
                            std::vector<uint8_t>& pubkey_out) const = 0;

    /// Retrieve a redeem/witness script whose HASH160 is @p script_hash.
    virtual bool get_script(const core::uint160& script_hash,
                            Script& script_out) const = 0;
};

// ---------------------------------------------------------------------------
// SimpleSigningProvider -- in-memory key / script store
// ---------------------------------------------------------------------------

/// A simple in-memory signing provider suitable for unit tests and
/// single-use signing contexts.
class SimpleSigningProvider : public SigningProvider {
public:
    /// Add a private key.  The corresponding compressed public key is
    /// derived and stored automatically, indexed by its HASH160.
    void add_key(const crypto::ECKey& key);

    /// Add a redeem or witness script, indexed by its HASH160.
    void add_script(const Script& script);

    bool get_key(const core::uint160& hash,
                 crypto::ECKey& key_out) const override;
    bool get_pubkey(const core::uint160& hash,
                    std::vector<uint8_t>& pubkey_out) const override;
    bool get_script(const core::uint160& hash,
                    Script& script_out) const override;

private:
    /// Maps HASH160(compressed_pubkey) -> 32-byte secret.
    std::map<core::uint160, std::array<uint8_t, 32>> keys_;

    /// Maps HASH160(compressed_pubkey) -> compressed pubkey bytes (33).
    std::map<core::uint160, std::vector<uint8_t>> pubkeys_;

    /// Maps HASH160(script) -> Script.
    std::map<core::uint160, Script> scripts_;
};

// ---------------------------------------------------------------------------
// Transaction signing
// ---------------------------------------------------------------------------

/// Sign a single transaction input in-place.
///
/// Detects the script type of @p script_pubkey and produces the
/// appropriate scriptSig and/or witness stack on @p tx.vin()[input_index].
///
/// Supported script types:
///   - P2PKH:  scriptSig = <sig> <pubkey>
///   - P2WPKH: witness = [<sig>, <pubkey>], empty scriptSig
///   - P2SH-P2WPKH: scriptSig = <push redeemScript>, witness = [sig, pk]
///   - P2WSH:  witness = [<sig>..., <witnessScript>], empty scriptSig
///
/// @param hash_type  SIGHASH flags (default SIGHASH_ALL = 1).
/// @returns true on success, false if a required key/script was not found.
bool sign_input(const SigningProvider& provider,
                Transaction& tx,
                size_t input_index,
                const Script& script_pubkey,
                Amount amount,
                int hash_type = Transaction::SIGHASH_ALL);

/// Low-level: produce a scriptSig and/or witness for a given script.
///
/// On success, writes the serialized scriptSig bytes into @p script_sig_out
/// and the witness stack into @p witness_out.
bool produce_signature(const SigningProvider& provider,
                       const Transaction& tx,
                       size_t input_index,
                       const Script& script_pubkey,
                       Amount amount,
                       int hash_type,
                       std::vector<uint8_t>& script_sig_out,
                       std::vector<std::vector<uint8_t>>& witness_out);

} // namespace primitives::script
