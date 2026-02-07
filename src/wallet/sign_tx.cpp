// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/sign_tx.h"
#include "core/logging.h"
#include "crypto/keccak.h"
#include "primitives/address.h"

namespace wallet {

// ---------------------------------------------------------------------------
// WalletSigningProvider
// ---------------------------------------------------------------------------

WalletSigningProvider::WalletSigningProvider(const KeyManager& keys)
    : keys_(keys) {}

bool WalletSigningProvider::get_key(
    const core::uint160& pubkey_hash,
    crypto::ECKey& key_out) const {

    auto result = keys_.get_key_by_hash(pubkey_hash);
    if (!result.ok()) return false;

    key_out = std::move(result).value();
    return true;
}

bool WalletSigningProvider::get_pubkey(
    const core::uint160& pubkey_hash,
    std::vector<uint8_t>& pubkey_out) const {

    auto result = keys_.get_key_by_hash(pubkey_hash);
    if (!result.ok()) return false;

    auto pubkey = result.value().pubkey_compressed();
    pubkey_out.assign(pubkey.begin(), pubkey.end());
    return true;
}

bool WalletSigningProvider::get_script(
    const core::uint160& script_hash,
    primitives::script::Script& script_out) const {

    // Check the script cache first.
    auto cache_it = script_cache_.find(script_hash);
    if (cache_it != script_cache_.end()) {
        script_out = cache_it->second;
        return true;
    }

    // For P2SH-P2WPKH, the redeem script is: OP_0 <20-byte-keyhash>.
    // We iterate over all keys and check if any produce a matching
    // P2SH-P2WPKH script hash.
    auto addresses = keys_.get_all_addresses();
    for (const auto& addr : addresses) {
        auto pkh_result = keys_.get_pubkey_hash(addr);
        if (!pkh_result.ok()) continue;

        auto pubkey_hash = pkh_result.value();

        // Build the P2WPKH witness program (redeem script for P2SH-P2WPKH).
        auto redeem_script = primitives::script::Script::p2wpkh(pubkey_hash);

        // Compute HASH160 of the redeem script.
        auto redeem_hash = redeem_script.script_hash();

        if (redeem_hash == script_hash) {
            script_cache_[script_hash] = redeem_script;
            script_out = redeem_script;
            return true;
        }
    }

    return false;
}

// ---------------------------------------------------------------------------
// Transaction signing (via KeyManager)
// ---------------------------------------------------------------------------

core::Result<primitives::Transaction> sign_transaction(
    primitives::Transaction tx,
    const KeyManager& keys,
    const std::vector<InputSigningInfo>& input_info,
    int sighash_type) {

    WalletSigningProvider provider(keys);
    return sign_transaction(std::move(tx), provider, input_info, sighash_type);
}

// ---------------------------------------------------------------------------
// Transaction signing (via SigningProvider)
// ---------------------------------------------------------------------------

core::Result<primitives::Transaction> sign_transaction(
    primitives::Transaction tx,
    const primitives::script::SigningProvider& provider,
    const std::vector<InputSigningInfo>& input_info,
    int sighash_type) {

    if (input_info.size() != tx.vin().size()) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "Input info count (" +
                           std::to_string(input_info.size()) +
                           ") does not match transaction input count (" +
                           std::to_string(tx.vin().size()) + ")");
    }

    size_t signed_count = 0;

    for (size_t i = 0; i < tx.vin().size(); ++i) {
        const auto& info = input_info[i];

        bool success = primitives::script::sign_input(
            provider, tx, i, info.script_pubkey, info.amount, sighash_type);

        if (success) {
            ++signed_count;
            LOG_DEBUG(core::LogCategory::WALLET,
                      "Signed input " + std::to_string(i) +
                      " of transaction");
        } else {
            LOG_WARN(core::LogCategory::WALLET,
                     "Failed to sign input " + std::to_string(i) +
                     " -- key not found or unsupported script type");
        }
    }

    if (signed_count == 0) {
        return core::Error(core::ErrorCode::WALLET_KEY_MISS,
                           "Could not sign any inputs");
    }

    if (signed_count < tx.vin().size()) {
        LOG_WARN(core::LogCategory::WALLET,
                 "Partially signed transaction: " +
                 std::to_string(signed_count) + "/" +
                 std::to_string(tx.vin().size()) + " inputs signed");
    }

    LOG_INFO(core::LogCategory::WALLET,
             "Transaction signed: " + std::to_string(signed_count) +
             "/" + std::to_string(tx.vin().size()) + " inputs, txid=" +
             tx.txid().to_hex());

    return tx;
}

// ---------------------------------------------------------------------------
// Signature checking helpers
// ---------------------------------------------------------------------------

bool is_fully_signed(const primitives::Transaction& tx) {
    for (size_t i = 0; i < tx.vin().size(); ++i) {
        if (!is_input_signed(tx, i)) return false;
    }
    return !tx.vin().empty();
}

bool is_input_signed(const primitives::Transaction& tx, size_t input_index) {
    if (input_index >= tx.vin().size()) return false;

    const auto& input = tx.vin()[input_index];

    // Check for witness data (segwit inputs).
    if (!input.witness.empty()) {
        // P2WPKH witness: [signature, pubkey]
        if (input.witness.size() >= 2) {
            const auto& sig = input.witness[0];
            const auto& pubkey = input.witness[1];
            // DER signature is typically 70-73 bytes + 1 sighash byte.
            if (sig.size() >= 64 && pubkey.size() >= 33) {
                return true;
            }
        }
        // P2WSH or other witness types with multiple items.
        if (input.witness.size() >= 1 && input.witness[0].size() >= 64) {
            return true;
        }
    }

    // Check for script_sig (legacy P2PKH inputs).
    if (!input.script_sig.empty()) {
        // P2PKH scriptSig: <sig> <pubkey>
        // Minimum: a DER signature (~70 bytes) pushed, then a pubkey (33 bytes).
        if (input.script_sig.size() >= 100) {
            return true;
        }
        // P2SH-P2WPKH: scriptSig contains the redeem script push.
        if (input.script_sig.size() >= 23 && !input.witness.empty()) {
            return true;
        }
    }

    return false;
}

size_t count_signed_inputs(const primitives::Transaction& tx) {
    size_t count = 0;
    for (size_t i = 0; i < tx.vin().size(); ++i) {
        if (is_input_signed(tx, i)) ++count;
    }
    return count;
}

} // namespace wallet
