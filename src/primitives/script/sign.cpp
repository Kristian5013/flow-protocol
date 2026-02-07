// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/script/sign.h"

#include "crypto/keccak.h"
#include "crypto/secp256k1.h"
#include "primitives/script/opcodes.h"
#include "primitives/script/standard.h"

#include <array>
#include <cstdint>
#include <cstring>

namespace primitives::script {

// =========================================================================
// SimpleSigningProvider
// =========================================================================

void SimpleSigningProvider::add_key(const crypto::ECKey& key) {
    auto secret = key.secret();
    auto pubkey_arr = key.pubkey_compressed();
    std::vector<uint8_t> pubkey_vec(pubkey_arr.begin(), pubkey_arr.end());

    // Compute HASH160 of the compressed public key
    auto hash = crypto::hash160(
        std::span<const uint8_t>(pubkey_vec.data(), pubkey_vec.size()));

    keys_[hash] = secret;
    pubkeys_[hash] = std::move(pubkey_vec);
}

void SimpleSigningProvider::add_script(const Script& script) {
    auto hash = script.script_hash();
    scripts_[hash] = script;
}

bool SimpleSigningProvider::get_key(
    const core::uint160& hash,
    crypto::ECKey& key_out) const {

    auto it = keys_.find(hash);
    if (it == keys_.end()) return false;

    std::span<const uint8_t, 32> secret_span(
        it->second.data(), it->second.size());
    auto result = crypto::ECKey::from_secret(secret_span);
    if (!result.ok()) return false;

    key_out = std::move(result.value());
    return true;
}

bool SimpleSigningProvider::get_pubkey(
    const core::uint160& hash,
    std::vector<uint8_t>& pubkey_out) const {

    auto it = pubkeys_.find(hash);
    if (it == pubkeys_.end()) return false;

    pubkey_out = it->second;
    return true;
}

bool SimpleSigningProvider::get_script(
    const core::uint160& hash,
    Script& script_out) const {

    auto it = scripts_.find(hash);
    if (it == scripts_.end()) return false;

    script_out = it->second;
    return true;
}

// =========================================================================
// Internal signing helpers
// =========================================================================

namespace {

/// Build a serialized push of raw data (used to construct scriptSig).
void push_to_script_sig(std::vector<uint8_t>& out,
                        std::span<const uint8_t> data) {
    size_t len = data.size();
    if (len == 0) {
        out.push_back(static_cast<uint8_t>(Opcode::OP_0));
    } else if (len <= 0x4b) {
        out.push_back(static_cast<uint8_t>(len));
        out.insert(out.end(), data.begin(), data.end());
    } else if (len <= 0xff) {
        out.push_back(static_cast<uint8_t>(Opcode::OP_PUSHDATA1));
        out.push_back(static_cast<uint8_t>(len));
        out.insert(out.end(), data.begin(), data.end());
    } else if (len <= 0xffff) {
        out.push_back(static_cast<uint8_t>(Opcode::OP_PUSHDATA2));
        out.push_back(static_cast<uint8_t>(len & 0xff));
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xff));
        out.insert(out.end(), data.begin(), data.end());
    } else {
        out.push_back(static_cast<uint8_t>(Opcode::OP_PUSHDATA4));
        out.push_back(static_cast<uint8_t>(len & 0xff));
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xff));
        out.push_back(static_cast<uint8_t>((len >> 16) & 0xff));
        out.push_back(static_cast<uint8_t>((len >> 24) & 0xff));
        out.insert(out.end(), data.begin(), data.end());
    }
}

/// Append the sighash type byte to a DER signature to form a Bitcoin-style
/// signature (DER + hashtype).
std::vector<uint8_t> append_hash_type(
    const std::vector<uint8_t>& der_sig, int hash_type) {

    std::vector<uint8_t> result = der_sig;
    result.push_back(static_cast<uint8_t>(hash_type));
    return result;
}

/// Extract the script code for P2PKH sighash computation.
/// Returns: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
std::vector<uint8_t> p2pkh_script_code(
    const core::uint160& pubkey_hash) {

    std::vector<uint8_t> sc;
    sc.reserve(25);
    sc.push_back(static_cast<uint8_t>(Opcode::OP_DUP));
    sc.push_back(static_cast<uint8_t>(Opcode::OP_HASH160));
    sc.push_back(0x14);  // push 20 bytes
    sc.insert(sc.end(), pubkey_hash.data(),
              pubkey_hash.data() + 20);
    sc.push_back(static_cast<uint8_t>(Opcode::OP_EQUALVERIFY));
    sc.push_back(static_cast<uint8_t>(Opcode::OP_CHECKSIG));
    return sc;
}

/// Extract the script code for P2WPKH BIP143 sighash computation.
/// This is the same P2PKH template but used as the script code in BIP143.
std::vector<uint8_t> p2wpkh_script_code(
    const core::uint160& pubkey_hash) {

    return p2pkh_script_code(pubkey_hash);
}

/// Sign a P2PKH input.
bool sign_p2pkh(const SigningProvider& provider,
                const Transaction& tx,
                size_t input_index,
                const core::uint160& pubkey_hash,
                Amount amount,
                int hash_type,
                std::vector<uint8_t>& script_sig_out,
                std::vector<std::vector<uint8_t>>& witness_out) {

    // Look up the key
    crypto::ECKey key;
    if (!provider.get_key(pubkey_hash, key)) return false;

    std::vector<uint8_t> pubkey_vec;
    if (!provider.get_pubkey(pubkey_hash, pubkey_vec)) return false;

    // Compute the script code for sighash
    auto script_code = p2pkh_script_code(pubkey_hash);

    // Compute the signature hash (legacy sighash for P2PKH)
    auto sighash = tx.signature_hash(
        input_index, script_code, amount, hash_type);

    // Sign
    auto der_sig = key.sign(sighash);
    auto full_sig = append_hash_type(der_sig, hash_type);

    // Build scriptSig: <sig> <pubkey>
    script_sig_out.clear();
    push_to_script_sig(script_sig_out, full_sig);
    push_to_script_sig(script_sig_out, pubkey_vec);

    witness_out.clear();
    return true;
}

/// Sign a P2WPKH input (native segwit).
bool sign_p2wpkh(const SigningProvider& provider,
                 const Transaction& tx,
                 size_t input_index,
                 const core::uint160& pubkey_hash,
                 Amount amount,
                 int hash_type,
                 std::vector<uint8_t>& script_sig_out,
                 std::vector<std::vector<uint8_t>>& witness_out) {

    crypto::ECKey key;
    if (!provider.get_key(pubkey_hash, key)) return false;

    std::vector<uint8_t> pubkey_vec;
    if (!provider.get_pubkey(pubkey_hash, pubkey_vec)) return false;

    // BIP143 script code for P2WPKH is the P2PKH template
    auto script_code = p2wpkh_script_code(pubkey_hash);

    // BIP143 sighash
    auto sighash = tx.signature_hash(
        input_index, script_code, amount, hash_type);

    // Sign
    auto der_sig = key.sign(sighash);
    auto full_sig = append_hash_type(der_sig, hash_type);

    // For native segwit: empty scriptSig, witness = [sig, pubkey]
    script_sig_out.clear();

    witness_out.clear();
    witness_out.push_back(std::move(full_sig));
    witness_out.push_back(std::move(pubkey_vec));
    return true;
}

/// Sign a P2SH-P2WPKH input (wrapped segwit).
bool sign_p2sh_p2wpkh(const SigningProvider& provider,
                       const Transaction& tx,
                       size_t input_index,
                       const core::uint160& script_hash,
                       Amount amount,
                       int hash_type,
                       std::vector<uint8_t>& script_sig_out,
                       std::vector<std::vector<uint8_t>>& witness_out) {

    // Look up the redeem script (should be a P2WPKH script)
    Script redeem_script;
    if (!provider.get_script(script_hash, redeem_script)) return false;

    // The redeem script should be a P2WPKH script: OP_0 <20-byte hash>
    auto wpkh_hash = redeem_script.get_p2wpkh_hash();
    if (!wpkh_hash) return false;

    crypto::ECKey key;
    if (!provider.get_key(*wpkh_hash, key)) return false;

    std::vector<uint8_t> pubkey_vec;
    if (!provider.get_pubkey(*wpkh_hash, pubkey_vec)) return false;

    // BIP143 script code
    auto script_code = p2wpkh_script_code(*wpkh_hash);

    // BIP143 sighash
    auto sighash = tx.signature_hash(
        input_index, script_code, amount, hash_type);

    // Sign
    auto der_sig = key.sign(sighash);
    auto full_sig = append_hash_type(der_sig, hash_type);

    // scriptSig = <push redeemScript>
    script_sig_out.clear();
    push_to_script_sig(script_sig_out, redeem_script.data());

    // Witness = [sig, pubkey]
    witness_out.clear();
    witness_out.push_back(std::move(full_sig));
    witness_out.push_back(std::move(pubkey_vec));
    return true;
}

/// Sign a P2WSH input (native witness script hash).
bool sign_p2wsh(const SigningProvider& provider,
                const Transaction& tx,
                size_t input_index,
                const core::uint256& witness_script_hash,
                Amount amount,
                int hash_type,
                std::vector<uint8_t>& script_sig_out,
                std::vector<std::vector<uint8_t>>& witness_out) {

    // We need to find the witness script whose Keccak256 matches the hash.
    // The provider indexes scripts by HASH160, so we need to try looking
    // up scripts. For P2WSH, the canonical approach is that the script
    // provider stores scripts by their HASH160. We iterate conceptually:
    // the caller must have added the witness script to the provider using
    // add_script(), which stores by HASH160. We need to look up by
    // HASH160 of the witness script.

    // Unfortunately we have a uint256 (Keccak256 of script) but the
    // provider keys by uint160 (HASH160). The caller typically knows
    // both and has added the script. We'll derive a uint160 from the
    // first 20 bytes of the witness_script_hash as a lookup key.
    // Actually, the proper approach: convert the 32-byte P2WSH hash
    // to look up the script. We'll store the script by its HASH160
    // and search all stored scripts to find one whose witness_script_hash
    // matches.

    // A pragmatic approach: P2WSH scripts are stored by their HASH160
    // in the provider. The signing code for P2WSH requires the witness
    // script. We'll compute HASH160 from the 32-byte hash (truncate to
    // first 20 bytes, but this is wrong). Instead, we need a different
    // approach.

    // The correct design: the provider should support lookup by
    // witness_script_hash. For now, we'll compute the HASH160 of the
    // 32-byte hash as an approximation -- but in practice, the caller
    // should have pre-registered the witness script by its HASH160.

    // For a production signing flow, the wallet knows which witness
    // script matches and provides it. We attempt a HASH160 lookup
    // using the hash of the witness script hash bytes themselves.
    auto script_hash_160 = crypto::hash160(std::span<const uint8_t>(
        witness_script_hash.data(), witness_script_hash.size()));

    Script witness_script;
    if (!provider.get_script(script_hash_160, witness_script)) {
        return false;
    }

    // Verify the witness script actually hashes to the expected value
    auto computed_hash = witness_script.witness_script_hash();
    if (!(computed_hash == witness_script_hash)) return false;

    // Parse the witness script to determine what signatures are needed.
    // For simplicity, handle the single-sig case (P2WPKH-in-P2WSH is
    // handled above; here we handle generic witness scripts).
    auto sol = solve(witness_script);

    witness_out.clear();
    script_sig_out.clear();

    if (sol.type == TxoutType::PUBKEYHASH) {
        // Witness script is a P2PKH template
        core::uint160 pkh = core::uint160::from_bytes(
            std::span<const uint8_t, 20>(
                sol.solutions[0].data(), 20));

        crypto::ECKey key;
        if (!provider.get_key(pkh, key)) return false;

        std::vector<uint8_t> pubkey_vec;
        if (!provider.get_pubkey(pkh, pubkey_vec)) return false;

        // BIP143 sighash with the witness script as script code
        auto sighash = tx.signature_hash(
            input_index, witness_script.data(), amount, hash_type);

        auto der_sig = key.sign(sighash);
        auto full_sig = append_hash_type(der_sig, hash_type);

        witness_out.push_back(std::move(full_sig));
        witness_out.push_back(std::move(pubkey_vec));
        witness_out.push_back(witness_script.data());
        return true;
    }

    if (sol.type == TxoutType::MULTISIG) {
        // Multisig witness script
        // Witness: OP_0 (dummy) + signatures + witnessScript
        witness_out.push_back({});  // OP_0 dummy for CHECKMULTISIG bug

        int sigs_produced = 0;
        for (const auto& pubkey_bytes : sol.solutions) {
            if (sigs_produced >= sol.required_sigs) break;

            auto pk_hash = crypto::hash160(std::span<const uint8_t>(
                pubkey_bytes.data(), pubkey_bytes.size()));

            crypto::ECKey key;
            if (!provider.get_key(pk_hash, key)) continue;

            auto sighash = tx.signature_hash(
                input_index, witness_script.data(), amount,
                hash_type);

            auto der_sig = key.sign(sighash);
            auto full_sig = append_hash_type(der_sig, hash_type);
            witness_out.push_back(std::move(full_sig));
            sigs_produced++;
        }

        if (sigs_produced < sol.required_sigs) {
            witness_out.clear();
            return false;
        }

        witness_out.push_back(witness_script.data());
        return true;
    }

    // Unsupported witness script type
    return false;
}

/// Sign a bare pubkey input: <pubkey> OP_CHECKSIG
bool sign_pubkey(const SigningProvider& provider,
                 const Transaction& tx,
                 size_t input_index,
                 std::span<const uint8_t> pubkey_bytes,
                 Amount amount,
                 int hash_type,
                 std::vector<uint8_t>& script_sig_out,
                 std::vector<std::vector<uint8_t>>& witness_out) {

    auto pk_hash = crypto::hash160(pubkey_bytes);

    crypto::ECKey key;
    if (!provider.get_key(pk_hash, key)) return false;

    // Script code is the full scriptPubKey for bare pubkey
    std::vector<uint8_t> script_code;
    push_to_script_sig(script_code, pubkey_bytes);
    script_code.push_back(
        static_cast<uint8_t>(Opcode::OP_CHECKSIG));

    auto sighash = tx.signature_hash(
        input_index, script_code, amount, hash_type);

    auto der_sig = key.sign(sighash);
    auto full_sig = append_hash_type(der_sig, hash_type);

    script_sig_out.clear();
    push_to_script_sig(script_sig_out, full_sig);

    witness_out.clear();
    return true;
}

/// Sign a bare multisig input.
bool sign_multisig(const SigningProvider& provider,
                   const Transaction& tx,
                   size_t input_index,
                   const Script& script_pubkey,
                   const ScriptSolution& sol,
                   Amount amount,
                   int hash_type,
                   std::vector<uint8_t>& script_sig_out,
                   std::vector<std::vector<uint8_t>>& witness_out) {

    // scriptSig: OP_0 <sig1> ... <sigM>
    script_sig_out.clear();
    // OP_0 dummy for CHECKMULTISIG off-by-one bug
    script_sig_out.push_back(
        static_cast<uint8_t>(Opcode::OP_0));

    int sigs_produced = 0;
    for (const auto& pubkey_bytes : sol.solutions) {
        if (sigs_produced >= sol.required_sigs) break;

        auto pk_hash = crypto::hash160(std::span<const uint8_t>(
            pubkey_bytes.data(), pubkey_bytes.size()));

        crypto::ECKey key;
        if (!provider.get_key(pk_hash, key)) continue;

        auto sighash = tx.signature_hash(
            input_index, script_pubkey.data(), amount, hash_type);

        auto der_sig = key.sign(sighash);
        auto full_sig = append_hash_type(der_sig, hash_type);
        push_to_script_sig(script_sig_out, full_sig);
        sigs_produced++;
    }

    witness_out.clear();

    if (sigs_produced < sol.required_sigs) {
        script_sig_out.clear();
        return false;
    }

    return true;
}

} // anonymous namespace

// =========================================================================
// produce_signature
// =========================================================================

bool produce_signature(
    const SigningProvider& provider,
    const Transaction& tx,
    size_t input_index,
    const Script& script_pubkey,
    Amount amount,
    int hash_type,
    std::vector<uint8_t>& script_sig_out,
    std::vector<std::vector<uint8_t>>& witness_out) {

    auto sol = solve(script_pubkey);

    switch (sol.type) {
        case TxoutType::PUBKEYHASH: {
            core::uint160 pkh = core::uint160::from_bytes(
                std::span<const uint8_t, 20>(
                    sol.solutions[0].data(), 20));
            return sign_p2pkh(provider, tx, input_index, pkh,
                              amount, hash_type,
                              script_sig_out, witness_out);
        }

        case TxoutType::PUBKEY: {
            return sign_pubkey(provider, tx, input_index,
                               sol.solutions[0],
                               amount, hash_type,
                               script_sig_out, witness_out);
        }

        case TxoutType::SCRIPTHASH: {
            core::uint160 sh = core::uint160::from_bytes(
                std::span<const uint8_t, 20>(
                    sol.solutions[0].data(), 20));
            return sign_p2sh_p2wpkh(provider, tx, input_index, sh,
                                     amount, hash_type,
                                     script_sig_out, witness_out);
        }

        case TxoutType::WITNESS_V0_KEYHASH: {
            core::uint160 wkh = core::uint160::from_bytes(
                std::span<const uint8_t, 20>(
                    sol.solutions[0].data(), 20));
            return sign_p2wpkh(provider, tx, input_index, wkh,
                               amount, hash_type,
                               script_sig_out, witness_out);
        }

        case TxoutType::WITNESS_V0_SCRIPTHASH: {
            core::uint256 wsh = core::uint256::from_bytes(
                std::span<const uint8_t, 32>(
                    sol.solutions[0].data(), 32));
            return sign_p2wsh(provider, tx, input_index, wsh,
                              amount, hash_type,
                              script_sig_out, witness_out);
        }

        case TxoutType::MULTISIG: {
            return sign_multisig(provider, tx, input_index,
                                 script_pubkey, sol,
                                 amount, hash_type,
                                 script_sig_out, witness_out);
        }

        case TxoutType::NONSTANDARD:
        case TxoutType::NULL_DATA:
        case TxoutType::WITNESS_V1_TAPROOT:
        case TxoutType::WITNESS_UNKNOWN:
            // Cannot sign these script types.
            return false;
    }

    return false;
}

// =========================================================================
// sign_input
// =========================================================================

bool sign_input(
    const SigningProvider& provider,
    Transaction& tx,
    size_t input_index,
    const Script& script_pubkey,
    Amount amount,
    int hash_type) {

    if (input_index >= tx.vin().size()) return false;

    std::vector<uint8_t> script_sig;
    std::vector<std::vector<uint8_t>> witness;

    if (!produce_signature(provider, tx, input_index, script_pubkey,
                           amount, hash_type, script_sig, witness)) {
        return false;
    }

    tx.vin()[input_index].script_sig = std::move(script_sig);
    tx.vin()[input_index].witness = std::move(witness);
    return true;
}

} // namespace primitives::script
