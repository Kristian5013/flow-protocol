// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/address.h"

#include "core/base58.h"
#include "core/bech32.h"
#include "core/error.h"
#include "core/types.h"
#include "crypto/keccak.h"
#include "primitives/script/script.h"

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace primitives {

// =========================================================================
// Factory methods: create from components
// =========================================================================

Address Address::from_pubkey_hash(const core::uint160& hash,
                                   const std::string& /*hrp*/) {
    Address addr;
    addr.type_ = AddressType::P2PKH;
    addr.hash_.assign(hash.data(), hash.data() + 20);
    addr.encoded_ = core::encode_with_version(
        VERSION_P2PKH,
        std::span<const uint8_t>(hash.data(), 20));
    return addr;
}

Address Address::from_script_hash(const core::uint160& hash) {
    Address addr;
    addr.type_ = AddressType::P2SH;
    addr.hash_.assign(hash.data(), hash.data() + 20);
    addr.encoded_ = core::encode_with_version(
        VERSION_P2SH,
        std::span<const uint8_t>(hash.data(), 20));
    return addr;
}

Address Address::from_witness_v0_keyhash(const core::uint160& hash,
                                          const std::string& hrp) {
    Address addr;
    addr.type_ = AddressType::P2WPKH;
    addr.hash_.assign(hash.data(), hash.data() + 20);
    addr.encoded_ = core::encode_segwit(
        hrp, 0, std::span<const uint8_t>(hash.data(), 20));
    return addr;
}

Address Address::from_witness_v0_scripthash(const core::uint256& hash,
                                             const std::string& hrp) {
    Address addr;
    addr.type_ = AddressType::P2WSH;
    addr.hash_.assign(hash.data(), hash.data() + 32);
    addr.encoded_ = core::encode_segwit(
        hrp, 0, std::span<const uint8_t>(hash.data(), 32));
    return addr;
}

Address Address::from_witness_v1_taproot(const core::uint256& output_key,
                                          const std::string& hrp) {
    Address addr;
    addr.type_ = AddressType::P2TR;
    addr.hash_.assign(output_key.data(), output_key.data() + 32);
    addr.encoded_ = core::encode_segwit(
        hrp, 1, std::span<const uint8_t>(output_key.data(), 32));
    return addr;
}

// =========================================================================
// from_pubkey: hash a raw public key and build the appropriate address
// =========================================================================

Address Address::from_pubkey(std::span<const uint8_t> pubkey,
                              AddressType type,
                              const std::string& hrp) {
    switch (type) {
        case AddressType::P2PKH: {
            auto hash = crypto::hash160(pubkey);
            return from_pubkey_hash(hash, hrp);
        }
        case AddressType::P2WPKH: {
            auto hash = crypto::hash160(pubkey);
            return from_witness_v0_keyhash(hash, hrp);
        }
        case AddressType::P2SH: {
            // P2SH-P2WPKH: redeem script = OP_0 <20-byte keyhash>
            auto keyhash = crypto::hash160(pubkey);
            // Build the P2WPKH redeem script
            std::vector<uint8_t> redeem;
            redeem.push_back(0x00);  // OP_0
            redeem.push_back(0x14);  // push 20 bytes
            redeem.insert(redeem.end(), keyhash.data(),
                          keyhash.data() + 20);
            // HASH160 of the redeem script
            auto script_hash = crypto::hash160(
                std::span<const uint8_t>(redeem.data(), redeem.size()));
            return from_script_hash(script_hash);
        }
        case AddressType::P2WSH: {
            // Hash the pubkey script as a witness script
            auto keyhash = crypto::hash160(pubkey);
            // Build a simple P2PKH witness script
            script::Script ws = script::Script::p2pkh(keyhash);
            auto wsh = crypto::keccak256(
                std::span<const uint8_t>(ws.data()));
            return from_witness_v0_scripthash(wsh, hrp);
        }
        case AddressType::P2TR: {
            // For P2TR from a pubkey, assume the pubkey is a 32-byte
            // x-only key (Schnorr). If it's a 33-byte compressed key,
            // strip the prefix byte.
            if (pubkey.size() == 32) {
                auto key = core::uint256::from_bytes(
                    std::span<const uint8_t, 32>(
                        pubkey.data(), 32));
                return from_witness_v1_taproot(key, hrp);
            }
            if (pubkey.size() == 33) {
                auto key = core::uint256::from_bytes(
                    std::span<const uint8_t, 32>(
                        pubkey.data() + 1, 32));
                return from_witness_v1_taproot(key, hrp);
            }
            // Invalid pubkey size for taproot
            return Address{};
        }
        case AddressType::UNKNOWN:
            break;
    }
    return Address{};
}

// =========================================================================
// from_string: parse and auto-detect address format
// =========================================================================

core::Result<Address> Address::from_string(std::string_view str,
                                            const std::string& hrp) {
    if (str.empty()) {
        return core::make_error(
            core::ErrorCode::PARSE_BAD_FORMAT,
            "Empty address string");
    }

    // ---------------------------------------------------------------
    // Try bech32/bech32m first (segwit addresses start with hrp + "1")
    // ---------------------------------------------------------------
    auto segwit_result = core::decode_segwit(hrp, str);
    if (segwit_result) {
        auto [witness_version, program] = *segwit_result;

        Address addr;
        addr.hash_ = program;
        addr.encoded_ = std::string(str);

        if (witness_version == 0 && program.size() == 20) {
            addr.type_ = AddressType::P2WPKH;
            return addr;
        }
        if (witness_version == 0 && program.size() == 32) {
            addr.type_ = AddressType::P2WSH;
            return addr;
        }
        if (witness_version == 1 && program.size() == 32) {
            addr.type_ = AddressType::P2TR;
            return addr;
        }

        // Valid segwit but unrecognised program length or version
        return core::make_error(
            core::ErrorCode::PARSE_BAD_FORMAT,
            "Unsupported witness program version/length");
    }

    // ---------------------------------------------------------------
    // Try base58check (legacy P2PKH or P2SH)
    // ---------------------------------------------------------------
    auto b58_result = core::decode_with_version(str);
    if (b58_result) {
        auto [version, payload] = *b58_result;

        if (version == VERSION_P2PKH && payload.size() == 20) {
            Address addr;
            addr.type_ = AddressType::P2PKH;
            addr.hash_ = std::move(payload);
            addr.encoded_ = std::string(str);
            return addr;
        }

        if (version == VERSION_P2SH && payload.size() == 20) {
            Address addr;
            addr.type_ = AddressType::P2SH;
            addr.hash_ = std::move(payload);
            addr.encoded_ = std::string(str);
            return addr;
        }

        return core::make_error(
            core::ErrorCode::PARSE_BAD_FORMAT,
            "Unknown base58check version byte: " +
                std::to_string(version));
    }

    return core::make_error(
        core::ErrorCode::PARSE_BAD_FORMAT,
        "Failed to decode address: neither valid bech32 nor base58check");
}

// =========================================================================
// to_script: generate the corresponding scriptPubKey
// =========================================================================

script::Script Address::to_script() const {
    switch (type_) {
        case AddressType::P2PKH: {
            auto h = core::uint160::from_bytes(
                std::span<const uint8_t, 20>(hash_.data(), 20));
            return script::Script::p2pkh(h);
        }
        case AddressType::P2SH: {
            auto h = core::uint160::from_bytes(
                std::span<const uint8_t, 20>(hash_.data(), 20));
            return script::Script::p2sh(h);
        }
        case AddressType::P2WPKH: {
            auto h = core::uint160::from_bytes(
                std::span<const uint8_t, 20>(hash_.data(), 20));
            return script::Script::p2wpkh(h);
        }
        case AddressType::P2WSH: {
            auto h = core::uint256::from_bytes(
                std::span<const uint8_t, 32>(hash_.data(), 32));
            return script::Script::p2wsh(h);
        }
        case AddressType::P2TR: {
            auto h = core::uint256::from_bytes(
                std::span<const uint8_t, 32>(hash_.data(), 32));
            return script::Script::p2tr(h);
        }
        case AddressType::UNKNOWN:
            break;
    }

    // Return an empty script for unknown address types
    return script::Script{};
}

} // namespace primitives
