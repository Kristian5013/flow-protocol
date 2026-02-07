#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "core/types.h"
#include "primitives/script/script.h"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace primitives {

// ---------------------------------------------------------------------------
// Address types
// ---------------------------------------------------------------------------

enum class AddressType {
    P2PKH,      // Legacy: base58check, version 0x00
    P2SH,       // Script hash: base58check, version 0x05
    P2WPKH,     // Native segwit v0 keyhash: bech32
    P2WSH,      // Native segwit v0 scripthash: bech32
    P2TR,       // Taproot (segwit v1): bech32m
    UNKNOWN,
};

// ---------------------------------------------------------------------------
// Address  --  parsed/validated FTC address
// ---------------------------------------------------------------------------

/// Represents a decoded FTC address with its type, hash data, and encoded
/// string form.  Supports all standard address formats:
///
///   - P2PKH:  base58check with version byte 0x00 (starts with '1')
///   - P2SH:   base58check with version byte 0x05 (starts with '3')
///   - P2WPKH: bech32 with HRP "fc", witness version 0, 20-byte program
///   - P2WSH:  bech32 with HRP "fc", witness version 0, 32-byte program
///   - P2TR:   bech32m with HRP "fc", witness version 1, 32-byte program
class Address {
public:
    Address() = default;

    // -- Factory methods: create from components ----------------------------

    /// Create a P2PKH address from a 20-byte pubkey hash.
    static Address from_pubkey_hash(const core::uint160& hash,
                                     const std::string& hrp = "fc");

    /// Create a P2SH address from a 20-byte script hash.
    static Address from_script_hash(const core::uint160& hash);

    /// Create a native segwit P2WPKH address from a 20-byte keyhash.
    static Address from_witness_v0_keyhash(
        const core::uint160& hash,
        const std::string& hrp = "fc");

    /// Create a native segwit P2WSH address from a 32-byte scripthash.
    static Address from_witness_v0_scripthash(
        const core::uint256& hash,
        const std::string& hrp = "fc");

    /// Create a taproot P2TR address from a 32-byte output key.
    static Address from_witness_v1_taproot(
        const core::uint256& output_key,
        const std::string& hrp = "fc");

    /// Create an address from a raw public key, using the specified type.
    /// The public key is hashed appropriately for the chosen address type.
    /// Default type is P2WPKH (modern best practice).
    static Address from_pubkey(std::span<const uint8_t> pubkey,
                                AddressType type = AddressType::P2WPKH,
                                const std::string& hrp = "fc");

    /// Parse an address string (auto-detect format: base58check or bech32).
    /// Returns an error if the string is not a valid FTC address.
    static core::Result<Address> from_string(
        std::string_view str,
        const std::string& hrp = "fc");

    // -- Script generation --------------------------------------------------

    /// Generate the scriptPubKey corresponding to this address.
    script::Script to_script() const;

    // -- Accessors ----------------------------------------------------------

    [[nodiscard]] AddressType type() const { return type_; }
    [[nodiscard]] const std::string& to_string() const { return encoded_; }
    [[nodiscard]] const std::vector<uint8_t>& hash() const { return hash_; }
    [[nodiscard]] bool is_valid() const {
        return type_ != AddressType::UNKNOWN;
    }

    bool operator==(const Address& other) const {
        return encoded_ == other.encoded_;
    }
    bool operator!=(const Address& other) const {
        return encoded_ != other.encoded_;
    }

private:
    AddressType type_ = AddressType::UNKNOWN;
    std::vector<uint8_t> hash_;   // 20 bytes for P2PKH/P2SH/P2WPKH;
                                  // 32 bytes for P2WSH/P2TR
    std::string encoded_;         // The human-readable address string

    // Version bytes for base58check encoding
    static constexpr uint8_t VERSION_P2PKH = 0x00;
    static constexpr uint8_t VERSION_P2SH  = 0x05;
};

} // namespace primitives
