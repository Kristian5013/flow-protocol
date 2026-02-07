#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"
#include "core/types.h"
#include "primitives/address.h"
#include "primitives/script/script.h"
#include "wallet/walletdb.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace wallet {

// ---------------------------------------------------------------------------
// AddressBook -- address labels and metadata
// ---------------------------------------------------------------------------
// Manages the mapping between addresses, labels, and their purpose (receiving
// or change). Persists all data through the WalletDB.
// ---------------------------------------------------------------------------

/// The type/purpose of an address in the address book.
enum class AddressPurpose : uint8_t {
    RECEIVING = 0,
    CHANGE    = 1,
};

/// Full address entry with metadata.
struct AddressEntry {
    std::string address;
    std::string label;
    AddressPurpose purpose = AddressPurpose::RECEIVING;
    primitives::AddressType type = primitives::AddressType::P2WPKH;
};

class AddressBook {
public:
    AddressBook() = default;

    /// Initialize the address book with a wallet database reference.
    core::Result<void> init(WalletDB& db);

    // -- Address creation ---------------------------------------------------

    /// Add a new receiving address with the given label.
    /// The address should already exist in the key manager.
    core::Result<std::string> add_receiving(
        const std::string& address,
        const std::string& label = "");

    /// Add a new change address.
    core::Result<std::string> add_change(const std::string& address);

    // -- Label management ---------------------------------------------------

    /// Get the label for an address.
    [[nodiscard]] std::string get_label(const std::string& address) const;

    /// Set or update the label for an address.
    core::Result<void> set_label(const std::string& address,
                                  const std::string& label);

    // -- Listing ------------------------------------------------------------

    /// List all receiving addresses with their labels.
    [[nodiscard]] std::vector<AddressEntry> list_receiving() const;

    /// List all change addresses.
    [[nodiscard]] std::vector<AddressEntry> list_change() const;

    /// List all addresses (both receiving and change).
    [[nodiscard]] std::vector<AddressEntry> list_all() const;

    /// Check if an address is in the address book.
    [[nodiscard]] bool contains(const std::string& address) const;

    /// Get the purpose of an address.
    [[nodiscard]] AddressPurpose get_purpose(
        const std::string& address) const;

    /// Get the full entry for an address.
    core::Result<AddressEntry> get_entry(const std::string& address) const;

    // -- Script generation --------------------------------------------------

    /// Generate the scriptPubKey corresponding to an address string.
    static core::Result<primitives::script::Script> get_script_for_address(
        const std::string& address);

    /// Determine the address type from an address string.
    static primitives::AddressType detect_address_type(
        const std::string& address);

    // -- Counts -------------------------------------------------------------

    [[nodiscard]] size_t receiving_count() const;
    [[nodiscard]] size_t change_count() const;
    [[nodiscard]] size_t total_count() const;

private:
    mutable std::mutex mutex_;
    WalletDB* db_ = nullptr;

    /// In-memory address book.
    std::unordered_map<std::string, AddressEntry> entries_;

    /// Persist an entry to the database.
    core::Result<void> store_entry(const AddressEntry& entry);

    /// Load all entries from the database.
    core::Result<void> load_entries();
};

} // namespace wallet
