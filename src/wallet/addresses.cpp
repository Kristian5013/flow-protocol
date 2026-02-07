// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/addresses.h"
#include "core/logging.h"

#include <algorithm>

namespace wallet {

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

core::Result<void> AddressBook::init(WalletDB& db) {
    std::lock_guard lock(mutex_);
    db_ = &db;

    auto result = load_entries();
    if (!result.ok()) return result;

    LOG_INFO(core::LogCategory::WALLET,
             "AddressBook initialized with " +
             std::to_string(entries_.size()) + " entries");
    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// Address creation
// ---------------------------------------------------------------------------

core::Result<std::string> AddressBook::add_receiving(
    const std::string& address, const std::string& label) {
    std::lock_guard lock(mutex_);

    if (!db_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "AddressBook not initialized");
    }

    // Check for duplicate.
    if (entries_.count(address) > 0) {
        // Update label if provided.
        if (!label.empty()) {
            entries_[address].label = label;
            auto result = store_entry(entries_[address]);
            if (!result.ok()) return result.error();
        }
        return address;
    }

    AddressEntry entry;
    entry.address = address;
    entry.label = label;
    entry.purpose = AddressPurpose::RECEIVING;
    entry.type = detect_address_type(address);

    auto result = store_entry(entry);
    if (!result.ok()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Failed to store address: " +
                           result.error().message());
    }

    entries_[address] = std::move(entry);

    LOG_DEBUG(core::LogCategory::WALLET,
              "Added receiving address: " + address);
    return address;
}

core::Result<std::string> AddressBook::add_change(
    const std::string& address) {
    std::lock_guard lock(mutex_);

    if (!db_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "AddressBook not initialized");
    }

    if (entries_.count(address) > 0) {
        return address;
    }

    AddressEntry entry;
    entry.address = address;
    entry.label = "";  // Change addresses typically have no label.
    entry.purpose = AddressPurpose::CHANGE;
    entry.type = detect_address_type(address);

    auto result = store_entry(entry);
    if (!result.ok()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Failed to store change address: " +
                           result.error().message());
    }

    entries_[address] = std::move(entry);

    LOG_DEBUG(core::LogCategory::WALLET,
              "Added change address: " + address);
    return address;
}

// ---------------------------------------------------------------------------
// Label management
// ---------------------------------------------------------------------------

std::string AddressBook::get_label(const std::string& address) const {
    std::lock_guard lock(mutex_);

    auto it = entries_.find(address);
    if (it == entries_.end()) return "";
    return it->second.label;
}

core::Result<void> AddressBook::set_label(
    const std::string& address, const std::string& label) {
    std::lock_guard lock(mutex_);

    if (!db_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "AddressBook not initialized");
    }

    auto it = entries_.find(address);
    if (it == entries_.end()) {
        return core::Error(core::ErrorCode::STORAGE_NOT_FOUND,
                           "Address not in address book: " + address);
    }

    it->second.label = label;
    return store_entry(it->second);
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

std::vector<AddressEntry> AddressBook::list_receiving() const {
    std::lock_guard lock(mutex_);

    std::vector<AddressEntry> result;
    for (const auto& [addr, entry] : entries_) {
        if (entry.purpose == AddressPurpose::RECEIVING) {
            result.push_back(entry);
        }
    }

    std::sort(result.begin(), result.end(),
              [](const auto& a, const auto& b) {
                  return a.address < b.address;
              });
    return result;
}

std::vector<AddressEntry> AddressBook::list_change() const {
    std::lock_guard lock(mutex_);

    std::vector<AddressEntry> result;
    for (const auto& [addr, entry] : entries_) {
        if (entry.purpose == AddressPurpose::CHANGE) {
            result.push_back(entry);
        }
    }

    std::sort(result.begin(), result.end(),
              [](const auto& a, const auto& b) {
                  return a.address < b.address;
              });
    return result;
}

std::vector<AddressEntry> AddressBook::list_all() const {
    std::lock_guard lock(mutex_);

    std::vector<AddressEntry> result;
    result.reserve(entries_.size());
    for (const auto& [addr, entry] : entries_) {
        result.push_back(entry);
    }

    std::sort(result.begin(), result.end(),
              [](const auto& a, const auto& b) {
                  return a.address < b.address;
              });
    return result;
}

bool AddressBook::contains(const std::string& address) const {
    std::lock_guard lock(mutex_);
    return entries_.count(address) > 0;
}

AddressPurpose AddressBook::get_purpose(const std::string& address) const {
    std::lock_guard lock(mutex_);
    auto it = entries_.find(address);
    if (it == entries_.end()) return AddressPurpose::RECEIVING;
    return it->second.purpose;
}

core::Result<AddressEntry> AddressBook::get_entry(
    const std::string& address) const {
    std::lock_guard lock(mutex_);

    auto it = entries_.find(address);
    if (it == entries_.end()) {
        return core::Error(core::ErrorCode::STORAGE_NOT_FOUND,
                           "Address not in address book: " + address);
    }

    return it->second;
}

// ---------------------------------------------------------------------------
// Script generation
// ---------------------------------------------------------------------------

core::Result<primitives::script::Script> AddressBook::get_script_for_address(
    const std::string& address) {
    auto addr_result = primitives::Address::from_string(address);
    if (!addr_result.ok()) {
        return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                           "Invalid address: " + address);
    }

    return addr_result.value().to_script();
}

primitives::AddressType AddressBook::detect_address_type(
    const std::string& address) {
    auto addr_result = primitives::Address::from_string(address);
    if (!addr_result.ok()) {
        return primitives::AddressType::UNKNOWN;
    }
    return addr_result.value().type();
}

// ---------------------------------------------------------------------------
// Counts
// ---------------------------------------------------------------------------

size_t AddressBook::receiving_count() const {
    std::lock_guard lock(mutex_);
    size_t count = 0;
    for (const auto& [_, entry] : entries_) {
        if (entry.purpose == AddressPurpose::RECEIVING) ++count;
    }
    return count;
}

size_t AddressBook::change_count() const {
    std::lock_guard lock(mutex_);
    size_t count = 0;
    for (const auto& [_, entry] : entries_) {
        if (entry.purpose == AddressPurpose::CHANGE) ++count;
    }
    return count;
}

size_t AddressBook::total_count() const {
    std::lock_guard lock(mutex_);
    return entries_.size();
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

core::Result<void> AddressBook::store_entry(const AddressEntry& entry) {
    if (!db_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "AddressBook not initialized");
    }

    // DB key: "addr_book:<address>"
    // Value format: [1B purpose][1B type][2B label_len][label bytes]
    std::vector<uint8_t> data;
    data.push_back(static_cast<uint8_t>(entry.purpose));
    data.push_back(static_cast<uint8_t>(entry.type));

    auto label_len = static_cast<uint16_t>(
        std::min(entry.label.size(), size_t(65535)));
    data.push_back(static_cast<uint8_t>(label_len & 0xFF));
    data.push_back(static_cast<uint8_t>((label_len >> 8) & 0xFF));

    if (label_len > 0) {
        data.insert(data.end(), entry.label.begin(),
                    entry.label.begin() + label_len);
    }

    std::string db_key = "addr_book:" + entry.address;
    return db_->write(db_key, std::span<const uint8_t>(data));
}

core::Result<void> AddressBook::load_entries() {
    if (!db_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "AddressBook not initialized");
    }

    entries_.clear();

    auto records = db_->read_by_prefix("addr_book:");
    for (const auto& [db_key, data] : records) {
        if (data.size() < 4) {
            LOG_WARN(core::LogCategory::WALLET,
                     "Skipping malformed address book entry: " + db_key);
            continue;
        }

        AddressEntry entry;

        // Extract address from key.
        entry.address = db_key.substr(10);  // "addr_book:" = 10 chars

        entry.purpose = static_cast<AddressPurpose>(data[0]);
        entry.type = static_cast<primitives::AddressType>(data[1]);

        uint16_t label_len = static_cast<uint16_t>(data[2]) |
                             (static_cast<uint16_t>(data[3]) << 8);

        if (label_len > 0 && data.size() >= 4u + label_len) {
            entry.label.assign(
                reinterpret_cast<const char*>(data.data() + 4),
                label_len);
        }

        entries_[entry.address] = std::move(entry);
    }

    return core::Result<void>{};
}

} // namespace wallet
