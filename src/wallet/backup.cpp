// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/backup.h"
#include "core/logging.h"
#include "wallet/keys.h"
#include "wallet/walletdb.h"

#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>

namespace wallet {

// ---------------------------------------------------------------------------
// Backup
// ---------------------------------------------------------------------------

core::Result<void> backup_wallet(WalletDB& db,
                                  const std::filesystem::path& dest_path) {
    // Flush the database to ensure all data is written to disk.
    auto flush_result = db.flush();
    if (!flush_result.ok()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Failed to flush wallet before backup: " +
                           flush_result.error().message());
    }

    const auto& src_path = db.path();
    if (src_path.empty()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Wallet database path is empty");
    }

    if (!std::filesystem::exists(src_path)) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Wallet database file does not exist: " +
                           src_path.string());
    }

    // Create destination parent directories.
    std::error_code ec;
    std::filesystem::create_directories(dest_path.parent_path(), ec);
    if (ec) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Cannot create backup directory: " + ec.message());
    }

    // Copy to temporary file first, then rename atomically.
    auto temp_path = dest_path;
    temp_path += ".tmp";

    // Open source and dest for binary copy.
    std::ifstream src(src_path, std::ios::binary);
    if (!src) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Cannot open wallet for reading: " +
                           src_path.string());
    }

    std::ofstream dst(temp_path, std::ios::binary | std::ios::trunc);
    if (!dst) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Cannot open backup temp file for writing: " +
                           temp_path.string());
    }

    // Copy in chunks.
    constexpr size_t CHUNK_SIZE = 65536;
    char buffer[CHUNK_SIZE];
    while (src.read(buffer, CHUNK_SIZE) || src.gcount() > 0) {
        dst.write(buffer, src.gcount());
        if (!dst.good()) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                               "Error writing backup data");
        }
    }

    dst.flush();
    dst.close();
    src.close();

    // Atomic rename.
    std::filesystem::remove(dest_path, ec);  // Remove target if exists (Windows).
    std::filesystem::rename(temp_path, dest_path, ec);
    if (ec) {
        std::filesystem::remove(temp_path, ec);
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Cannot rename backup temp file: " + ec.message());
    }

    LOG_INFO(core::LogCategory::WALLET,
             "Wallet backed up to: " + dest_path.string());
    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

core::Result<void> restore_wallet(const std::filesystem::path& src_path,
                                   const std::filesystem::path& dest_path) {
    // Verify the backup file is valid.
    auto verify_result = verify_backup(src_path);
    if (!verify_result.ok()) {
        return verify_result;
    }

    // Check destination does not already exist (safety).
    if (std::filesystem::exists(dest_path)) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Destination wallet already exists: " +
                           dest_path.string() +
                           ". Remove it first to avoid accidental overwrite.");
    }

    // Create parent directories.
    std::error_code ec;
    std::filesystem::create_directories(dest_path.parent_path(), ec);
    if (ec) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Cannot create destination directory: " +
                           ec.message());
    }

    // Copy the backup to the destination.
    auto temp_path = dest_path;
    temp_path += ".tmp";

    std::ifstream src(src_path, std::ios::binary);
    if (!src) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Cannot open backup file: " + src_path.string());
    }

    std::ofstream dst(temp_path, std::ios::binary | std::ios::trunc);
    if (!dst) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Cannot open destination temp file: " +
                           temp_path.string());
    }

    constexpr size_t CHUNK_SIZE = 65536;
    char buffer[CHUNK_SIZE];
    while (src.read(buffer, CHUNK_SIZE) || src.gcount() > 0) {
        dst.write(buffer, src.gcount());
        if (!dst.good()) {
            return core::Error(core::ErrorCode::STORAGE_ERROR,
                               "Error writing restored wallet data");
        }
    }

    dst.flush();
    dst.close();
    src.close();

    // Atomic rename.
    std::filesystem::rename(temp_path, dest_path, ec);
    if (ec) {
        std::filesystem::remove(temp_path, ec);
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Cannot rename restored wallet file: " +
                           ec.message());
    }

    LOG_INFO(core::LogCategory::WALLET,
             "Wallet restored from: " + src_path.string() +
             " to: " + dest_path.string());
    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

core::Result<std::string> export_wallet(const KeyManager& keys) {
    if (!keys.is_unlocked()) {
        return core::Error(core::ErrorCode::WALLET_LOCKED,
                           "Wallet must be unlocked to export keys");
    }

    auto addresses = keys.get_all_addresses();

    std::ostringstream oss;

    // Header.
    auto now = std::chrono::system_clock::now();
    auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();

    oss << "# FTC Wallet Dump\n";
    oss << "# Created: " << epoch << "\n";
    oss << "# Total keys: " << addresses.size() << "\n";
    oss << "# Format: <WIF_private_key> <timestamp> label=<label>\n";
    oss << "#\n";

    for (const auto& addr : addresses) {
        auto wif_result = keys.export_key(addr);
        if (!wif_result.ok()) {
            LOG_WARN(core::LogCategory::WALLET,
                     "Skipping key export for address: " + addr +
                     " -- " + wif_result.error().message());
            continue;
        }

        oss << wif_result.value() << " " << epoch << " label=" << addr << "\n";
    }

    oss << "# End of dump\n";

    LOG_INFO(core::LogCategory::WALLET,
             "Exported " + std::to_string(addresses.size()) + " keys");
    return oss.str();
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

core::Result<size_t> import_wallet(KeyManager& keys,
                                    const std::string& dump) {
    std::istringstream iss(dump);
    std::string line;
    size_t imported = 0;
    size_t line_num = 0;
    size_t skipped = 0;

    while (std::getline(iss, line)) {
        ++line_num;

        // Skip empty lines and comments.
        if (line.empty() || line[0] == '#') continue;

        // Trim whitespace.
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;

        // Extract the WIF key (first token).
        size_t end = line.find_first_of(" \t", start);
        std::string wif;
        if (end == std::string::npos) {
            wif = line.substr(start);
        } else {
            wif = line.substr(start, end - start);
        }

        if (wif.empty()) continue;

        // Try to import the key.
        auto result = keys.import_key(wif);
        if (result.ok()) {
            ++imported;
            LOG_DEBUG(core::LogCategory::WALLET,
                      "Imported key at line " + std::to_string(line_num) +
                      ": " + result.value());
        } else {
            // Could be a duplicate or invalid key.
            ++skipped;
            LOG_DEBUG(core::LogCategory::WALLET,
                      "Skipped line " + std::to_string(line_num) +
                      ": " + result.error().message());
        }
    }

    LOG_INFO(core::LogCategory::WALLET,
             "Import complete: " + std::to_string(imported) +
             " imported, " + std::to_string(skipped) + " skipped");
    return imported;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

core::Result<void> verify_backup(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        return core::Error(core::ErrorCode::STORAGE_NOT_FOUND,
                           "Backup file not found: " + path.string());
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Cannot open backup file: " + path.string());
    }

    // Read and verify magic bytes.
    char magic[4];
    if (!file.read(magic, 4)) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Backup file too short to contain header");
    }

    if (std::memcmp(magic, WalletDB::MAGIC, 4) != 0) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Invalid wallet backup magic bytes");
    }

    // Read and verify version.
    uint8_t version_bytes[4];
    if (!file.read(reinterpret_cast<char*>(version_bytes), 4)) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Cannot read backup file version");
    }

    uint32_t version = static_cast<uint32_t>(version_bytes[0]) |
                       (static_cast<uint32_t>(version_bytes[1]) << 8) |
                       (static_cast<uint32_t>(version_bytes[2]) << 16) |
                       (static_cast<uint32_t>(version_bytes[3]) << 24);

    if (version > WalletDB::CURRENT_VERSION) {
        return core::Error(core::ErrorCode::STORAGE_CORRUPT,
                           "Unsupported backup version: " +
                           std::to_string(version));
    }

    LOG_DEBUG(core::LogCategory::WALLET,
              "Backup file verified: " + path.string() +
              " (version " + std::to_string(version) + ")");
    return core::Result<void>{};
}

} // namespace wallet
