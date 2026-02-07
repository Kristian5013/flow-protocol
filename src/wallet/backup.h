#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"

#include <cstddef>
#include <filesystem>
#include <string>

namespace wallet {

// Forward declarations.
class Wallet;
class WalletDB;
class KeyManager;

// ---------------------------------------------------------------------------
// Wallet backup and restore
// ---------------------------------------------------------------------------
// Provides atomic backup of the wallet file, restore from backup, and
// human-readable dump/import of wallet keys.
// ---------------------------------------------------------------------------

/// Create an atomic backup of the wallet database.
///
/// The backup is performed by:
///   1. Flushing the wallet database to disk.
///   2. Copying the wallet file to a temporary file at the destination.
///   3. Atomically renaming the temporary file to the final destination.
///
/// @param db         The wallet database to back up.
/// @param dest_path  The destination file path for the backup.
/// @returns Success or an error if the backup failed.
core::Result<void> backup_wallet(WalletDB& db,
                                  const std::filesystem::path& dest_path);

/// Restore a wallet from a backup file.
///
/// Validates the backup file format before copying to the destination.
///
/// @param src_path   Path to the backup file.
/// @param dest_path  Path where the restored wallet should be placed.
/// @returns Success or an error if the restore failed.
core::Result<void> restore_wallet(const std::filesystem::path& src_path,
                                   const std::filesystem::path& dest_path);

/// Export wallet keys as a human-readable text dump.
///
/// The dump format is one key per line:
///   <WIF_private_key> <unix_timestamp> label=<label>
///
/// Lines starting with '#' are comments. The header contains metadata
/// about the wallet and the export time.
///
/// @param keys  The key manager to export from.
/// @returns The text dump as a string, or an error.
core::Result<std::string> export_wallet(const KeyManager& keys);

/// Import keys from a text dump into the wallet.
///
/// Each line must contain a WIF-encoded private key. Optional label
/// can follow after whitespace as "label=<value>".
///
/// @param keys  The key manager to import into.
/// @param dump  The text dump string.
/// @returns The number of keys successfully imported, or an error.
core::Result<size_t> import_wallet(KeyManager& keys,
                                    const std::string& dump);

/// Verify the integrity of a wallet backup file.
///
/// Reads the magic bytes and version to confirm the file is a valid
/// FTC wallet database.
///
/// @param path  Path to the file to verify.
/// @returns Success or an error describing the problem.
core::Result<void> verify_backup(const std::filesystem::path& path);

} // namespace wallet
