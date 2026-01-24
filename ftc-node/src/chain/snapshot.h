/**
 * FTC Node - UTXO Snapshot Format
 * Fast synchronization via UTXO state snapshots
 *
 * Snapshot format:
 * - Header: magic + version + height + block_hash + utxo_count + total_value
 * - UTXO entries: serialized UTXOs
 * - Checksum: Keccak256 of all above
 */

#ifndef FTC_CHAIN_SNAPSHOT_H
#define FTC_CHAIN_SNAPSHOT_H

#include "chain/utxo_set.h"
#include "crypto/keccak256.h"
#include <string>
#include <vector>
#include <functional>

namespace ftc {
namespace chain {

// Snapshot file magic bytes: "FTCS"
constexpr uint32_t SNAPSHOT_MAGIC = 0x53435446;  // "FTCS" in little-endian
constexpr uint32_t SNAPSHOT_VERSION = 1;

/**
 * Snapshot header - fixed size metadata
 */
struct SnapshotHeader {
    uint32_t magic = SNAPSHOT_MAGIC;
    uint32_t version = SNAPSHOT_VERSION;
    int32_t height = 0;              // Block height at snapshot
    crypto::Hash256 block_hash;       // Best block hash at snapshot
    uint64_t utxo_count = 0;          // Number of UTXOs
    uint64_t total_value = 0;         // Total FTC in UTXOs (for verification)

    // Serialize to bytes (60 bytes total)
    std::vector<uint8_t> serialize() const;

    // Deserialize from bytes
    bool deserialize(const uint8_t* data, size_t len);

    // Header size
    static constexpr size_t SIZE = 4 + 4 + 4 + 32 + 8 + 8;  // 60 bytes
};

/**
 * Snapshot metadata - returned without loading full snapshot
 */
struct SnapshotInfo {
    SnapshotHeader header;
    std::string file_path;
    size_t file_size = 0;
    bool valid = false;
    std::string error;
};

/**
 * Progress callback for export/import
 */
using SnapshotProgressCallback = std::function<void(uint64_t processed, uint64_t total)>;

/**
 * Snapshot - UTXO state snapshot for fast sync
 *
 * Usage:
 *   // Export
 *   Snapshot::exportToFile(utxo_set, height, block_hash, "snapshot.dat", progress_cb);
 *
 *   // Import
 *   auto info = Snapshot::getInfo("snapshot.dat");
 *   if (info.valid) {
 *       Snapshot::importFromFile(utxo_set, "snapshot.dat", progress_cb);
 *   }
 */
class Snapshot {
public:
    /**
     * Export UTXO set to snapshot file
     * @param utxo_set Source UTXO set
     * @param height Current block height
     * @param block_hash Best block hash
     * @param file_path Output file path
     * @param progress Optional progress callback
     * @return true on success
     */
    static bool exportToFile(
        const UTXOSet& utxo_set,
        int32_t height,
        const crypto::Hash256& block_hash,
        const std::string& file_path,
        SnapshotProgressCallback progress = nullptr
    );

    /**
     * Import UTXO set from snapshot file
     * @param utxo_set Target UTXO set (will be cleared first)
     * @param file_path Input file path
     * @param progress Optional progress callback
     * @return true on success
     */
    static bool importFromFile(
        UTXOSet& utxo_set,
        const std::string& file_path,
        SnapshotProgressCallback progress = nullptr
    );

    /**
     * Get snapshot info without loading full file
     * @param file_path Snapshot file path
     * @return Snapshot metadata
     */
    static SnapshotInfo getInfo(const std::string& file_path);

    /**
     * Verify snapshot file integrity
     * @param file_path Snapshot file path
     * @return true if checksum matches
     */
    static bool verify(const std::string& file_path);

    /**
     * Export UTXO set to memory buffer
     * @param utxo_set Source UTXO set
     * @param height Current block height
     * @param block_hash Best block hash
     * @return Serialized snapshot data
     */
    static std::vector<uint8_t> exportToBuffer(
        const UTXOSet& utxo_set,
        int32_t height,
        const crypto::Hash256& block_hash
    );

    /**
     * Import UTXO set from memory buffer
     * @param utxo_set Target UTXO set
     * @param data Snapshot data
     * @return true on success
     */
    static bool importFromBuffer(
        UTXOSet& utxo_set,
        const std::vector<uint8_t>& data
    );

private:
    // Serialize single UTXO entry
    static std::vector<uint8_t> serializeUTXO(const Outpoint& outpoint, const UTXOEntry& entry);

    // Deserialize single UTXO entry, returns bytes consumed
    static size_t deserializeUTXO(const uint8_t* data, size_t len,
                                   Outpoint& outpoint, UTXOEntry& entry);
};

} // namespace chain
} // namespace ftc

#endif // FTC_CHAIN_SNAPSHOT_H
