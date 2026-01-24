/**
 * FTC Node - UTXO Snapshot Implementation
 */

#include "chain/snapshot.h"
#include "util/logging.h"
#include <fstream>
#include <filesystem>
#include <cstring>

namespace ftc {
namespace chain {

namespace fs = std::filesystem;

// ============================================================================
// SnapshotHeader implementation
// ============================================================================

std::vector<uint8_t> SnapshotHeader::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(SIZE);

    // Magic (4 bytes, little-endian)
    data.push_back(magic & 0xFF);
    data.push_back((magic >> 8) & 0xFF);
    data.push_back((magic >> 16) & 0xFF);
    data.push_back((magic >> 24) & 0xFF);

    // Version (4 bytes)
    data.push_back(version & 0xFF);
    data.push_back((version >> 8) & 0xFF);
    data.push_back((version >> 16) & 0xFF);
    data.push_back((version >> 24) & 0xFF);

    // Height (4 bytes)
    uint32_t h = static_cast<uint32_t>(height);
    data.push_back(h & 0xFF);
    data.push_back((h >> 8) & 0xFF);
    data.push_back((h >> 16) & 0xFF);
    data.push_back((h >> 24) & 0xFF);

    // Block hash (32 bytes)
    data.insert(data.end(), block_hash.begin(), block_hash.end());

    // UTXO count (8 bytes)
    for (int i = 0; i < 8; i++) {
        data.push_back((utxo_count >> (i * 8)) & 0xFF);
    }

    // Total value (8 bytes)
    for (int i = 0; i < 8; i++) {
        data.push_back((total_value >> (i * 8)) & 0xFF);
    }

    return data;
}

bool SnapshotHeader::deserialize(const uint8_t* data, size_t len) {
    if (len < SIZE) return false;

    size_t pos = 0;

    // Magic
    magic = data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16) | (data[pos + 3] << 24);
    pos += 4;

    if (magic != SNAPSHOT_MAGIC) return false;

    // Version
    version = data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16) | (data[pos + 3] << 24);
    pos += 4;

    if (version > SNAPSHOT_VERSION) return false;  // Future version

    // Height
    height = static_cast<int32_t>(data[pos] | (data[pos + 1] << 8) |
                                   (data[pos + 2] << 16) | (data[pos + 3] << 24));
    pos += 4;

    // Block hash
    std::memcpy(block_hash.data(), data + pos, 32);
    pos += 32;

    // UTXO count
    utxo_count = 0;
    for (int i = 0; i < 8; i++) {
        utxo_count |= static_cast<uint64_t>(data[pos++]) << (i * 8);
    }

    // Total value
    total_value = 0;
    for (int i = 0; i < 8; i++) {
        total_value |= static_cast<uint64_t>(data[pos++]) << (i * 8);
    }

    return true;
}

// ============================================================================
// Snapshot implementation
// ============================================================================

std::vector<uint8_t> Snapshot::serializeUTXO(const Outpoint& outpoint, const UTXOEntry& entry) {
    std::vector<uint8_t> data;

    // TXID (32 bytes)
    data.insert(data.end(), outpoint.txid.begin(), outpoint.txid.end());

    // Index (4 bytes)
    data.push_back(outpoint.index & 0xFF);
    data.push_back((outpoint.index >> 8) & 0xFF);
    data.push_back((outpoint.index >> 16) & 0xFF);
    data.push_back((outpoint.index >> 24) & 0xFF);

    // Entry data
    auto entry_data = entry.serialize();
    data.insert(data.end(), entry_data.begin(), entry_data.end());

    return data;
}

size_t Snapshot::deserializeUTXO(const uint8_t* data, size_t len,
                                  Outpoint& outpoint, UTXOEntry& entry) {
    if (len < 36) return 0;  // Minimum: 32 + 4

    size_t pos = 0;

    // TXID
    std::memcpy(outpoint.txid.data(), data + pos, 32);
    pos += 32;

    // Index
    outpoint.index = data[pos] | (data[pos + 1] << 8) |
                     (data[pos + 2] << 16) | (data[pos + 3] << 24);
    pos += 4;

    // Entry (variable size)
    // Read entry size from the entry itself (value=8, height=4, coinbase=1, script_len=2)
    if (pos + 15 > len) return 0;

    // Peek at script length to know full entry size
    uint16_t script_len = data[pos + 13] | (data[pos + 14] << 8);
    size_t entry_size = 15 + script_len;

    if (pos + entry_size > len) return 0;

    if (!entry.deserialize(data + pos, entry_size)) {
        return 0;
    }

    return pos + entry_size;
}

bool Snapshot::exportToFile(
    const UTXOSet& utxo_set,
    int32_t height,
    const crypto::Hash256& block_hash,
    const std::string& file_path,
    SnapshotProgressCallback progress
) {
    LOG_INFO("Exporting UTXO snapshot to {}", file_path);

    // Create temp file
    std::string temp_path = file_path + ".tmp";
    std::ofstream file(temp_path, std::ios::binary);
    if (!file) {
        LOG_ERROR("Failed to create snapshot file: {}", temp_path);
        return false;
    }

    // Build header
    SnapshotHeader header;
    header.height = height;
    header.block_hash = block_hash;
    header.utxo_count = utxo_set.getUTXOCount();
    header.total_value = utxo_set.getTotalValue();

    // Write header
    auto header_data = header.serialize();
    file.write(reinterpret_cast<const char*>(header_data.data()), header_data.size());

    // Initialize hasher for checksum
    crypto::Keccak256 hasher;
    hasher.update(header_data.data(), header_data.size());

    // Export UTXOs
    // Note: We need to iterate through the UTXO set
    // Since UTXOSet doesn't expose iteration, we'll need to add that
    // For now, we'll use a workaround by getting all addresses and their UTXOs

    uint64_t processed = 0;
    uint64_t total = header.utxo_count;

    // Get all UTXOs via internal map access
    // This requires a friend function or adding an iterate method to UTXOSet
    // For now, we'll serialize directly from the buffer approach

    auto buffer = exportToBuffer(utxo_set, height, block_hash);
    if (buffer.empty()) {
        file.close();
        fs::remove(temp_path);
        return false;
    }

    // Write buffer (skip header, we already wrote it)
    // Actually, let's just write the entire buffer since it includes checksum
    file.close();

    // Write full buffer directly
    std::ofstream full_file(temp_path, std::ios::binary);
    if (!full_file) {
        return false;
    }
    full_file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    full_file.close();

    // Atomic rename
    try {
        fs::rename(temp_path, file_path);
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to rename snapshot file: {}", e.what());
        fs::remove(temp_path);
        return false;
    }

    LOG_INFO("Snapshot exported: {} UTXOs, {} bytes", header.utxo_count, buffer.size());
    return true;
}

bool Snapshot::importFromFile(
    UTXOSet& utxo_set,
    const std::string& file_path,
    SnapshotProgressCallback progress
) {
    LOG_INFO("Importing UTXO snapshot from {}", file_path);

    // Read file
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file) {
        LOG_ERROR("Failed to open snapshot file: {}", file_path);
        return false;
    }

    size_t file_size = file.tellg();
    file.seekg(0);

    if (file_size < SnapshotHeader::SIZE + 32) {  // Header + checksum
        LOG_ERROR("Snapshot file too small");
        return false;
    }

    // Read entire file
    std::vector<uint8_t> data(file_size);
    file.read(reinterpret_cast<char*>(data.data()), file_size);
    file.close();

    return importFromBuffer(utxo_set, data);
}

SnapshotInfo Snapshot::getInfo(const std::string& file_path) {
    SnapshotInfo info;
    info.file_path = file_path;

    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file) {
        info.error = "Failed to open file";
        return info;
    }

    info.file_size = file.tellg();
    file.seekg(0);

    if (info.file_size < SnapshotHeader::SIZE) {
        info.error = "File too small";
        return info;
    }

    // Read header
    std::vector<uint8_t> header_data(SnapshotHeader::SIZE);
    file.read(reinterpret_cast<char*>(header_data.data()), SnapshotHeader::SIZE);

    if (!info.header.deserialize(header_data.data(), header_data.size())) {
        info.error = "Invalid header";
        return info;
    }

    info.valid = true;
    return info;
}

bool Snapshot::verify(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file) return false;

    size_t file_size = file.tellg();
    file.seekg(0);

    if (file_size < SnapshotHeader::SIZE + 32) return false;

    // Read entire file
    std::vector<uint8_t> data(file_size);
    file.read(reinterpret_cast<char*>(data.data()), file_size);
    file.close();

    // Extract stored checksum (last 32 bytes)
    crypto::Hash256 stored_checksum;
    std::memcpy(stored_checksum.data(), data.data() + file_size - 32, 32);

    // Calculate checksum of data (excluding checksum itself)
    crypto::Hash256 calculated = crypto::keccak256(data.data(), file_size - 32);

    return stored_checksum == calculated;
}

std::vector<uint8_t> Snapshot::exportToBuffer(
    const UTXOSet& utxo_set,
    int32_t height,
    const crypto::Hash256& block_hash
) {
    std::vector<uint8_t> buffer;

    // Build header
    SnapshotHeader header;
    header.height = height;
    header.block_hash = block_hash;
    header.utxo_count = utxo_set.getUTXOCount();
    header.total_value = utxo_set.getTotalValue();

    // Serialize header
    auto header_data = header.serialize();
    buffer.insert(buffer.end(), header_data.begin(), header_data.end());

    // Serialize all UTXOs
    utxo_set.forEachUTXO([&buffer](const Outpoint& outpoint, const UTXOEntry& entry) {
        auto utxo_data = serializeUTXO(outpoint, entry);
        buffer.insert(buffer.end(), utxo_data.begin(), utxo_data.end());
    });

    // Calculate and append checksum
    crypto::Hash256 checksum = crypto::keccak256(buffer.data(), buffer.size());
    buffer.insert(buffer.end(), checksum.begin(), checksum.end());

    LOG_DEBUG("Snapshot buffer: {} bytes, {} UTXOs", buffer.size(), header.utxo_count);

    return buffer;
}

bool Snapshot::importFromBuffer(
    UTXOSet& utxo_set,
    const std::vector<uint8_t>& data
) {
    if (data.size() < SnapshotHeader::SIZE + 32) {
        LOG_ERROR("Snapshot buffer too small");
        return false;
    }

    // Verify checksum
    crypto::Hash256 stored_checksum;
    std::memcpy(stored_checksum.data(), data.data() + data.size() - 32, 32);

    crypto::Hash256 calculated = crypto::keccak256(data.data(), data.size() - 32);

    if (stored_checksum != calculated) {
        LOG_ERROR("Snapshot checksum mismatch");
        return false;
    }

    // Parse header
    SnapshotHeader header;
    if (!header.deserialize(data.data(), data.size())) {
        LOG_ERROR("Failed to parse snapshot header");
        return false;
    }

    LOG_INFO("Loading snapshot: height={}, utxos={}, value={}",
             header.height, header.utxo_count, header.total_value);

    // Clear existing UTXOs
    utxo_set.clear();

    // Parse and import UTXOs
    size_t pos = SnapshotHeader::SIZE;
    size_t end = data.size() - 32;  // Exclude checksum
    uint64_t loaded = 0;

    while (pos < end && loaded < header.utxo_count) {
        Outpoint outpoint;
        UTXOEntry entry;

        size_t consumed = deserializeUTXO(data.data() + pos, end - pos, outpoint, entry);
        if (consumed == 0) {
            LOG_ERROR("Failed to parse UTXO at position {}", pos);
            return false;
        }

        // Add to UTXO set
        utxo_set.importUTXO(outpoint, entry);

        pos += consumed;
        loaded++;

        // Log progress every 100k UTXOs
        if (loaded % 100000 == 0) {
            LOG_INFO("Snapshot import progress: {}/{} UTXOs", loaded, header.utxo_count);
        }
    }

    if (loaded != header.utxo_count) {
        LOG_ERROR("UTXO count mismatch: expected {}, got {}", header.utxo_count, loaded);
        return false;
    }

    // Set snapshot height for reference
    utxo_set.setSnapshotHeight(header.height);

    LOG_INFO("Snapshot imported: {} UTXOs at height {}", loaded, header.height);
    return true;
}

} // namespace chain
} // namespace ftc
