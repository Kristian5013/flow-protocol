#include "chain/transaction.h"
#include "crypto/bech32.h"
#include "util/hex.h"

#include <cstring>
#include <sstream>
#include <iomanip>

namespace ftc {
namespace chain {

// ============================================================================
// Varint
// ============================================================================

namespace varint {

std::vector<uint8_t> encode(uint64_t value) {
    std::vector<uint8_t> result;

    if (value < 0xFD) {
        result.push_back(static_cast<uint8_t>(value));
    } else if (value <= 0xFFFF) {
        result.push_back(0xFD);
        result.push_back(value & 0xFF);
        result.push_back((value >> 8) & 0xFF);
    } else if (value <= 0xFFFFFFFF) {
        result.push_back(0xFE);
        result.push_back(value & 0xFF);
        result.push_back((value >> 8) & 0xFF);
        result.push_back((value >> 16) & 0xFF);
        result.push_back((value >> 24) & 0xFF);
    } else {
        result.push_back(0xFF);
        for (int i = 0; i < 8; i++) {
            result.push_back((value >> (i * 8)) & 0xFF);
        }
    }

    return result;
}

std::optional<uint64_t> decode(const uint8_t* data, size_t len, size_t& offset) {
    if (offset >= len) return std::nullopt;

    uint8_t first = data[offset++];

    if (first < 0xFD) {
        return first;
    } else if (first == 0xFD) {
        if (offset + 2 > len) return std::nullopt;
        uint64_t value = data[offset] | (static_cast<uint64_t>(data[offset + 1]) << 8);
        offset += 2;
        return value;
    } else if (first == 0xFE) {
        if (offset + 4 > len) return std::nullopt;
        uint64_t value = data[offset] |
                        (static_cast<uint64_t>(data[offset + 1]) << 8) |
                        (static_cast<uint64_t>(data[offset + 2]) << 16) |
                        (static_cast<uint64_t>(data[offset + 3]) << 24);
        offset += 4;
        return value;
    } else {
        if (offset + 8 > len) return std::nullopt;
        uint64_t value = 0;
        for (int i = 0; i < 8; i++) {
            value |= static_cast<uint64_t>(data[offset + i]) << (i * 8);
        }
        offset += 8;
        return value;
    }
}

size_t encodedSize(uint64_t value) {
    if (value < 0xFD) return 1;
    if (value <= 0xFFFF) return 3;
    if (value <= 0xFFFFFFFF) return 5;
    return 9;
}

} // namespace varint

// ============================================================================
// OutPoint
// ============================================================================

std::string OutPoint::toString() const {
    return crypto::Keccak256::toHex(txid) + ":" + std::to_string(index);
}

// ============================================================================
// TxInput
// ============================================================================

std::vector<uint8_t> TxInput::serializeForSigning() const {
    std::vector<uint8_t> result;
    result.reserve(36 + 4);

    // Previous output hash (32 bytes)
    result.insert(result.end(), prevout.txid.begin(), prevout.txid.end());

    // Previous output index (4 bytes, little-endian)
    result.push_back(prevout.index & 0xFF);
    result.push_back((prevout.index >> 8) & 0xFF);
    result.push_back((prevout.index >> 16) & 0xFF);
    result.push_back((prevout.index >> 24) & 0xFF);

    // Sequence (4 bytes, little-endian)
    result.push_back(sequence & 0xFF);
    result.push_back((sequence >> 8) & 0xFF);
    result.push_back((sequence >> 16) & 0xFF);
    result.push_back((sequence >> 24) & 0xFF);

    return result;
}

std::vector<uint8_t> TxInput::serialize() const {
    std::vector<uint8_t> result;

    // Previous output hash (32 bytes)
    result.insert(result.end(), prevout.txid.begin(), prevout.txid.end());

    // Previous output index (4 bytes, little-endian)
    result.push_back(prevout.index & 0xFF);
    result.push_back((prevout.index >> 8) & 0xFF);
    result.push_back((prevout.index >> 16) & 0xFF);
    result.push_back((prevout.index >> 24) & 0xFF);

    // Script length + script
    auto script_len = varint::encode(script_sig.size());
    result.insert(result.end(), script_len.begin(), script_len.end());
    result.insert(result.end(), script_sig.begin(), script_sig.end());

    // Sequence (4 bytes, little-endian)
    result.push_back(sequence & 0xFF);
    result.push_back((sequence >> 8) & 0xFF);
    result.push_back((sequence >> 16) & 0xFF);
    result.push_back((sequence >> 24) & 0xFF);

    return result;
}

std::optional<TxInput> TxInput::deserialize(const uint8_t* data, size_t len, size_t& offset) {
    if (offset + 36 > len) return std::nullopt;

    TxInput input;

    // Previous output hash
    std::memcpy(input.prevout.txid.data(), data + offset, 32);
    offset += 32;

    // Previous output index
    input.prevout.index = data[offset] |
                         (static_cast<uint32_t>(data[offset + 1]) << 8) |
                         (static_cast<uint32_t>(data[offset + 2]) << 16) |
                         (static_cast<uint32_t>(data[offset + 3]) << 24);
    offset += 4;

    // Script
    auto script_len = varint::decode(data, len, offset);
    if (!script_len || offset + *script_len > len) return std::nullopt;

    input.script_sig.resize(*script_len);
    std::memcpy(input.script_sig.data(), data + offset, *script_len);
    offset += *script_len;

    // Sequence
    if (offset + 4 > len) return std::nullopt;
    input.sequence = data[offset] |
                    (static_cast<uint32_t>(data[offset + 1]) << 8) |
                    (static_cast<uint32_t>(data[offset + 2]) << 16) |
                    (static_cast<uint32_t>(data[offset + 3]) << 24);
    offset += 4;

    return input;
}

// ============================================================================
// TxOutput
// ============================================================================

std::vector<uint8_t> TxOutput::serialize() const {
    std::vector<uint8_t> result;

    // Value (8 bytes, little-endian)
    for (int i = 0; i < 8; i++) {
        result.push_back((value >> (i * 8)) & 0xFF);
    }

    // Script length + script
    auto script_len = varint::encode(script_pubkey.size());
    result.insert(result.end(), script_len.begin(), script_len.end());
    result.insert(result.end(), script_pubkey.begin(), script_pubkey.end());

    return result;
}

std::optional<TxOutput> TxOutput::deserialize(const uint8_t* data, size_t len, size_t& offset) {
    if (offset + 8 > len) return std::nullopt;

    TxOutput output;

    // Value
    output.value = 0;
    for (int i = 0; i < 8; i++) {
        output.value |= static_cast<uint64_t>(data[offset + i]) << (i * 8);
    }
    offset += 8;

    // Script
    auto script_len = varint::decode(data, len, offset);
    if (!script_len || offset + *script_len > len) return std::nullopt;

    output.script_pubkey.resize(*script_len);
    std::memcpy(output.script_pubkey.data(), data + offset, *script_len);
    offset += *script_len;

    return output;
}

std::string TxOutput::getAddress() const {
    // P2WPKH: OP_0 <20-byte-hash>
    if (script_pubkey.size() == 22 &&
        script_pubkey[0] == 0x00 && script_pubkey[1] == 0x14) {
        return crypto::bech32::addressFromPubKeyHash(script_pubkey.data() + 2);
    }

    // P2PKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    auto pubkey_hash = script::extractP2PKH(script_pubkey);
    if (pubkey_hash) {
        return crypto::bech32::addressFromPubKeyHash(pubkey_hash->data());
    }

    return "";
}

// ============================================================================
// Transaction
// ============================================================================

crypto::Hash256 Transaction::getTxId() const {
    if (cached_txid_) {
        return *cached_txid_;
    }

    auto data = serialize();
    auto hash = crypto::Keccak256::hash(data);
    cached_txid_ = hash;
    return hash;
}

crypto::Hash256 Transaction::getSignatureHash(size_t input_index,
                                              const std::vector<uint8_t>& prev_script_pubkey,
                                              uint32_t hash_type) const {
    // Create a copy for signing
    std::vector<uint8_t> data;

    // Version
    data.push_back(version & 0xFF);
    data.push_back((version >> 8) & 0xFF);
    data.push_back((version >> 16) & 0xFF);
    data.push_back((version >> 24) & 0xFF);

    // Input count
    auto in_count = varint::encode(inputs.size());
    data.insert(data.end(), in_count.begin(), in_count.end());

    // Inputs
    for (size_t i = 0; i < inputs.size(); i++) {
        const auto& input = inputs[i];

        // Previous output
        data.insert(data.end(), input.prevout.txid.begin(), input.prevout.txid.end());
        data.push_back(input.prevout.index & 0xFF);
        data.push_back((input.prevout.index >> 8) & 0xFF);
        data.push_back((input.prevout.index >> 16) & 0xFF);
        data.push_back((input.prevout.index >> 24) & 0xFF);

        // Script: empty for non-signing inputs, prev_script_pubkey for signing input
        if (i == input_index) {
            auto script_len = varint::encode(prev_script_pubkey.size());
            data.insert(data.end(), script_len.begin(), script_len.end());
            data.insert(data.end(), prev_script_pubkey.begin(), prev_script_pubkey.end());
        } else {
            data.push_back(0);  // Empty script
        }

        // Sequence
        data.push_back(input.sequence & 0xFF);
        data.push_back((input.sequence >> 8) & 0xFF);
        data.push_back((input.sequence >> 16) & 0xFF);
        data.push_back((input.sequence >> 24) & 0xFF);
    }

    // Output count
    auto out_count = varint::encode(outputs.size());
    data.insert(data.end(), out_count.begin(), out_count.end());

    // Outputs
    for (const auto& output : outputs) {
        auto out_data = output.serialize();
        data.insert(data.end(), out_data.begin(), out_data.end());
    }

    // Locktime
    data.push_back(locktime & 0xFF);
    data.push_back((locktime >> 8) & 0xFF);
    data.push_back((locktime >> 16) & 0xFF);
    data.push_back((locktime >> 24) & 0xFF);

    // Hash type
    data.push_back(hash_type & 0xFF);
    data.push_back((hash_type >> 8) & 0xFF);
    data.push_back((hash_type >> 16) & 0xFF);
    data.push_back((hash_type >> 24) & 0xFF);

    // Double hash
    return crypto::Keccak256::doubleHash(data.data(), data.size());
}

std::vector<uint8_t> Transaction::serialize() const {
    std::vector<uint8_t> data;

    // Version
    data.push_back(version & 0xFF);
    data.push_back((version >> 8) & 0xFF);
    data.push_back((version >> 16) & 0xFF);
    data.push_back((version >> 24) & 0xFF);

    // Input count
    auto in_count = varint::encode(inputs.size());
    data.insert(data.end(), in_count.begin(), in_count.end());

    // Inputs
    for (const auto& input : inputs) {
        auto in_data = input.serialize();
        data.insert(data.end(), in_data.begin(), in_data.end());
    }

    // Output count
    auto out_count = varint::encode(outputs.size());
    data.insert(data.end(), out_count.begin(), out_count.end());

    // Outputs
    for (const auto& output : outputs) {
        auto out_data = output.serialize();
        data.insert(data.end(), out_data.begin(), out_data.end());
    }

    // Locktime
    data.push_back(locktime & 0xFF);
    data.push_back((locktime >> 8) & 0xFF);
    data.push_back((locktime >> 16) & 0xFF);
    data.push_back((locktime >> 24) & 0xFF);

    return data;
}

std::optional<Transaction> Transaction::deserialize(const uint8_t* data, size_t len) {
    size_t offset = 0;

    if (len < 10) return std::nullopt;

    Transaction tx;

    // Version
    tx.version = data[offset] |
                (static_cast<uint32_t>(data[offset + 1]) << 8) |
                (static_cast<uint32_t>(data[offset + 2]) << 16) |
                (static_cast<uint32_t>(data[offset + 3]) << 24);
    offset += 4;

    // Input count
    auto in_count = varint::decode(data, len, offset);
    if (!in_count) return std::nullopt;

    // Inputs
    for (uint64_t i = 0; i < *in_count; i++) {
        auto input = TxInput::deserialize(data, len, offset);
        if (!input) return std::nullopt;
        tx.inputs.push_back(*input);
    }

    // Output count
    auto out_count = varint::decode(data, len, offset);
    if (!out_count) return std::nullopt;

    // Outputs
    for (uint64_t i = 0; i < *out_count; i++) {
        auto output = TxOutput::deserialize(data, len, offset);
        if (!output) return std::nullopt;
        tx.outputs.push_back(*output);
    }

    // Locktime
    if (offset + 4 > len) return std::nullopt;
    tx.locktime = data[offset] |
                 (static_cast<uint32_t>(data[offset + 1]) << 8) |
                 (static_cast<uint32_t>(data[offset + 2]) << 16) |
                 (static_cast<uint32_t>(data[offset + 3]) << 24);

    return tx;
}

std::optional<Transaction> Transaction::deserialize(const std::vector<uint8_t>& data) {
    return deserialize(data.data(), data.size());
}

bool Transaction::isCoinbase() const {
    if (inputs.size() != 1) return false;
    return inputs[0].prevout.isNull();
}

bool Transaction::isValid() const {
    // Must have inputs and outputs
    if (inputs.empty() || outputs.empty()) return false;

    // Size limit
    if (getSize() > MAX_TX_SIZE) return false;

    // No duplicate inputs
    for (size_t i = 0; i < inputs.size(); i++) {
        for (size_t j = i + 1; j < inputs.size(); j++) {
            if (inputs[i].prevout == inputs[j].prevout) return false;
        }
    }

    // Outputs must have valid values
    uint64_t total = 0;
    for (const auto& output : outputs) {
        if (output.value > 21000000ULL * COIN) return false;  // Max supply
        total += output.value;
        if (total > 21000000ULL * COIN) return false;
    }

    return true;
}

uint64_t Transaction::getTotalOutputValue() const {
    uint64_t total = 0;
    for (const auto& output : outputs) {
        total += output.value;
    }
    return total;
}

size_t Transaction::getSize() const {
    return serialize().size();
}

std::string Transaction::toString() const {
    std::ostringstream oss;
    oss << "Transaction " << crypto::Keccak256::toHex(getTxId()) << "\n";
    oss << "  Version: " << version << "\n";
    oss << "  Inputs: " << inputs.size() << "\n";
    for (size_t i = 0; i < inputs.size(); i++) {
        oss << "    [" << i << "] " << inputs[i].prevout.toString() << "\n";
    }
    oss << "  Outputs: " << outputs.size() << "\n";
    for (size_t i = 0; i < outputs.size(); i++) {
        oss << "    [" << i << "] " << (outputs[i].value / COIN) << "."
            << std::setfill('0') << std::setw(8) << (outputs[i].value % COIN) << " FTC\n";
    }
    oss << "  Locktime: " << locktime << "\n";
    return oss.str();
}

// ============================================================================
// Script helpers
// ============================================================================

namespace script {

std::vector<uint8_t> createP2PKH(const uint8_t* pubkey_hash20) {
    std::vector<uint8_t> script;
    script.push_back(OP_DUP);
    script.push_back(OP_HASH160);
    script.push_back(20);  // Push 20 bytes
    script.insert(script.end(), pubkey_hash20, pubkey_hash20 + 20);
    script.push_back(OP_EQUALVERIFY);
    script.push_back(OP_CHECKSIG);
    return script;
}

std::vector<uint8_t> createP2PKHFromAddress(const std::string& address) {
    // Use the correct crypto::bech32 implementation
    // The previous implementation had a bug: it removed the version byte
    // BEFORE bit conversion, which changes the bit alignment and produces
    // a wrong pubkey hash.

    // Check for ftc1/tftc1 prefix
    if (address.size() < 4) return {};
    std::string prefix = address.substr(0, 4);
    for (auto& c : prefix) c = std::tolower(c);

    if (prefix != "ftc1" && prefix != "tftc") {
        // Check for 5-char tftc1
        if (address.size() >= 5) {
            prefix = address.substr(0, 5);
            for (auto& c : prefix) c = std::tolower(c);
            if (prefix != "tftc1") return {};
        } else {
            return {};
        }
    }

    // Use the canonical bech32 implementation
    auto hash_opt = crypto::bech32::pubKeyHashFromAddress(address);
    if (!hash_opt || hash_opt->size() != 20) {
        return {};
    }

    // Build P2WPKH script: OP_0 <20 bytes>
    std::vector<uint8_t> script;
    script.push_back(OP_0);      // Witness version 0
    script.push_back(20);        // Push 20 bytes
    script.insert(script.end(), hash_opt->begin(), hash_opt->end());

    return script;
}

std::optional<std::array<uint8_t, 20>> extractP2PKH(const std::vector<uint8_t>& script) {
    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if (script.size() != 25) return std::nullopt;
    if (script[0] != OP_DUP) return std::nullopt;
    if (script[1] != OP_HASH160) return std::nullopt;
    if (script[2] != 20) return std::nullopt;
    if (script[23] != OP_EQUALVERIFY) return std::nullopt;
    if (script[24] != OP_CHECKSIG) return std::nullopt;

    std::array<uint8_t, 20> hash;
    std::memcpy(hash.data(), script.data() + 3, 20);
    return hash;
}

std::vector<uint8_t> createSigScript(const crypto::Signature& sig,
                                     const crypto::PublicKey& pubkey) {
    std::vector<uint8_t> script;

    // Signature (DER encoded + hash type)
    auto der_sig = crypto::Secp256k1::instance().signatureToDER(sig);
    der_sig.push_back(0x01);  // SIGHASH_ALL

    script.push_back(static_cast<uint8_t>(der_sig.size()));
    script.insert(script.end(), der_sig.begin(), der_sig.end());

    // Public key (compressed)
    script.push_back(static_cast<uint8_t>(pubkey.size()));
    script.insert(script.end(), pubkey.begin(), pubkey.end());

    return script;
}

bool isP2PKH(const std::vector<uint8_t>& script) {
    return extractP2PKH(script).has_value();
}

} // namespace script

} // namespace chain
} // namespace ftc
