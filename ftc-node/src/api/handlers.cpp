#include "api/handlers.h"
#include "crypto/keccak256.h"
#include "crypto/bech32.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cctype>

namespace ftc {
namespace api {

// Helper function for Hash256 to hex conversion
static std::string hashToHex(const crypto::Hash256& hash) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (const auto& byte : hash) {
        result += hex_chars[(byte >> 4) & 0x0F];
        result += hex_chars[byte & 0x0F];
    }
    return result;
}

//-----------------------------------------------------------------------------
// Hex encoding/decoding
//-----------------------------------------------------------------------------

std::string toHex(const std::vector<uint8_t>& data) {
    return toHex(data.data(), data.size());
}

std::string toHex(const uint8_t* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);

    for (size_t i = 0; i < len; ++i) {
        result += hex_chars[(data[i] >> 4) & 0x0F];
        result += hex_chars[data[i] & 0x0F];
    }

    return result;
}

std::vector<uint8_t> fromHex(const std::string& hex) {
    std::vector<uint8_t> result;

    // Remove optional 0x prefix
    size_t start = 0;
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        start = 2;
    }

    if ((hex.size() - start) % 2 != 0) {
        return result;  // Invalid length
    }

    result.reserve((hex.size() - start) / 2);

    for (size_t i = start; i < hex.size(); i += 2) {
        int hi = -1, lo = -1;

        char c = hex[i];
        if (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;

        c = hex[i + 1];
        if (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;

        if (hi < 0 || lo < 0) {
            result.clear();
            return result;  // Invalid character
        }

        result.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }

    return result;
}

bool isValidHex(const std::string& hex) {
    size_t start = 0;
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        start = 2;
    }

    if ((hex.size() - start) % 2 != 0) {
        return false;
    }

    for (size_t i = start; i < hex.size(); ++i) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }

    return true;
}

//-----------------------------------------------------------------------------
// Bech32 implementation
//-----------------------------------------------------------------------------

namespace bech32 {

uint32_t polymod(const std::vector<uint8_t>& values) {
    uint32_t chk = 1;
    const uint32_t generator[] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

    for (uint8_t v : values) {
        uint8_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (int i = 0; i < 5; ++i) {
            if ((top >> i) & 1) {
                chk ^= generator[i];
            }
        }
    }

    return chk;
}

std::vector<uint8_t> hrpExpand(const std::string& hrp) {
    std::vector<uint8_t> ret;
    ret.reserve(hrp.size() * 2 + 1);

    for (char c : hrp) {
        ret.push_back(static_cast<uint8_t>(c >> 5));
    }
    ret.push_back(0);
    for (char c : hrp) {
        ret.push_back(static_cast<uint8_t>(c & 0x1f));
    }

    return ret;
}

bool verifyChecksum(const std::string& hrp, const std::vector<uint8_t>& values) {
    auto expanded = hrpExpand(hrp);
    expanded.insert(expanded.end(), values.begin(), values.end());
    return polymod(expanded) == 1;
}

std::vector<uint8_t> createChecksum(const std::string& hrp, const std::vector<uint8_t>& values) {
    auto expanded = hrpExpand(hrp);
    expanded.insert(expanded.end(), values.begin(), values.end());
    expanded.insert(expanded.end(), 6, 0);

    uint32_t mod = polymod(expanded) ^ 1;
    std::vector<uint8_t> ret(6);
    for (int i = 0; i < 6; ++i) {
        ret[i] = (mod >> (5 * (5 - i))) & 0x1f;
    }

    return ret;
}

std::string encode(const std::string& hrp, const std::vector<uint8_t>& values) {
    auto checksum = createChecksum(hrp, values);

    std::string ret = hrp + '1';
    ret.reserve(hrp.size() + 1 + values.size() + 6);

    for (uint8_t v : values) {
        ret += BECH32_CHARSET[v];
    }
    for (uint8_t v : checksum) {
        ret += BECH32_CHARSET[v];
    }

    return ret;
}

std::pair<std::string, std::vector<uint8_t>> decode(const std::string& str) {
    // Find separator
    size_t pos = str.rfind('1');
    if (pos == std::string::npos || pos == 0 || pos + 7 > str.size()) {
        return {"", {}};
    }

    // Extract HRP
    std::string hrp = str.substr(0, pos);
    for (char& c : hrp) {
        if (c >= 'A' && c <= 'Z') {
            c = c - 'A' + 'a';  // Lowercase
        }
    }

    // Decode data part
    std::vector<uint8_t> values;
    values.reserve(str.size() - pos - 1);

    for (size_t i = pos + 1; i < str.size(); ++i) {
        char c = str[i];
        if (c >= 'A' && c <= 'Z') {
            c = c - 'A' + 'a';
        }

        const char* found = std::find(BECH32_CHARSET, BECH32_CHARSET + 32, c);
        if (found == BECH32_CHARSET + 32) {
            return {"", {}};  // Invalid character
        }
        values.push_back(static_cast<uint8_t>(found - BECH32_CHARSET));
    }

    // Verify checksum
    if (!verifyChecksum(hrp, values)) {
        return {"", {}};
    }

    // Remove checksum from values
    values.resize(values.size() - 6);

    return {hrp, values};
}

std::vector<uint8_t> convertBits(const std::vector<uint8_t>& data,
                                  int from_bits, int to_bits, bool pad) {
    std::vector<uint8_t> ret;
    uint32_t acc = 0;
    int bits = 0;
    uint32_t max_v = (1 << to_bits) - 1;

    for (uint8_t value : data) {
        if ((value >> from_bits) != 0) {
            return {};  // Invalid value
        }
        acc = (acc << from_bits) | value;
        bits += from_bits;
        while (bits >= to_bits) {
            bits -= to_bits;
            ret.push_back((acc >> bits) & max_v);
        }
    }

    if (pad) {
        if (bits > 0) {
            ret.push_back((acc << (to_bits - bits)) & max_v);
        }
    } else if (bits >= from_bits || ((acc << (to_bits - bits)) & max_v) != 0) {
        return {};  // Invalid padding
    }

    return ret;
}

} // namespace bech32

//-----------------------------------------------------------------------------
// Address encoding/decoding
//-----------------------------------------------------------------------------

std::string encodeAddress(const std::vector<uint8_t>& script_pubkey) {
    // P2WPKH: OP_0 <20-byte-hash>
    if (script_pubkey.size() == 22 &&
        script_pubkey[0] == 0x00 && script_pubkey[1] == 0x14) {
        std::vector<uint8_t> hash(script_pubkey.begin() + 2, script_pubkey.end());
        auto values = bech32::convertBits(hash, 8, 5, true);
        values.insert(values.begin(), 0);  // Witness version 0
        return bech32::encode("ftc", values);
    }

    // P2WSH: OP_0 <32-byte-hash>
    if (script_pubkey.size() == 34 &&
        script_pubkey[0] == 0x00 && script_pubkey[1] == 0x20) {
        std::vector<uint8_t> hash(script_pubkey.begin() + 2, script_pubkey.end());
        auto values = bech32::convertBits(hash, 8, 5, true);
        values.insert(values.begin(), 0);  // Witness version 0
        return bech32::encode("ftc", values);
    }

    // P2PKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    if (script_pubkey.size() == 25 &&
        script_pubkey[0] == 0x76 && script_pubkey[1] == 0xa9 &&
        script_pubkey[2] == 0x14 && script_pubkey[23] == 0x88 &&
        script_pubkey[24] == 0xac) {
        // Legacy P2PKH - not using bech32
        // For now, return hex-encoded script
        return "legacy:" + toHex(script_pubkey);
    }

    // Unknown script type
    return "";
}

std::vector<uint8_t> decodeAddress(const std::string& address) {
    // Check for ftc1 prefix (bech32)
    if (address.size() >= 4 &&
        (address.substr(0, 4) == "ftc1" || address.substr(0, 4) == "FTC1")) {

        // Use crypto::bech32 implementation which is known to work
        auto hash_opt = crypto::bech32::pubKeyHashFromAddress(address);
        if (!hash_opt || hash_opt->size() != 20) {
            return {};
        }

        // Build P2WPKH script: OP_0 <20-byte-hash>
        std::vector<uint8_t> script;
        script.push_back(0x00);  // OP_0 (witness version 0)
        script.push_back(0x14);  // Push 20 bytes
        script.insert(script.end(), hash_opt->begin(), hash_opt->end());

        return script;
    }

    // Legacy address handling would go here
    // For now, try to decode as hex
    return fromHex(address);
}

bool isValidAddress(const std::string& address) {
    if (address.empty()) {
        return false;
    }

    // Check bech32 format using crypto::bech32
    if (address.size() >= 4 &&
        (address.substr(0, 4) == "ftc1" || address.substr(0, 4) == "FTC1")) {
        auto hash_opt = crypto::bech32::pubKeyHashFromAddress(address);
        return hash_opt.has_value() && hash_opt->size() == 20;
    }

    return false;
}

AddressType getAddressType(const std::vector<uint8_t>& script_pubkey) {
    // P2WPKH: OP_0 <20-byte-hash>
    if (script_pubkey.size() == 22 &&
        script_pubkey[0] == 0x00 && script_pubkey[1] == 0x14) {
        return AddressType::P2WPKH;
    }

    // P2WSH: OP_0 <32-byte-hash>
    if (script_pubkey.size() == 34 &&
        script_pubkey[0] == 0x00 && script_pubkey[1] == 0x20) {
        return AddressType::P2WSH;
    }

    // P2PKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    if (script_pubkey.size() == 25 &&
        script_pubkey[0] == 0x76 && script_pubkey[1] == 0xa9 &&
        script_pubkey[2] == 0x14 && script_pubkey[23] == 0x88 &&
        script_pubkey[24] == 0xac) {
        return AddressType::P2PKH;
    }

    // P2SH: OP_HASH160 <20-byte-hash> OP_EQUAL
    if (script_pubkey.size() == 23 &&
        script_pubkey[0] == 0xa9 && script_pubkey[1] == 0x14 &&
        script_pubkey[22] == 0x87) {
        return AddressType::P2SH;
    }

    // P2TR: OP_1 <32-byte-key>
    if (script_pubkey.size() == 34 &&
        script_pubkey[0] == 0x51 && script_pubkey[1] == 0x20) {
        return AddressType::P2TR;
    }

    return AddressType::UNKNOWN;
}

AddressType getAddressType(const std::string& address) {
    auto script = decodeAddress(address);
    if (script.empty()) {
        return AddressType::UNKNOWN;
    }
    return getAddressType(script);
}

//-----------------------------------------------------------------------------
// Transaction building helpers
//-----------------------------------------------------------------------------

std::vector<uint8_t> buildTransaction(
    const std::vector<chain::Outpoint>& inputs,
    const std::vector<std::pair<std::string, uint64_t>>& outputs,
    uint32_t locktime) {

    chain::Transaction tx;
    tx.version = 2;
    tx.locktime = locktime;

    // Add inputs
    for (const auto& input : inputs) {
        chain::TxInput in;
        in.prevout.txid = input.txid;
        in.prevout.index = input.index;
        in.sequence = 0xFFFFFFFE;  // Enable RBF
        tx.inputs.push_back(in);
    }

    // Add outputs
    for (const auto& [address, amount] : outputs) {
        chain::TxOutput out;
        out.value = amount;
        out.script_pubkey = decodeAddress(address);
        if (out.script_pubkey.empty()) {
            return {};  // Invalid address
        }
        tx.outputs.push_back(out);
    }

    // Serialize (unsigned)
    return tx.serialize();
}

size_t estimateTxSize(size_t num_inputs, size_t num_outputs) {
    // Non-segwit estimate:
    // 4 (version) + 1 (input count) + num_inputs * 148 + 1 (output count) +
    // num_outputs * 34 + 4 (locktime)
    return 4 + 1 + num_inputs * 148 + 1 + num_outputs * 34 + 4;
}

size_t estimateTxVSize(size_t num_inputs, size_t num_outputs, bool segwit) {
    if (!segwit) {
        return estimateTxSize(num_inputs, num_outputs);
    }

    // Segwit P2WPKH estimate:
    // Base size: 4 + 1 + num_inputs * 41 + 1 + num_outputs * 31 + 4
    // Witness: 2 + num_inputs * 107
    // vsize = (base * 3 + total) / 4

    size_t base_size = 4 + 1 + num_inputs * 41 + 1 + num_outputs * 31 + 4;
    size_t witness_size = 2 + num_inputs * 107;
    size_t total_size = base_size + witness_size;

    // Virtual size with witness discount
    return (base_size * 3 + total_size + 3) / 4;
}

uint64_t calculateFee(size_t vsize, uint64_t fee_rate_per_vbyte) {
    return vsize * fee_rate_per_vbyte;
}

//-----------------------------------------------------------------------------
// Script helpers
//-----------------------------------------------------------------------------

std::vector<uint8_t> createP2WPKHScript(const std::vector<uint8_t>& pubkey_hash) {
    if (pubkey_hash.size() != 20) {
        return {};
    }

    std::vector<uint8_t> script;
    script.push_back(0x00);  // OP_0
    script.push_back(0x14);  // Push 20 bytes
    script.insert(script.end(), pubkey_hash.begin(), pubkey_hash.end());
    return script;
}

std::vector<uint8_t> createP2WSHScript(const std::vector<uint8_t>& script_hash) {
    if (script_hash.size() != 32) {
        return {};
    }

    std::vector<uint8_t> script;
    script.push_back(0x00);  // OP_0
    script.push_back(0x20);  // Push 32 bytes
    script.insert(script.end(), script_hash.begin(), script_hash.end());
    return script;
}

std::vector<uint8_t> createP2PKHScript(const std::vector<uint8_t>& pubkey_hash) {
    if (pubkey_hash.size() != 20) {
        return {};
    }

    std::vector<uint8_t> script;
    script.push_back(0x76);  // OP_DUP
    script.push_back(0xa9);  // OP_HASH160
    script.push_back(0x14);  // Push 20 bytes
    script.insert(script.end(), pubkey_hash.begin(), pubkey_hash.end());
    script.push_back(0x88);  // OP_EQUALVERIFY
    script.push_back(0xac);  // OP_CHECKSIG
    return script;
}

std::vector<uint8_t> createP2SHScript(const std::vector<uint8_t>& script_hash) {
    if (script_hash.size() != 20) {
        return {};
    }

    std::vector<uint8_t> script;
    script.push_back(0xa9);  // OP_HASH160
    script.push_back(0x14);  // Push 20 bytes
    script.insert(script.end(), script_hash.begin(), script_hash.end());
    script.push_back(0x87);  // OP_EQUAL
    return script;
}

std::vector<uint8_t> extractHashFromScript(const std::vector<uint8_t>& script) {
    auto type = getAddressType(script);

    switch (type) {
        case AddressType::P2WPKH:
            return std::vector<uint8_t>(script.begin() + 2, script.end());
        case AddressType::P2WSH:
            return std::vector<uint8_t>(script.begin() + 2, script.end());
        case AddressType::P2PKH:
            return std::vector<uint8_t>(script.begin() + 3, script.begin() + 23);
        case AddressType::P2SH:
            return std::vector<uint8_t>(script.begin() + 2, script.begin() + 22);
        case AddressType::P2TR:
            return std::vector<uint8_t>(script.begin() + 2, script.end());
        default:
            return {};
    }
}

bool isStandardScript(const std::vector<uint8_t>& script) {
    return getAddressType(script) != AddressType::UNKNOWN;
}

//-----------------------------------------------------------------------------
// Block/Transaction serialization to JSON
//-----------------------------------------------------------------------------

std::string blockToJson(const chain::Block& block, bool include_txs) {
    JsonBuilder json;
    json.beginObject()
        .key("hash").value(hashToHex(block.getHash()))
        .key("version").value(static_cast<int64_t>(block.header.version))
        .key("prev_block").value(hashToHex(block.header.prev_hash))
        .key("merkle_root").value(hashToHex(block.header.merkle_root))
        .key("timestamp").value(static_cast<uint64_t>(block.header.timestamp))
        .key("bits").value(static_cast<uint64_t>(block.header.bits))
        .key("nonce").value(static_cast<uint64_t>(block.header.nonce))
        .key("tx_count").value(static_cast<uint64_t>(block.transactions.size()));

    if (include_txs) {
        json.key("tx").beginArray();
        for (const auto& tx : block.transactions) {
            json.value(hashToHex(tx.getTxId()));
        }
        json.endArray();
    }

    json.endObject();
    return json.build();
}

std::string transactionToJson(const chain::Transaction& tx, bool include_hex) {
    JsonBuilder json;
    json.beginObject()
        .key("txid").value(hashToHex(tx.getTxId()))
        .key("version").value(static_cast<int64_t>(tx.version))
        .key("locktime").value(static_cast<uint64_t>(tx.locktime))
        .key("size").value(static_cast<uint64_t>(tx.serialize().size()));

    // Inputs
    json.key("vin").beginArray();
    for (const auto& input : tx.inputs) {
        json.beginObject()
            .key("txid").value(hashToHex(input.prevout.txid))
            .key("vout").value(static_cast<uint64_t>(input.prevout.index))
            .key("script_sig").value(toHex(input.script_sig))
            .key("sequence").value(static_cast<uint64_t>(input.sequence))
            .endObject();
    }
    json.endArray();

    // Outputs
    json.key("vout").beginArray();
    uint32_t n = 0;
    for (const auto& output : tx.outputs) {
        json.beginObject()
            .key("value").value(output.value)
            .key("n").value(static_cast<uint64_t>(n++))
            .key("script_pubkey").beginObject()
                .key("hex").value(toHex(output.script_pubkey))
                .key("address").value(encodeAddress(output.script_pubkey))
            .endObject()
            .endObject();
    }
    json.endArray();

    if (include_hex) {
        json.key("hex").value(toHex(tx.serialize()));
    }

    json.endObject();
    return json.build();
}

std::string headerToJson(const chain::BlockHeader& header) {
    JsonBuilder json;
    json.beginObject()
        .key("hash").value(hashToHex(header.getHash()))
        .key("version").value(static_cast<int64_t>(header.version))
        .key("prev_block").value(hashToHex(header.prev_hash))
        .key("merkle_root").value(hashToHex(header.merkle_root))
        .key("timestamp").value(static_cast<uint64_t>(header.timestamp))
        .key("bits").value(static_cast<uint64_t>(header.bits))
        .key("nonce").value(static_cast<uint64_t>(header.nonce))
        .endObject();
    return json.build();
}

std::string utxoToJson(const chain::UTXOEntry& utxo, const chain::Outpoint& outpoint) {
    JsonBuilder json;
    json.beginObject()
        .key("txid").value(hashToHex(outpoint.txid))
        .key("vout").value(static_cast<uint64_t>(outpoint.index))
        .key("amount").value(utxo.value)
        .key("script_pubkey").value(toHex(utxo.script_pubkey))
        .key("address").value(encodeAddress(utxo.script_pubkey))
        .key("height").value(static_cast<int64_t>(utxo.height))
        .key("coinbase").value(utxo.coinbase)
        .endObject();
    return json.build();
}

//-----------------------------------------------------------------------------
// Validation helpers
//-----------------------------------------------------------------------------

bool validateTransactionFormat(const chain::Transaction& tx, std::string& error) {
    // Check version
    if (tx.version < 1 || tx.version > 2) {
        error = "Invalid transaction version";
        return false;
    }

    // Check inputs
    if (tx.inputs.empty()) {
        error = "Transaction has no inputs";
        return false;
    }

    for (const auto& input : tx.inputs) {
        if (input.script_sig.size() > 10000) {
            error = "Script sig too large";
            return false;
        }
    }

    // Check outputs
    if (tx.outputs.empty()) {
        error = "Transaction has no outputs";
        return false;
    }

    uint64_t total_output = 0;
    for (const auto& output : tx.outputs) {
        if (output.value > 21000000ULL * 100000000ULL) {
            error = "Output value too large";
            return false;
        }
        total_output += output.value;
        if (total_output > 21000000ULL * 100000000ULL) {
            error = "Total output value too large";
            return false;
        }
        if (output.script_pubkey.size() > 10000) {
            error = "Script pubkey too large";
            return false;
        }
    }

    // Check size
    auto serialized = tx.serialize();
    if (serialized.size() > 1000000) {
        error = "Transaction too large";
        return false;
    }

    return true;
}

bool validateBlockFormat(const chain::Block& block, std::string& error) {
    // Check header
    if (block.header.version < 1) {
        error = "Invalid block version";
        return false;
    }

    // Check transactions
    if (block.transactions.empty()) {
        error = "Block has no transactions";
        return false;
    }

    // First transaction must be coinbase
    if (!block.transactions[0].inputs.empty()) {
        const auto& first_input = block.transactions[0].inputs[0];
        // Coinbase has null prevout (all zeros txid, index 0xFFFFFFFF)
        bool is_zero_txid = std::all_of(first_input.prevout.txid.begin(),
                                        first_input.prevout.txid.end(),
                                        [](uint8_t b) { return b == 0; });
        bool is_coinbase = is_zero_txid && first_input.prevout.index == 0xFFFFFFFF;
        if (!is_coinbase) {
            error = "First transaction is not coinbase";
            return false;
        }
    }

    // Check each transaction
    for (size_t i = 1; i < block.transactions.size(); ++i) {
        std::string tx_error;
        if (!validateTransactionFormat(block.transactions[i], tx_error)) {
            error = "Invalid transaction " + std::to_string(i) + ": " + tx_error;
            return false;
        }
    }

    return true;
}

bool validateAddressChecksum(const std::string& address) {
    if (address.size() >= 4 &&
        (address.substr(0, 4) == "ftc1" || address.substr(0, 4) == "FTC1")) {
        auto hash_opt = crypto::bech32::pubKeyHashFromAddress(address);
        return hash_opt.has_value();
    }
    return false;
}

//-----------------------------------------------------------------------------
// Rate limiting
//-----------------------------------------------------------------------------

RateLimiter::RateLimiter(size_t max_requests, std::chrono::seconds window)
    : max_tokens_(max_requests), refill_window_(window) {}

bool RateLimiter::allowRequest(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::steady_clock::now();

    auto it = buckets_.find(client_id);
    if (it == buckets_.end()) {
        // New client
        buckets_[client_id] = Bucket{max_tokens_ - 1, now};
        return true;
    }

    Bucket& bucket = it->second;

    // Refill tokens based on elapsed time
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - bucket.last_refill);
    if (elapsed >= refill_window_) {
        bucket.tokens = max_tokens_;
        bucket.last_refill = now;
    }

    if (bucket.tokens > 0) {
        bucket.tokens--;
        return true;
    }

    return false;  // Rate limited
}

size_t RateLimiter::getRemainingRequests(const std::string& client_id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = buckets_.find(client_id);
    if (it == buckets_.end()) {
        return max_tokens_;
    }

    return it->second.tokens;
}

void RateLimiter::reset(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    buckets_.erase(client_id);
}

void RateLimiter::cleanup() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::steady_clock::now();

    for (auto it = buckets_.begin(); it != buckets_.end();) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.last_refill);

        // Remove buckets that haven't been used for a while
        if (elapsed > refill_window_ * 10) {
            it = buckets_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace api
} // namespace ftc
