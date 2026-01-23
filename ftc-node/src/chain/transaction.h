#ifndef FTC_CHAIN_TRANSACTION_H
#define FTC_CHAIN_TRANSACTION_H

#include "crypto/keccak256.h"
#include "crypto/secp256k1.h"

#include <cstdint>
#include <vector>
#include <string>
#include <optional>

namespace ftc {
namespace chain {

// ============================================================================
// Constants
// ============================================================================

// 1 FTC = 100,000,000 satoshis (like Bitcoin)
constexpr uint64_t COIN = 100000000ULL;

// Maximum transaction size
constexpr size_t MAX_TX_SIZE = 100000;  // 100 KB

// ============================================================================
// OutPoint - Reference to a previous output
// ============================================================================

struct OutPoint {
    crypto::Hash256 txid;     // Transaction ID
    uint32_t index;           // Output index

    OutPoint() : index(0) {}
    OutPoint(const crypto::Hash256& txid_, uint32_t idx) : txid(txid_), index(idx) {}

    bool operator==(const OutPoint& other) const {
        return txid == other.txid && index == other.index;
    }

    bool operator<(const OutPoint& other) const {
        if (txid != other.txid) return txid < other.txid;
        return index < other.index;
    }

    bool isNull() const {
        return crypto::Keccak256::isZero(txid) && index == 0xFFFFFFFF;
    }

    std::string toString() const;
};

// ============================================================================
// TxInput - Transaction input
// ============================================================================

struct TxInput {
    OutPoint prevout;                    // Previous output being spent
    std::vector<uint8_t> script_sig;     // Unlocking script (signature)
    uint32_t sequence;                   // Sequence number (for replace-by-fee)

    TxInput() : sequence(0xFFFFFFFF) {}

    // Serialize for signing (without script_sig)
    std::vector<uint8_t> serializeForSigning() const;

    // Full serialization
    std::vector<uint8_t> serialize() const;

    // Deserialization
    static std::optional<TxInput> deserialize(const uint8_t* data, size_t len, size_t& offset);
};

// ============================================================================
// TxOutput - Transaction output
// ============================================================================

struct TxOutput {
    uint64_t value;                      // Amount in satoshis
    std::vector<uint8_t> script_pubkey;  // Locking script (address)

    TxOutput() : value(0) {}
    TxOutput(uint64_t val, const std::vector<uint8_t>& script)
        : value(val), script_pubkey(script) {}

    // Serialize
    std::vector<uint8_t> serialize() const;

    // Deserialization
    static std::optional<TxOutput> deserialize(const uint8_t* data, size_t len, size_t& offset);

    // Extract address from script
    std::string getAddress() const;
};

// ============================================================================
// Transaction
// ============================================================================

class Transaction {
public:
    uint32_t version;
    std::vector<TxInput> inputs;
    std::vector<TxOutput> outputs;
    std::vector<std::vector<std::vector<uint8_t>>> witness;  // SegWit witness data per input
    uint32_t locktime;

    Transaction() : version(1), locktime(0) {}

    // Get transaction ID (hash of serialized tx)
    crypto::Hash256 getTxId() const;

    // Get hash for signing a specific input
    crypto::Hash256 getSignatureHash(size_t input_index,
                                     const std::vector<uint8_t>& prev_script_pubkey,
                                     uint32_t hash_type = 1) const;

    // Serialize
    std::vector<uint8_t> serialize() const;

    // Deserialize
    static std::optional<Transaction> deserialize(const uint8_t* data, size_t len);
    static std::optional<Transaction> deserialize(const std::vector<uint8_t>& data);

    // Validation
    bool isCoinbase() const;
    bool isValid() const;  // Basic format validation

    // Calculate total input/output values (needs UTXO set for inputs)
    uint64_t getTotalOutputValue() const;

    // Size
    size_t getSize() const;

    // Display
    std::string toString() const;

private:
    mutable std::optional<crypto::Hash256> cached_txid_;
};

// ============================================================================
// Script helpers
// ============================================================================

namespace script {

// OP codes
constexpr uint8_t OP_DUP = 0x76;
constexpr uint8_t OP_HASH160 = 0xA9;
constexpr uint8_t OP_EQUALVERIFY = 0x88;
constexpr uint8_t OP_CHECKSIG = 0xAC;
constexpr uint8_t OP_0 = 0x00;
constexpr uint8_t OP_RETURN = 0x6A;

// Create P2PKH script (Pay to Public Key Hash)
std::vector<uint8_t> createP2PKH(const uint8_t* pubkey_hash20);

// Create P2PKH script from address
std::vector<uint8_t> createP2PKHFromAddress(const std::string& address);

// Extract pubkey hash from P2PKH script
std::optional<std::array<uint8_t, 20>> extractP2PKH(const std::vector<uint8_t>& script);

// Create signature script (for spending P2PKH)
std::vector<uint8_t> createSigScript(const crypto::Signature& sig,
                                     const crypto::PublicKey& pubkey);

// Check if script is P2PKH
bool isP2PKH(const std::vector<uint8_t>& script);

} // namespace script

// ============================================================================
// Varint encoding (Bitcoin-style)
// ============================================================================

namespace varint {

std::vector<uint8_t> encode(uint64_t value);
std::optional<uint64_t> decode(const uint8_t* data, size_t len, size_t& offset);
size_t encodedSize(uint64_t value);

} // namespace varint

} // namespace chain
} // namespace ftc

#endif // FTC_CHAIN_TRANSACTION_H
