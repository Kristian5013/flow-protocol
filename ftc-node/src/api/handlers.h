#ifndef FTC_API_HANDLERS_H
#define FTC_API_HANDLERS_H

#include "api/server.h"
#include "chain/chain.h"
#include "chain/mempool.h"
#include "chain/utxo_set.h"
#include "chain/transaction.h"
#include "chain/block.h"
#include "p2p/peer_manager.h"
#include "crypto/keccak256.h"
#include "ftc/version.h"
#include <string>
#include <vector>
#include <optional>

namespace ftc {
namespace api {

/**
 * API Handlers - utility functions for API endpoints
 *
 * These helpers handle common operations like:
 * - Address encoding/decoding (bech32)
 * - Transaction building
 * - Script parsing
 * - Hex encoding/decoding
 */

//-----------------------------------------------------------------------------
// Hex encoding/decoding
//-----------------------------------------------------------------------------

// Convert bytes to hex string
std::string toHex(const std::vector<uint8_t>& data);
std::string toHex(const uint8_t* data, size_t len);

// Convert hex string to bytes (returns empty on error)
std::vector<uint8_t> fromHex(const std::string& hex);

// Validate hex string
bool isValidHex(const std::string& hex);

//-----------------------------------------------------------------------------
// Bech32 Address encoding/decoding
//-----------------------------------------------------------------------------

// Bech32 character set
const char* const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Encode address from script pubkey
// Returns ftc1... address for P2WPKH/P2WSH
std::string encodeAddress(const std::vector<uint8_t>& script_pubkey);

// Decode address to script pubkey
// Returns empty vector on error
std::vector<uint8_t> decodeAddress(const std::string& address);

// Validate address format
bool isValidAddress(const std::string& address);

// Get address type from script
enum class AddressType {
    UNKNOWN,
    P2PKH,      // Pay to Public Key Hash (legacy)
    P2SH,       // Pay to Script Hash (legacy)
    P2WPKH,     // Pay to Witness Public Key Hash (native segwit)
    P2WSH,      // Pay to Witness Script Hash (native segwit)
    P2TR        // Pay to Taproot (future)
};

AddressType getAddressType(const std::vector<uint8_t>& script_pubkey);
AddressType getAddressType(const std::string& address);

//-----------------------------------------------------------------------------
// Transaction building helpers
//-----------------------------------------------------------------------------

// Build a simple P2WPKH transaction
// Returns serialized transaction (unsigned)
std::vector<uint8_t> buildTransaction(
    const std::vector<chain::Outpoint>& inputs,
    const std::vector<std::pair<std::string, uint64_t>>& outputs,  // address -> amount
    uint32_t locktime = 0
);

// Estimate transaction size (for fee calculation)
size_t estimateTxSize(size_t num_inputs, size_t num_outputs);

// Estimate transaction virtual size (with segwit discount)
size_t estimateTxVSize(size_t num_inputs, size_t num_outputs, bool segwit = true);

// Calculate required fee for transaction
uint64_t calculateFee(size_t vsize, uint64_t fee_rate_per_vbyte);

//-----------------------------------------------------------------------------
// Script helpers
//-----------------------------------------------------------------------------

// Create P2WPKH script from public key hash (20 bytes)
std::vector<uint8_t> createP2WPKHScript(const std::vector<uint8_t>& pubkey_hash);

// Create P2WSH script from script hash (32 bytes)
std::vector<uint8_t> createP2WSHScript(const std::vector<uint8_t>& script_hash);

// Create P2PKH script from public key hash (20 bytes)
std::vector<uint8_t> createP2PKHScript(const std::vector<uint8_t>& pubkey_hash);

// Create P2SH script from script hash (20 bytes)
std::vector<uint8_t> createP2SHScript(const std::vector<uint8_t>& script_hash);

// Extract hash from script (returns empty on unknown script type)
std::vector<uint8_t> extractHashFromScript(const std::vector<uint8_t>& script);

// Check if script is standard
bool isStandardScript(const std::vector<uint8_t>& script);

//-----------------------------------------------------------------------------
// Block/Transaction serialization
//-----------------------------------------------------------------------------

// Serialize block to JSON
std::string blockToJson(const chain::Block& block, bool include_txs = true);

// Serialize transaction to JSON
std::string transactionToJson(const chain::Transaction& tx, bool include_hex = false);

// Serialize block header to JSON
std::string headerToJson(const chain::BlockHeader& header);

// Serialize UTXO to JSON
std::string utxoToJson(const chain::UTXOEntry& utxo, const chain::Outpoint& outpoint);

//-----------------------------------------------------------------------------
// Validation helpers
//-----------------------------------------------------------------------------

// Validate transaction format (basic checks)
bool validateTransactionFormat(const chain::Transaction& tx, std::string& error);

// Validate block format (basic checks)
bool validateBlockFormat(const chain::Block& block, std::string& error);

// Validate address checksum
bool validateAddressChecksum(const std::string& address);

//-----------------------------------------------------------------------------
// Rate limiting (simple token bucket)
//-----------------------------------------------------------------------------

class RateLimiter {
public:
    RateLimiter(size_t max_requests, std::chrono::seconds window);

    // Check if request is allowed (and consume a token if so)
    bool allowRequest(const std::string& client_id);

    // Get remaining requests for client
    size_t getRemainingRequests(const std::string& client_id) const;

    // Reset rate limit for client
    void reset(const std::string& client_id);

    // Cleanup expired entries
    void cleanup();

private:
    struct Bucket {
        size_t tokens;
        std::chrono::steady_clock::time_point last_refill;
    };

    size_t max_tokens_;
    std::chrono::seconds refill_window_;
    std::map<std::string, Bucket> buckets_;
    mutable std::mutex mutex_;
};

//-----------------------------------------------------------------------------
// API context (passed to all handlers)
//-----------------------------------------------------------------------------

struct ApiContext {
    chain::Chain* chain = nullptr;
    chain::Mempool* mempool = nullptr;
    chain::UTXOSet* utxo_set = nullptr;
    p2p::PeerManager* peer_manager = nullptr;
    RateLimiter* rate_limiter = nullptr;

    // Node info
    std::string version = FTC_VERSION;
    std::string network = "mainnet";
    bool testnet = false;

    // Utility methods
    bool isReady() const {
        return chain != nullptr && mempool != nullptr && utxo_set != nullptr;
    }
};

//-----------------------------------------------------------------------------
// Bech32 implementation details
//-----------------------------------------------------------------------------

namespace bech32 {

// Encode data to bech32
std::string encode(const std::string& hrp, const std::vector<uint8_t>& values);

// Decode bech32 string
// Returns (hrp, data) or empty strings on error
std::pair<std::string, std::vector<uint8_t>> decode(const std::string& str);

// Convert between 5-bit and 8-bit groups
std::vector<uint8_t> convertBits(const std::vector<uint8_t>& data,
                                  int from_bits, int to_bits, bool pad);

// Compute bech32 checksum
std::vector<uint8_t> createChecksum(const std::string& hrp,
                                     const std::vector<uint8_t>& values);

// Verify bech32 checksum
bool verifyChecksum(const std::string& hrp, const std::vector<uint8_t>& values);

// Polymod for checksum calculation
uint32_t polymod(const std::vector<uint8_t>& values);

// HRP expansion for checksum
std::vector<uint8_t> hrpExpand(const std::string& hrp);

} // namespace bech32

} // namespace api
} // namespace ftc

#endif // FTC_API_HANDLERS_H
