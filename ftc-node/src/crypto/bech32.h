#ifndef FTC_CRYPTO_BECH32_H
#define FTC_CRYPTO_BECH32_H

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace ftc {
namespace crypto {

// Bech32 encoding for FTC addresses (ftc1...)
namespace bech32 {

// Human-readable part for mainnet
constexpr const char* HRP_MAINNET = "ftc";
constexpr const char* HRP_TESTNET = "tftc";

// Encode data to bech32 address
std::string encode(const std::string& hrp, const std::vector<uint8_t>& data);

// Decode bech32 address
std::optional<std::pair<std::string, std::vector<uint8_t>>> decode(const std::string& str);

// Create address from public key hash (20 bytes)
std::string addressFromPubKeyHash(const uint8_t* hash20, bool testnet = false);

// Extract public key hash from address
std::optional<std::vector<uint8_t>> pubKeyHashFromAddress(const std::string& address);

// Convert between bit widths (for internal use and handlers)
std::vector<uint8_t> convertBits(const std::vector<uint8_t>& data, int fromBits, int toBits, bool pad);

} // namespace bech32
} // namespace crypto
} // namespace ftc

#endif // FTC_CRYPTO_BECH32_H
