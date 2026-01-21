#ifndef FTC_CRYPTO_BASE58_H
#define FTC_CRYPTO_BASE58_H

#include <string>
#include <vector>
#include <optional>

namespace ftc {
namespace crypto {

// Base58 encoding (Bitcoin-style)
std::string base58Encode(const std::vector<uint8_t>& data);
std::optional<std::vector<uint8_t>> base58Decode(const std::string& str);

// Base58Check (with checksum)
std::string base58CheckEncode(const std::vector<uint8_t>& data);
std::optional<std::vector<uint8_t>> base58CheckDecode(const std::string& str);

} // namespace crypto
} // namespace ftc

#endif // FTC_CRYPTO_BASE58_H
