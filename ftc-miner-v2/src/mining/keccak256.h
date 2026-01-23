#ifndef FTC_MINER_MINING_KECCAK256_H
#define FTC_MINER_MINING_KECCAK256_H

#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <vector>

namespace mining {

using Hash256 = std::array<uint8_t, 32>;

class Keccak256 {
public:
    // Hash raw data
    static Hash256 hash(const uint8_t* data, size_t length);
    static Hash256 hash(const std::vector<uint8_t>& data);

    // Hash block header with nonce
    static Hash256 hashHeader(const uint8_t* header76, uint32_t nonce);

    // Convert target bits to 256-bit target
    static Hash256 bitsToTarget(uint32_t bits);

    // Check if hash meets target
    static bool meetsTarget(const Hash256& hash, const Hash256& target);

    // Utility
    static std::string toHex(const Hash256& hash);
    static Hash256 fromHex(const std::string& hex);

private:
    static void keccakF1600(uint64_t state[25]);
};

} // namespace mining

#endif // FTC_MINER_MINING_KECCAK256_H
