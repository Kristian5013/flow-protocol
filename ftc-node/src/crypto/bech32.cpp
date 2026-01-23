#include "crypto/bech32.h"
#include <algorithm>
#include <cctype>
#include <cstring>

namespace ftc {
namespace crypto {
namespace bech32 {

static const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t polymod(const std::vector<uint8_t>& values) {
    uint32_t chk = 1;
    for (uint8_t v : values) {
        uint8_t top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ v;
        if (top & 1) chk ^= 0x3b6a57b2;
        if (top & 2) chk ^= 0x26508e6d;
        if (top & 4) chk ^= 0x1ea119fa;
        if (top & 8) chk ^= 0x3d4233dd;
        if (top & 16) chk ^= 0x2a1462b3;
    }
    return chk;
}

static std::vector<uint8_t> hrpExpand(const std::string& hrp) {
    std::vector<uint8_t> ret;
    ret.reserve(hrp.size() * 2 + 1);

    for (char c : hrp) {
        ret.push_back(c >> 5);
    }
    ret.push_back(0);
    for (char c : hrp) {
        ret.push_back(c & 31);
    }

    return ret;
}

static std::vector<uint8_t> createChecksum(const std::string& hrp, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> values = hrpExpand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.insert(values.end(), 6, 0);

    uint32_t mod = polymod(values) ^ 1;
    std::vector<uint8_t> ret(6);
    for (int i = 0; i < 6; i++) {
        ret[i] = (mod >> (5 * (5 - i))) & 31;
    }
    return ret;
}

static bool verifyChecksum(const std::string& hrp, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> values = hrpExpand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    return polymod(values) == 1;
}

static std::vector<uint8_t> convertBits(const std::vector<uint8_t>& data, int fromBits, int toBits, bool pad) {
    std::vector<uint8_t> ret;
    int acc = 0;
    int bits = 0;

    int maxv = (1 << toBits) - 1;

    for (uint8_t value : data) {
        acc = (acc << fromBits) | value;
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            ret.push_back((acc >> bits) & maxv);
        }
    }

    if (pad) {
        if (bits > 0) {
            ret.push_back((acc << (toBits - bits)) & maxv);
        }
    }

    return ret;
}

std::string encode(const std::string& hrp, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> combined = data;
    auto checksum = createChecksum(hrp, data);
    combined.insert(combined.end(), checksum.begin(), checksum.end());

    std::string ret = hrp + "1";
    for (uint8_t c : combined) {
        ret += CHARSET[c];
    }

    return ret;
}

std::optional<std::pair<std::string, std::vector<uint8_t>>> decode(const std::string& str) {
    // Find separator
    size_t pos = str.rfind('1');
    if (pos == std::string::npos || pos == 0 || pos + 7 > str.size()) {
        return std::nullopt;
    }

    std::string hrp = str.substr(0, pos);
    for (char& c : hrp) {
        c = std::tolower(c);
    }

    std::vector<uint8_t> data;
    for (size_t i = pos + 1; i < str.size(); i++) {
        char c = std::tolower(str[i]);
        const char* p = std::strchr(CHARSET, c);
        if (!p) return std::nullopt;
        data.push_back(static_cast<uint8_t>(p - CHARSET));
    }

    if (!verifyChecksum(hrp, data)) {
        return std::nullopt;
    }

    // Remove checksum
    data.resize(data.size() - 6);

    return std::make_pair(hrp, data);
}

std::string addressFromPubKeyHash(const uint8_t* hash20, bool testnet) {
    const char* hrp = testnet ? HRP_TESTNET : HRP_MAINNET;

    // Version 0 + 20-byte hash
    std::vector<uint8_t> data = {0};
    data.insert(data.end(), hash20, hash20 + 20);

    // Convert to 5-bit groups
    auto converted = convertBits(data, 8, 5, true);

    return encode(hrp, converted);
}

std::optional<std::vector<uint8_t>> pubKeyHashFromAddress(const std::string& address) {
    auto decoded = decode(address);
    if (!decoded) return std::nullopt;

    // Check HRP
    if (decoded->first != HRP_MAINNET && decoded->first != HRP_TESTNET) {
        return std::nullopt;
    }

    // Convert from 5-bit to 8-bit
    auto data = convertBits(decoded->second, 5, 8, false);

    // Check version (first byte should be 0)
    if (data.empty() || data[0] != 0) return std::nullopt;

    // Return hash (skip version byte)
    return std::vector<uint8_t>(data.begin() + 1, data.end());
}

} // namespace bech32
} // namespace crypto
} // namespace ftc
