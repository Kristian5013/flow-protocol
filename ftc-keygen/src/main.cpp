/**
 * FTC Keygen - Offline key generator for Flow Token Chain
 *
 * Generates secp256k1 keypairs and FTC addresses.
 * Can run completely offline - no network access required.
 *
 * Usage:
 *   ftc-keygen              Generate new keypair
 *   ftc-keygen --testnet    Generate testnet address
 *   ftc-keygen --from-hex   Derive address from private key hex
 */

#include <iostream>
#include <iomanip>
#include <sstream>
#include <random>
#include <cstring>
#include <array>
#include <vector>

// ============================================================================
// Embedded Keccak-256 Implementation
// ============================================================================

namespace keccak {

constexpr uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

void keccakF(uint64_t* state) {
    for (int round = 0; round < 24; round++) {
        // Theta
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 25; y += 5) {
                state[y + x] ^= D[x];
            }
        }

        // Rho and Pi
        uint64_t temp = state[1];
        for (int i = 0; i < 24; i++) {
            static const int pi[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                                       15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};
            static const int rho[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                                        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
            int j = pi[i];
            uint64_t t = state[j];
            state[j] = rotl64(temp, rho[i]);
            temp = t;
        }

        // Chi
        for (int y = 0; y < 25; y += 5) {
            uint64_t t[5];
            for (int x = 0; x < 5; x++) t[x] = state[y + x];
            for (int x = 0; x < 5; x++) {
                state[y + x] = t[x] ^ ((~t[(x + 1) % 5]) & t[(x + 2) % 5]);
            }
        }

        // Iota
        state[0] ^= RC[round];
    }
}

std::array<uint8_t, 32> hash256(const uint8_t* data, size_t len) {
    uint64_t state[25] = {0};
    constexpr size_t RATE = 136;

    // Absorb
    size_t offset = 0;
    while (offset + RATE <= len) {
        for (size_t i = 0; i < RATE / 8; i++) {
            uint64_t word;
            memcpy(&word, data + offset + i * 8, 8);
            state[i] ^= word;
        }
        keccakF(state);
        offset += RATE;
    }

    // Final block with padding
    uint8_t buffer[RATE] = {0};
    size_t remaining = len - offset;
    memcpy(buffer, data + offset, remaining);
    buffer[remaining] = 0x01;
    buffer[RATE - 1] |= 0x80;

    for (size_t i = 0; i < RATE / 8; i++) {
        uint64_t word;
        memcpy(&word, buffer + i * 8, 8);
        state[i] ^= word;
    }
    keccakF(state);

    // Squeeze
    std::array<uint8_t, 32> result;
    memcpy(result.data(), state, 32);
    return result;
}

} // namespace keccak

// ============================================================================
// Embedded secp256k1 (simplified for key generation only)
// ============================================================================

namespace secp256k1 {

// Field prime p = 2^256 - 2^32 - 977
static const uint8_t P[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F
};

// Curve order n
static const uint8_t N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

// Generator point G
static const uint8_t GX[32] = {
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
    0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
};

static const uint8_t GY[32] = {
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
    0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
    0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
};

// 256-bit unsigned integer
class Uint256 {
public:
    uint32_t d[8] = {0};

    void fromBytes(const uint8_t* bytes) {
        for (int i = 0; i < 8; i++) {
            d[i] = (uint32_t)bytes[31 - i*4] |
                   ((uint32_t)bytes[30 - i*4] << 8) |
                   ((uint32_t)bytes[29 - i*4] << 16) |
                   ((uint32_t)bytes[28 - i*4] << 24);
        }
    }

    void toBytes(uint8_t* bytes) const {
        for (int i = 0; i < 8; i++) {
            bytes[31 - i*4] = d[i] & 0xFF;
            bytes[30 - i*4] = (d[i] >> 8) & 0xFF;
            bytes[29 - i*4] = (d[i] >> 16) & 0xFF;
            bytes[28 - i*4] = (d[i] >> 24) & 0xFF;
        }
    }

    bool isZero() const {
        for (int i = 0; i < 8; i++) if (d[i]) return false;
        return true;
    }

    int compare(const Uint256& o) const {
        for (int i = 7; i >= 0; i--) {
            if (d[i] < o.d[i]) return -1;
            if (d[i] > o.d[i]) return 1;
        }
        return 0;
    }

    bool operator<(const Uint256& o) const { return compare(o) < 0; }
    bool operator>=(const Uint256& o) const { return compare(o) >= 0; }

    Uint256 add(const Uint256& o) const {
        Uint256 r;
        uint64_t c = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t s = (uint64_t)d[i] + o.d[i] + c;
            r.d[i] = (uint32_t)s;
            c = s >> 32;
        }
        return r;
    }

    Uint256 sub(const Uint256& o) const {
        Uint256 r;
        int64_t b = 0;
        for (int i = 0; i < 8; i++) {
            int64_t diff = (int64_t)d[i] - o.d[i] - b;
            if (diff < 0) { diff += 0x100000000LL; b = 1; }
            else b = 0;
            r.d[i] = (uint32_t)diff;
        }
        return r;
    }

    bool getBit(int n) const { return (d[n/32] >> (n%32)) & 1; }
};

// Field element operations (simplified)
class FieldElement {
public:
    Uint256 v;
    static Uint256 p;

    void fromBytes(const uint8_t* bytes) { v.fromBytes(bytes); reduce(); }
    void toBytes(uint8_t* bytes) const { v.toBytes(bytes); }

    void reduce() { while (v >= p) v = v.sub(p); }

    FieldElement add(const FieldElement& o) const {
        FieldElement r; r.v = v.add(o.v); r.reduce(); return r;
    }

    FieldElement sub(const FieldElement& o) const {
        FieldElement r;
        if (v < o.v) r.v = v.add(p).sub(o.v);
        else r.v = v.sub(o.v);
        return r;
    }

    FieldElement mul(const FieldElement& o) const {
        // Simplified multiplication - slow but correct
        uint64_t t[16] = {0};
        for (int i = 0; i < 8; i++) {
            uint64_t c = 0;
            for (int j = 0; j < 8; j++) {
                uint64_t prod = (uint64_t)v.d[i] * o.v.d[j] + t[i+j] + c;
                t[i+j] = prod & 0xFFFFFFFF;
                c = prod >> 32;
            }
            t[i+8] = c;
        }

        // Reduce
        for (int i = 15; i >= 8; i--) {
            if (t[i] == 0) continue;
            uint64_t h = t[i];
            uint64_t c = 0;
            uint64_t al = h * 977;
            for (int j = i-8; j < 8 && (al || c); j++) {
                uint64_t s = t[j] + (al & 0xFFFFFFFF) + c;
                t[j] = s & 0xFFFFFFFF;
                c = s >> 32;
                al >>= 32;
            }
            c = 0;
            for (int j = i-7; j < 8 && (h || c); j++) {
                uint64_t s = t[j] + h + c;
                t[j] = s & 0xFFFFFFFF;
                c = s >> 32;
                h = 0;
            }
            t[i] = 0;
        }

        FieldElement r;
        for (int i = 0; i < 8; i++) r.v.d[i] = (uint32_t)t[i];
        while (r.v >= p) r.v = r.v.sub(p);
        return r;
    }

    FieldElement square() const { return mul(*this); }

    FieldElement inverse() const {
        Uint256 exp = p; exp = exp.sub(Uint256{2,0,0,0,0,0,0,0});
        FieldElement r; r.v.d[0] = 1;
        FieldElement b = *this;
        for (int i = 0; i < 256; i++) {
            if (exp.getBit(i)) r = r.mul(b);
            b = b.square();
        }
        return r;
    }

    FieldElement sqrt() const {
        Uint256 exp = p; exp = exp.add(Uint256{1,0,0,0,0,0,0,0});
        exp.d[0] >>= 2;
        for (int i = 1; i < 8; i++) { exp.d[i-1] |= exp.d[i] << 30; exp.d[i] >>= 2; }

        FieldElement r; r.v.d[0] = 1;
        FieldElement b = *this;
        for (int i = 0; i < 256; i++) {
            if (exp.getBit(i)) r = r.mul(b);
            b = b.square();
        }
        return r;
    }

    bool isEven() const { return (v.d[0] & 1) == 0; }
};

Uint256 FieldElement::p;

// Point on curve
struct Point {
    FieldElement x, y;
    bool inf = true;

    Point doubleP() const {
        if (inf || y.v.isZero()) return Point{};
        FieldElement x2 = x.square();
        FieldElement num = x2.add(x2).add(x2);
        FieldElement denom = y.add(y);
        FieldElement lam = num.mul(denom.inverse());
        FieldElement x3 = lam.square().sub(x).sub(x);
        FieldElement y3 = lam.mul(x.sub(x3)).sub(y);
        return Point{x3, y3, false};
    }

    Point add(const Point& o) const {
        if (inf) return o;
        if (o.inf) return *this;
        if (x.v.compare(o.x.v) == 0) {
            if (y.v.compare(o.y.v) == 0) return doubleP();
            return Point{};
        }
        FieldElement dx = o.x.sub(x);
        FieldElement dy = o.y.sub(y);
        FieldElement lam = dy.mul(dx.inverse());
        FieldElement x3 = lam.square().sub(x).sub(o.x);
        FieldElement y3 = lam.mul(x.sub(x3)).sub(y);
        return Point{x3, y3, false};
    }

    Point mul(const Uint256& k) const {
        Point r, b = *this;
        for (int i = 0; i < 256; i++) {
            if (k.getBit(i)) r = r.add(b);
            b = b.doubleP();
        }
        return r;
    }
};

void init() {
    FieldElement::p.fromBytes(P);
}

bool generateKeypair(uint8_t* privkey, uint8_t* pubkey) {
    init();

    // Generate random private key
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    Uint256 n; n.fromBytes(N);

    do {
        for (int i = 0; i < 4; i++) {
            uint64_t r = dis(gen);
            privkey[i*8+0] = (r >> 56) & 0xFF;
            privkey[i*8+1] = (r >> 48) & 0xFF;
            privkey[i*8+2] = (r >> 40) & 0xFF;
            privkey[i*8+3] = (r >> 32) & 0xFF;
            privkey[i*8+4] = (r >> 24) & 0xFF;
            privkey[i*8+5] = (r >> 16) & 0xFF;
            privkey[i*8+6] = (r >> 8) & 0xFF;
            privkey[i*8+7] = r & 0xFF;
        }
        Uint256 k; k.fromBytes(privkey);
        if (!k.isZero() && k < n) break;
    } while (true);

    // Derive public key
    Uint256 k; k.fromBytes(privkey);

    FieldElement gx, gy;
    gx.fromBytes(GX);
    gy.fromBytes(GY);
    Point G{gx, gy, false};

    Point P = G.mul(k);

    // Compressed format
    pubkey[0] = P.y.isEven() ? 0x02 : 0x03;
    P.x.toBytes(pubkey + 1);

    return true;
}

bool derivePublicKey(const uint8_t* privkey, uint8_t* pubkey) {
    init();

    Uint256 k; k.fromBytes(privkey);
    Uint256 n; n.fromBytes(N);

    if (k.isZero() || k >= n) return false;

    FieldElement gx, gy;
    gx.fromBytes(GX);
    gy.fromBytes(GY);
    Point G{gx, gy, false};

    Point P = G.mul(k);

    pubkey[0] = P.y.isEven() ? 0x02 : 0x03;
    P.x.toBytes(pubkey + 1);

    return true;
}

} // namespace secp256k1

// ============================================================================
// Bech32 Encoding
// ============================================================================

namespace bech32 {

static const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

uint32_t polymod(const std::vector<uint8_t>& v) {
    uint32_t c = 1;
    for (uint8_t d : v) {
        uint8_t c0 = c >> 25;
        c = ((c & 0x1ffffff) << 5) ^ d;
        if (c0 & 1) c ^= 0x3b6a57b2;
        if (c0 & 2) c ^= 0x26508e6d;
        if (c0 & 4) c ^= 0x1ea119fa;
        if (c0 & 8) c ^= 0x3d4233dd;
        if (c0 & 16) c ^= 0x2a1462b3;
    }
    return c;
}

std::string encode(const std::string& hrp, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> values;
    for (char c : hrp) values.push_back(c >> 5);
    values.push_back(0);
    for (char c : hrp) values.push_back(c & 31);
    values.insert(values.end(), data.begin(), data.end());
    values.insert(values.end(), 6, 0);

    uint32_t mod = polymod(values) ^ 1;

    std::string result = hrp + "1";
    for (uint8_t d : data) result += CHARSET[d];
    for (int i = 0; i < 6; i++) result += CHARSET[(mod >> (5 * (5 - i))) & 31];

    return result;
}

std::string addressFromHash(const uint8_t* hash20, bool testnet) {
    // Convert 8-bit to 5-bit
    std::vector<uint8_t> data = {0}; // Version 0

    int acc = 0, bits = 0;
    for (int i = 0; i < 20; i++) {
        acc = (acc << 8) | hash20[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            data.push_back((acc >> bits) & 31);
        }
    }
    if (bits > 0) data.push_back((acc << (5 - bits)) & 31);

    return encode(testnet ? "tftc" : "ftc", data);
}

} // namespace bech32

// ============================================================================
// Utilities
// ============================================================================

std::string toHex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

bool fromHex(const std::string& hex, uint8_t* data, size_t len) {
    std::string clean = hex;
    if (clean.size() >= 2 && clean[0] == '0' && (clean[1] == 'x' || clean[1] == 'X')) {
        clean = clean.substr(2);
    }
    if (clean.size() != len * 2) return false;

    for (size_t i = 0; i < len; i++) {
        char c1 = clean[i*2], c2 = clean[i*2+1];
        int v1, v2;
        if (c1 >= '0' && c1 <= '9') v1 = c1 - '0';
        else if (c1 >= 'a' && c1 <= 'f') v1 = c1 - 'a' + 10;
        else if (c1 >= 'A' && c1 <= 'F') v1 = c1 - 'A' + 10;
        else return false;
        if (c2 >= '0' && c2 <= '9') v2 = c2 - '0';
        else if (c2 >= 'a' && c2 <= 'f') v2 = c2 - 'a' + 10;
        else if (c2 >= 'A' && c2 <= 'F') v2 = c2 - 'A' + 10;
        else return false;
        data[i] = (v1 << 4) | v2;
    }
    return true;
}

// ============================================================================
// Main
// ============================================================================

void printUsage() {
    std::cout << "FTC Keygen 1.0.0\n\n";
    std::cout << "Usage:\n";
    std::cout << "  ftc-keygen              Generate new keypair\n";
    std::cout << "  ftc-keygen --testnet    Generate testnet address\n";
    std::cout << "  ftc-keygen --from-hex PRIVKEY  Derive from private key\n";
    std::cout << "\n";
}

int main(int argc, char** argv) {
    bool testnet = false;
    std::string from_hex;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        } else if (arg == "--testnet") {
            testnet = true;
        } else if (arg == "--from-hex" && i + 1 < argc) {
            from_hex = argv[++i];
        }
    }

    uint8_t privkey[32];
    uint8_t pubkey[33];

    if (!from_hex.empty()) {
        // Derive from provided private key
        if (!fromHex(from_hex, privkey, 32)) {
            std::cerr << "Error: Invalid private key hex\n";
            return 1;
        }
        if (!secp256k1::derivePublicKey(privkey, pubkey)) {
            std::cerr << "Error: Invalid private key\n";
            return 1;
        }
    } else {
        // Generate new keypair
        if (!secp256k1::generateKeypair(privkey, pubkey)) {
            std::cerr << "Error: Failed to generate keypair\n";
            return 1;
        }
    }

    // Hash public key to get address
    auto pubkey_hash = keccak::hash256(pubkey, 33);

    // Take first 20 bytes
    uint8_t hash20[20];
    memcpy(hash20, pubkey_hash.data(), 20);

    // Generate address
    std::string address = bech32::addressFromHash(hash20, testnet);

    // Output
    std::cout << "\n";
    std::cout << "===========================================\n";
    std::cout << "FTC Key Generator\n";
    std::cout << "===========================================\n\n";
    std::cout << "Private Key: " << toHex(privkey, 32) << "\n";
    std::cout << "Public Key:  " << toHex(pubkey, 33) << "\n";
    std::cout << "Address:     " << address << "\n";
    std::cout << "\n";
    std::cout << "===========================================\n";
    std::cout << "IMPORTANT: Keep your private key SECRET!\n";
    std::cout << "           Anyone with this key can spend\n";
    std::cout << "           your FTC coins.\n";
    std::cout << "===========================================\n\n";

    return 0;
}
