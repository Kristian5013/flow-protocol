/**
 * FTC Wallet - Command-line wallet for Flow Token Chain
 *
 * Kristian Pilatovich 20091227 - First Real P2P
 *
 * Features:
 *   - Generate new keypairs
 *   - Check balance
 *   - Send transactions
 *   - View transaction history
 *   - List UTXOs
 *
 * Usage:
 *   ftc-wallet new                          Generate new wallet
 *   ftc-wallet balance <address> [node]     Check balance
 *   ftc-wallet send <privkey> <to> <amount> [node]  Send FTC
 *   ftc-wallet history <address> [node]     Transaction history
 *   ftc-wallet utxos <address> [node]       List UTXOs
 */

#include <iostream>
#include <iomanip>
#include <sstream>
#include <random>
#include <cstring>
#include <array>
#include <vector>
#include <optional>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#define closesocket close
#define SOCKET int
#define INVALID_SOCKET -1
#endif

// ============================================================================
// Keccak-256 Implementation
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

        for (int y = 0; y < 25; y += 5) {
            uint64_t t[5];
            for (int x = 0; x < 5; x++) t[x] = state[y + x];
            for (int x = 0; x < 5; x++) {
                state[y + x] = t[x] ^ ((~t[(x + 1) % 5]) & t[(x + 2) % 5]);
            }
        }

        state[0] ^= RC[round];
    }
}

std::array<uint8_t, 32> hash256(const uint8_t* data, size_t len) {
    uint64_t state[25] = {0};
    constexpr size_t RATE = 136;

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

    std::array<uint8_t, 32> result;
    memcpy(result.data(), state, 32);
    return result;
}

std::array<uint8_t, 32> doubleHash(const uint8_t* data, size_t len) {
    auto first = hash256(data, len);
    return hash256(first.data(), 32);
}

} // namespace keccak

// ============================================================================
// secp256k1 Implementation
// ============================================================================

namespace secp256k1 {

static const uint8_t P[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F
};

static const uint8_t N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

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
    bool operator==(const Uint256& o) const { return compare(o) == 0; }

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

    bool isEven() const { return (v.d[0] & 1) == 0; }
};

Uint256 FieldElement::p;

class Scalar {
public:
    Uint256 v;
    static Uint256 n;

    void fromBytes(const uint8_t* bytes) { v.fromBytes(bytes); reduce(); }
    void reduce() { while (v >= n) v = v.sub(n); }

    Scalar add(const Scalar& o) const {
        Scalar r; r.v = v.add(o.v); r.reduce(); return r;
    }

    Scalar mul(const Scalar& o) const {
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

        Scalar r;
        for (int i = 0; i < 8; i++) r.v.d[i] = (uint32_t)t[i];
        while (r.v >= n) r.v = r.v.sub(n);
        return r;
    }

    Scalar inverse() const {
        Uint256 exp = n.sub(Uint256{2,0,0,0,0,0,0,0});
        Scalar r; r.v.d[0] = 1;
        Scalar b = *this;
        for (int i = 0; i < 256; i++) {
            if (exp.getBit(i)) r = r.mul(b);
            b = b.mul(b);
        }
        return r;
    }
};

Uint256 Scalar::n;

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
        if (x.v == o.x.v) {
            if (y.v == o.y.v) return doubleP();
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

static Point G;

void init() {
    FieldElement::p.fromBytes(P);
    Scalar::n.fromBytes(N);
    FieldElement gx, gy;
    gx.fromBytes(GX);
    gy.fromBytes(GY);
    G = Point{gx, gy, false};
}

bool derivePublicKey(const uint8_t* privkey, uint8_t* pubkey) {
    Scalar k; k.fromBytes(privkey);
    if (k.v.isZero()) return false;
    Point P = G.mul(k.v);
    pubkey[0] = P.y.isEven() ? 0x02 : 0x03;
    P.x.toBytes(pubkey + 1);
    return true;
}

bool sign(const uint8_t* msg32, const uint8_t* privkey, uint8_t* sig) {
    Scalar z, d;
    z.fromBytes(msg32);
    d.fromBytes(privkey);
    if (d.v.isZero()) return false;

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    uint8_t k_bytes[32];
    Scalar k;

    while (true) {
        for (int i = 0; i < 4; i++) {
            uint64_t r = dis(gen);
            k_bytes[i*8+0] = (r >> 56) & 0xFF;
            k_bytes[i*8+1] = (r >> 48) & 0xFF;
            k_bytes[i*8+2] = (r >> 40) & 0xFF;
            k_bytes[i*8+3] = (r >> 32) & 0xFF;
            k_bytes[i*8+4] = (r >> 24) & 0xFF;
            k_bytes[i*8+5] = (r >> 16) & 0xFF;
            k_bytes[i*8+6] = (r >> 8) & 0xFF;
            k_bytes[i*8+7] = r & 0xFF;
        }

        k.fromBytes(k_bytes);
        if (k.v.isZero()) continue;

        Point R = G.mul(k.v);
        if (R.inf) continue;

        Scalar r;
        uint8_t rx[32];
        R.x.toBytes(rx);
        r.fromBytes(rx);
        if (r.v.isZero()) continue;

        Scalar rd = r.mul(d);
        Scalar zrd = z.add(rd);
        Scalar k_inv = k.inverse();
        Scalar s = k_inv.mul(zrd);
        if (s.v.isZero()) continue;

        r.v.toBytes(sig);
        s.v.toBytes(sig + 32);
        return true;
    }
}

std::vector<uint8_t> signatureToDER(const uint8_t* sig) {
    std::vector<uint8_t> der;

    auto encodeInt = [](const uint8_t* data, std::vector<uint8_t>& out) {
        int start = 0;
        while (start < 32 && data[start] == 0) start++;
        if (start == 32) {
            out.push_back(0x02);
            out.push_back(0x01);
            out.push_back(0x00);
            return;
        }

        bool needZero = (data[start] & 0x80) != 0;
        int len = 32 - start + (needZero ? 1 : 0);

        out.push_back(0x02);
        out.push_back((uint8_t)len);
        if (needZero) out.push_back(0x00);
        for (int i = start; i < 32; i++) out.push_back(data[i]);
    };

    std::vector<uint8_t> r_enc, s_enc;
    encodeInt(sig, r_enc);
    encodeInt(sig + 32, s_enc);

    der.push_back(0x30);
    der.push_back((uint8_t)(r_enc.size() + s_enc.size()));
    der.insert(der.end(), r_enc.begin(), r_enc.end());
    der.insert(der.end(), s_enc.begin(), s_enc.end());

    return der;
}

bool generateKeypair(uint8_t* privkey, uint8_t* pubkey) {
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

    return derivePublicKey(privkey, pubkey);
}

} // namespace secp256k1

// ============================================================================
// Bech32 Encoding/Decoding
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

std::string addressFromHash(const uint8_t* hash20, bool testnet = false) {
    std::vector<uint8_t> data = {0};

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

std::optional<std::array<uint8_t, 20>> decodeAddress(const std::string& addr) {
    size_t sep = addr.rfind('1');
    if (sep == std::string::npos || sep < 1 || sep + 7 > addr.size()) {
        return std::nullopt;
    }

    std::string hrp = addr.substr(0, sep);
    std::string data_part = addr.substr(sep + 1);

    if (hrp != "ftc" && hrp != "tftc") return std::nullopt;

    std::vector<uint8_t> data5bit;
    for (char c : data_part) {
        const char* p = strchr(CHARSET, tolower(c));
        if (!p) return std::nullopt;
        data5bit.push_back((uint8_t)(p - CHARSET));
    }

    if (data5bit.size() < 39) return std::nullopt;
    if (data5bit[0] != 0) return std::nullopt;  // Version 0 only

    std::vector<uint8_t> data5bit_payload(data5bit.begin() + 1, data5bit.end() - 6);

    std::vector<uint8_t> program;
    int acc = 0, bits = 0;
    for (uint8_t v : data5bit_payload) {
        acc = (acc << 5) | v;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            program.push_back((acc >> bits) & 0xFF);
        }
    }

    if (program.size() != 20) return std::nullopt;

    std::array<uint8_t, 20> result;
    std::copy(program.begin(), program.end(), result.begin());
    return result;
}

} // namespace bech32

// ============================================================================
// Utilities
// ============================================================================

std::string toHex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << (int)data[i];
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
// HTTP Client (IPv6 only)
// ============================================================================

std::string httpGet(const std::string& host, int port, const std::string& path) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    SOCKET sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return "";

    struct sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    inet_pton(AF_INET6, host.c_str(), &addr.sin6_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        closesocket(sock);
        return "";
    }

    std::string request = "GET " + path + " HTTP/1.1\r\nHost: [" + host + "]\r\nConnection: close\r\n\r\n";
    send(sock, request.c_str(), (int)request.size(), 0);

    std::string response;
    char buf[4096];
    int n;
    while ((n = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = 0;
        response += buf;
    }

    closesocket(sock);

    size_t body_start = response.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        return response.substr(body_start + 4);
    }
    return response;
}

std::string httpPost(const std::string& host, int port, const std::string& path, const std::string& body) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    SOCKET sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return "";

    struct sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    inet_pton(AF_INET6, host.c_str(), &addr.sin6_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        closesocket(sock);
        return "";
    }

    std::string request = "POST " + path + " HTTP/1.1\r\nHost: [" + host + "]" +
                          "\r\nContent-Type: application/json\r\nContent-Length: " +
                          std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    send(sock, request.c_str(), (int)request.size(), 0);

    std::string response;
    char buf[4096];
    int n;
    while ((n = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = 0;
        response += buf;
    }

    closesocket(sock);

    size_t body_start = response.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        return response.substr(body_start + 4);
    }
    return response;
}

// ============================================================================
// Simple JSON Parser (minimal)
// ============================================================================

std::string jsonGetString(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    size_t end = json.find("\"", pos);
    if (end == std::string::npos) return "";
    return json.substr(pos, end - pos);
}

int64_t jsonGetInt(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return -1;
    pos += search.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    std::string num;
    while (pos < json.size() && (json[pos] >= '0' && json[pos] <= '9')) {
        num += json[pos++];
    }
    if (num.empty()) return -1;
    return std::stoll(num);
}

// ============================================================================
// Transaction Building
// ============================================================================

struct UTXO {
    std::array<uint8_t, 32> txid;
    uint32_t index;
    uint64_t value;
    std::vector<uint8_t> script_pubkey;
    uint32_t height = 0;
    bool coinbase = false;
};

std::vector<uint8_t> buildTransaction(
    const std::vector<UTXO>& utxos,
    const std::array<uint8_t, 20>& to_hash,
    uint64_t amount,
    uint64_t fee,
    const std::array<uint8_t, 20>& change_hash,
    const uint8_t* privkey,
    const uint8_t* pubkey
) {
    uint64_t total_input = 0;
    for (const auto& utxo : utxos) total_input += utxo.value;

    if (total_input < amount + fee) {
        return {};  // Insufficient funds
    }

    uint64_t change = total_input - amount - fee;

    // Build unsigned transaction
    std::vector<uint8_t> tx;

    // Version (4 bytes)
    tx.push_back(0x01);
    tx.push_back(0x00);
    tx.push_back(0x00);
    tx.push_back(0x00);

    // Input count
    tx.push_back((uint8_t)utxos.size());

    // Inputs (without signatures for now)
    for (const auto& utxo : utxos) {
        tx.insert(tx.end(), utxo.txid.begin(), utxo.txid.end());
        tx.push_back(utxo.index & 0xFF);
        tx.push_back((utxo.index >> 8) & 0xFF);
        tx.push_back((utxo.index >> 16) & 0xFF);
        tx.push_back((utxo.index >> 24) & 0xFF);
        tx.push_back(0x00);  // Empty script sig for now
        tx.push_back(0xFF);
        tx.push_back(0xFF);
        tx.push_back(0xFF);
        tx.push_back(0xFF);  // Sequence
    }

    // Output count
    int out_count = (change > 0) ? 2 : 1;
    tx.push_back((uint8_t)out_count);

    // Output 1: recipient
    for (int i = 0; i < 8; i++) tx.push_back((amount >> (i * 8)) & 0xFF);
    // P2WPKH script: OP_0 <20 bytes>
    tx.push_back(22);  // Script length
    tx.push_back(0x00);  // OP_0
    tx.push_back(20);  // Push 20 bytes
    tx.insert(tx.end(), to_hash.begin(), to_hash.end());

    // Output 2: change (if any)
    if (change > 0) {
        for (int i = 0; i < 8; i++) tx.push_back((change >> (i * 8)) & 0xFF);
        tx.push_back(22);
        tx.push_back(0x00);
        tx.push_back(20);
        tx.insert(tx.end(), change_hash.begin(), change_hash.end());
    }

    // Locktime
    tx.push_back(0x00);
    tx.push_back(0x00);
    tx.push_back(0x00);
    tx.push_back(0x00);

    // Now sign each input
    std::vector<std::vector<uint8_t>> signatures;

    for (size_t i = 0; i < utxos.size(); i++) {
        // Build signature hash
        std::vector<uint8_t> sighash_preimage;

        // Version
        sighash_preimage.push_back(0x01);
        sighash_preimage.push_back(0x00);
        sighash_preimage.push_back(0x00);
        sighash_preimage.push_back(0x00);

        // Input count
        sighash_preimage.push_back((uint8_t)utxos.size());

        // Inputs
        for (size_t j = 0; j < utxos.size(); j++) {
            const auto& utxo = utxos[j];
            sighash_preimage.insert(sighash_preimage.end(), utxo.txid.begin(), utxo.txid.end());
            sighash_preimage.push_back(utxo.index & 0xFF);
            sighash_preimage.push_back((utxo.index >> 8) & 0xFF);
            sighash_preimage.push_back((utxo.index >> 16) & 0xFF);
            sighash_preimage.push_back((utxo.index >> 24) & 0xFF);

            if (i == j) {
                // Include the scriptPubKey for the input being signed
                sighash_preimage.push_back((uint8_t)utxo.script_pubkey.size());
                sighash_preimage.insert(sighash_preimage.end(),
                    utxo.script_pubkey.begin(), utxo.script_pubkey.end());
            } else {
                sighash_preimage.push_back(0x00);  // Empty script
            }

            sighash_preimage.push_back(0xFF);
            sighash_preimage.push_back(0xFF);
            sighash_preimage.push_back(0xFF);
            sighash_preimage.push_back(0xFF);
        }

        // Output count
        sighash_preimage.push_back((uint8_t)out_count);

        // Outputs
        for (int i = 0; i < 8; i++) sighash_preimage.push_back((amount >> (i * 8)) & 0xFF);
        sighash_preimage.push_back(22);
        sighash_preimage.push_back(0x00);
        sighash_preimage.push_back(20);
        sighash_preimage.insert(sighash_preimage.end(), to_hash.begin(), to_hash.end());

        if (change > 0) {
            for (int i = 0; i < 8; i++) sighash_preimage.push_back((change >> (i * 8)) & 0xFF);
            sighash_preimage.push_back(22);
            sighash_preimage.push_back(0x00);
            sighash_preimage.push_back(20);
            sighash_preimage.insert(sighash_preimage.end(), change_hash.begin(), change_hash.end());
        }

        // Locktime
        sighash_preimage.push_back(0x00);
        sighash_preimage.push_back(0x00);
        sighash_preimage.push_back(0x00);
        sighash_preimage.push_back(0x00);

        // SIGHASH_ALL
        sighash_preimage.push_back(0x01);
        sighash_preimage.push_back(0x00);
        sighash_preimage.push_back(0x00);
        sighash_preimage.push_back(0x00);

        // Double hash
        auto hash = keccak::doubleHash(sighash_preimage.data(), sighash_preimage.size());

        // Sign
        uint8_t sig[64];
        if (!secp256k1::sign(hash.data(), privkey, sig)) {
            return {};
        }

        auto der = secp256k1::signatureToDER(sig);
        der.push_back(0x01);  // SIGHASH_ALL

        // Create scriptSig: <sig> <pubkey>
        std::vector<uint8_t> script_sig;
        script_sig.push_back((uint8_t)der.size());
        script_sig.insert(script_sig.end(), der.begin(), der.end());
        script_sig.push_back(33);  // Compressed pubkey
        script_sig.insert(script_sig.end(), pubkey, pubkey + 33);

        signatures.push_back(script_sig);
    }

    // Rebuild transaction with signatures
    std::vector<uint8_t> signed_tx;

    // Version
    signed_tx.push_back(0x01);
    signed_tx.push_back(0x00);
    signed_tx.push_back(0x00);
    signed_tx.push_back(0x00);

    // Input count
    signed_tx.push_back((uint8_t)utxos.size());

    // Inputs with signatures
    for (size_t i = 0; i < utxos.size(); i++) {
        const auto& utxo = utxos[i];
        signed_tx.insert(signed_tx.end(), utxo.txid.begin(), utxo.txid.end());
        signed_tx.push_back(utxo.index & 0xFF);
        signed_tx.push_back((utxo.index >> 8) & 0xFF);
        signed_tx.push_back((utxo.index >> 16) & 0xFF);
        signed_tx.push_back((utxo.index >> 24) & 0xFF);

        // Script sig
        const auto& sig = signatures[i];
        signed_tx.push_back((uint8_t)sig.size());
        signed_tx.insert(signed_tx.end(), sig.begin(), sig.end());

        signed_tx.push_back(0xFF);
        signed_tx.push_back(0xFF);
        signed_tx.push_back(0xFF);
        signed_tx.push_back(0xFF);
    }

    // Output count
    signed_tx.push_back((uint8_t)out_count);

    // Outputs
    for (int i = 0; i < 8; i++) signed_tx.push_back((amount >> (i * 8)) & 0xFF);
    signed_tx.push_back(22);
    signed_tx.push_back(0x00);
    signed_tx.push_back(20);
    signed_tx.insert(signed_tx.end(), to_hash.begin(), to_hash.end());

    if (change > 0) {
        for (int i = 0; i < 8; i++) signed_tx.push_back((change >> (i * 8)) & 0xFF);
        signed_tx.push_back(22);
        signed_tx.push_back(0x00);
        signed_tx.push_back(20);
        signed_tx.insert(signed_tx.end(), change_hash.begin(), change_hash.end());
    }

    // Locktime
    signed_tx.push_back(0x00);
    signed_tx.push_back(0x00);
    signed_tx.push_back(0x00);
    signed_tx.push_back(0x00);

    return signed_tx;
}

// ============================================================================
// Commands
// ============================================================================

void cmdNew() {
    secp256k1::init();

    uint8_t privkey[32];
    uint8_t pubkey[33];

    secp256k1::generateKeypair(privkey, pubkey);

    auto pubkey_hash = keccak::hash256(pubkey, 33);
    uint8_t hash20[20];
    memcpy(hash20, pubkey_hash.data(), 20);

    std::string address = bech32::addressFromHash(hash20);

    std::cout << "\n";
    std::cout << "===========================================\n";
    std::cout << "           FTC Wallet Generated\n";
    std::cout << "===========================================\n\n";
    std::cout << "Private Key: " << toHex(privkey, 32) << "\n";
    std::cout << "Public Key:  " << toHex(pubkey, 33) << "\n";
    std::cout << "Address:     " << address << "\n\n";
    std::cout << "===========================================\n";
    std::cout << "   KEEP YOUR PRIVATE KEY SECRET!\n";
    std::cout << "===========================================\n\n";
}

// Parse IPv6 node address: [ipv6]:port or ipv6 (default port 17319)
void parseNodeAddress(const std::string& node, std::string& host, int& port) {
    port = 17319;  // Default API port

    if (node.empty() || node == "::1") {
        host = "::1";
        return;
    }

    // IPv6 format: [addr]:port
    if (node[0] == '[') {
        size_t bracket_end = node.find(']');
        if (bracket_end != std::string::npos) {
            host = node.substr(1, bracket_end - 1);
            if (bracket_end + 1 < node.size() && node[bracket_end + 1] == ':') {
                port = std::stoi(node.substr(bracket_end + 2));
            }
        } else {
            host = node.substr(1);  // Missing closing bracket
        }
    } else {
        // Bare IPv6 address (no port)
        host = node;
    }
}

void cmdBalance(const std::string& address, const std::string& node = "::1") {
    std::string host;
    int port;
    parseNodeAddress(node, host, port);

    std::string json = httpGet(host, port, "/balance/" + address);

    if (json.empty()) {
        std::cerr << "Error: Could not connect to node\n";
        return;
    }

    int64_t confirmed = jsonGetInt(json, "confirmed");
    int64_t unconfirmed = jsonGetInt(json, "unconfirmed");
    int64_t total = jsonGetInt(json, "total");

    if (confirmed < 0) {
        std::cerr << "Error: " << json << "\n";
        return;
    }

    std::cout << "\n";
    std::cout << "Address:     " << address << "\n";
    std::cout << "Confirmed:   " << (confirmed / 100000000) << "." << std::setfill('0') << std::setw(8) << (confirmed % 100000000) << " FTC\n";
    std::cout << "Unconfirmed: " << (unconfirmed / 100000000) << "." << std::setfill('0') << std::setw(8) << (unconfirmed % 100000000) << " FTC\n";
    std::cout << "Total:       " << (total / 100000000) << "." << std::setfill('0') << std::setw(8) << (total % 100000000) << " FTC\n\n";
}

void cmdSend(const std::string& privkey_hex, const std::string& to_address,
             const std::string& amount_str, const std::string& node = "::1") {
    secp256k1::init();

    // Parse private key
    uint8_t privkey[32];
    if (!fromHex(privkey_hex, privkey, 32)) {
        std::cerr << "Error: Invalid private key\n";
        return;
    }

    // Derive public key and address
    uint8_t pubkey[33];
    if (!secp256k1::derivePublicKey(privkey, pubkey)) {
        std::cerr << "Error: Failed to derive public key\n";
        return;
    }

    auto pubkey_hash = keccak::hash256(pubkey, 33);
    uint8_t from_hash20[20];
    memcpy(from_hash20, pubkey_hash.data(), 20);
    std::string from_address = bech32::addressFromHash(from_hash20);

    // Parse recipient address
    auto to_hash_opt = bech32::decodeAddress(to_address);
    if (!to_hash_opt) {
        std::cerr << "Error: Invalid recipient address\n";
        return;
    }

    // Parse amount
    double amount_ftc = std::stod(amount_str);
    uint64_t amount = (uint64_t)(amount_ftc * 100000000);

    // Connect to node
    std::string host;
    int port;
    parseNodeAddress(node, host, port);

    // Get UTXOs
    std::string utxo_json = httpGet(host, port, "/utxo/" + from_address);
    if (utxo_json.empty()) {
        std::cerr << "Error: Could not connect to node\n";
        return;
    }

    // Parse UTXOs (simple JSON parsing)
    std::vector<UTXO> utxos;
    size_t pos = 0;
    while ((pos = utxo_json.find("\"txid\":", pos)) != std::string::npos) {
        UTXO utxo;

        // txid
        size_t start = utxo_json.find("\"", pos + 7) + 1;
        size_t end = utxo_json.find("\"", start);
        std::string txid_hex = utxo_json.substr(start, end - start);
        fromHex(txid_hex, utxo.txid.data(), 32);

        // vout
        size_t vout_pos = utxo_json.find("\"vout\":", pos);
        if (vout_pos != std::string::npos && vout_pos < pos + 200) {
            utxo.index = (uint32_t)jsonGetInt(utxo_json.substr(vout_pos), "vout");
        }

        // amount (API returns "amount" not "value")
        size_t amount_pos = utxo_json.find("\"amount\":", pos);
        if (amount_pos != std::string::npos && amount_pos < pos + 200) {
            utxo.value = jsonGetInt(utxo_json.substr(amount_pos), "amount");
        }

        // script_pubkey
        size_t script_pos = utxo_json.find("\"script_pubkey\":", pos);
        if (script_pos != std::string::npos && script_pos < pos + 300) {
            size_t script_start = utxo_json.find("\"", script_pos + 16) + 1;
            size_t script_end = utxo_json.find("\"", script_start);
            std::string script_hex = utxo_json.substr(script_start, script_end - script_start);
            utxo.script_pubkey.resize(script_hex.size() / 2);
            fromHex(script_hex, utxo.script_pubkey.data(), utxo.script_pubkey.size());
        }

        // height
        size_t height_pos = utxo_json.find("\"height\":", pos);
        if (height_pos != std::string::npos && height_pos < pos + 400) {
            utxo.height = (uint32_t)jsonGetInt(utxo_json.substr(height_pos), "height");
        }

        // coinbase
        size_t coinbase_pos = utxo_json.find("\"coinbase\":", pos);
        if (coinbase_pos != std::string::npos && coinbase_pos < pos + 400) {
            utxo.coinbase = (utxo_json.find("true", coinbase_pos) < coinbase_pos + 20);
        }

        if (utxo.value > 0) {
            utxos.push_back(utxo);
        }
        pos = end;
    }

    if (utxos.empty()) {
        std::cerr << "Error: No UTXOs available\n";
        return;
    }

    // Get current chain height for coinbase maturity check
    std::string status_json = httpGet(host, port, "/status");
    uint32_t current_height = 0;
    size_t height_pos = status_json.find("\"height\":");
    if (height_pos != std::string::npos) {
        current_height = (uint32_t)jsonGetInt(status_json.substr(height_pos), "height");
    }

    // Filter out immature coinbase UTXOs and sort by height (oldest first)
    std::vector<UTXO> mature_utxos;
    for (const auto& utxo : utxos) {
        if (utxo.coinbase) {
            // Coinbase requires 100 confirmations
            uint32_t confirmations = current_height - utxo.height;
            if (confirmations < 100) {
                continue;  // Skip immature coinbase
            }
        }
        mature_utxos.push_back(utxo);
    }

    // Sort by height (oldest first = most confirmations)
    std::sort(mature_utxos.begin(), mature_utxos.end(), [](const UTXO& a, const UTXO& b) {
        return a.height < b.height;
    });

    if (mature_utxos.empty()) {
        std::cerr << "Error: No mature UTXOs available (coinbase requires 100 confirmations)\n";
        std::cerr << "Current height: " << current_height << "\n";
        return;
    }

    // Calculate total available (mature only)
    uint64_t total_available = 0;
    for (const auto& utxo : mature_utxos) total_available += utxo.value;

    uint64_t fee = 1000;  // 0.00001 FTC fee

    if (total_available < amount + fee) {
        std::cerr << "Error: Insufficient funds. Available (mature): "
                  << (total_available / 100000000.0) << " FTC\n";
        return;
    }

    // Select UTXOs (oldest first)
    std::vector<UTXO> selected_utxos;
    uint64_t selected_amount = 0;
    for (const auto& utxo : mature_utxos) {
        selected_utxos.push_back(utxo);
        selected_amount += utxo.value;
        if (selected_amount >= amount + fee) break;
    }

    // Build transaction
    std::array<uint8_t, 20> to_hash = *to_hash_opt;
    std::array<uint8_t, 20> change_hash;
    memcpy(change_hash.data(), from_hash20, 20);

    auto tx = buildTransaction(selected_utxos, to_hash, amount, fee, change_hash, privkey, pubkey);

    if (tx.empty()) {
        std::cerr << "Error: Failed to build transaction\n";
        return;
    }

    std::string tx_hex = toHex(tx.data(), tx.size());

    // Broadcast
    std::string post_body = "{\"hex\":\"" + tx_hex + "\"}";
    std::string result = httpPost(host, port, "/tx", post_body);

    std::cout << "\n";
    std::cout << "Transaction sent!\n";
    std::cout << "From:    " << from_address << "\n";
    std::cout << "To:      " << to_address << "\n";
    std::cout << "Amount:  " << (amount / 100000000.0) << " FTC\n";
    std::cout << "Fee:     " << (fee / 100000000.0) << " FTC\n";
    std::cout << "TX Hex:  " << tx_hex.substr(0, 64) << "...\n";
    std::cout << "Result:  " << result << "\n\n";
}

void cmdUtxos(const std::string& address, const std::string& node = "::1") {
    std::string host;
    int port;
    parseNodeAddress(node, host, port);

    std::string json = httpGet(host, port, "/utxo/" + address);

    if (json.empty()) {
        std::cerr << "Error: Could not connect to node\n";
        return;
    }

    if (json.find("\"error\"") != std::string::npos) {
        std::cerr << "Error: " << json << "\n";
        return;
    }

    std::cout << "\n";
    std::cout << "UTXOs for " << address << "\n";
    std::cout << std::string(72, '=') << "\n";
    std::cout << std::left << std::setw(66) << "TXID" << " "
              << std::setw(5) << "VOUT" << " "
              << std::setw(18) << "AMOUNT" << " "
              << std::setw(8) << "HEIGHT" << "\n";
    std::cout << std::string(72, '-') << "\n";

    // Parse UTXOs from JSON
    size_t pos = 0;
    int count = 0;
    uint64_t total = 0;

    while ((pos = json.find("\"txid\":", pos)) != std::string::npos) {
        // txid
        size_t start = json.find("\"", pos + 7) + 1;
        size_t end = json.find("\"", start);
        std::string txid = json.substr(start, end - start);

        // vout
        int64_t vout = jsonGetInt(json.substr(pos), "vout");

        // amount
        int64_t amount = jsonGetInt(json.substr(pos), "amount");

        // height
        int64_t height = jsonGetInt(json.substr(pos), "height");

        std::cout << txid.substr(0, 64) << "... "
                  << std::setw(5) << vout << " "
                  << std::setw(18) << std::fixed << std::setprecision(8) << (amount / 100000000.0) << " "
                  << std::setw(8) << height << "\n";

        total += amount;
        count++;
        pos = end;
    }

    std::cout << std::string(72, '=') << "\n";
    std::cout << "Total: " << count << " UTXOs, " << std::fixed << std::setprecision(8)
              << (total / 100000000.0) << " FTC\n\n";
}

void cmdHistory(const std::string& address, const std::string& node = "::1") {
    std::string host;
    int port;
    parseNodeAddress(node, host, port);

    std::string json = httpGet(host, port, "/address/" + address + "/history");

    if (json.empty()) {
        std::cerr << "Error: Could not connect to node\n";
        return;
    }

    if (json.find("\"error\"") != std::string::npos) {
        std::cerr << "Error: " << json << "\n";
        return;
    }

    std::cout << "\n";
    std::cout << "Transaction History for " << address << "\n";
    std::cout << std::string(80, '=') << "\n";
    std::cout << std::left << std::setw(66) << "TXID" << " "
              << std::setw(8) << "TYPE" << " "
              << std::setw(18) << "AMOUNT" << " "
              << std::setw(8) << "CONFS" << "\n";
    std::cout << std::string(80, '-') << "\n";

    // Parse transactions from JSON
    size_t pos = 0;
    int count = 0;

    while ((pos = json.find("\"txid\":", pos)) != std::string::npos) {
        // txid
        size_t start = json.find("\"", pos + 7) + 1;
        size_t end = json.find("\"", start);
        std::string txid = json.substr(start, end - start);

        // type
        std::string tx_type = jsonGetString(json.substr(pos), "type");

        // amount
        int64_t amount = jsonGetInt(json.substr(pos), "amount");

        // confirmations
        int64_t confs = jsonGetInt(json.substr(pos), "confirmations");

        std::cout << txid.substr(0, 64) << "... "
                  << std::setw(8) << tx_type << " "
                  << std::setw(18) << std::fixed << std::setprecision(8) << (amount / 100000000.0) << " "
                  << std::setw(8) << confs << "\n";

        count++;
        pos = end;
    }

    std::cout << std::string(80, '=') << "\n";
    std::cout << "Total: " << count << " transactions\n\n";
}

void printUsage() {
    std::cout << "FTC Wallet 1.0.0\n";
    std::cout << "Kristian Pilatovich 20091227 - First Real P2P\n\n";
    std::cout << "Usage:\n";
    std::cout << "  ftc-wallet new                              Generate new wallet\n";
    std::cout << "  ftc-wallet balance <address> [node]         Check balance\n";
    std::cout << "  ftc-wallet send <privkey> <to> <amount> [node]  Send FTC\n";
    std::cout << "  ftc-wallet history <address> [node]         Transaction history\n";
    std::cout << "  ftc-wallet utxos <address> [node]           List UTXOs\n";
    std::cout << "\n";
    std::cout << "Examples:\n";
    std::cout << "  ftc-wallet new\n";
    std::cout << "  ftc-wallet balance ftc1q3rk5jjlt50gs3n9p402063h54g9xdxgtmkpeyy\n";
    std::cout << "  ftc-wallet utxos ftc1q3rk5jjlt50gs3n9p402063h54g9xdxgtmkpeyy\n";
    std::cout << "  ftc-wallet history ftc1q3rk5jjlt50gs3n9p402063h54g9xdxgtmkpeyy\n";
    std::cout << "  ftc-wallet send 0da370538de77c959b4d267682bf98aad0447469347d89b6314dfd47d477dc07 \\\n";
    std::cout << "                  ftc1qd235kpsaazd6tl0je4jl2wm43jd9sw2u2ecwk2 10.5\n\n";
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    if (argc < 2) {
        printUsage();
        return 0;
    }

    std::string cmd = argv[1];

    if (cmd == "new" || cmd == "generate") {
        cmdNew();
    } else if (cmd == "balance" || cmd == "bal") {
        if (argc < 3) {
            std::cerr << "Usage: ftc-wallet balance <address> [node]\n";
            return 1;
        }
        std::string node = (argc >= 4) ? argv[3] : "::1";
        cmdBalance(argv[2], node);
    } else if (cmd == "send") {
        if (argc < 5) {
            std::cerr << "Usage: ftc-wallet send <privkey> <to> <amount> [node]\n";
            return 1;
        }
        std::string node = (argc >= 6) ? argv[5] : "::1";
        cmdSend(argv[2], argv[3], argv[4], node);
    } else if (cmd == "utxos" || cmd == "utxo") {
        if (argc < 3) {
            std::cerr << "Usage: ftc-wallet utxos <address> [node]\n";
            return 1;
        }
        std::string node = (argc >= 4) ? argv[3] : "::1";
        cmdUtxos(argv[2], node);
    } else if (cmd == "history" || cmd == "hist" || cmd == "txs") {
        if (argc < 3) {
            std::cerr << "Usage: ftc-wallet history <address> [node]\n";
            return 1;
        }
        std::string node = (argc >= 4) ? argv[3] : "::1";
        cmdHistory(argv[2], node);
    } else if (cmd == "--help" || cmd == "-h") {
        printUsage();
    } else {
        std::cerr << "Unknown command: " << cmd << "\n";
        printUsage();
        return 1;
    }

    return 0;
}
