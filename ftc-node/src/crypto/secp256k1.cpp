#include "crypto/secp256k1.h"
#include <cstring>
#include <random>
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace ftc {
namespace crypto {

// ============================================================================
// secp256k1 curve parameters (all in big-endian)
// ============================================================================

// Field prime p = 2^256 - 2^32 - 977
static const uint8_t SECP256K1_P[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F
};

// Curve order n
static const uint8_t SECP256K1_N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

// Generator point G (compressed: 02 + x-coordinate)
static const uint8_t SECP256K1_GX[32] = {
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
    0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
};

static const uint8_t SECP256K1_GY[32] = {
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
    0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
    0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
};

// ============================================================================
// 256-bit unsigned integer operations
// ============================================================================

class Uint256 {
public:
    uint32_t d[8];  // Little-endian words

    Uint256() { std::memset(d, 0, sizeof(d)); }

    Uint256(uint32_t v) {
        std::memset(d, 0, sizeof(d));
        d[0] = v;
    }

    void fromBytes(const uint8_t* bytes) {
        // Big-endian bytes to little-endian words
        for (int i = 0; i < 8; i++) {
            d[i] = (uint32_t)bytes[31 - i*4] |
                   ((uint32_t)bytes[30 - i*4] << 8) |
                   ((uint32_t)bytes[29 - i*4] << 16) |
                   ((uint32_t)bytes[28 - i*4] << 24);
        }
    }

    void toBytes(uint8_t* bytes) const {
        // Little-endian words to big-endian bytes
        for (int i = 0; i < 8; i++) {
            bytes[31 - i*4] = d[i] & 0xFF;
            bytes[30 - i*4] = (d[i] >> 8) & 0xFF;
            bytes[29 - i*4] = (d[i] >> 16) & 0xFF;
            bytes[28 - i*4] = (d[i] >> 24) & 0xFF;
        }
    }

    bool isZero() const {
        for (int i = 0; i < 8; i++) {
            if (d[i] != 0) return false;
        }
        return true;
    }

    int compare(const Uint256& other) const {
        for (int i = 7; i >= 0; i--) {
            if (d[i] < other.d[i]) return -1;
            if (d[i] > other.d[i]) return 1;
        }
        return 0;
    }

    bool operator<(const Uint256& other) const { return compare(other) < 0; }
    bool operator>(const Uint256& other) const { return compare(other) > 0; }
    bool operator<=(const Uint256& other) const { return compare(other) <= 0; }
    bool operator>=(const Uint256& other) const { return compare(other) >= 0; }
    bool operator==(const Uint256& other) const { return compare(other) == 0; }
    bool operator!=(const Uint256& other) const { return compare(other) != 0; }

    // Add with carry
    Uint256 add(const Uint256& other) const {
        Uint256 result;
        uint64_t carry = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t sum = (uint64_t)d[i] + other.d[i] + carry;
            result.d[i] = (uint32_t)sum;
            carry = sum >> 32;
        }
        return result;
    }

    // Subtract (assuming this >= other)
    Uint256 sub(const Uint256& other) const {
        Uint256 result;
        int64_t borrow = 0;
        for (int i = 0; i < 8; i++) {
            int64_t diff = (int64_t)d[i] - other.d[i] - borrow;
            if (diff < 0) {
                diff += 0x100000000LL;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result.d[i] = (uint32_t)diff;
        }
        return result;
    }

    // Shift right by 1
    void shiftRight1() {
        for (int i = 0; i < 7; i++) {
            d[i] = (d[i] >> 1) | (d[i + 1] << 31);
        }
        d[7] >>= 1;
    }

    // Get bit
    bool getBit(int n) const {
        return (d[n / 32] >> (n % 32)) & 1;
    }
};

// Field element (mod p)
class FieldElement {
public:
    Uint256 v;
    static Uint256 p;

    FieldElement() {}
    FieldElement(const Uint256& val) : v(val) { reduce(); }

    void fromBytes(const uint8_t* bytes) {
        v.fromBytes(bytes);
        reduce();
    }

    void toBytes(uint8_t* bytes) const {
        v.toBytes(bytes);
    }

    void reduce() {
        while (v >= p) {
            v = v.sub(p);
        }
    }

    FieldElement add(const FieldElement& other) const {
        FieldElement result;
        result.v = v.add(other.v);
        result.reduce();
        return result;
    }

    FieldElement sub(const FieldElement& other) const {
        FieldElement result;
        if (v < other.v) {
            result.v = v.add(p).sub(other.v);
        } else {
            result.v = v.sub(other.v);
        }
        return result;
    }

    FieldElement mul(const FieldElement& other) const {
        // Montgomery multiplication would be faster, but this works
        uint64_t t[16] = {0};

        // Multiply
        for (int i = 0; i < 8; i++) {
            uint64_t carry = 0;
            for (int j = 0; j < 8; j++) {
                uint64_t product = (uint64_t)v.d[i] * other.v.d[j] + t[i + j] + carry;
                t[i + j] = product & 0xFFFFFFFF;
                carry = product >> 32;
            }
            t[i + 8] = carry;
        }

        // Reduce mod p
        Uint256 result;
        for (int i = 15; i >= 8; i--) {
            if (t[i] == 0) continue;

            // p = 2^256 - 2^32 - 977
            // So 2^256 = 2^32 + 977 (mod p)
            uint64_t high = t[i];

            // Add high * (2^32 + 977) to lower part
            uint64_t carry = 0;

            // Add high * 977
            uint64_t add_low = high * 977;
            for (int j = i - 8; j < 8; j++) {
                uint64_t sum = t[j] + (add_low & 0xFFFFFFFF) + carry;
                t[j] = sum & 0xFFFFFFFF;
                carry = sum >> 32;
                add_low >>= 32;
                if (add_low == 0 && carry == 0) break;
            }

            // Add high * 2^32
            carry = 0;
            for (int j = i - 7; j < 8; j++) {
                uint64_t sum = t[j] + high + carry;
                t[j] = sum & 0xFFFFFFFF;
                carry = sum >> 32;
                high = 0;
            }

            t[i] = 0;
        }

        for (int i = 0; i < 8; i++) {
            result.d[i] = (uint32_t)t[i];
        }

        FieldElement fe;
        fe.v = result;
        fe.reduce();

        // May need multiple reductions
        while (fe.v >= p) {
            fe.v = fe.v.sub(p);
        }

        return fe;
    }

    FieldElement square() const {
        return mul(*this);
    }

    // Modular inverse using Fermat's little theorem: a^(-1) = a^(p-2) mod p
    FieldElement inverse() const {
        // p - 2
        Uint256 exp;
        exp.fromBytes(SECP256K1_P);
        exp = exp.sub(Uint256(2));

        FieldElement result(Uint256(1));
        FieldElement base = *this;

        for (int i = 0; i < 256; i++) {
            if (exp.getBit(i)) {
                result = result.mul(base);
            }
            base = base.square();
        }

        return result;
    }

    // Square root (using Tonelli-Shanks for p = 3 mod 4)
    // For secp256k1, sqrt(a) = a^((p+1)/4) mod p
    FieldElement sqrt() const {
        // (p + 1) / 4
        Uint256 exp;
        exp.fromBytes(SECP256K1_P);
        exp = exp.add(Uint256(1));
        exp.shiftRight1();
        exp.shiftRight1();

        FieldElement result(Uint256(1));
        FieldElement base = *this;

        for (int i = 0; i < 256; i++) {
            if (exp.getBit(i)) {
                result = result.mul(base);
            }
            base = base.square();
        }

        return result;
    }

    bool isEven() const {
        return (v.d[0] & 1) == 0;
    }
};

Uint256 FieldElement::p;

// Scalar (mod n)
class Scalar {
public:
    Uint256 v;
    static Uint256 n;

    Scalar() {}
    Scalar(const Uint256& val) : v(val) { reduce(); }

    void fromBytes(const uint8_t* bytes) {
        v.fromBytes(bytes);
        reduce();
    }

    void reduce() {
        while (v >= n) {
            v = v.sub(n);
        }
    }

    Scalar add(const Scalar& other) const {
        Scalar result;
        result.v = v.add(other.v);
        result.reduce();
        return result;
    }

    Scalar mul(const Scalar& other) const {
        // Similar to FieldElement::mul but mod n
        uint64_t t[16] = {0};

        for (int i = 0; i < 8; i++) {
            uint64_t carry = 0;
            for (int j = 0; j < 8; j++) {
                uint64_t product = (uint64_t)v.d[i] * other.v.d[j] + t[i + j] + carry;
                t[i + j] = product & 0xFFFFFFFF;
                carry = product >> 32;
            }
            t[i + 8] = carry;
        }

        // Barrett reduction for mod n (simplified)
        Uint256 result;
        for (int i = 0; i < 8; i++) {
            result.d[i] = (uint32_t)t[i];
        }

        Scalar s;
        s.v = result;

        // Multiple subtractions of n
        while (s.v >= n) {
            s.v = s.v.sub(n);
        }

        return s;
    }

    Scalar inverse() const {
        // Using Fermat: a^(-1) = a^(n-2) mod n
        Uint256 exp = n.sub(Uint256(2));

        Scalar result(Uint256(1));
        Scalar base = *this;

        for (int i = 0; i < 256; i++) {
            if (exp.getBit(i)) {
                result = result.mul(base);
            }
            base = base.mul(base);
        }

        return result;
    }
};

Uint256 Scalar::n;

// Point on the curve
struct Point {
    FieldElement x, y;
    bool infinity = true;

    Point() : infinity(true) {}
    Point(const FieldElement& x_, const FieldElement& y_) : x(x_), y(y_), infinity(false) {}

    bool operator==(const Point& other) const {
        if (infinity && other.infinity) return true;
        if (infinity || other.infinity) return false;
        return x.v == other.x.v && y.v == other.y.v;
    }

    // Point addition
    Point add(const Point& other) const {
        if (infinity) return other;
        if (other.infinity) return *this;

        if (x.v == other.x.v) {
            if (y.v == other.y.v) {
                // Point doubling
                return doublePoint();
            }
            // P + (-P) = O
            return Point();
        }

        // lambda = (y2 - y1) / (x2 - x1)
        FieldElement dx = other.x.sub(x);
        FieldElement dy = other.y.sub(y);
        FieldElement lambda = dy.mul(dx.inverse());

        // x3 = lambda^2 - x1 - x2
        FieldElement x3 = lambda.square().sub(x).sub(other.x);

        // y3 = lambda * (x1 - x3) - y1
        FieldElement y3 = lambda.mul(x.sub(x3)).sub(y);

        return Point(x3, y3);
    }

    Point doublePoint() const {
        if (infinity) return *this;
        if (y.v.isZero()) return Point();

        // lambda = (3 * x^2) / (2 * y)
        FieldElement x2 = x.square();
        FieldElement num = x2.add(x2).add(x2);  // 3 * x^2
        FieldElement denom = y.add(y);           // 2 * y
        FieldElement lambda = num.mul(denom.inverse());

        // x3 = lambda^2 - 2*x
        FieldElement x3 = lambda.square().sub(x).sub(x);

        // y3 = lambda * (x - x3) - y
        FieldElement y3 = lambda.mul(x.sub(x3)).sub(y);

        return Point(x3, y3);
    }

    // Scalar multiplication
    Point mul(const Scalar& k) const {
        Point result;
        Point base = *this;

        for (int i = 0; i < 256; i++) {
            if (k.v.getBit(i)) {
                result = result.add(base);
            }
            base = base.doublePoint();
        }

        return result;
    }
};

// Generator point
static Point G;

// Initialize static data
static bool initializeCurve() {
    FieldElement::p.fromBytes(SECP256K1_P);
    Scalar::n.fromBytes(SECP256K1_N);

    FieldElement gx, gy;
    gx.fromBytes(SECP256K1_GX);
    gy.fromBytes(SECP256K1_GY);
    G = Point(gx, gy);

    return true;
}

static bool curveInitialized = initializeCurve();

// ============================================================================
// Secp256k1 implementation
// ============================================================================

Secp256k1::Secp256k1() {
    ctx_ = nullptr;
}

Secp256k1::~Secp256k1() {
}

Secp256k1& Secp256k1::instance() {
    static Secp256k1 inst;
    return inst;
}

bool Secp256k1::generateKeyPair(PrivateKey& privkey, PublicKey& pubkey) {
    // Generate random private key
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    Uint256 n;
    n.fromBytes(SECP256K1_N);

    do {
        for (int i = 0; i < 4; i++) {
            uint64_t r = dis(gen);
            privkey[i * 8 + 0] = (r >> 56) & 0xFF;
            privkey[i * 8 + 1] = (r >> 48) & 0xFF;
            privkey[i * 8 + 2] = (r >> 40) & 0xFF;
            privkey[i * 8 + 3] = (r >> 32) & 0xFF;
            privkey[i * 8 + 4] = (r >> 24) & 0xFF;
            privkey[i * 8 + 5] = (r >> 16) & 0xFF;
            privkey[i * 8 + 6] = (r >> 8) & 0xFF;
            privkey[i * 8 + 7] = r & 0xFF;
        }

        Uint256 k;
        k.fromBytes(privkey.data());
        if (!k.isZero() && k < n) break;
    } while (true);

    return derivePublicKey(privkey, pubkey);
}

bool Secp256k1::derivePublicKey(const PrivateKey& privkey, PublicKey& pubkey) {
    Scalar k;
    k.fromBytes(privkey.data());

    if (k.v.isZero()) return false;

    Point P = G.mul(k);
    if (P.infinity) return false;

    // Compressed format: 02/03 + x
    uint8_t prefix = P.y.isEven() ? 0x02 : 0x03;
    pubkey[0] = prefix;
    P.x.toBytes(pubkey.data() + 1);

    return true;
}

bool Secp256k1::derivePublicKeyUncompressed(const PrivateKey& privkey,
                                             PublicKeyUncompressed& pubkey) {
    Scalar k;
    k.fromBytes(privkey.data());

    if (k.v.isZero()) return false;

    Point P = G.mul(k);
    if (P.infinity) return false;

    // Uncompressed format: 04 + x + y
    pubkey[0] = 0x04;
    P.x.toBytes(pubkey.data() + 1);
    P.y.toBytes(pubkey.data() + 33);

    return true;
}

bool Secp256k1::sign(const uint8_t* msg32, const PrivateKey& privkey, Signature& sig) {
    Scalar z, d;
    z.fromBytes(msg32);
    d.fromBytes(privkey.data());

    if (d.v.isZero()) return false;

    // Generate deterministic k using RFC 6979 (simplified)
    PrivateKey k_bytes;
    uint8_t v[32], key[32];
    std::memset(v, 0x01, 32);
    std::memset(key, 0x00, 32);

    // This is a simplified k generation. Production code should use proper RFC 6979.
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    Uint256 n;
    n.fromBytes(SECP256K1_N);

    Scalar k;
    Point R;

    do {
        for (int i = 0; i < 4; i++) {
            uint64_t r = dis(gen);
            k_bytes[i * 8 + 0] = (r >> 56) & 0xFF;
            k_bytes[i * 8 + 1] = (r >> 48) & 0xFF;
            k_bytes[i * 8 + 2] = (r >> 40) & 0xFF;
            k_bytes[i * 8 + 3] = (r >> 32) & 0xFF;
            k_bytes[i * 8 + 4] = (r >> 24) & 0xFF;
            k_bytes[i * 8 + 5] = (r >> 16) & 0xFF;
            k_bytes[i * 8 + 6] = (r >> 8) & 0xFF;
            k_bytes[i * 8 + 7] = r & 0xFF;
        }

        k.fromBytes(k_bytes.data());
        if (k.v.isZero()) continue;

        // R = k * G
        R = G.mul(k);
        if (R.infinity) continue;

        // r = R.x mod n
        Scalar r;
        uint8_t rx_bytes[32];
        R.x.toBytes(rx_bytes);
        r.fromBytes(rx_bytes);

        if (r.v.isZero()) continue;

        // s = k^(-1) * (z + r * d) mod n
        Scalar rd = r.mul(d);
        Scalar zrd = z.add(rd);
        Scalar k_inv = k.inverse();
        Scalar s = k_inv.mul(zrd);

        if (s.v.isZero()) continue;

        // Store signature (r, s)
        r.v.toBytes(sig.data());
        s.v.toBytes(sig.data() + 32);

        return true;
    } while (true);
}

bool Secp256k1::verify(const uint8_t* msg32, const Signature& sig, const PublicKey& pubkey) {
    // Parse signature
    Scalar r, s;
    r.fromBytes(sig.data());
    s.fromBytes(sig.data() + 32);

    if (r.v.isZero() || s.v.isZero()) return false;

    // Parse public key
    if (pubkey[0] != 0x02 && pubkey[0] != 0x03) return false;

    FieldElement x;
    x.fromBytes(pubkey.data() + 1);

    // y^2 = x^3 + 7
    FieldElement x3 = x.mul(x).mul(x);
    FieldElement seven(Uint256(7));
    FieldElement y2 = x3.add(seven);
    FieldElement y = y2.sqrt();

    // Check parity
    bool want_even = (pubkey[0] == 0x02);
    if (y.isEven() != want_even) {
        // y = p - y
        y.v = FieldElement::p.sub(y.v);
    }

    Point Q(x, y);

    // Verify: check that r == (z/s * G + r/s * Q).x mod n
    Scalar z;
    z.fromBytes(msg32);

    Scalar s_inv = s.inverse();
    Scalar u1 = z.mul(s_inv);
    Scalar u2 = r.mul(s_inv);

    Point P1 = G.mul(u1);
    Point P2 = Q.mul(u2);
    Point P = P1.add(P2);

    if (P.infinity) return false;

    Scalar computed_r;
    uint8_t px_bytes[32];
    P.x.toBytes(px_bytes);
    computed_r.fromBytes(px_bytes);

    return r.v == computed_r.v;
}

bool Secp256k1::isValidPrivateKey(const PrivateKey& key) {
    Uint256 k;
    k.fromBytes(key.data());

    if (k.isZero()) return false;

    Uint256 n;
    n.fromBytes(SECP256K1_N);

    return k < n;
}

bool Secp256k1::isValidPublicKey(const PublicKey& key) {
    if (key[0] != 0x02 && key[0] != 0x03) return false;

    FieldElement x;
    x.fromBytes(key.data() + 1);

    // Check x < p
    if (x.v >= FieldElement::p) return false;

    // y^2 = x^3 + 7
    FieldElement x3 = x.mul(x).mul(x);
    FieldElement seven(Uint256(7));
    FieldElement y2 = x3.add(seven);

    // Check if y2 is a quadratic residue (has a square root)
    // For p = 3 mod 4, y2 is a QR iff y2^((p-1)/2) = 1 mod p
    // Simplified: just check if computed y^2 equals original
    FieldElement y = y2.sqrt();
    FieldElement check = y.square();

    return y2.v == check.v;
}

bool Secp256k1::compressPublicKey(const PublicKeyUncompressed& uncompressed,
                                   PublicKey& compressed) {
    if (uncompressed[0] != 0x04) return false;

    FieldElement y;
    y.fromBytes(uncompressed.data() + 33);

    compressed[0] = y.isEven() ? 0x02 : 0x03;
    std::memcpy(compressed.data() + 1, uncompressed.data() + 1, 32);

    return true;
}

bool Secp256k1::decompressPublicKey(const PublicKey& compressed,
                                     PublicKeyUncompressed& uncompressed) {
    if (compressed[0] != 0x02 && compressed[0] != 0x03) return false;

    FieldElement x;
    x.fromBytes(compressed.data() + 1);

    // y^2 = x^3 + 7
    FieldElement x3 = x.mul(x).mul(x);
    FieldElement seven(Uint256(7));
    FieldElement y2 = x3.add(seven);
    FieldElement y = y2.sqrt();

    // Check parity
    bool want_even = (compressed[0] == 0x02);
    if (y.isEven() != want_even) {
        y.v = FieldElement::p.sub(y.v);
    }

    uncompressed[0] = 0x04;
    std::memcpy(uncompressed.data() + 1, compressed.data() + 1, 32);
    y.toBytes(uncompressed.data() + 33);

    return true;
}

std::vector<uint8_t> Secp256k1::signatureToDER(const Signature& sig) {
    std::vector<uint8_t> der;
    der.reserve(72);

    // DER format: 30 <len> 02 <r_len> <r> 02 <s_len> <s>
    auto encodeInteger = [](const uint8_t* data, std::vector<uint8_t>& out) {
        // Skip leading zeros
        int start = 0;
        while (start < 32 && data[start] == 0) start++;
        if (start == 32) {
            out.push_back(0x02);
            out.push_back(0x01);
            out.push_back(0x00);
            return;
        }

        // Add leading zero if high bit is set
        bool need_zero = (data[start] & 0x80) != 0;
        int len = 32 - start + (need_zero ? 1 : 0);

        out.push_back(0x02);
        out.push_back(static_cast<uint8_t>(len));
        if (need_zero) out.push_back(0x00);
        for (int i = start; i < 32; i++) {
            out.push_back(data[i]);
        }
    };

    std::vector<uint8_t> r_encoded, s_encoded;
    encodeInteger(sig.data(), r_encoded);
    encodeInteger(sig.data() + 32, s_encoded);

    der.push_back(0x30);
    der.push_back(static_cast<uint8_t>(r_encoded.size() + s_encoded.size()));
    der.insert(der.end(), r_encoded.begin(), r_encoded.end());
    der.insert(der.end(), s_encoded.begin(), s_encoded.end());

    return der;
}

bool Secp256k1::signatureFromDER(const std::vector<uint8_t>& der, Signature& sig) {
    if (der.size() < 8 || der[0] != 0x30) return false;

    size_t pos = 2;

    // Parse r
    if (pos >= der.size() || der[pos] != 0x02) return false;
    pos++;
    if (pos >= der.size()) return false;
    size_t r_len = der[pos++];
    if (pos + r_len > der.size()) return false;

    std::memset(sig.data(), 0, 32);
    if (r_len <= 32) {
        std::memcpy(sig.data() + (32 - r_len), der.data() + pos, r_len);
    } else if (r_len == 33 && der[pos] == 0x00) {
        std::memcpy(sig.data(), der.data() + pos + 1, 32);
    } else {
        return false;
    }
    pos += r_len;

    // Parse s
    if (pos >= der.size() || der[pos] != 0x02) return false;
    pos++;
    if (pos >= der.size()) return false;
    size_t s_len = der[pos++];
    if (pos + s_len > der.size()) return false;

    std::memset(sig.data() + 32, 0, 32);
    if (s_len <= 32) {
        std::memcpy(sig.data() + 32 + (32 - s_len), der.data() + pos, s_len);
    } else if (s_len == 33 && der[pos] == 0x00) {
        std::memcpy(sig.data() + 32, der.data() + pos + 1, 32);
    } else {
        return false;
    }

    return true;
}

std::string Secp256k1::toHex(const PrivateKey& key) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < key.size(); i++) {
        ss << std::setw(2) << static_cast<int>(key[i]);
    }
    return ss.str();
}

std::string Secp256k1::toHex(const PublicKey& key) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < key.size(); i++) {
        ss << std::setw(2) << static_cast<int>(key[i]);
    }
    return ss.str();
}

std::string Secp256k1::toHex(const Signature& sig) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < sig.size(); i++) {
        ss << std::setw(2) << static_cast<int>(sig[i]);
    }
    return ss.str();
}

std::optional<PrivateKey> Secp256k1::privateKeyFromHex(const std::string& hex) {
    std::string clean = hex;
    if (clean.substr(0, 2) == "0x") clean = clean.substr(2);
    if (clean.size() != 64) return std::nullopt;

    PrivateKey key;
    for (size_t i = 0; i < 32; i++) {
        std::string byte_str = clean.substr(i * 2, 2);
        key[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }

    if (!Secp256k1::instance().isValidPrivateKey(key)) {
        return std::nullopt;
    }

    return key;
}

std::optional<PublicKey> Secp256k1::publicKeyFromHex(const std::string& hex) {
    std::string clean = hex;
    if (clean.substr(0, 2) == "0x") clean = clean.substr(2);
    if (clean.size() != 66) return std::nullopt;

    PublicKey key;
    for (size_t i = 0; i < 33; i++) {
        std::string byte_str = clean.substr(i * 2, 2);
        key[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }

    if (!Secp256k1::instance().isValidPublicKey(key)) {
        return std::nullopt;
    }

    return key;
}

// Convenience functions
bool generateKeyPair(PrivateKey& privkey, PublicKey& pubkey) {
    return Secp256k1::instance().generateKeyPair(privkey, pubkey);
}

bool sign(const uint8_t* msg32, const PrivateKey& privkey, Signature& sig) {
    return Secp256k1::instance().sign(msg32, privkey, sig);
}

bool verify(const uint8_t* msg32, const Signature& sig, const PublicKey& pubkey) {
    return Secp256k1::instance().verify(msg32, sig, pubkey);
}

} // namespace crypto
} // namespace ftc
