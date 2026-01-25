#include "node_id.h"
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace dht {

// Simple SHA1 implementation for node ID generation
namespace {

class SHA1 {
public:
    SHA1() { reset(); }

    void reset() {
        h_[0] = 0x67452301;
        h_[1] = 0xEFCDAB89;
        h_[2] = 0x98BADCFE;
        h_[3] = 0x10325476;
        h_[4] = 0xC3D2E1F0;
        block_idx_ = 0;
        total_bits_ = 0;
    }

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; i++) {
            block_[block_idx_++] = data[i];
            total_bits_ += 8;
            if (block_idx_ == 64) {
                processBlock();
                block_idx_ = 0;
            }
        }
    }

    void update(const std::string& data) {
        update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }

    std::array<uint8_t, 20> final() {
        // Padding
        block_[block_idx_++] = 0x80;
        if (block_idx_ > 56) {
            while (block_idx_ < 64) block_[block_idx_++] = 0;
            processBlock();
            block_idx_ = 0;
        }
        while (block_idx_ < 56) block_[block_idx_++] = 0;

        // Length in bits (big-endian)
        for (int i = 7; i >= 0; i--) {
            block_[block_idx_++] = (total_bits_ >> (i * 8)) & 0xFF;
        }
        processBlock();

        // Output (big-endian)
        std::array<uint8_t, 20> result;
        for (int i = 0; i < 5; i++) {
            result[i * 4 + 0] = (h_[i] >> 24) & 0xFF;
            result[i * 4 + 1] = (h_[i] >> 16) & 0xFF;
            result[i * 4 + 2] = (h_[i] >> 8) & 0xFF;
            result[i * 4 + 3] = h_[i] & 0xFF;
        }
        return result;
    }

private:
    uint32_t h_[5];
    uint8_t block_[64];
    size_t block_idx_;
    uint64_t total_bits_;

    static uint32_t rotl(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    void processBlock() {
        uint32_t w[80];

        // Prepare message schedule
        for (int i = 0; i < 16; i++) {
            w[i] = (block_[i * 4] << 24) | (block_[i * 4 + 1] << 16) |
                   (block_[i * 4 + 2] << 8) | block_[i * 4 + 3];
        }
        for (int i = 16; i < 80; i++) {
            w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];

        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        }

        h_[0] += a;
        h_[1] += b;
        h_[2] += c;
        h_[3] += d;
        h_[4] += e;
    }
};

} // anonymous namespace

NodeId::NodeId() {
    data_.fill(0);
}

NodeId::NodeId(const std::array<uint8_t, SIZE>& data) : data_(data) {}

NodeId::NodeId(const uint8_t* data) {
    std::memcpy(data_.data(), data, SIZE);
}

NodeId::NodeId(const std::string& data) {
    if (data.size() >= SIZE) {
        std::memcpy(data_.data(), data.data(), SIZE);
    } else {
        data_.fill(0);
        std::memcpy(data_.data(), data.data(), data.size());
    }
}

NodeId NodeId::random() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;

    std::array<uint8_t, SIZE> data;
    for (size_t i = 0; i < SIZE; i += 8) {
        uint64_t val = dist(gen);
        for (size_t j = 0; j < 8 && i + j < SIZE; j++) {
            data[i + j] = (val >> (j * 8)) & 0xFF;
        }
    }
    return NodeId(data);
}

NodeId NodeId::fromHash(const std::string& data) {
    SHA1 sha1;
    sha1.update(data);
    return NodeId(sha1.final());
}

NodeId NodeId::operator^(const NodeId& other) const {
    std::array<uint8_t, SIZE> result;
    for (size_t i = 0; i < SIZE; i++) {
        result[i] = data_[i] ^ other.data_[i];
    }
    return NodeId(result);
}

bool NodeId::operator<(const NodeId& other) const {
    return std::memcmp(data_.data(), other.data_.data(), SIZE) < 0;
}

bool NodeId::operator==(const NodeId& other) const {
    return std::memcmp(data_.data(), other.data_.data(), SIZE) == 0;
}

bool NodeId::operator!=(const NodeId& other) const {
    return !(*this == other);
}

int NodeId::bucketIndex(const NodeId& other) const {
    NodeId dist = *this ^ other;
    for (int i = 0; i < static_cast<int>(SIZE); i++) {
        if (dist.data_[i] != 0) {
            // Find first set bit in this byte
            uint8_t b = dist.data_[i];
            int bit = 7;
            while ((b & 0x80) == 0) {
                b <<= 1;
                bit--;
            }
            return (SIZE - 1 - i) * 8 + bit;
        }
    }
    return 0; // Same ID
}

std::string NodeId::toHex() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : data_) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

NodeId NodeId::fromHex(const std::string& hex) {
    std::array<uint8_t, SIZE> data;
    data.fill(0);

    size_t len = std::min(hex.size() / 2, SIZE);
    for (size_t i = 0; i < len; i++) {
        char c1 = hex[i * 2];
        char c2 = hex[i * 2 + 1];

        auto hexVal = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return 0;
        };

        data[i] = (hexVal(c1) << 4) | hexVal(c2);
    }
    return NodeId(data);
}

size_t NodeId::Hash::operator()(const NodeId& id) const {
    size_t hash = 0;
    for (size_t i = 0; i < std::min(sizeof(size_t), NodeId::SIZE); i++) {
        hash = (hash << 8) | id.data()[i];
    }
    return hash;
}

} // namespace dht
