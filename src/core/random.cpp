#include "random.h"

#include <bit>
#include <cstring>
#include <limits>
#include <stdexcept>

#include <openssl/rand.h>

namespace core {

// ---------------------------------------------------------------------------
// Cryptographic helpers
// ---------------------------------------------------------------------------

void get_random_bytes(std::span<uint8_t> buf) {
    if (buf.empty()) {
        return;
    }
    // RAND_bytes returns 1 on success, 0 or -1 on failure.
    if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1) {
        throw std::runtime_error(
            "core::get_random_bytes: RAND_bytes failed"
        );
    }
}

uint64_t get_random_uint64() {
    uint64_t value = 0;
    auto buf = std::span<uint8_t>(
        reinterpret_cast<uint8_t*>(&value), sizeof(value)
    );
    get_random_bytes(buf);
    return value;
}

uint32_t get_random_uint32() {
    uint32_t value = 0;
    auto buf = std::span<uint8_t>(
        reinterpret_cast<uint8_t*>(&value), sizeof(value)
    );
    get_random_bytes(buf);
    return value;
}

uint64_t get_random_range(uint64_t max) {
    if (max == 0) {
        throw std::invalid_argument(
            "core::get_random_range: max must be > 0"
        );
    }
    if (max == 1) {
        return 0;
    }

    // Rejection sampling to eliminate modulo bias.
    // threshold == (2^64 - max) % max, which is the number of values in
    // [0, threshold) that would cause bias if we took value % max.
    const uint64_t threshold = (-max) % max;

    for (;;) {
        const uint64_t value = get_random_uint64();
        if (value >= threshold) {
            return value % max;
        }
        // Retry probability < max / 2^64, typically negligible.
    }
}

void random_seed(std::span<const uint8_t> seed) {
    if (!seed.empty()) {
        RAND_seed(seed.data(), static_cast<int>(seed.size()));
    }
}

std::vector<uint8_t> get_random_bytes_vec(size_t count) {
    std::vector<uint8_t> result(count);
    if (count > 0) {
        get_random_bytes(result);
    }
    return result;
}

// ---------------------------------------------------------------------------
// InsecureRandom -- xoshiro256** implementation
// ---------------------------------------------------------------------------

// splitmix64 is used to expand a single 64-bit seed into the 256-bit state
// required by xoshiro256**.
static uint64_t splitmix64(uint64_t& state) {
    state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

void InsecureRandom::seed_from(uint64_t value) {
    uint64_t sm = value;
    state_[0] = splitmix64(sm);
    state_[1] = splitmix64(sm);
    state_[2] = splitmix64(sm);
    state_[3] = splitmix64(sm);
}

InsecureRandom::InsecureRandom(uint64_t seed) {
    if (seed == 0) {
        // Auto-seed from the cryptographic RNG.
        auto buf = std::span<uint8_t>(
            reinterpret_cast<uint8_t*>(state_.data()),
            state_.size() * sizeof(uint64_t)
        );
        get_random_bytes(buf);
        // Ensure state is not all-zero (degenerate for xoshiro).
        bool all_zero = true;
        for (auto s : state_) {
            if (s != 0) { all_zero = false; break; }
        }
        if (all_zero) {
            state_[0] = 1;
        }
    } else {
        seed_from(seed);
    }
}

uint64_t InsecureRandom::next_raw() {
    // xoshiro256** -- Blackman & Vigna 2018.
    const uint64_t result =
        std::rotl(state_[1] * 5, 7) * 9;

    const uint64_t t = state_[1] << 17;

    state_[2] ^= state_[0];
    state_[3] ^= state_[1];
    state_[1] ^= state_[2];
    state_[0] ^= state_[3];

    state_[2] ^= t;
    state_[3] = std::rotl(state_[3], 45);

    return result;
}

uint64_t InsecureRandom::next() {
    return next_raw();
}

uint64_t InsecureRandom::range(uint64_t max) {
    if (max == 0) {
        throw std::invalid_argument(
            "InsecureRandom::range: max must be > 0"
        );
    }
    if (max == 1) {
        return 0;
    }

    // Classic rejection sampling -- portable across all compilers (no
    // __uint128_t required, which MSVC does not support).
    // We compute the largest multiple of |max| that fits in [0, 2^64)
    // and reject any sample that falls in the leftover tail.
    const uint64_t threshold = (-max) % max;  // (2^64 - max) % max

    for (;;) {
        const uint64_t value = next_raw();
        if (value >= threshold) {
            return value % max;
        }
        // Retry probability < max / 2^64, typically negligible.
    }
}

}  // namespace core
