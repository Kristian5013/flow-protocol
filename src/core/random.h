#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace core {

// Fill |buf| with cryptographically secure random bytes (OpenSSL RAND_bytes).
// Throws std::runtime_error on failure.
void get_random_bytes(std::span<uint8_t> buf);

// Return a single cryptographically secure random 64-bit integer.
uint64_t get_random_uint64();

// Return a single cryptographically secure random 32-bit integer.
uint32_t get_random_uint32();

// Return a uniform random value in the half-open range [0, max).
// Throws std::invalid_argument if max == 0.
uint64_t get_random_range(uint64_t max);

// Add |seed| bytes of additional entropy to the OpenSSL PRNG pool.
void random_seed(std::span<const uint8_t> seed);

// Convenience wrapper that allocates and returns a vector of |count|
// cryptographically secure random bytes.
std::vector<uint8_t> get_random_bytes_vec(size_t count);

// ---------------------------------------------------------------------------
// InsecureRandom -- fast, non-cryptographic PRNG (xoshiro256**)
// ---------------------------------------------------------------------------
// Suitable for hash-table salting, randomised algorithms, fuzzing, etc.
// Do NOT use for any security-sensitive purpose.
class InsecureRandom {
public:
    // If |seed| is 0 the generator is automatically seeded from the
    // cryptographic RNG (get_random_bytes).
    explicit InsecureRandom(uint64_t seed = 0);

    // Return the next pseudo-random 64-bit value.
    uint64_t next();

    // Return a uniform pseudo-random value in [0, max).
    // Throws std::invalid_argument if max == 0.
    uint64_t range(uint64_t max);

private:
    // Internal helper: advance the xoshiro256** state.
    uint64_t next_raw();

    // Seed the four-element state array from a single 64-bit value using
    // splitmix64.
    void seed_from(uint64_t value);

    std::array<uint64_t, 4> state_{};
};

}  // namespace core
