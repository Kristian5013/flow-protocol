#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "core/error.h"

namespace crypto {

// Generate a BIP39 mnemonic phrase with the given word count.
// Valid word counts: 12, 15, 18, 21, 24 (corresponding to 128..256 bits of
// entropy in 32-bit increments).
// Uses OS-provided cryptographic randomness for entropy generation.
std::vector<std::string> generate_mnemonic(size_t word_count = 24);

// Convert a BIP39 mnemonic phrase to a 64-byte (512-bit) seed.
// Uses PBKDF2-HMAC-SHA512 with 2048 iterations and salt = "mnemonic" +
// passphrase (standard BIP39 seed derivation for interoperability).
// An empty passphrase is valid (no passphrase).
core::Result<std::vector<uint8_t>> mnemonic_to_seed(
    const std::vector<std::string>& words,
    std::string_view passphrase = "");

// Validate a mnemonic: checks that every word is in the BIP39 English
// wordlist, the word count is valid, and the checksum bits are correct.
// Checksum = first ENT/32 bits of Keccak256(entropy).
bool validate_mnemonic(const std::vector<std::string>& words);

// Convert a valid mnemonic back to its underlying entropy bytes.
// Returns an error if the mnemonic is invalid.
core::Result<std::vector<uint8_t>> mnemonic_to_entropy(
    const std::vector<std::string>& words);

// Convert raw entropy bytes to a mnemonic phrase.
// Entropy must be 16, 20, 24, 28, or 32 bytes (128..256 bits).
// Checksum = first ENT/32 bits of Keccak256(entropy).
core::Result<std::vector<std::string>> entropy_to_mnemonic(
    std::span<const uint8_t> entropy);

} // namespace crypto
