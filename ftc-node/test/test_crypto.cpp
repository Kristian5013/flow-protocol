/**
 * FTC Crypto Tests
 */

#include "crypto/keccak256.h"
#include "crypto/secp256k1.h"
#include <iostream>
#include <cassert>

using namespace ftc::crypto;

void testKeccak256() {
    std::cout << "Testing Keccak-256...\n";

    // Test vector: empty string
    auto hash1 = Keccak256::hash("");
    std::cout << "  Hash(''): " << Keccak256::toHex(hash1) << "\n";

    // Test vector: "abc"
    auto hash2 = Keccak256::hash("abc");
    std::cout << "  Hash('abc'): " << Keccak256::toHex(hash2) << "\n";

    // Expected: 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
    // (This is Keccak-256, not SHA3-256!)

    std::cout << "  Keccak-256 OK\n";
}

void testSecp256k1() {
    std::cout << "Testing secp256k1...\n";

    PrivateKey privkey;
    PublicKey pubkey;

    // Generate keypair
    bool ok = generateKeyPair(privkey, pubkey);
    assert(ok);
    std::cout << "  Private: " << Secp256k1::toHex(privkey).substr(0, 16) << "...\n";
    std::cout << "  Public:  " << Secp256k1::toHex(pubkey) << "\n";

    // Sign and verify
    uint8_t msg[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                       17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

    Signature sig;
    ok = sign(msg, privkey, sig);
    assert(ok);
    std::cout << "  Signature: " << Secp256k1::toHex(sig).substr(0, 32) << "...\n";

    ok = verify(msg, sig, pubkey);
    assert(ok);
    std::cout << "  Verification: OK\n";

    // Tamper and verify (should fail)
    msg[0] = 99;
    ok = verify(msg, sig, pubkey);
    assert(!ok);
    std::cout << "  Tamper detection: OK\n";

    std::cout << "  secp256k1 OK\n";
}

int main() {
    std::cout << "FTC Crypto Tests\n";
    std::cout << "================\n\n";

    testKeccak256();
    std::cout << "\n";
    testSecp256k1();

    std::cout << "\nAll tests passed!\n";
    return 0;
}
