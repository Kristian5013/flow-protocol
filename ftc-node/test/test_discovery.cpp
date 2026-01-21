/**
 * FTC Discovery Tests
 */

#include "discovery/ntp_client.h"
#include "discovery/range_calculator.h"
#include "discovery/discovery_engine.h"
#include "util/logging.h"
#include <iostream>
#include <cassert>

using namespace ftc::discovery;

void testRangeCalculator() {
    std::cout << "Testing Range Calculator...\n";

    RangeCalculator calc;

    std::cout << "  Total IPv4 /24 ranges: " << calc.getTotalIPv4Ranges() << "\n";

    // Test slot calculation
    uint64_t time_ms = 1737331200000ULL;  // 2026-01-20 00:00:00 UTC
    uint64_t slot = RangeCalculator::calculateSlot(time_ms);
    std::cout << "  Slot at genesis time: " << slot << "\n";

    // Test determinism - same slot should give same range
    uint32_t range1 = calc.getIPv4Range(slot);
    uint32_t range2 = calc.getIPv4Range(slot);
    assert(range1 == range2);
    std::cout << "  Determinism: OK (same slot -> same range)\n";

    // Test range expansion
    auto ips = RangeCalculator::expandIPv4Range(range1);
    assert(ips.size() == 254);
    std::cout << "  Range expansion: " << ips.size() << " IPs\n";

    // Test reserved check
    assert(RangeCalculator::isReservedIPv4(0x0A000001));  // 10.0.0.1
    assert(RangeCalculator::isReservedIPv4(0xC0A80001));  // 192.168.0.1
    assert(RangeCalculator::isReservedIPv4(0x7F000001));  // 127.0.0.1
    assert(!RangeCalculator::isReservedIPv4(0x08080808)); // 8.8.8.8
    std::cout << "  Reserved check: OK\n";

    std::cout << "  Range Calculator OK\n";
}

void testSlotSynchronization() {
    std::cout << "Testing Slot Synchronization...\n";

    // Simulate two nodes at the same time
    uint64_t time_ms = 1737331200000ULL + 12345678;  // Some arbitrary time

    uint64_t slot_node1 = RangeCalculator::calculateSlot(time_ms);
    uint64_t slot_node2 = RangeCalculator::calculateSlot(time_ms);

    assert(slot_node1 == slot_node2);
    std::cout << "  Same time -> same slot: OK\n";

    // Same slot -> same range
    RangeCalculator calc;
    uint32_t range_node1 = calc.getIPv4Range(slot_node1);
    uint32_t range_node2 = calc.getIPv4Range(slot_node2);

    assert(range_node1 == range_node2);
    std::cout << "  Same slot -> same range: OK\n";

    std::cout << "  Slot range: " << RangeCalculator::ipv4ToString(range_node1) << "/24\n";

    std::cout << "  Slot Synchronization OK\n";
}

void testIPv6Range() {
    std::cout << "Testing IPv6 Range...\n";

    RangeCalculator calc;
    uint64_t slot = 12345;

    IPv6Addr range = calc.getIPv6Range(slot);
    std::cout << "  IPv6 range: " << range.toString() << "/112\n";

    // Check it's in global unicast (2000::/3)
    assert((range.bytes[0] & 0xE0) == 0x20);
    std::cout << "  Global unicast check: OK\n";

    // Test sampling
    auto samples = RangeCalculator::sampleIPv6Range(range, 100);
    assert(samples.size() == 100);
    std::cout << "  IPv6 sampling: " << samples.size() << " addresses\n";

    std::cout << "  IPv6 Range OK\n";
}

int main() {
    ftc::log::init(ftc::log::Level::INFO);

    std::cout << "FTC Discovery Tests\n";
    std::cout << "===================\n\n";

    testRangeCalculator();
    std::cout << "\n";
    testSlotSynchronization();
    std::cout << "\n";
    testIPv6Range();

    std::cout << "\nAll tests passed!\n";
    return 0;
}
