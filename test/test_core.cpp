// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Unit tests for the core module.

#include "test_framework.h"

#include "core/types.h"
#include "core/hex.h"
#include "core/error.h"
#include "core/varint.h"
#include "core/base58.h"
#include "core/stream.h"
#include "core/serialize.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// Types -- uint256
// ============================================================================

TEST_CASE(Types, uint256_default_is_zero) {
    core::uint256 z;
    CHECK(z.is_zero());
    CHECK_EQ(z.to_hex(),
             "0000000000000000000000000000000000000000000000000000000000000000");
}

TEST_CASE(Types, uint256_from_hex_roundtrip) {
    std::string hex =
        "00000000000000000007a4e02e4a058662db0e67e8d2074b592603ed0db7ae53";
    auto val = core::uint256::from_hex(hex);
    CHECK(!val.is_zero());
    CHECK_EQ(val.to_hex(), hex);
}

TEST_CASE(Types, uint256_from_hex_with_prefix) {
    std::string hex =
        "0x00000000000000000007a4e02e4a058662db0e67e8d2074b592603ed0db7ae53";
    auto val = core::uint256::from_hex(hex);
    CHECK_EQ(val.to_hex(),
             "00000000000000000007a4e02e4a058662db0e67e8d2074b592603ed0db7ae53");
}

TEST_CASE(Types, uint256_from_bytes) {
    std::array<uint8_t, 32> bytes{};
    bytes[0] = 0x01;  // least-significant byte in LE storage
    auto val = core::uint256::from_bytes(std::span<const uint8_t, 32>(bytes));
    CHECK(!val.is_zero());
    // LE byte 0 = 0x01 means the number is 1, displayed as ...0001 in BE hex
    CHECK_EQ(val.to_hex(),
             "0000000000000000000000000000000000000000000000000000000000000001");
}

TEST_CASE(Types, uint256_comparison) {
    auto a = core::uint256::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000001");
    auto b = core::uint256::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000002");
    auto c = core::uint256::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000001");

    CHECK(a == c);
    CHECK(a != b);
    CHECK(a < b);
    CHECK(b > a);
    CHECK(a <= c);
    CHECK(a <= b);
    CHECK(b >= a);
}

TEST_CASE(Types, uint256_arithmetic) {
    auto val = core::uint256::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000006");
    auto doubled = val * 2;
    CHECK_EQ(doubled.to_hex(),
             "000000000000000000000000000000000000000000000000000000000000000c");

    auto halved = doubled / 2;
    CHECK_EQ(halved.to_hex(), val.to_hex());

    // In-place multiply
    val *= 3;
    CHECK_EQ(val.to_hex(),
             "0000000000000000000000000000000000000000000000000000000000000012");
    // In-place divide
    val /= 3;
    CHECK_EQ(val.to_hex(),
             "0000000000000000000000000000000000000000000000000000000000000006");
}

TEST_CASE(Types, uint256_shift_operators) {
    auto val = core::uint256::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000001");
    auto shifted = val << 8;
    CHECK_EQ(shifted.to_hex(),
             "0000000000000000000000000000000000000000000000000000000000000100");

    auto back = shifted >> 8;
    CHECK_EQ(back.to_hex(), val.to_hex());

    // In-place shift
    val <<= 4;
    CHECK_EQ(val.to_hex(),
             "0000000000000000000000000000000000000000000000000000000000000010");
    val >>= 4;
    CHECK_EQ(val.to_hex(),
             "0000000000000000000000000000000000000000000000000000000000000001");
}

// ============================================================================
// Types -- uint160
// ============================================================================

TEST_CASE(Types, uint160_default_is_zero) {
    core::uint160 z;
    CHECK(z.is_zero());
    CHECK_EQ(z.to_hex(), "0000000000000000000000000000000000000000");
}

TEST_CASE(Types, uint160_from_hex_roundtrip) {
    std::string hex = "89abcdef0123456789abcdef0123456789abcdef";
    auto val = core::uint160::from_hex(hex);
    CHECK(!val.is_zero());
    CHECK_EQ(val.to_hex(), hex);
}

TEST_CASE(Types, uint160_from_bytes) {
    std::array<uint8_t, 20> bytes{};
    bytes[19] = 0xff;  // most-significant byte in LE storage
    auto val = core::uint160::from_bytes(std::span<const uint8_t, 20>(bytes));
    CHECK(!val.is_zero());
    CHECK_EQ(val.to_hex(), "ff00000000000000000000000000000000000000");
}

TEST_CASE(Types, uint160_comparison) {
    auto a = core::uint160::from_hex(
        "0000000000000000000000000000000000000001");
    auto b = core::uint160::from_hex(
        "0000000000000000000000000000000000000002");
    CHECK(a < b);
    CHECK(a != b);
    CHECK(a == a);
}

// ============================================================================
// Hex
// ============================================================================

TEST_CASE(Hex, to_hex_basic) {
    std::vector<uint8_t> data = {0xde, 0xad, 0xbe, 0xef};
    CHECK_EQ(core::to_hex(data), "deadbeef");
}

TEST_CASE(Hex, to_hex_empty) {
    std::vector<uint8_t> data;
    CHECK_EQ(core::to_hex(data), "");
}

TEST_CASE(Hex, from_hex_valid) {
    auto result = core::from_hex("deadbeef");
    CHECK(result.has_value());
    CHECK_EQ(result->size(), 4u);
    CHECK_EQ((*result)[0], 0xde);
    CHECK_EQ((*result)[1], 0xad);
    CHECK_EQ((*result)[2], 0xbe);
    CHECK_EQ((*result)[3], 0xef);
}

TEST_CASE(Hex, from_hex_invalid) {
    // Odd length
    auto r1 = core::from_hex("abc");
    CHECK(!r1.has_value());
    // Non-hex characters
    auto r2 = core::from_hex("zzzz");
    CHECK(!r2.has_value());
}

TEST_CASE(Hex, is_hex_checks) {
    CHECK(core::is_hex("0123456789abcdefABCDEF"));
    CHECK(core::is_hex(""));
    CHECK(!core::is_hex("0g"));
    CHECK(!core::is_hex("abc"));  // odd length
}

TEST_CASE(Hex, reverse_hex) {
    // "aabbccdd" -> bytes aa bb cc dd -> reversed dd cc bb aa -> "ddccbbaa"
    CHECK_EQ(core::reverse_hex("aabbccdd"), "ddccbbaa");
    CHECK_EQ(core::reverse_hex("0102"), "0201");
    CHECK_EQ(core::reverse_hex(""), "");
}

// ============================================================================
// Error / Result
// ============================================================================

TEST_CASE(ErrorResult, error_creation) {
    core::Error err(core::ErrorCode::PARSE_ERROR, "bad input");
    CHECK_EQ(err.code(), core::ErrorCode::PARSE_ERROR);
    CHECK_EQ(err.message(), "bad input");
    CHECK(!err.is_ok());
    CHECK(static_cast<bool>(err));  // explicit bool: true when not ok
}

TEST_CASE(ErrorResult, error_none_is_ok) {
    core::Error ok_err;
    CHECK(ok_err.is_ok());
    CHECK(!static_cast<bool>(ok_err));
    CHECK_EQ(ok_err.code(), core::ErrorCode::NONE);
}

TEST_CASE(ErrorResult, result_with_value) {
    core::Result<int> r = 42;
    CHECK(r.ok());
    CHECK_EQ(r.value(), 42);
}

TEST_CASE(ErrorResult, result_with_error) {
    core::Result<int> r = core::Error(core::ErrorCode::PARSE_ERROR, "fail");
    CHECK(!r.ok());
    CHECK_EQ(r.error().code(), core::ErrorCode::PARSE_ERROR);
}

TEST_CASE(ErrorResult, result_value_or) {
    core::Result<int> good = 42;
    core::Result<int> bad = core::Error(core::ErrorCode::INTERNAL_ERROR, "x");
    CHECK_EQ(good.value_or(0), 42);
    CHECK_EQ(bad.value_or(-1), -1);
}

TEST_CASE(ErrorResult, result_map) {
    core::Result<int> r = 10;
    auto mapped = r.map([](int v) { return v * 2; });
    CHECK(mapped.ok());
    CHECK_EQ(mapped.value(), 20);

    // map over an error propagates the error
    core::Result<int> err = core::Error(core::ErrorCode::PARSE_ERROR, "e");
    auto mapped_err = err.map([](int v) { return v * 2; });
    CHECK(!mapped_err.ok());
    CHECK_EQ(mapped_err.error().code(), core::ErrorCode::PARSE_ERROR);
}

TEST_CASE(ErrorResult, result_and_then) {
    core::Result<int> r = 5;
    auto chained = r.and_then([](int v) -> core::Result<std::string> {
        return std::to_string(v * 3);
    });
    CHECK(chained.ok());
    CHECK_EQ(chained.value(), "15");

    // and_then on error propagates the error
    core::Result<int> err = core::Error(core::ErrorCode::VALIDATION_ERROR, "v");
    auto chained_err = err.and_then([](int v) -> core::Result<std::string> {
        return std::to_string(v);
    });
    CHECK(!chained_err.ok());
    CHECK_EQ(chained_err.error().code(), core::ErrorCode::VALIDATION_ERROR);
}

// ============================================================================
// Varint
// ============================================================================

TEST_CASE(Varint, encode_decode_zero) {
    auto encoded = core::encode_varint(0);
    CHECK_EQ(encoded.size(), 1u);
    CHECK_EQ(encoded[0], 0x00);

    auto [value, consumed] = core::decode_varint(encoded);
    CHECK_EQ(value, 0u);
    CHECK_EQ(consumed, 1u);
}

TEST_CASE(Varint, encode_decode_single_byte_max) {
    // 127 fits in a single byte
    auto encoded = core::encode_varint(127);
    CHECK_EQ(encoded.size(), 1u);
    CHECK_EQ(encoded[0], 0x7f);

    auto [value, consumed] = core::decode_varint(encoded);
    CHECK_EQ(value, 127u);
    CHECK_EQ(consumed, 1u);
}

TEST_CASE(Varint, encode_decode_two_bytes) {
    // 128 requires two bytes: 0x80 0x01
    auto encoded = core::encode_varint(128);
    CHECK_EQ(encoded.size(), 2u);
    CHECK_EQ(encoded[0], 0x80);
    CHECK_EQ(encoded[1], 0x01);

    auto [value, consumed] = core::decode_varint(encoded);
    CHECK_EQ(value, 128u);
    CHECK_EQ(consumed, 2u);
}

TEST_CASE(Varint, encode_decode_300) {
    // 300 -> 0xAC 0x02
    auto encoded = core::encode_varint(300);
    CHECK_EQ(encoded.size(), 2u);
    CHECK_EQ(encoded[0], 0xAC);
    CHECK_EQ(encoded[1], 0x02);

    auto [value, consumed] = core::decode_varint(encoded);
    CHECK_EQ(value, 300u);
    CHECK_EQ(consumed, 2u);
}

TEST_CASE(Varint, encode_decode_large_value) {
    uint64_t large = 0xFFFFFFFFFFFFFFFFULL;
    auto encoded = core::encode_varint(large);
    auto [value, consumed] = core::decode_varint(encoded);
    CHECK_EQ(value, large);
    CHECK_EQ(consumed, encoded.size());
}

TEST_CASE(Varint, varint_size_values) {
    CHECK_EQ(core::varint_size(0), 1u);
    CHECK_EQ(core::varint_size(127), 1u);
    CHECK_EQ(core::varint_size(128), 2u);
    CHECK_EQ(core::varint_size(300), 2u);
    CHECK_EQ(core::varint_size(16383), 2u);
    CHECK_EQ(core::varint_size(16384), 3u);
}

// ============================================================================
// Base58
// ============================================================================

TEST_CASE(Base58, encode_decode_roundtrip) {
    std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0x03, 0xff};
    std::string encoded = core::base58_encode(data);
    CHECK(!encoded.empty());

    auto decoded = core::base58_decode(encoded);
    CHECK(decoded.has_value());
    CHECK_EQ(decoded->size(), data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        CHECK_EQ((*decoded)[i], data[i]);
    }
}

TEST_CASE(Base58, encode_leading_zeros) {
    // Leading zero bytes map to leading '1' characters
    std::vector<uint8_t> data = {0x00, 0x00, 0x01};
    std::string encoded = core::base58_encode(data);
    CHECK_EQ(encoded[0], '1');
    CHECK_EQ(encoded[1], '1');
}

TEST_CASE(Base58, decode_invalid_character) {
    // '0', 'O', 'I', 'l' are not in the base58 alphabet
    auto result = core::base58_decode("0OIl");
    CHECK(!result.has_value());
}

TEST_CASE(Base58, base58check_roundtrip) {
    std::vector<uint8_t> payload = {0x01, 0x09, 0x66, 0x77, 0x60};
    std::string encoded = core::base58check_encode(payload);
    CHECK(!encoded.empty());

    auto decoded = core::base58check_decode(encoded);
    CHECK(decoded.has_value());
    CHECK_EQ(decoded->size(), payload.size());
    for (size_t i = 0; i < payload.size(); ++i) {
        CHECK_EQ((*decoded)[i], payload[i]);
    }
}

TEST_CASE(Base58, base58check_corrupted) {
    std::vector<uint8_t> payload = {0xAB, 0xCD};
    std::string encoded = core::base58check_encode(payload);
    // Corrupt last character
    std::string corrupted = encoded;
    corrupted.back() = (corrupted.back() == '1') ? '2' : '1';
    auto decoded = core::base58check_decode(corrupted);
    CHECK(!decoded.has_value());
}

TEST_CASE(Base58, encode_decode_with_version) {
    uint8_t version = 0x00;
    std::vector<uint8_t> payload = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14
    };
    std::string encoded = core::encode_with_version(version, payload);
    CHECK(!encoded.empty());

    auto decoded = core::decode_with_version(encoded);
    CHECK(decoded.has_value());
    CHECK_EQ(decoded->first, version);
    CHECK_EQ(decoded->second.size(), payload.size());
    for (size_t i = 0; i < payload.size(); ++i) {
        CHECK_EQ(decoded->second[i], payload[i]);
    }
}

// ============================================================================
// Stream
// ============================================================================

TEST_CASE(Stream, datastream_write_read) {
    core::DataStream ds;
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    ds.write(data);

    CHECK_EQ(ds.size(), 4u);
    CHECK_EQ(ds.remaining(), 4u);
    CHECK(!ds.eof());

    uint8_t buf[4];
    ds.read(std::span<uint8_t>(buf, 4));
    CHECK_EQ(buf[0], 0x01);
    CHECK_EQ(buf[1], 0x02);
    CHECK_EQ(buf[2], 0x03);
    CHECK_EQ(buf[3], 0x04);
    CHECK(ds.eof());
    CHECK_EQ(ds.remaining(), 0u);
}

TEST_CASE(Stream, datastream_from_vector) {
    std::vector<uint8_t> data = {0xAA, 0xBB, 0xCC};
    core::DataStream ds(data);

    CHECK_EQ(ds.size(), 3u);
    uint8_t b;
    ds.read(std::span<uint8_t>(&b, 1));
    CHECK_EQ(b, 0xAA);
    CHECK_EQ(ds.remaining(), 2u);
}

TEST_CASE(Stream, datastream_seek_and_tell) {
    std::vector<uint8_t> data = {0x10, 0x20, 0x30, 0x40};
    core::DataStream ds(data);

    CHECK_EQ(ds.tell(), 0u);
    ds.skip(2);
    CHECK_EQ(ds.tell(), 2u);

    uint8_t b;
    ds.read(std::span<uint8_t>(&b, 1));
    CHECK_EQ(b, 0x30);

    ds.seek(0);
    CHECK_EQ(ds.tell(), 0u);
    ds.read(std::span<uint8_t>(&b, 1));
    CHECK_EQ(b, 0x10);
}

TEST_CASE(Stream, datastream_clear_and_release) {
    core::DataStream ds;
    std::vector<uint8_t> data = {0x01, 0x02};
    ds.write(data);
    CHECK_EQ(ds.size(), 2u);

    auto released = ds.release();
    CHECK_EQ(released.size(), 2u);
    CHECK_EQ(ds.size(), 0u);

    ds.write(data);
    ds.clear();
    CHECK_EQ(ds.size(), 0u);
}

TEST_CASE(Stream, span_reader_basic) {
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    core::SpanReader reader(data);

    CHECK_EQ(reader.remaining(), 4u);
    CHECK(!reader.eof());

    uint8_t buf[2];
    reader.read(std::span<uint8_t>(buf, 2));
    CHECK_EQ(buf[0], 0xDE);
    CHECK_EQ(buf[1], 0xAD);
    CHECK_EQ(reader.remaining(), 2u);

    reader.read(std::span<uint8_t>(buf, 2));
    CHECK_EQ(buf[0], 0xBE);
    CHECK_EQ(buf[1], 0xEF);
    CHECK(reader.eof());
}

// ============================================================================
// Serialization
// ============================================================================

TEST_CASE(Serialization, ser_u32_roundtrip) {
    core::DataStream ds;
    core::ser_write_u32(ds, 0x12345678);

    CHECK_EQ(ds.size(), 4u);
    // Little-endian: least significant byte first
    CHECK_EQ(ds.data()[0], 0x78);
    CHECK_EQ(ds.data()[1], 0x56);
    CHECK_EQ(ds.data()[2], 0x34);
    CHECK_EQ(ds.data()[3], 0x12);

    uint32_t val = core::ser_read_u32(ds);
    CHECK_EQ(val, 0x12345678u);
}

TEST_CASE(Serialization, ser_u64_roundtrip) {
    core::DataStream ds;
    core::ser_write_u64(ds, 0xDEADBEEFCAFEBABEULL);

    CHECK_EQ(ds.size(), 8u);
    uint64_t val = core::ser_read_u64(ds);
    CHECK_EQ(val, 0xDEADBEEFCAFEBABEULL);
}

TEST_CASE(Serialization, ser_u8_and_u16) {
    core::DataStream ds;
    core::ser_write_u8(ds, 0xFF);
    core::ser_write_u16(ds, 0xABCD);

    CHECK_EQ(ds.size(), 3u);

    uint8_t v8 = core::ser_read_u8(ds);
    CHECK_EQ(v8, 0xFF);

    uint16_t v16 = core::ser_read_u16(ds);
    CHECK_EQ(v16, 0xABCD);
}

TEST_CASE(Serialization, ser_compact_size) {
    // Small value (< 253) uses 1 byte
    core::DataStream ds1;
    core::ser_write_compact_size(ds1, 100);
    CHECK_EQ(ds1.size(), 1u);
    CHECK_EQ(core::ser_read_compact_size(ds1), 100u);

    // Value 0xFFFF uses 3 bytes (0xFD prefix + 2 bytes)
    core::DataStream ds2;
    core::ser_write_compact_size(ds2, 0xFFFF);
    CHECK_EQ(ds2.size(), 3u);
    CHECK_EQ(core::ser_read_compact_size(ds2), 0xFFFFu);

    // Value 0x10000 uses 5 bytes (0xFE prefix + 4 bytes)
    core::DataStream ds3;
    core::ser_write_compact_size(ds3, 0x10000);
    CHECK_EQ(ds3.size(), 5u);
    CHECK_EQ(core::ser_read_compact_size(ds3), 0x10000u);
}

TEST_CASE(Serialization, ser_string_roundtrip) {
    core::DataStream ds;
    core::ser_write_string(ds, "hello");

    std::string result = core::ser_read_string(ds);
    CHECK_EQ(result, "hello");
    CHECK(ds.eof());
}

TEST_CASE(Serialization, ser_write_read_multiple) {
    // Write multiple values, read them back in order
    core::DataStream ds;
    core::ser_write_u32(ds, 1);
    core::ser_write_u64(ds, 2);
    core::ser_write_u8(ds, 3);

    CHECK_EQ(ds.size(), 4u + 8u + 1u);

    CHECK_EQ(core::ser_read_u32(ds), 1u);
    CHECK_EQ(core::ser_read_u64(ds), 2u);
    CHECK_EQ(core::ser_read_u8(ds), 3u);
    CHECK(ds.eof());
}

