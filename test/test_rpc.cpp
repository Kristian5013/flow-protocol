// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_framework.h"

#include "rpc/request.h"
#include "rpc/server.h"
#include "rpc/util.h"

#include <string>
#include <vector>

// ===================================================================
// JsonValue tests
// ===================================================================

TEST_CASE(JsonValue, TypeConstruction) {
    rpc::JsonValue null_val;
    CHECK(null_val.is_null());

    rpc::JsonValue bool_val(true);
    CHECK(bool_val.is_bool());
    CHECK_EQ(bool_val.get_bool(), true);

    rpc::JsonValue int_val(42);
    CHECK(int_val.is_int());
    CHECK_EQ(int_val.get_int(), static_cast<int64_t>(42));

    rpc::JsonValue double_val(3.14);
    CHECK(double_val.is_double());
    CHECK_NEAR(double_val.get_double(), 3.14, 0.001);

    rpc::JsonValue str_val("hello");
    CHECK(str_val.is_string());
    CHECK_EQ(str_val.get_string(), std::string("hello"));
}

TEST_CASE(JsonValue, ArrayAndObject) {
    rpc::JsonValue::Array arr;
    arr.push_back(rpc::JsonValue(1));
    arr.push_back(rpc::JsonValue("two"));
    arr.push_back(rpc::JsonValue(3.0));

    rpc::JsonValue arr_val(arr);
    CHECK(arr_val.is_array());
    CHECK_EQ(arr_val.size(), static_cast<size_t>(3));
    CHECK_EQ(arr_val[static_cast<size_t>(0)].get_int(), static_cast<int64_t>(1));
    CHECK_EQ(arr_val[static_cast<size_t>(1)].get_string(), std::string("two"));

    rpc::JsonValue::Object obj;
    obj["name"] = rpc::JsonValue("test");
    obj["count"] = rpc::JsonValue(5);

    rpc::JsonValue obj_val(obj);
    CHECK(obj_val.is_object());
    CHECK(obj_val.has_key("name"));
    CHECK(obj_val.has_key("count"));
    CHECK(!obj_val.has_key("missing"));
    CHECK_EQ(obj_val["name"].get_string(), std::string("test"));
    CHECK_EQ(obj_val["count"].get_int(), static_cast<int64_t>(5));
}

TEST_CASE(JsonValue, Equality) {
    rpc::JsonValue a(42);
    rpc::JsonValue b(42);
    rpc::JsonValue c(99);

    CHECK(a == b);
    CHECK(a != c);

    rpc::JsonValue s1("hello");
    rpc::JsonValue s2("hello");
    rpc::JsonValue s3("world");
    CHECK(s1 == s2);
    CHECK(s1 != s3);
}

// ===================================================================
// JSON parsing / serialization tests
// ===================================================================

TEST_CASE(JsonParsing, ParseSimpleValues) {
    auto val = rpc::parse_json("42");
    CHECK(val.is_int());
    CHECK_EQ(val.get_int(), static_cast<int64_t>(42));

    auto str = rpc::parse_json("\"hello world\"");
    CHECK(str.is_string());
    CHECK_EQ(str.get_string(), std::string("hello world"));

    auto bool_true = rpc::parse_json("true");
    CHECK(bool_true.is_bool());
    CHECK_EQ(bool_true.get_bool(), true);

    auto bool_false = rpc::parse_json("false");
    CHECK(bool_false.is_bool());
    CHECK_EQ(bool_false.get_bool(), false);

    auto null_val = rpc::parse_json("null");
    CHECK(null_val.is_null());
}

TEST_CASE(JsonParsing, ParseObject) {
    auto val = rpc::parse_json(R"({"method":"getinfo","params":[],"id":1})");
    CHECK(val.is_object());
    CHECK(val.has_key("method"));
    CHECK_EQ(val["method"].get_string(), std::string("getinfo"));
    CHECK(val["params"].is_array());
    CHECK_EQ(val["params"].size(), static_cast<size_t>(0));
    CHECK_EQ(val["id"].get_int(), static_cast<int64_t>(1));
}

TEST_CASE(JsonParsing, SerializeRoundTrip) {
    rpc::JsonValue::Object obj;
    obj["key"] = rpc::JsonValue("value");
    obj["num"] = rpc::JsonValue(123);
    rpc::JsonValue original(obj);

    std::string json_str = rpc::json_serialize(original);
    CHECK(!json_str.empty());

    auto parsed = rpc::parse_json(json_str);
    CHECK(parsed.is_object());
    CHECK_EQ(parsed["key"].get_string(), std::string("value"));
    CHECK_EQ(parsed["num"].get_int(), static_cast<int64_t>(123));
}

// ===================================================================
// RpcRequest tests
// ===================================================================

TEST_CASE(RpcRequest, FromJson) {
    rpc::JsonValue::Object obj;
    obj["method"] = rpc::JsonValue("getblockcount");
    obj["params"] = rpc::JsonValue(rpc::JsonValue::Array{});
    obj["id"] = rpc::JsonValue(1);

    auto req = rpc::RpcRequest::from_json(rpc::JsonValue(obj));
    CHECK_EQ(req.method, std::string("getblockcount"));
    CHECK(req.params.is_array());
    CHECK_EQ(req.id, static_cast<int64_t>(1));
}

TEST_CASE(RpcRequest, FromJsonWithParams) {
    rpc::JsonValue::Array params;
    params.push_back(rpc::JsonValue("blockhash123"));
    params.push_back(rpc::JsonValue(true));

    rpc::JsonValue::Object obj;
    obj["method"] = rpc::JsonValue("getblock");
    obj["params"] = rpc::JsonValue(params);
    obj["id"] = rpc::JsonValue(42);

    auto req = rpc::RpcRequest::from_json(rpc::JsonValue(obj));
    CHECK_EQ(req.method, std::string("getblock"));
    CHECK_EQ(req.params.size(), static_cast<size_t>(2));
    CHECK_EQ(req.params[static_cast<size_t>(0)].get_string(), std::string("blockhash123"));
    CHECK_EQ(req.params[static_cast<size_t>(1)].get_bool(), true);
    CHECK_EQ(req.id, static_cast<int64_t>(42));
}

// ===================================================================
// RpcResponse tests
// ===================================================================

TEST_CASE(RpcResponse, MakeResult) {
    auto resp = rpc::make_result(rpc::JsonValue(100), 1);
    CHECK_EQ(resp.id, static_cast<int64_t>(1));
    CHECK(resp.result.is_int());
    CHECK_EQ(resp.result.get_int(), static_cast<int64_t>(100));
    CHECK(resp.error.is_null());
}

TEST_CASE(RpcResponse, MakeError) {
    auto resp = rpc::make_error(rpc::RpcError::METHOD_NOT_FOUND, "Method not found", 5);
    CHECK_EQ(resp.id, static_cast<int64_t>(5));
    CHECK(resp.result.is_null());
    CHECK(!resp.error.is_null());
}

TEST_CASE(RpcResponse, ToJsonAndSerialize) {
    auto resp = rpc::make_result(rpc::JsonValue("ok"), 7);
    auto json_obj = resp.to_json();
    CHECK(json_obj.is_object());

    auto json_str = resp.serialize();
    CHECK(!json_str.empty());

    // Round-trip: parse the serialized string back
    auto parsed = rpc::parse_json(json_str);
    CHECK(parsed.is_object());
    CHECK(parsed.has_key("result"));
    CHECK_EQ(parsed["result"].get_string(), std::string("ok"));
}

// ===================================================================
// RPC utility tests
// ===================================================================

TEST_CASE(RpcUtil, ParamExtraction) {
    rpc::JsonValue::Array params;
    params.push_back(rpc::JsonValue("hello"));
    params.push_back(rpc::JsonValue(42));
    params.push_back(rpc::JsonValue(true));
    params.push_back(rpc::JsonValue(3.14));
    rpc::JsonValue params_val(params);

    CHECK_EQ(rpc::param_count(params_val), static_cast<size_t>(4));
    CHECK(rpc::param_exists(params_val, 0));
    CHECK(rpc::param_exists(params_val, 3));
    CHECK(!rpc::param_exists(params_val, 4));

    CHECK_EQ(rpc::param_string(params_val, 0), std::string("hello"));
    CHECK_EQ(rpc::param_int(params_val, 1), static_cast<int64_t>(42));
    CHECK_EQ(rpc::param_bool(params_val, 2), true);
    CHECK_NEAR(rpc::param_double(params_val, 3), 3.14, 0.001);
}

TEST_CASE(RpcUtil, ParamDefaults) {
    rpc::JsonValue::Array params;
    params.push_back(rpc::JsonValue("first"));
    rpc::JsonValue params_val(params);

    // Index 1 is out of range; should return defaults
    CHECK_EQ(rpc::param_string(params_val, 1, "default"), std::string("default"));
    CHECK_EQ(rpc::param_int(params_val, 1, 99), static_cast<int64_t>(99));
    CHECK_EQ(rpc::param_bool(params_val, 1, false), false);
    CHECK_NEAR(rpc::param_double(params_val, 1, 1.5), 1.5, 0.001);
}

TEST_CASE(RpcUtil, HexEncodeDecode) {
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    std::string hex = rpc::hex_encode(data);
    CHECK_EQ(hex, std::string("deadbeef"));

    auto decoded = rpc::hex_decode(hex);
    CHECK_EQ(decoded.size(), static_cast<size_t>(4));
    CHECK_EQ(decoded[0], static_cast<uint8_t>(0xDE));
    CHECK_EQ(decoded[1], static_cast<uint8_t>(0xAD));
    CHECK_EQ(decoded[2], static_cast<uint8_t>(0xBE));
    CHECK_EQ(decoded[3], static_cast<uint8_t>(0xEF));

    // Round-trip
    CHECK_EQ(rpc::hex_encode(rpc::hex_decode("cafebabe")), std::string("cafebabe"));
}

TEST_CASE(RpcUtil, HexValidation) {
    CHECK(rpc::is_valid_hex("deadbeef"));
    CHECK(rpc::is_valid_hex("0123456789abcdef"));
    CHECK(!rpc::is_valid_hex("xyz"));
    CHECK(!rpc::is_valid_hex("deadbee")); // odd length

    // With expected byte length
    CHECK(rpc::is_valid_hex("deadbeef", 4));
    CHECK(!rpc::is_valid_hex("deadbeef", 3));
}

TEST_CASE(RpcUtil, Base64EncodeDecode) {
    std::string input = "hello:world";
    std::string encoded = rpc::base64_encode(input);
    CHECK(!encoded.empty());
    std::string decoded = rpc::base64_decode(encoded);
    CHECK_EQ(decoded, input);

    // Known value: base64("user:pass") = "dXNlcjpwYXNz"
    CHECK_EQ(rpc::base64_encode("user:pass"), std::string("dXNlcjpwYXNz"));
    CHECK_EQ(rpc::base64_decode("dXNlcjpwYXNz"), std::string("user:pass"));
}

TEST_CASE(RpcUtil, FormatAmount) {
    CHECK_EQ(rpc::format_amount(100000000), std::string("1.00000000"));
    CHECK_EQ(rpc::format_amount(0), std::string("0.00000000"));
    CHECK_EQ(rpc::format_amount(50000000), std::string("0.50000000"));
    CHECK_EQ(rpc::format_amount(123456789), std::string("1.23456789"));
}

TEST_CASE(RpcUtil, ParseAmount) {
    // Integer value is treated as FTC: 1 FTC = 100,000,000 satoshis
    CHECK_EQ(rpc::parse_amount(rpc::JsonValue(1)), static_cast<int64_t>(100000000));

    // Floating-point FTC value: 1.0 FTC = 100,000,000 satoshis
    CHECK_EQ(rpc::parse_amount(rpc::JsonValue(1.0)), static_cast<int64_t>(100000000));
    CHECK_EQ(rpc::parse_amount(rpc::JsonValue(0.5)), static_cast<int64_t>(50000000));
}

// ===================================================================
// RpcServer::Config tests (no socket/startup needed)
// ===================================================================

TEST_CASE(RpcServer, ConfigDefaults) {
    rpc::RpcServer::Config cfg;
    CHECK_EQ(cfg.bind_address, std::string("127.0.0.1"));
    CHECK_EQ(cfg.port, static_cast<uint16_t>(8332));
    CHECK_EQ(cfg.num_threads, 4);
    CHECK_EQ(cfg.max_request_size, static_cast<size_t>(16 * 1024 * 1024));
}

TEST_CASE(RpcServer, RegisterCommand) {
    rpc::RpcServer::Config cfg;
    cfg.rpc_user = "testuser";
    cfg.rpc_password = "testpass";
    rpc::RpcServer server(cfg);

    // Register a simple command -- should not throw
    CHECK_NOTHROW(server.register_command(rpc::RpcCommand{
        "echo",
        [](const rpc::RpcRequest& req) -> rpc::RpcResponse {
            return rpc::make_result(req.params, req.id);
        },
        "Echo parameters back",
        "test"
    }));
}

// ===================================================================
// RpcError enum values
// ===================================================================

TEST_CASE(RpcError, StandardCodes) {
    CHECK_EQ(static_cast<int>(rpc::RpcError::PARSE_ERROR), -32700);
    CHECK_EQ(static_cast<int>(rpc::RpcError::INVALID_REQUEST), -32600);
    CHECK_EQ(static_cast<int>(rpc::RpcError::METHOD_NOT_FOUND), -32601);
    CHECK_EQ(static_cast<int>(rpc::RpcError::INVALID_PARAMS), -32602);
    CHECK_EQ(static_cast<int>(rpc::RpcError::INTERNAL_ERROR), -32603);
}
