#pragma once

#include <string>
#include <vector>
#include <map>
#include <variant>
#include <cstdint>

namespace dht {

// Bencode value types
struct BencodeValue;
using BencodeList = std::vector<BencodeValue>;
using BencodeDict = std::map<std::string, BencodeValue>;

struct BencodeValue {
    std::variant<int64_t, std::string, BencodeList, BencodeDict> data;

    BencodeValue() : data(int64_t(0)) {}
    BencodeValue(int64_t i) : data(i) {}
    BencodeValue(int i) : data(int64_t(i)) {}
    BencodeValue(const std::string& s) : data(s) {}
    BencodeValue(const char* s) : data(std::string(s)) {}
    BencodeValue(const BencodeList& l) : data(l) {}
    BencodeValue(const BencodeDict& d) : data(d) {}
    BencodeValue(const std::vector<uint8_t>& bytes) : data(std::string(bytes.begin(), bytes.end())) {}

    bool isInt() const { return std::holds_alternative<int64_t>(data); }
    bool isString() const { return std::holds_alternative<std::string>(data); }
    bool isList() const { return std::holds_alternative<BencodeList>(data); }
    bool isDict() const { return std::holds_alternative<BencodeDict>(data); }

    int64_t asInt() const { return std::get<int64_t>(data); }
    const std::string& asString() const { return std::get<std::string>(data); }
    const BencodeList& asList() const { return std::get<BencodeList>(data); }
    const BencodeDict& asDict() const { return std::get<BencodeDict>(data); }

    BencodeList& asList() { return std::get<BencodeList>(data); }
    BencodeDict& asDict() { return std::get<BencodeDict>(data); }
};

class Bencode {
public:
    // Encode value to bencoded string
    static std::string encode(const BencodeValue& value);

    // Decode bencoded string to value
    static bool decode(const std::string& data, BencodeValue& out);
    static bool decode(const uint8_t* data, size_t len, BencodeValue& out);

private:
    static std::string encodeInt(int64_t i);
    static std::string encodeString(const std::string& s);
    static std::string encodeList(const BencodeList& l);
    static std::string encodeDict(const BencodeDict& d);

    static bool decodeValue(const uint8_t*& p, const uint8_t* end, BencodeValue& out);
    static bool decodeInt(const uint8_t*& p, const uint8_t* end, int64_t& out);
    static bool decodeString(const uint8_t*& p, const uint8_t* end, std::string& out);
};

} // namespace dht
