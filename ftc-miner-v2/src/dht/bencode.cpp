#include "bencode.h"
#include <sstream>
#include <algorithm>

namespace dht {

std::string Bencode::encode(const BencodeValue& value) {
    if (value.isInt()) {
        return encodeInt(value.asInt());
    } else if (value.isString()) {
        return encodeString(value.asString());
    } else if (value.isList()) {
        return encodeList(value.asList());
    } else if (value.isDict()) {
        return encodeDict(value.asDict());
    }
    return "";
}

std::string Bencode::encodeInt(int64_t i) {
    return "i" + std::to_string(i) + "e";
}

std::string Bencode::encodeString(const std::string& s) {
    return std::to_string(s.size()) + ":" + s;
}

std::string Bencode::encodeList(const BencodeList& l) {
    std::string result = "l";
    for (const auto& item : l) {
        result += encode(item);
    }
    result += "e";
    return result;
}

std::string Bencode::encodeDict(const BencodeDict& d) {
    std::string result = "d";
    // Keys must be sorted (map is already sorted)
    for (const auto& [key, value] : d) {
        result += encodeString(key);
        result += encode(value);
    }
    result += "e";
    return result;
}

bool Bencode::decode(const std::string& data, BencodeValue& out) {
    return decode(reinterpret_cast<const uint8_t*>(data.data()), data.size(), out);
}

bool Bencode::decode(const uint8_t* data, size_t len, BencodeValue& out) {
    const uint8_t* p = data;
    const uint8_t* end = data + len;
    return decodeValue(p, end, out);
}

bool Bencode::decodeValue(const uint8_t*& p, const uint8_t* end, BencodeValue& out) {
    if (p >= end) return false;

    if (*p == 'i') {
        // Integer
        int64_t val;
        if (!decodeInt(p, end, val)) return false;
        out = BencodeValue(val);
        return true;
    } else if (*p == 'l') {
        // List
        p++; // skip 'l'
        BencodeList list;
        while (p < end && *p != 'e') {
            BencodeValue item;
            if (!decodeValue(p, end, item)) return false;
            list.push_back(std::move(item));
        }
        if (p >= end || *p != 'e') return false;
        p++; // skip 'e'
        out = BencodeValue(list);
        return true;
    } else if (*p == 'd') {
        // Dictionary
        p++; // skip 'd'
        BencodeDict dict;
        while (p < end && *p != 'e') {
            std::string key;
            if (!decodeString(p, end, key)) return false;
            BencodeValue value;
            if (!decodeValue(p, end, value)) return false;
            dict[key] = std::move(value);
        }
        if (p >= end || *p != 'e') return false;
        p++; // skip 'e'
        out = BencodeValue(dict);
        return true;
    } else if (*p >= '0' && *p <= '9') {
        // String
        std::string str;
        if (!decodeString(p, end, str)) return false;
        out = BencodeValue(str);
        return true;
    }

    return false;
}

bool Bencode::decodeInt(const uint8_t*& p, const uint8_t* end, int64_t& out) {
    if (p >= end || *p != 'i') return false;
    p++; // skip 'i'

    bool negative = false;
    if (p < end && *p == '-') {
        negative = true;
        p++;
    }

    int64_t value = 0;
    bool has_digit = false;
    while (p < end && *p >= '0' && *p <= '9') {
        value = value * 10 + (*p - '0');
        has_digit = true;
        p++;
    }

    if (!has_digit || p >= end || *p != 'e') return false;
    p++; // skip 'e'

    out = negative ? -value : value;
    return true;
}

bool Bencode::decodeString(const uint8_t*& p, const uint8_t* end, std::string& out) {
    // Parse length
    size_t len = 0;
    bool has_digit = false;
    while (p < end && *p >= '0' && *p <= '9') {
        len = len * 10 + (*p - '0');
        has_digit = true;
        p++;
    }

    if (!has_digit || p >= end || *p != ':') return false;
    p++; // skip ':'

    if (p + len > end) return false;

    out.assign(reinterpret_cast<const char*>(p), len);
    p += len;
    return true;
}

} // namespace dht
