#include "primitives/script/opcodes.h"

#include <array>
#include <cstdio>
#include <unordered_map>

namespace primitives::script {

// ---------------------------------------------------------------------------
// opcode_name  --  canonical display string for every Opcode value
// ---------------------------------------------------------------------------

// For OP_PUSHBYTES_1..75 we generate names on first use and keep them in a
// static table so we can return string_view without allocation.
namespace detail {

struct PushBytesNames {
    // "OP_PUSHBYTES_NN\0" is at most 16 chars; 17 with null terminator.
    std::array<std::array<char, 20>, 76> buf{};
    std::array<std::string_view, 76> views{};

    PushBytesNames() {
        for (int i = 1; i <= 75; ++i) {
            auto n = std::snprintf(
                buf[static_cast<size_t>(i)].data(),
                buf[static_cast<size_t>(i)].size(),
                "OP_PUSHBYTES_%d", i);
            views[static_cast<size_t>(i)] = std::string_view(
                buf[static_cast<size_t>(i)].data(),
                static_cast<size_t>(n));
        }
    }
};

static const PushBytesNames& push_bytes_names() {
    static const PushBytesNames instance;
    return instance;
}

// For truly unknown opcodes (0xbb-0xfe range that has no name) we keep a
// small table of "OP_UNKNOWN_XX" strings.
struct UnknownNames {
    std::array<std::array<char, 16>, 256> buf{};
    std::array<std::string_view, 256> views{};

    UnknownNames() {
        for (int i = 0; i < 256; ++i) {
            auto n = std::snprintf(
                buf[static_cast<size_t>(i)].data(),
                buf[static_cast<size_t>(i)].size(),
                "OP_UNKNOWN_%02x", i);
            views[static_cast<size_t>(i)] = std::string_view(
                buf[static_cast<size_t>(i)].data(),
                static_cast<size_t>(n));
        }
    }
};

static const UnknownNames& unknown_names() {
    static const UnknownNames instance;
    return instance;
}

} // namespace detail

std::string_view opcode_name(Opcode op) {
    auto raw = static_cast<uint8_t>(op);

    // Implicit push-bytes range 0x01 .. 0x4b
    if (raw >= 0x01 && raw <= 0x4b) {
        return detail::push_bytes_names().views[raw];
    }

    switch (op) {
    // Push value
    case Opcode::OP_0:              return "OP_0";
    case Opcode::OP_PUSHDATA1:      return "OP_PUSHDATA1";
    case Opcode::OP_PUSHDATA2:      return "OP_PUSHDATA2";
    case Opcode::OP_PUSHDATA4:      return "OP_PUSHDATA4";
    case Opcode::OP_1NEGATE:        return "OP_1NEGATE";
    case Opcode::OP_RESERVED:       return "OP_RESERVED";
    case Opcode::OP_1:              return "OP_1";
    case Opcode::OP_2:              return "OP_2";
    case Opcode::OP_3:              return "OP_3";
    case Opcode::OP_4:              return "OP_4";
    case Opcode::OP_5:              return "OP_5";
    case Opcode::OP_6:              return "OP_6";
    case Opcode::OP_7:              return "OP_7";
    case Opcode::OP_8:              return "OP_8";
    case Opcode::OP_9:              return "OP_9";
    case Opcode::OP_10:             return "OP_10";
    case Opcode::OP_11:             return "OP_11";
    case Opcode::OP_12:             return "OP_12";
    case Opcode::OP_13:             return "OP_13";
    case Opcode::OP_14:             return "OP_14";
    case Opcode::OP_15:             return "OP_15";
    case Opcode::OP_16:             return "OP_16";

    // Flow control
    case Opcode::OP_NOP:            return "OP_NOP";
    case Opcode::OP_VER:            return "OP_VER";
    case Opcode::OP_IF:             return "OP_IF";
    case Opcode::OP_NOTIF:          return "OP_NOTIF";
    case Opcode::OP_VERIF:          return "OP_VERIF";
    case Opcode::OP_VERNOTIF:       return "OP_VERNOTIF";
    case Opcode::OP_ELSE:           return "OP_ELSE";
    case Opcode::OP_ENDIF:          return "OP_ENDIF";
    case Opcode::OP_VERIFY:         return "OP_VERIFY";
    case Opcode::OP_RETURN:         return "OP_RETURN";

    // Stack
    case Opcode::OP_TOALTSTACK:     return "OP_TOALTSTACK";
    case Opcode::OP_FROMALTSTACK:   return "OP_FROMALTSTACK";
    case Opcode::OP_2DROP:          return "OP_2DROP";
    case Opcode::OP_2DUP:           return "OP_2DUP";
    case Opcode::OP_3DUP:           return "OP_3DUP";
    case Opcode::OP_2OVER:          return "OP_2OVER";
    case Opcode::OP_2ROT:           return "OP_2ROT";
    case Opcode::OP_2SWAP:          return "OP_2SWAP";
    case Opcode::OP_IFDUP:          return "OP_IFDUP";
    case Opcode::OP_DEPTH:          return "OP_DEPTH";
    case Opcode::OP_DROP:           return "OP_DROP";
    case Opcode::OP_DUP:            return "OP_DUP";
    case Opcode::OP_NIP:            return "OP_NIP";
    case Opcode::OP_OVER:           return "OP_OVER";
    case Opcode::OP_PICK:           return "OP_PICK";
    case Opcode::OP_ROLL:           return "OP_ROLL";
    case Opcode::OP_ROT:            return "OP_ROT";
    case Opcode::OP_SWAP:           return "OP_SWAP";
    case Opcode::OP_TUCK:           return "OP_TUCK";

    // Splice
    case Opcode::OP_CAT:            return "OP_CAT";
    case Opcode::OP_SUBSTR:         return "OP_SUBSTR";
    case Opcode::OP_LEFT:           return "OP_LEFT";
    case Opcode::OP_RIGHT:          return "OP_RIGHT";
    case Opcode::OP_SIZE:           return "OP_SIZE";

    // Bitwise logic
    case Opcode::OP_INVERT:         return "OP_INVERT";
    case Opcode::OP_AND:            return "OP_AND";
    case Opcode::OP_OR:             return "OP_OR";
    case Opcode::OP_XOR:            return "OP_XOR";
    case Opcode::OP_EQUAL:          return "OP_EQUAL";
    case Opcode::OP_EQUALVERIFY:    return "OP_EQUALVERIFY";
    case Opcode::OP_RESERVED1:      return "OP_RESERVED1";
    case Opcode::OP_RESERVED2:      return "OP_RESERVED2";

    // Arithmetic
    case Opcode::OP_1ADD:           return "OP_1ADD";
    case Opcode::OP_1SUB:           return "OP_1SUB";
    case Opcode::OP_2MUL:           return "OP_2MUL";
    case Opcode::OP_2DIV:           return "OP_2DIV";
    case Opcode::OP_NEGATE:         return "OP_NEGATE";
    case Opcode::OP_ABS:            return "OP_ABS";
    case Opcode::OP_NOT:            return "OP_NOT";
    case Opcode::OP_0NOTEQUAL:      return "OP_0NOTEQUAL";
    case Opcode::OP_ADD:            return "OP_ADD";
    case Opcode::OP_SUB:            return "OP_SUB";
    case Opcode::OP_MUL:            return "OP_MUL";
    case Opcode::OP_DIV:            return "OP_DIV";
    case Opcode::OP_MOD:            return "OP_MOD";
    case Opcode::OP_LSHIFT:         return "OP_LSHIFT";
    case Opcode::OP_RSHIFT:         return "OP_RSHIFT";
    case Opcode::OP_BOOLAND:        return "OP_BOOLAND";
    case Opcode::OP_BOOLOR:         return "OP_BOOLOR";
    case Opcode::OP_NUMEQUAL:       return "OP_NUMEQUAL";
    case Opcode::OP_NUMEQUALVERIFY: return "OP_NUMEQUALVERIFY";
    case Opcode::OP_NUMNOTEQUAL:    return "OP_NUMNOTEQUAL";
    case Opcode::OP_LESSTHAN:       return "OP_LESSTHAN";
    case Opcode::OP_GREATERTHAN:    return "OP_GREATERTHAN";
    case Opcode::OP_LESSTHANOREQUAL:    return "OP_LESSTHANOREQUAL";
    case Opcode::OP_GREATERTHANOREQUAL: return "OP_GREATERTHANOREQUAL";
    case Opcode::OP_MIN:            return "OP_MIN";
    case Opcode::OP_MAX:            return "OP_MAX";
    case Opcode::OP_WITHIN:         return "OP_WITHIN";

    // Crypto
    case Opcode::OP_RIPEMD160:      return "OP_RIPEMD160";
    case Opcode::OP_SHA1:           return "OP_SHA1";
    case Opcode::OP_KECCAK256:      return "OP_KECCAK256";
    case Opcode::OP_HASH160:        return "OP_HASH160";
    case Opcode::OP_HASH256:        return "OP_HASH256";
    case Opcode::OP_CODESEPARATOR:  return "OP_CODESEPARATOR";
    case Opcode::OP_CHECKSIG:       return "OP_CHECKSIG";
    case Opcode::OP_CHECKSIGVERIFY: return "OP_CHECKSIGVERIFY";
    case Opcode::OP_CHECKMULTISIG:  return "OP_CHECKMULTISIG";
    case Opcode::OP_CHECKMULTISIGVERIFY: return "OP_CHECKMULTISIGVERIFY";

    // Expansion / locktime
    // Note: OP_NOP2 == OP_CHECKLOCKTIMEVERIFY (0xb1)
    //       OP_NOP3 == OP_CHECKSEQUENCEVERIFY (0xb2)
    // We return the BIP65/BIP112 names for those values.
    case Opcode::OP_NOP1:               return "OP_NOP1";
    case Opcode::OP_CHECKLOCKTIMEVERIFY: return "OP_CHECKLOCKTIMEVERIFY";
    case Opcode::OP_CHECKSEQUENCEVERIFY: return "OP_CHECKSEQUENCEVERIFY";
    case Opcode::OP_NOP4:               return "OP_NOP4";
    case Opcode::OP_NOP5:               return "OP_NOP5";
    case Opcode::OP_NOP6:               return "OP_NOP6";
    case Opcode::OP_NOP7:               return "OP_NOP7";
    case Opcode::OP_NOP8:               return "OP_NOP8";
    case Opcode::OP_NOP9:               return "OP_NOP9";
    case Opcode::OP_NOP10:              return "OP_NOP10";

    // Taproot
    case Opcode::OP_CHECKSIGADD:    return "OP_CHECKSIGADD";

    // Invalid
    case Opcode::OP_INVALIDOPCODE:  return "OP_INVALIDOPCODE";
    }

    // Opcodes in the 0xbb-0xfe range that have no defined name.
    return detail::unknown_names().views[raw];
}

// ---------------------------------------------------------------------------
// opcode_from_name  --  reverse lookup by canonical name
// ---------------------------------------------------------------------------

namespace detail {

struct NameMap {
    std::unordered_map<std::string_view, Opcode> map;

    NameMap() {
        // Insert all 256 possible byte values so that every name returned
        // by opcode_name() is present in the map.
        for (int i = 0; i < 256; ++i) {
            auto op = static_cast<Opcode>(static_cast<uint8_t>(i));
            auto name = opcode_name(op);
            // First insertion wins -- this is important because aliases
            // like OP_FALSE/OP_0 and OP_TRUE/OP_1 share the same byte.
            map.try_emplace(name, op);
        }

        // Register well-known aliases that are NOT the canonical name
        // returned by opcode_name().
        map.try_emplace("OP_FALSE",    Opcode::OP_FALSE);
        map.try_emplace("OP_TRUE",     Opcode::OP_TRUE);
        map.try_emplace("OP_NOP2",     Opcode::OP_NOP2);
        map.try_emplace("OP_NOP3",     Opcode::OP_NOP3);
    }
};

static const NameMap& name_map() {
    static const NameMap instance;
    return instance;
}

} // namespace detail

std::optional<Opcode> opcode_from_name(std::string_view name) {
    const auto& m = detail::name_map().map;
    auto it = m.find(name);
    if (it != m.end()) {
        return it->second;
    }
    return std::nullopt;
}

} // namespace primitives::script
