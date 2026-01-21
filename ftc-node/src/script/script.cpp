#include "script/script.h"
#include <algorithm>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace ftc {
namespace script {

//-----------------------------------------------------------------------------
// Script error messages
//-----------------------------------------------------------------------------

const char* ScriptErrorString(ScriptError error) {
    switch (error) {
        case ScriptError::OK: return "No error";
        case ScriptError::UNKNOWN_ERROR: return "Unknown error";
        case ScriptError::EVAL_FALSE: return "Script evaluated without error but finished with a false/empty top stack element";
        case ScriptError::OP_RETURN: return "OP_RETURN was encountered";

        case ScriptError::SCRIPT_SIZE: return "Script is too big";
        case ScriptError::PUSH_SIZE: return "Push value size limit exceeded";
        case ScriptError::OP_COUNT: return "Operation limit exceeded";
        case ScriptError::STACK_SIZE: return "Stack size limit exceeded";
        case ScriptError::SIG_COUNT: return "Signature count negative or greater than pubkey count";
        case ScriptError::PUBKEY_COUNT: return "Pubkey count negative or limit exceeded";

        case ScriptError::INVALID_OPCODE: return "Invalid opcode";
        case ScriptError::DISABLED_OPCODE: return "Disabled opcode";
        case ScriptError::INVALID_STACK_OPERATION: return "Invalid stack operation";
        case ScriptError::INVALID_ALTSTACK_OPERATION: return "Invalid altstack operation";
        case ScriptError::UNBALANCED_CONDITIONAL: return "Unbalanced conditional";

        case ScriptError::NEGATIVE_LOCKTIME: return "Negative locktime";
        case ScriptError::UNSATISFIED_LOCKTIME: return "Locktime requirement not satisfied";
        case ScriptError::UNSATISFIED_SEQUENCE: return "Sequence requirement not satisfied";

        case ScriptError::SIG_HASHTYPE: return "Invalid signature hash type";
        case ScriptError::SIG_DER: return "Non-canonical DER signature";
        case ScriptError::MINIMALDATA: return "Data push larger than necessary";
        case ScriptError::SIG_PUSHONLY: return "Only push operators allowed in signatures";
        case ScriptError::SIG_HIGH_S: return "Non-canonical signature: S value is unnecessarily high";
        case ScriptError::SIG_NULLDUMMY: return "Dummy CHECKMULTISIG argument must be zero";
        case ScriptError::PUBKEYTYPE: return "Public key is neither compressed nor uncompressed";
        case ScriptError::CLEANSTACK: return "Stack size must be exactly one after execution";
        case ScriptError::MINIMALIF: return "OP_IF/NOTIF argument must be minimal";
        case ScriptError::SIG_NULLFAIL: return "Signature must be zero for failed CHECK(MULTI)SIG operation";

        case ScriptError::SIG_VERIFY: return "Signature verification failed";
        case ScriptError::MULTISIG_VERIFY: return "Multisig verification failed";

        case ScriptError::WITNESS_PROGRAM_WRONG_LENGTH: return "Witness program has incorrect length";
        case ScriptError::WITNESS_PROGRAM_WITNESS_EMPTY: return "Witness program was passed an empty witness";
        case ScriptError::WITNESS_PROGRAM_MISMATCH: return "Witness program hash mismatch";
        case ScriptError::WITNESS_MALLEATED: return "Witness requires empty scriptSig";
        case ScriptError::WITNESS_MALLEATED_P2SH: return "Witness requires only-redeemscript scriptSig";
        case ScriptError::WITNESS_UNEXPECTED: return "Witness provided for non-witness script";
        case ScriptError::WITNESS_PUBKEYTYPE: return "Witness program requires compressed pubkeys";

        case ScriptError::TAPROOT_WRONG_CONTROL_SIZE: return "Taproot control block size invalid";
        case ScriptError::TAPROOT_ANNEX_UNSUPPORTED: return "Taproot annex not supported";
        case ScriptError::TAPROOT_INVALID_INTERNAL_KEY: return "Taproot internal key invalid";
        case ScriptError::TAPROOT_INVALID_PARITY: return "Taproot parity bit invalid";
        case ScriptError::TAPROOT_INVALID_MERKLE_ROOT: return "Taproot merkle root invalid";
        case ScriptError::TAPSCRIPT_VALIDATION_WEIGHT: return "Tapscript validation weight exceeded";
        case ScriptError::TAPSCRIPT_CHECKMULTISIG: return "CHECKMULTISIG not allowed in tapscript";
        case ScriptError::TAPSCRIPT_MINIMALIF: return "Tapscript MINIMALIF requirement not met";

        case ScriptError::OP_CODESEPARATOR: return "OP_CODESEPARATOR not allowed";
        case ScriptError::SIG_FINDANDDELETE: return "FindAndDelete not allowed";

        default: return "Unknown error";
    }
}

//-----------------------------------------------------------------------------
// Script class implementation
//-----------------------------------------------------------------------------

Script& Script::operator<<(Opcode opcode) {
    data_.push_back(static_cast<uint8_t>(opcode));
    return *this;
}

Script& Script::operator<<(const std::vector<uint8_t>& data) {
    size_t size = data.size();

    if (size < static_cast<uint8_t>(Opcode::OP_PUSHDATA1)) {
        // Direct push
        data_.push_back(static_cast<uint8_t>(size));
    } else if (size <= 0xff) {
        data_.push_back(static_cast<uint8_t>(Opcode::OP_PUSHDATA1));
        data_.push_back(static_cast<uint8_t>(size));
    } else if (size <= 0xffff) {
        data_.push_back(static_cast<uint8_t>(Opcode::OP_PUSHDATA2));
        data_.push_back(static_cast<uint8_t>(size & 0xff));
        data_.push_back(static_cast<uint8_t>((size >> 8) & 0xff));
    } else {
        data_.push_back(static_cast<uint8_t>(Opcode::OP_PUSHDATA4));
        data_.push_back(static_cast<uint8_t>(size & 0xff));
        data_.push_back(static_cast<uint8_t>((size >> 8) & 0xff));
        data_.push_back(static_cast<uint8_t>((size >> 16) & 0xff));
        data_.push_back(static_cast<uint8_t>((size >> 24) & 0xff));
    }

    data_.insert(data_.end(), data.begin(), data.end());
    return *this;
}

Script& Script::operator<<(int64_t n) {
    if (n == -1 || (n >= 1 && n <= 16)) {
        data_.push_back(static_cast<uint8_t>(n + (static_cast<uint8_t>(Opcode::OP_1) - 1)));
    } else if (n == 0) {
        data_.push_back(static_cast<uint8_t>(Opcode::OP_0));
    } else {
        *this << intToStackElement(n);
    }
    return *this;
}

// P2PKH: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
bool Script::isPayToPublicKeyHash() const {
    return data_.size() == 25 &&
           data_[0] == static_cast<uint8_t>(Opcode::OP_DUP) &&
           data_[1] == static_cast<uint8_t>(Opcode::OP_HASH160) &&
           data_[2] == 0x14 &&  // 20 bytes
           data_[23] == static_cast<uint8_t>(Opcode::OP_EQUALVERIFY) &&
           data_[24] == static_cast<uint8_t>(Opcode::OP_CHECKSIG);
}

// P2SH: OP_HASH160 <script_hash> OP_EQUAL
bool Script::isPayToScriptHash() const {
    return data_.size() == 23 &&
           data_[0] == static_cast<uint8_t>(Opcode::OP_HASH160) &&
           data_[1] == 0x14 &&  // 20 bytes
           data_[22] == static_cast<uint8_t>(Opcode::OP_EQUAL);
}

// P2WPKH: OP_0 <20-byte pubkey_hash>
bool Script::isPayToWitnessKeyHash() const {
    return data_.size() == 22 &&
           data_[0] == static_cast<uint8_t>(Opcode::OP_0) &&
           data_[1] == 0x14;  // 20 bytes
}

// P2WSH: OP_0 <32-byte script_hash>
bool Script::isPayToWitnessScriptHash() const {
    return data_.size() == 34 &&
           data_[0] == static_cast<uint8_t>(Opcode::OP_0) &&
           data_[1] == 0x20;  // 32 bytes
}

// P2TR: OP_1 <32-byte output_key>
bool Script::isPayToTaproot() const {
    return data_.size() == 34 &&
           data_[0] == static_cast<uint8_t>(Opcode::OP_1) &&
           data_[1] == 0x20;  // 32 bytes
}

bool Script::isWitnessProgram(int& version, std::vector<uint8_t>& program) const {
    if (data_.size() < 4 || data_.size() > 42) {
        return false;
    }

    // First byte must be OP_0 - OP_16
    uint8_t first = data_[0];
    if (first == static_cast<uint8_t>(Opcode::OP_0)) {
        version = 0;
    } else if (first >= static_cast<uint8_t>(Opcode::OP_1) &&
               first <= static_cast<uint8_t>(Opcode::OP_16)) {
        version = first - static_cast<uint8_t>(Opcode::OP_1) + 1;
    } else {
        return false;
    }

    // Second byte is the push length
    uint8_t push_size = data_[1];
    if (push_size < 2 || push_size > 40) {
        return false;
    }

    // Check total size matches
    if (data_.size() != static_cast<size_t>(push_size + 2)) {
        return false;
    }

    program.assign(data_.begin() + 2, data_.end());
    return true;
}

bool Script::isPushOnly() const {
    const uint8_t* pc = data_.data();
    const uint8_t* end = pc + data_.size();

    while (pc < end) {
        uint8_t opcode = *pc++;

        if (opcode > static_cast<uint8_t>(Opcode::OP_16)) {
            return false;
        }

        // Skip over push data
        if (opcode > 0 && opcode < static_cast<uint8_t>(Opcode::OP_PUSHDATA1)) {
            pc += opcode;
        } else if (opcode == static_cast<uint8_t>(Opcode::OP_PUSHDATA1)) {
            if (pc >= end) return false;
            pc += 1 + *pc;
        } else if (opcode == static_cast<uint8_t>(Opcode::OP_PUSHDATA2)) {
            if (pc + 2 > end) return false;
            uint16_t size = pc[0] | (pc[1] << 8);
            pc += 2 + size;
        } else if (opcode == static_cast<uint8_t>(Opcode::OP_PUSHDATA4)) {
            if (pc + 4 > end) return false;
            uint32_t size = pc[0] | (pc[1] << 8) | (pc[2] << 16) | (pc[3] << 24);
            pc += 4 + size;
        }
    }

    return pc == end;
}

bool Script::isUnspendable() const {
    return (!data_.empty() && data_[0] == static_cast<uint8_t>(Opcode::OP_RETURN)) ||
           data_.size() > 10000;  // Max script size
}

//-----------------------------------------------------------------------------
// Standard script creation
//-----------------------------------------------------------------------------

Script Script::createP2PKH(const std::vector<uint8_t>& pubkey_hash) {
    if (pubkey_hash.size() != 20) {
        return Script();
    }

    Script script;
    script << Opcode::OP_DUP
           << Opcode::OP_HASH160
           << pubkey_hash
           << Opcode::OP_EQUALVERIFY
           << Opcode::OP_CHECKSIG;
    return script;
}

Script Script::createP2SH(const std::vector<uint8_t>& script_hash) {
    if (script_hash.size() != 20) {
        return Script();
    }

    Script script;
    script << Opcode::OP_HASH160
           << script_hash
           << Opcode::OP_EQUAL;
    return script;
}

Script Script::createP2WPKH(const std::vector<uint8_t>& pubkey_hash) {
    if (pubkey_hash.size() != 20) {
        return Script();
    }

    Script script;
    script.data_.push_back(static_cast<uint8_t>(Opcode::OP_0));
    script.data_.push_back(0x14);  // 20 bytes
    script.data_.insert(script.data_.end(), pubkey_hash.begin(), pubkey_hash.end());
    return script;
}

Script Script::createP2WSH(const std::vector<uint8_t>& script_hash) {
    if (script_hash.size() != 32) {
        return Script();
    }

    Script script;
    script.data_.push_back(static_cast<uint8_t>(Opcode::OP_0));
    script.data_.push_back(0x20);  // 32 bytes
    script.data_.insert(script.data_.end(), script_hash.begin(), script_hash.end());
    return script;
}

Script Script::createP2TR(const std::vector<uint8_t>& output_key) {
    if (output_key.size() != 32) {
        return Script();
    }

    Script script;
    script.data_.push_back(static_cast<uint8_t>(Opcode::OP_1));
    script.data_.push_back(0x20);  // 32 bytes
    script.data_.insert(script.data_.end(), output_key.begin(), output_key.end());
    return script;
}

Script Script::createOpReturn(const std::vector<uint8_t>& data) {
    Script script;
    script << Opcode::OP_RETURN << data;
    return script;
}

Script Script::createMultisig(int required, const std::vector<std::vector<uint8_t>>& pubkeys) {
    if (required < 1 || required > 16 || pubkeys.size() < 1 || pubkeys.size() > 16 ||
        static_cast<size_t>(required) > pubkeys.size()) {
        return Script();
    }

    Script script;
    script << static_cast<int64_t>(required);

    for (const auto& pubkey : pubkeys) {
        script << pubkey;
    }

    script << static_cast<int64_t>(pubkeys.size());
    script << Opcode::OP_CHECKMULTISIG;

    return script;
}

//-----------------------------------------------------------------------------
// Serialization
//-----------------------------------------------------------------------------

static const char hex_chars[] = "0123456789abcdef";

std::string Script::toHex() const {
    std::string result;
    result.reserve(data_.size() * 2);

    for (uint8_t byte : data_) {
        result.push_back(hex_chars[byte >> 4]);
        result.push_back(hex_chars[byte & 0x0f]);
    }

    return result;
}

Script Script::fromHex(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        return Script();
    }

    std::vector<uint8_t> data;
    data.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        char c1 = hex[i];
        char c2 = hex[i + 1];

        int hi, lo;
        if (c1 >= '0' && c1 <= '9') hi = c1 - '0';
        else if (c1 >= 'a' && c1 <= 'f') hi = c1 - 'a' + 10;
        else if (c1 >= 'A' && c1 <= 'F') hi = c1 - 'A' + 10;
        else return Script();

        if (c2 >= '0' && c2 <= '9') lo = c2 - '0';
        else if (c2 >= 'a' && c2 <= 'f') lo = c2 - 'a' + 10;
        else if (c2 >= 'A' && c2 <= 'F') lo = c2 - 'A' + 10;
        else return Script();

        data.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }

    return Script(data);
}

std::string Script::toAsm() const {
    std::ostringstream oss;

    const uint8_t* pc = data_.data();
    const uint8_t* end = pc + data_.size();
    bool first = true;

    while (pc < end) {
        if (!first) oss << " ";
        first = false;

        uint8_t opcode = *pc++;

        if (opcode >= 1 && opcode <= 75) {
            // Direct push
            if (pc + opcode > end) break;
            oss << "OP_PUSHBYTES_" << static_cast<int>(opcode) << " ";
            for (int i = 0; i < opcode && pc < end; i++) {
                oss << hex_chars[*pc >> 4] << hex_chars[*pc & 0x0f];
                pc++;
            }
        } else if (opcode == static_cast<uint8_t>(Opcode::OP_PUSHDATA1)) {
            if (pc >= end) break;
            uint8_t size = *pc++;
            oss << "OP_PUSHDATA1 " << static_cast<int>(size) << " ";
            for (int i = 0; i < size && pc < end; i++) {
                oss << hex_chars[*pc >> 4] << hex_chars[*pc & 0x0f];
                pc++;
            }
        } else if (opcode == static_cast<uint8_t>(Opcode::OP_PUSHDATA2)) {
            if (pc + 2 > end) break;
            uint16_t size = pc[0] | (pc[1] << 8);
            pc += 2;
            oss << "OP_PUSHDATA2 " << size << " ";
            for (int i = 0; i < size && pc < end; i++) {
                oss << hex_chars[*pc >> 4] << hex_chars[*pc & 0x0f];
                pc++;
            }
        } else if (opcode == static_cast<uint8_t>(Opcode::OP_PUSHDATA4)) {
            if (pc + 4 > end) break;
            uint32_t size = pc[0] | (pc[1] << 8) | (pc[2] << 16) | (pc[3] << 24);
            pc += 4;
            oss << "OP_PUSHDATA4 " << size << " ";
            for (uint32_t i = 0; i < size && pc < end; i++) {
                oss << hex_chars[*pc >> 4] << hex_chars[*pc & 0x0f];
                pc++;
            }
        } else {
            oss << getOpcodeName(static_cast<Opcode>(opcode));
        }
    }

    return oss.str();
}

//-----------------------------------------------------------------------------
// Extract data
//-----------------------------------------------------------------------------

bool Script::extractPubKeyHash(std::vector<uint8_t>& hash) const {
    if (isPayToPublicKeyHash()) {
        // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        hash.assign(data_.begin() + 3, data_.begin() + 23);
        return true;
    }

    if (isPayToWitnessKeyHash()) {
        // P2WPKH: OP_0 <20 bytes>
        hash.assign(data_.begin() + 2, data_.end());
        return true;
    }

    return false;
}

bool Script::extractScriptHash(std::vector<uint8_t>& hash) const {
    if (isPayToScriptHash()) {
        // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
        hash.assign(data_.begin() + 2, data_.begin() + 22);
        return true;
    }

    if (isPayToWitnessScriptHash()) {
        // P2WSH: OP_0 <32 bytes>
        hash.assign(data_.begin() + 2, data_.end());
        return true;
    }

    return false;
}

//-----------------------------------------------------------------------------
// Stack element utilities
//-----------------------------------------------------------------------------

int64_t stackElementToInt(const StackElement& elem, bool require_minimal, size_t max_len) {
    if (elem.empty()) {
        return 0;
    }

    if (elem.size() > max_len) {
        throw std::runtime_error("Script number overflow");
    }

    if (require_minimal) {
        // Check for minimal encoding
        if ((elem.back() & 0x7f) == 0) {
            // Last byte is 0x00 or 0x80 - not minimal unless sign bit needed
            if (elem.size() <= 1 || (elem[elem.size() - 2] & 0x80) == 0) {
                throw std::runtime_error("Non-minimal encoded number");
            }
        }
    }

    int64_t result = 0;
    for (size_t i = 0; i < elem.size(); i++) {
        result |= static_cast<int64_t>(elem[i]) << (8 * i);
    }

    // Handle sign bit
    if (elem.back() & 0x80) {
        // Negative number - clear sign bit and negate
        result &= ~(static_cast<int64_t>(0x80) << (8 * (elem.size() - 1)));
        result = -result;
    }

    return result;
}

StackElement intToStackElement(int64_t value) {
    if (value == 0) {
        return {};
    }

    StackElement result;
    bool negative = value < 0;
    uint64_t absvalue = negative ? -value : value;

    while (absvalue) {
        result.push_back(static_cast<uint8_t>(absvalue & 0xff));
        absvalue >>= 8;
    }

    // If high bit is set, add extra byte for sign
    if (result.back() & 0x80) {
        result.push_back(negative ? 0x80 : 0x00);
    } else if (negative) {
        result.back() |= 0x80;
    }

    return result;
}

bool stackElementIsTrue(const StackElement& elem) {
    for (size_t i = 0; i < elem.size(); i++) {
        if (elem[i] != 0) {
            // Can be negative zero
            if (i == elem.size() - 1 && elem[i] == 0x80) {
                return false;
            }
            return true;
        }
    }
    return false;
}

//-----------------------------------------------------------------------------
// Opcode utilities
//-----------------------------------------------------------------------------

const char* getOpcodeName(Opcode opcode) {
    switch (opcode) {
        case Opcode::OP_0: return "OP_0";
        case Opcode::OP_PUSHDATA1: return "OP_PUSHDATA1";
        case Opcode::OP_PUSHDATA2: return "OP_PUSHDATA2";
        case Opcode::OP_PUSHDATA4: return "OP_PUSHDATA4";
        case Opcode::OP_1NEGATE: return "OP_1NEGATE";
        case Opcode::OP_RESERVED: return "OP_RESERVED";
        case Opcode::OP_1: return "OP_1";
        case Opcode::OP_2: return "OP_2";
        case Opcode::OP_3: return "OP_3";
        case Opcode::OP_4: return "OP_4";
        case Opcode::OP_5: return "OP_5";
        case Opcode::OP_6: return "OP_6";
        case Opcode::OP_7: return "OP_7";
        case Opcode::OP_8: return "OP_8";
        case Opcode::OP_9: return "OP_9";
        case Opcode::OP_10: return "OP_10";
        case Opcode::OP_11: return "OP_11";
        case Opcode::OP_12: return "OP_12";
        case Opcode::OP_13: return "OP_13";
        case Opcode::OP_14: return "OP_14";
        case Opcode::OP_15: return "OP_15";
        case Opcode::OP_16: return "OP_16";

        case Opcode::OP_NOP: return "OP_NOP";
        case Opcode::OP_VER: return "OP_VER";
        case Opcode::OP_IF: return "OP_IF";
        case Opcode::OP_NOTIF: return "OP_NOTIF";
        case Opcode::OP_VERIF: return "OP_VERIF";
        case Opcode::OP_VERNOTIF: return "OP_VERNOTIF";
        case Opcode::OP_ELSE: return "OP_ELSE";
        case Opcode::OP_ENDIF: return "OP_ENDIF";
        case Opcode::OP_VERIFY: return "OP_VERIFY";
        case Opcode::OP_RETURN: return "OP_RETURN";

        case Opcode::OP_TOALTSTACK: return "OP_TOALTSTACK";
        case Opcode::OP_FROMALTSTACK: return "OP_FROMALTSTACK";
        case Opcode::OP_2DROP: return "OP_2DROP";
        case Opcode::OP_2DUP: return "OP_2DUP";
        case Opcode::OP_3DUP: return "OP_3DUP";
        case Opcode::OP_2OVER: return "OP_2OVER";
        case Opcode::OP_2ROT: return "OP_2ROT";
        case Opcode::OP_2SWAP: return "OP_2SWAP";
        case Opcode::OP_IFDUP: return "OP_IFDUP";
        case Opcode::OP_DEPTH: return "OP_DEPTH";
        case Opcode::OP_DROP: return "OP_DROP";
        case Opcode::OP_DUP: return "OP_DUP";
        case Opcode::OP_NIP: return "OP_NIP";
        case Opcode::OP_OVER: return "OP_OVER";
        case Opcode::OP_PICK: return "OP_PICK";
        case Opcode::OP_ROLL: return "OP_ROLL";
        case Opcode::OP_ROT: return "OP_ROT";
        case Opcode::OP_SWAP: return "OP_SWAP";
        case Opcode::OP_TUCK: return "OP_TUCK";

        case Opcode::OP_CAT: return "OP_CAT";
        case Opcode::OP_SUBSTR: return "OP_SUBSTR";
        case Opcode::OP_LEFT: return "OP_LEFT";
        case Opcode::OP_RIGHT: return "OP_RIGHT";
        case Opcode::OP_SIZE: return "OP_SIZE";

        case Opcode::OP_INVERT: return "OP_INVERT";
        case Opcode::OP_AND: return "OP_AND";
        case Opcode::OP_OR: return "OP_OR";
        case Opcode::OP_XOR: return "OP_XOR";
        case Opcode::OP_EQUAL: return "OP_EQUAL";
        case Opcode::OP_EQUALVERIFY: return "OP_EQUALVERIFY";
        case Opcode::OP_RESERVED1: return "OP_RESERVED1";
        case Opcode::OP_RESERVED2: return "OP_RESERVED2";

        case Opcode::OP_1ADD: return "OP_1ADD";
        case Opcode::OP_1SUB: return "OP_1SUB";
        case Opcode::OP_2MUL: return "OP_2MUL";
        case Opcode::OP_2DIV: return "OP_2DIV";
        case Opcode::OP_NEGATE: return "OP_NEGATE";
        case Opcode::OP_ABS: return "OP_ABS";
        case Opcode::OP_NOT: return "OP_NOT";
        case Opcode::OP_0NOTEQUAL: return "OP_0NOTEQUAL";
        case Opcode::OP_ADD: return "OP_ADD";
        case Opcode::OP_SUB: return "OP_SUB";
        case Opcode::OP_MUL: return "OP_MUL";
        case Opcode::OP_DIV: return "OP_DIV";
        case Opcode::OP_MOD: return "OP_MOD";
        case Opcode::OP_LSHIFT: return "OP_LSHIFT";
        case Opcode::OP_RSHIFT: return "OP_RSHIFT";
        case Opcode::OP_BOOLAND: return "OP_BOOLAND";
        case Opcode::OP_BOOLOR: return "OP_BOOLOR";
        case Opcode::OP_NUMEQUAL: return "OP_NUMEQUAL";
        case Opcode::OP_NUMEQUALVERIFY: return "OP_NUMEQUALVERIFY";
        case Opcode::OP_NUMNOTEQUAL: return "OP_NUMNOTEQUAL";
        case Opcode::OP_LESSTHAN: return "OP_LESSTHAN";
        case Opcode::OP_GREATERTHAN: return "OP_GREATERTHAN";
        case Opcode::OP_LESSTHANOREQUAL: return "OP_LESSTHANOREQUAL";
        case Opcode::OP_GREATERTHANOREQUAL: return "OP_GREATERTHANOREQUAL";
        case Opcode::OP_MIN: return "OP_MIN";
        case Opcode::OP_MAX: return "OP_MAX";
        case Opcode::OP_WITHIN: return "OP_WITHIN";

        case Opcode::OP_RIPEMD160: return "OP_RIPEMD160";
        case Opcode::OP_SHA1: return "OP_SHA1";
        case Opcode::OP_SHA256: return "OP_SHA256";
        case Opcode::OP_HASH160: return "OP_HASH160";
        case Opcode::OP_HASH256: return "OP_HASH256";
        case Opcode::OP_CODESEPARATOR: return "OP_CODESEPARATOR";
        case Opcode::OP_CHECKSIG: return "OP_CHECKSIG";
        case Opcode::OP_CHECKSIGVERIFY: return "OP_CHECKSIGVERIFY";
        case Opcode::OP_CHECKMULTISIG: return "OP_CHECKMULTISIG";
        case Opcode::OP_CHECKMULTISIGVERIFY: return "OP_CHECKMULTISIGVERIFY";

        case Opcode::OP_NOP1: return "OP_NOP1";
        case Opcode::OP_CHECKLOCKTIMEVERIFY: return "OP_CHECKLOCKTIMEVERIFY";
        case Opcode::OP_CHECKSEQUENCEVERIFY: return "OP_CHECKSEQUENCEVERIFY";
        case Opcode::OP_NOP4: return "OP_NOP4";
        case Opcode::OP_NOP5: return "OP_NOP5";
        case Opcode::OP_NOP6: return "OP_NOP6";
        case Opcode::OP_NOP7: return "OP_NOP7";
        case Opcode::OP_NOP8: return "OP_NOP8";
        case Opcode::OP_NOP9: return "OP_NOP9";
        case Opcode::OP_NOP10: return "OP_NOP10";

        case Opcode::OP_CHECKSIGADD: return "OP_CHECKSIGADD";

        case Opcode::OP_INVALIDOPCODE: return "OP_INVALIDOPCODE";

        default: return "OP_UNKNOWN";
    }
}

bool isOpcodeDisabled(Opcode opcode) {
    switch (opcode) {
        case Opcode::OP_CAT:
        case Opcode::OP_SUBSTR:
        case Opcode::OP_LEFT:
        case Opcode::OP_RIGHT:
        case Opcode::OP_INVERT:
        case Opcode::OP_AND:
        case Opcode::OP_OR:
        case Opcode::OP_XOR:
        case Opcode::OP_2MUL:
        case Opcode::OP_2DIV:
        case Opcode::OP_MUL:
        case Opcode::OP_DIV:
        case Opcode::OP_MOD:
        case Opcode::OP_LSHIFT:
        case Opcode::OP_RSHIFT:
            return true;
        default:
            return false;
    }
}

bool isPushOpcode(uint8_t opcode) {
    return opcode <= static_cast<uint8_t>(Opcode::OP_16);
}

size_t getScriptNumSize(int64_t value) {
    if (value == 0) return 0;

    bool negative = value < 0;
    uint64_t absvalue = negative ? -value : value;

    size_t size = 0;
    while (absvalue) {
        size++;
        absvalue >>= 8;
    }

    // Need extra byte for sign if high bit set
    if ((negative ? -value : value) & (0x80ULL << (8 * (size - 1)))) {
        size++;
    }

    return size;
}

} // namespace script
} // namespace ftc
