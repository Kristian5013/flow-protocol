#include "script/interpreter.h"
#include "crypto/keccak256.h"
#include "crypto/secp256k1.h"
#include <cstring>
#include <algorithm>

namespace ftc {
namespace script {

//-----------------------------------------------------------------------------
// Signature Cache
//-----------------------------------------------------------------------------

SignatureCache& SignatureCache::instance() {
    static SignatureCache cache;
    return cache;
}

bool SignatureCache::get(const std::vector<uint8_t>& hash, bool& valid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(hash);
    if (it != cache_.end()) {
        valid = it->second;
        return true;
    }
    return false;
}

void SignatureCache::set(const std::vector<uint8_t>& hash, bool valid) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (cache_.size() >= max_entries_) {
        // Simple eviction: clear half the cache
        auto it = cache_.begin();
        for (size_t i = 0; i < max_entries_ / 2 && it != cache_.end(); i++) {
            it = cache_.erase(it);
        }
    }
    cache_[hash] = valid;
}

void SignatureCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
}

//-----------------------------------------------------------------------------
// PrecomputedTransactionData
//-----------------------------------------------------------------------------

void PrecomputedTransactionData::init(const chain::Transaction& tx,
                                       const std::vector<chain::TxOutput>& spent_outputs) {
    // Hash all prevouts
    std::vector<uint8_t> prevouts_data;
    for (const auto& input : tx.inputs) {
        // Append prevout hash (32 bytes) + index (4 bytes)
        prevouts_data.insert(prevouts_data.end(),
                              input.prevout.txid.begin(),
                              input.prevout.txid.end());
        uint32_t idx = input.prevout.index;
        prevouts_data.push_back(idx & 0xff);
        prevouts_data.push_back((idx >> 8) & 0xff);
        prevouts_data.push_back((idx >> 16) & 0xff);
        prevouts_data.push_back((idx >> 24) & 0xff);
    }
    // Double Keccak-256 hash
    auto first_hash = crypto::keccak256(prevouts_data.data(), prevouts_data.size());
    auto second_hash = crypto::keccak256(first_hash.data(), first_hash.size());
    hash_prevouts.assign(second_hash.begin(), second_hash.end());

    // Hash all sequences
    std::vector<uint8_t> sequence_data;
    for (const auto& input : tx.inputs) {
        uint32_t seq = input.sequence;
        sequence_data.push_back(seq & 0xff);
        sequence_data.push_back((seq >> 8) & 0xff);
        sequence_data.push_back((seq >> 16) & 0xff);
        sequence_data.push_back((seq >> 24) & 0xff);
    }
    first_hash = crypto::keccak256(sequence_data.data(), sequence_data.size());
    second_hash = crypto::keccak256(first_hash.data(), first_hash.size());
    hash_sequence.assign(second_hash.begin(), second_hash.end());

    // Hash all outputs
    std::vector<uint8_t> outputs_data;
    for (const auto& output : tx.outputs) {
        uint64_t val = output.value;
        outputs_data.push_back(val & 0xff);
        outputs_data.push_back((val >> 8) & 0xff);
        outputs_data.push_back((val >> 16) & 0xff);
        outputs_data.push_back((val >> 24) & 0xff);
        outputs_data.push_back((val >> 32) & 0xff);
        outputs_data.push_back((val >> 40) & 0xff);
        outputs_data.push_back((val >> 48) & 0xff);
        outputs_data.push_back((val >> 56) & 0xff);

        const auto& script = output.script_pubkey;
        // Varint length
        if (script.size() < 0xfd) {
            outputs_data.push_back(static_cast<uint8_t>(script.size()));
        } else if (script.size() <= 0xffff) {
            outputs_data.push_back(0xfd);
            outputs_data.push_back(script.size() & 0xff);
            outputs_data.push_back((script.size() >> 8) & 0xff);
        }
        outputs_data.insert(outputs_data.end(), script.begin(), script.end());
    }
    first_hash = crypto::keccak256(outputs_data.data(), outputs_data.size());
    second_hash = crypto::keccak256(first_hash.data(), first_hash.size());
    hash_outputs.assign(second_hash.begin(), second_hash.end());

    ready = true;
}

//-----------------------------------------------------------------------------
// TransactionSignatureChecker
//-----------------------------------------------------------------------------

TransactionSignatureChecker::TransactionSignatureChecker(
    const chain::Transaction* tx,
    unsigned int input_index,
    uint64_t amount,
    const PrecomputedTransactionData* precomputed)
    : tx_(tx), input_index_(input_index), amount_(amount), precomputed_(precomputed) {}

bool TransactionSignatureChecker::checkSig(const std::vector<uint8_t>& sig,
                                            const std::vector<uint8_t>& pubkey,
                                            const Script& script_code,
                                            SigVersion sigversion) const {
    if (sig.empty()) return false;

    // Get hash type from last byte of signature
    uint8_t hash_type = sig.back();

    // Remove hash type from signature
    std::vector<uint8_t> sig_data(sig.begin(), sig.end() - 1);

    // Compute signature hash
    std::vector<uint8_t> hash = signatureHash(*tx_, input_index_, script_code,
                                               hash_type, amount_, sigversion,
                                               precomputed_);

    // Check cache first
    std::vector<uint8_t> cache_key;
    cache_key.reserve(hash.size() + sig_data.size() + pubkey.size());
    cache_key.insert(cache_key.end(), hash.begin(), hash.end());
    cache_key.insert(cache_key.end(), sig_data.begin(), sig_data.end());
    cache_key.insert(cache_key.end(), pubkey.begin(), pubkey.end());

    bool cached_result;
    if (SignatureCache::instance().get(cache_key, cached_result)) {
        return cached_result;
    }

    // Verify signature
    bool result = verifySignature(sig_data, pubkey, hash);

    // Cache result
    SignatureCache::instance().set(cache_key, result);

    return result;
}

bool TransactionSignatureChecker::checkSchnorrSig(const std::vector<uint8_t>& sig,
                                                   const std::vector<uint8_t>& pubkey,
                                                   SigVersion sigversion,
                                                   ScriptError* error) const {
    // Schnorr signatures are 64 bytes (or 65 with hash type)
    if (sig.size() != 64 && sig.size() != 65) {
        if (error) *error = ScriptError::SIG_DER;
        return false;
    }

    // TODO: Implement Taproot signature verification
    return false;
}

bool TransactionSignatureChecker::checkLockTime(int64_t locktime) const {
    // Locktime must be same type (block height vs timestamp)
    // Block heights are < 500000000, timestamps are >= 500000000
    if ((tx_->locktime < 500000000 && locktime >= 500000000) ||
        (tx_->locktime >= 500000000 && locktime < 500000000)) {
        return false;
    }

    // Locktime must be satisfied
    if (locktime > static_cast<int64_t>(tx_->locktime)) {
        return false;
    }

    // Input must be finalizable (sequence != 0xffffffff)
    if (tx_->inputs[input_index_].sequence == 0xffffffff) {
        return false;
    }

    return true;
}

bool TransactionSignatureChecker::checkSequence(int64_t sequence) const {
    // Sequence lock disabled
    if (sequence & (1 << 31)) {
        return true;
    }

    // Version must be >= 2
    if (tx_->version < 2) {
        return false;
    }

    // Check sequence
    int64_t tx_sequence = tx_->inputs[input_index_].sequence;

    // Disabled flag in transaction
    if (tx_sequence & (1 << 31)) {
        return false;
    }

    // Type flags must match
    uint32_t type_mask = 1 << 22;
    if ((sequence & type_mask) != (tx_sequence & type_mask)) {
        return false;
    }

    // Compare sequence values (masked to 16 bits)
    if ((sequence & 0xffff) > (tx_sequence & 0xffff)) {
        return false;
    }

    return true;
}

//-----------------------------------------------------------------------------
// Helper functions
//-----------------------------------------------------------------------------

bool isValidSignatureEncoding(const std::vector<uint8_t>& sig) {
    // Minimum and maximum size constraints
    if (sig.size() < 9) return false;
    if (sig.size() > 73) return false;

    // DER signature format:
    // 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [hash-type]

    // Check header byte
    if (sig[0] != 0x30) return false;

    // Check length
    if (sig[1] != sig.size() - 3) return false;

    // Check R integer
    if (sig[2] != 0x02) return false;

    unsigned int len_r = sig[3];
    if (len_r == 0) return false;
    if (len_r > sig.size() - 7) return false;

    // Check R is positive (no leading 0x00 unless necessary)
    if ((sig[4] & 0x80) != 0) return false;  // R must be positive
    if (len_r > 1 && sig[4] == 0 && (sig[5] & 0x80) == 0) return false;  // No excessive padding

    // Check S integer
    unsigned int pos_s = 4 + len_r;
    if (sig[pos_s] != 0x02) return false;

    unsigned int len_s = sig[pos_s + 1];
    if (len_s == 0) return false;
    if (pos_s + len_s + 2 != sig.size() - 1) return false;

    // Check S is positive
    if ((sig[pos_s + 2] & 0x80) != 0) return false;
    if (len_s > 1 && sig[pos_s + 2] == 0 && (sig[pos_s + 3] & 0x80) == 0) return false;

    return true;
}

bool hasLowS(const std::vector<uint8_t>& sig) {
    if (!isValidSignatureEncoding(sig)) return false;

    // Extract S value
    unsigned int len_r = sig[3];
    unsigned int pos_s = 4 + len_r + 1;
    unsigned int len_s = sig[pos_s];

    // S must be <= order/2
    // secp256k1 order/2 in big endian:
    static const uint8_t half_order[] = {
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
        0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0
    };

    const uint8_t* s = sig.data() + pos_s + 1;

    // Compare with half order (need to handle different lengths)
    if (len_s > 32) return false;
    if (len_s < 32) return true;  // S is small enough

    return std::memcmp(s, half_order, 32) <= 0;
}

bool isValidPubKey(const std::vector<uint8_t>& pubkey) {
    if (pubkey.size() == 33) {
        // Compressed: 0x02 or 0x03
        return pubkey[0] == 0x02 || pubkey[0] == 0x03;
    } else if (pubkey.size() == 65) {
        // Uncompressed: 0x04
        return pubkey[0] == 0x04;
    }
    return false;
}

bool isCompressedPubKey(const std::vector<uint8_t>& pubkey) {
    if (pubkey.size() != 33) return false;
    return pubkey[0] == 0x02 || pubkey[0] == 0x03;
}

uint8_t getHashType(const std::vector<uint8_t>& sig) {
    if (sig.empty()) return 0;
    return sig.back();
}

//-----------------------------------------------------------------------------
// Signature Hashing
//-----------------------------------------------------------------------------

std::vector<uint8_t> signatureHash(const chain::Transaction& tx,
                                    unsigned int input_index,
                                    const Script& script_code,
                                    uint8_t hash_type,
                                    uint64_t amount,
                                    SigVersion sigversion,
                                    const PrecomputedTransactionData* precomputed) {
    if (sigversion == SigVersion::WITNESS_V0) {
        return signatureHashWitness(tx, input_index, script_code, hash_type, amount, precomputed);
    }
    return signatureHashLegacy(tx, input_index, script_code, hash_type);
}

std::vector<uint8_t> signatureHashLegacy(const chain::Transaction& tx,
                                          unsigned int input_index,
                                          const Script& script_code,
                                          uint8_t hash_type) {
    // Serialize transaction for signing
    std::vector<uint8_t> data;

    // Version
    uint32_t version = tx.version;
    data.push_back(version & 0xff);
    data.push_back((version >> 8) & 0xff);
    data.push_back((version >> 16) & 0xff);
    data.push_back((version >> 24) & 0xff);

    // Input count
    bool anyone_can_pay = (hash_type & SIGHASH_ANYONECANPAY) != 0;
    uint8_t base_type = hash_type & 0x1f;

    if (anyone_can_pay) {
        data.push_back(1);  // Only one input
    } else {
        // Varint input count
        size_t count = tx.inputs.size();
        if (count < 0xfd) {
            data.push_back(static_cast<uint8_t>(count));
        } else {
            data.push_back(0xfd);
            data.push_back(count & 0xff);
            data.push_back((count >> 8) & 0xff);
        }
    }

    // Inputs
    for (size_t i = 0; i < tx.inputs.size(); i++) {
        if (anyone_can_pay && i != input_index) continue;

        const auto& input = tx.inputs[i];

        // Prevout
        data.insert(data.end(), input.prevout.txid.begin(), input.prevout.txid.end());
        uint32_t idx = input.prevout.index;
        data.push_back(idx & 0xff);
        data.push_back((idx >> 8) & 0xff);
        data.push_back((idx >> 16) & 0xff);
        data.push_back((idx >> 24) & 0xff);

        // Script
        if (i == input_index) {
            const auto& sc = script_code.data();
            if (sc.size() < 0xfd) {
                data.push_back(static_cast<uint8_t>(sc.size()));
            } else {
                data.push_back(0xfd);
                data.push_back(sc.size() & 0xff);
                data.push_back((sc.size() >> 8) & 0xff);
            }
            data.insert(data.end(), sc.begin(), sc.end());
        } else {
            data.push_back(0);  // Empty script
        }

        // Sequence
        uint32_t seq = input.sequence;
        if (i != input_index && (base_type == SIGHASH_NONE || base_type == SIGHASH_SINGLE)) {
            seq = 0;
        }
        data.push_back(seq & 0xff);
        data.push_back((seq >> 8) & 0xff);
        data.push_back((seq >> 16) & 0xff);
        data.push_back((seq >> 24) & 0xff);
    }

    // Output count
    if (base_type == SIGHASH_NONE) {
        data.push_back(0);
    } else if (base_type == SIGHASH_SINGLE) {
        if (input_index >= tx.outputs.size()) {
            // Invalid SIGHASH_SINGLE, return special hash
            return std::vector<uint8_t>(32, 0);
        }
        size_t count = input_index + 1;
        if (count < 0xfd) {
            data.push_back(static_cast<uint8_t>(count));
        } else {
            data.push_back(0xfd);
            data.push_back(count & 0xff);
            data.push_back((count >> 8) & 0xff);
        }
    } else {
        size_t count = tx.outputs.size();
        if (count < 0xfd) {
            data.push_back(static_cast<uint8_t>(count));
        } else {
            data.push_back(0xfd);
            data.push_back(count & 0xff);
            data.push_back((count >> 8) & 0xff);
        }
    }

    // Outputs
    for (size_t i = 0; i < tx.outputs.size(); i++) {
        if (base_type == SIGHASH_NONE) break;
        if (base_type == SIGHASH_SINGLE && i > input_index) break;

        const auto& output = tx.outputs[i];

        if (base_type == SIGHASH_SINGLE && i < input_index) {
            // Empty output
            uint64_t val = 0xffffffffffffffff;
            data.push_back(val & 0xff);
            data.push_back((val >> 8) & 0xff);
            data.push_back((val >> 16) & 0xff);
            data.push_back((val >> 24) & 0xff);
            data.push_back((val >> 32) & 0xff);
            data.push_back((val >> 40) & 0xff);
            data.push_back((val >> 48) & 0xff);
            data.push_back((val >> 56) & 0xff);
            data.push_back(0);
        } else {
            // Value
            uint64_t val = output.value;
            data.push_back(val & 0xff);
            data.push_back((val >> 8) & 0xff);
            data.push_back((val >> 16) & 0xff);
            data.push_back((val >> 24) & 0xff);
            data.push_back((val >> 32) & 0xff);
            data.push_back((val >> 40) & 0xff);
            data.push_back((val >> 48) & 0xff);
            data.push_back((val >> 56) & 0xff);

            // Script
            const auto& script = output.script_pubkey;
            if (script.size() < 0xfd) {
                data.push_back(static_cast<uint8_t>(script.size()));
            } else {
                data.push_back(0xfd);
                data.push_back(script.size() & 0xff);
                data.push_back((script.size() >> 8) & 0xff);
            }
            data.insert(data.end(), script.begin(), script.end());
        }
    }

    // Locktime
    uint32_t locktime = tx.locktime;
    data.push_back(locktime & 0xff);
    data.push_back((locktime >> 8) & 0xff);
    data.push_back((locktime >> 16) & 0xff);
    data.push_back((locktime >> 24) & 0xff);

    // Hash type
    data.push_back(hash_type);
    data.push_back(0);
    data.push_back(0);
    data.push_back(0);

    // Double hash
    auto first_hash = crypto::keccak256(data.data(), data.size());
    auto second_hash = crypto::keccak256(first_hash.data(), first_hash.size());
    return std::vector<uint8_t>(second_hash.begin(), second_hash.end());
}

std::vector<uint8_t> signatureHashWitness(const chain::Transaction& tx,
                                           unsigned int input_index,
                                           const Script& script_code,
                                           uint8_t hash_type,
                                           uint64_t amount,
                                           const PrecomputedTransactionData* precomputed) {
    // BIP143 signature hash
    std::vector<uint8_t> data;

    bool anyone_can_pay = (hash_type & SIGHASH_ANYONECANPAY) != 0;
    uint8_t base_type = hash_type & 0x1f;

    // Version
    uint32_t version = tx.version;
    data.push_back(version & 0xff);
    data.push_back((version >> 8) & 0xff);
    data.push_back((version >> 16) & 0xff);
    data.push_back((version >> 24) & 0xff);

    // hashPrevouts
    if (!anyone_can_pay && precomputed && precomputed->ready) {
        data.insert(data.end(), precomputed->hash_prevouts.begin(), precomputed->hash_prevouts.end());
    } else if (!anyone_can_pay) {
        // Compute on the fly
        std::vector<uint8_t> prevouts_data;
        for (const auto& input : tx.inputs) {
            prevouts_data.insert(prevouts_data.end(),
                                  input.prevout.txid.begin(),
                                  input.prevout.txid.end());
            uint32_t idx = input.prevout.index;
            prevouts_data.push_back(idx & 0xff);
            prevouts_data.push_back((idx >> 8) & 0xff);
            prevouts_data.push_back((idx >> 16) & 0xff);
            prevouts_data.push_back((idx >> 24) & 0xff);
        }
        auto hash = crypto::keccak256(prevouts_data.data(), prevouts_data.size());
        hash = crypto::keccak256(hash.data(), hash.size());
        data.insert(data.end(), hash.begin(), hash.end());
    } else {
        data.insert(data.end(), 32, 0);
    }

    // hashSequence
    if (!anyone_can_pay && base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE) {
        if (precomputed && precomputed->ready) {
            data.insert(data.end(), precomputed->hash_sequence.begin(), precomputed->hash_sequence.end());
        } else {
            std::vector<uint8_t> seq_data;
            for (const auto& input : tx.inputs) {
                uint32_t seq = input.sequence;
                seq_data.push_back(seq & 0xff);
                seq_data.push_back((seq >> 8) & 0xff);
                seq_data.push_back((seq >> 16) & 0xff);
                seq_data.push_back((seq >> 24) & 0xff);
            }
            auto hash = crypto::keccak256(seq_data.data(), seq_data.size());
            hash = crypto::keccak256(hash.data(), hash.size());
            data.insert(data.end(), hash.begin(), hash.end());
        }
    } else {
        data.insert(data.end(), 32, 0);
    }

    // outpoint
    const auto& input = tx.inputs[input_index];
    data.insert(data.end(), input.prevout.txid.begin(), input.prevout.txid.end());
    uint32_t idx = input.prevout.index;
    data.push_back(idx & 0xff);
    data.push_back((idx >> 8) & 0xff);
    data.push_back((idx >> 16) & 0xff);
    data.push_back((idx >> 24) & 0xff);

    // scriptCode
    const auto& sc = script_code.data();
    if (sc.size() < 0xfd) {
        data.push_back(static_cast<uint8_t>(sc.size()));
    } else {
        data.push_back(0xfd);
        data.push_back(sc.size() & 0xff);
        data.push_back((sc.size() >> 8) & 0xff);
    }
    data.insert(data.end(), sc.begin(), sc.end());

    // amount
    data.push_back(amount & 0xff);
    data.push_back((amount >> 8) & 0xff);
    data.push_back((amount >> 16) & 0xff);
    data.push_back((amount >> 24) & 0xff);
    data.push_back((amount >> 32) & 0xff);
    data.push_back((amount >> 40) & 0xff);
    data.push_back((amount >> 48) & 0xff);
    data.push_back((amount >> 56) & 0xff);

    // sequence
    uint32_t seq = input.sequence;
    data.push_back(seq & 0xff);
    data.push_back((seq >> 8) & 0xff);
    data.push_back((seq >> 16) & 0xff);
    data.push_back((seq >> 24) & 0xff);

    // hashOutputs
    if (base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE) {
        if (precomputed && precomputed->ready) {
            data.insert(data.end(), precomputed->hash_outputs.begin(), precomputed->hash_outputs.end());
        } else {
            std::vector<uint8_t> out_data;
            for (const auto& output : tx.outputs) {
                uint64_t val = output.value;
                out_data.push_back(val & 0xff);
                out_data.push_back((val >> 8) & 0xff);
                out_data.push_back((val >> 16) & 0xff);
                out_data.push_back((val >> 24) & 0xff);
                out_data.push_back((val >> 32) & 0xff);
                out_data.push_back((val >> 40) & 0xff);
                out_data.push_back((val >> 48) & 0xff);
                out_data.push_back((val >> 56) & 0xff);

                const auto& script = output.script_pubkey;
                if (script.size() < 0xfd) {
                    out_data.push_back(static_cast<uint8_t>(script.size()));
                } else {
                    out_data.push_back(0xfd);
                    out_data.push_back(script.size() & 0xff);
                    out_data.push_back((script.size() >> 8) & 0xff);
                }
                out_data.insert(out_data.end(), script.begin(), script.end());
            }
            auto hash = crypto::keccak256(out_data.data(), out_data.size());
            hash = crypto::keccak256(hash.data(), hash.size());
            data.insert(data.end(), hash.begin(), hash.end());
        }
    } else if (base_type == SIGHASH_SINGLE && input_index < tx.outputs.size()) {
        const auto& output = tx.outputs[input_index];
        std::vector<uint8_t> out_data;
        uint64_t val = output.value;
        out_data.push_back(val & 0xff);
        out_data.push_back((val >> 8) & 0xff);
        out_data.push_back((val >> 16) & 0xff);
        out_data.push_back((val >> 24) & 0xff);
        out_data.push_back((val >> 32) & 0xff);
        out_data.push_back((val >> 40) & 0xff);
        out_data.push_back((val >> 48) & 0xff);
        out_data.push_back((val >> 56) & 0xff);

        const auto& script = output.script_pubkey;
        if (script.size() < 0xfd) {
            out_data.push_back(static_cast<uint8_t>(script.size()));
        } else {
            out_data.push_back(0xfd);
            out_data.push_back(script.size() & 0xff);
            out_data.push_back((script.size() >> 8) & 0xff);
        }
        out_data.insert(out_data.end(), script.begin(), script.end());

        auto hash = crypto::keccak256(out_data.data(), out_data.size());
        hash = crypto::keccak256(hash.data(), hash.size());
        data.insert(data.end(), hash.begin(), hash.end());
    } else {
        data.insert(data.end(), 32, 0);
    }

    // locktime
    uint32_t locktime = tx.locktime;
    data.push_back(locktime & 0xff);
    data.push_back((locktime >> 8) & 0xff);
    data.push_back((locktime >> 16) & 0xff);
    data.push_back((locktime >> 24) & 0xff);

    // hash type
    data.push_back(hash_type);
    data.push_back(0);
    data.push_back(0);
    data.push_back(0);

    // Double hash
    auto first_hash = crypto::keccak256(data.data(), data.size());
    auto second_hash = crypto::keccak256(first_hash.data(), first_hash.size());
    return std::vector<uint8_t>(second_hash.begin(), second_hash.end());
}

bool verifySignature(const std::vector<uint8_t>& sig,
                      const std::vector<uint8_t>& pubkey,
                      const std::vector<uint8_t>& hash) {
    if (sig.size() < 64 || pubkey.size() < 33 || hash.size() < 32) {
        return false;
    }

    // Convert DER signature to compact format
    crypto::Signature compact_sig;
    if (!crypto::Secp256k1::instance().signatureFromDER(sig, compact_sig)) {
        // Try treating as compact signature
        if (sig.size() == 64) {
            std::copy(sig.begin(), sig.end(), compact_sig.begin());
        } else {
            return false;
        }
    }

    // Convert pubkey
    crypto::PublicKey pk;
    if (pubkey.size() == 33) {
        std::copy(pubkey.begin(), pubkey.end(), pk.begin());
    } else {
        return false;
    }

    return crypto::verify(hash.data(), compact_sig, pk);
}

bool verifySchnorrSignature(const std::vector<uint8_t>& sig,
                             const std::vector<uint8_t>& pubkey,
                             const std::vector<uint8_t>& hash) {
    // TODO: Implement BIP340 Schnorr signature verification
    return false;
}

//-----------------------------------------------------------------------------
// Signature operation counting
//-----------------------------------------------------------------------------

unsigned int countSigOps(const Script& script, bool accurate) {
    unsigned int count = 0;
    const uint8_t* pc = script.begin();
    const uint8_t* end = script.end();
    uint8_t last_opcode = static_cast<uint8_t>(Opcode::OP_INVALIDOPCODE);

    while (pc < end) {
        uint8_t opcode = *pc++;

        // Skip push data
        if (opcode >= 1 && opcode <= 75) {
            pc += opcode;
        } else if (opcode == static_cast<uint8_t>(Opcode::OP_PUSHDATA1)) {
            if (pc >= end) break;
            pc += 1 + *pc;
        } else if (opcode == static_cast<uint8_t>(Opcode::OP_PUSHDATA2)) {
            if (pc + 2 > end) break;
            pc += 2 + (pc[0] | (pc[1] << 8));
        } else if (opcode == static_cast<uint8_t>(Opcode::OP_PUSHDATA4)) {
            if (pc + 4 > end) break;
            pc += 4 + (pc[0] | (pc[1] << 8) | (pc[2] << 16) | (pc[3] << 24));
        } else if (opcode == static_cast<uint8_t>(Opcode::OP_CHECKSIG) ||
                   opcode == static_cast<uint8_t>(Opcode::OP_CHECKSIGVERIFY)) {
            count++;
        } else if (opcode == static_cast<uint8_t>(Opcode::OP_CHECKMULTISIG) ||
                   opcode == static_cast<uint8_t>(Opcode::OP_CHECKMULTISIGVERIFY)) {
            if (accurate && last_opcode >= static_cast<uint8_t>(Opcode::OP_1) &&
                last_opcode <= static_cast<uint8_t>(Opcode::OP_16)) {
                count += last_opcode - static_cast<uint8_t>(Opcode::OP_1) + 1;
            } else {
                count += MAX_PUBKEYS_PER_MULTISIG;
            }
        }

        last_opcode = opcode;
    }

    return count;
}

unsigned int countP2SHSigOps(const Script& scriptSig, const Script& scriptPubKey) {
    if (!scriptPubKey.isPayToScriptHash()) {
        return countSigOps(scriptPubKey, true);
    }

    // Find the redeemScript (last push in scriptSig)
    std::vector<std::vector<uint8_t>> stack;
    const uint8_t* pc = scriptSig.begin();
    const uint8_t* end = scriptSig.end();

    while (pc < end) {
        uint8_t opcode = *pc++;
        std::vector<uint8_t> data;

        if (opcode >= 1 && opcode <= 75) {
            if (pc + opcode > end) break;
            data.assign(pc, pc + opcode);
            pc += opcode;
        } else if (opcode == static_cast<uint8_t>(Opcode::OP_PUSHDATA1)) {
            if (pc >= end) break;
            uint8_t size = *pc++;
            if (pc + size > end) break;
            data.assign(pc, pc + size);
            pc += size;
        } else if (opcode == static_cast<uint8_t>(Opcode::OP_PUSHDATA2)) {
            if (pc + 2 > end) break;
            uint16_t size = pc[0] | (pc[1] << 8);
            pc += 2;
            if (pc + size > end) break;
            data.assign(pc, pc + size);
            pc += size;
        } else if (opcode == static_cast<uint8_t>(Opcode::OP_PUSHDATA4)) {
            if (pc + 4 > end) break;
            uint32_t size = pc[0] | (pc[1] << 8) | (pc[2] << 16) | (pc[3] << 24);
            pc += 4;
            if (pc + size > end) break;
            data.assign(pc, pc + size);
            pc += size;
        } else {
            continue;
        }

        stack.push_back(data);
    }

    if (stack.empty()) {
        return 0;
    }

    Script redeemScript(stack.back());
    return countSigOps(redeemScript, true);
}

unsigned int countWitnessSigOps(int witness_version,
                                 const std::vector<uint8_t>& witness_program,
                                 const std::vector<std::vector<uint8_t>>& witness) {
    if (witness_version == 0) {
        if (witness_program.size() == 20) {
            // P2WPKH
            return 1;
        } else if (witness_program.size() == 32 && !witness.empty()) {
            // P2WSH - count sigops in witness script
            Script witnessScript(witness.back());
            return countSigOps(witnessScript, true);
        }
    }
    return 0;
}

//-----------------------------------------------------------------------------
// Interpreter
//-----------------------------------------------------------------------------

bool Interpreter::evalScript(const Script& script,
                              uint32_t flags,
                              const BaseSignatureChecker& checker,
                              SigVersion sigversion,
                              ScriptError* error,
                              std::vector<StackElement>* stack) const {
    if (script.size() > MAX_SCRIPT_SIZE) {
        if (error) *error = ScriptError::SCRIPT_SIZE;
        return false;
    }

    ScriptExecutionContext ctx;
    if (stack) {
        ctx.stack = *stack;
    }

    const uint8_t* pc = script.begin();
    const uint8_t* end = script.end();
    const uint8_t* script_begin = pc;

    while (pc < end) {
        uint8_t opcode = *pc;

        if (!executeOpcode(opcode, pc, end, flags, checker, sigversion, ctx, error)) {
            return false;
        }

        // Check stack size
        if (ctx.stack.size() + ctx.altstack.size() > MAX_STACK_SIZE) {
            if (error) *error = ScriptError::STACK_SIZE;
            return false;
        }
    }

    // Check balanced conditionals
    if (!ctx.exec_stack.empty()) {
        if (error) *error = ScriptError::UNBALANCED_CONDITIONAL;
        return false;
    }

    if (stack) {
        *stack = ctx.stack;
    }

    return true;
}

bool Interpreter::executeOpcode(uint8_t opcode,
                                 const uint8_t*& pc,
                                 const uint8_t* end,
                                 uint32_t flags,
                                 const BaseSignatureChecker& checker,
                                 SigVersion sigversion,
                                 ScriptExecutionContext& ctx,
                                 ScriptError* error) const {
    pc++;  // Move past opcode

    bool executing = ctx.executing();

    // Push data opcodes (1-75 bytes)
    if (opcode >= 1 && opcode <= 75) {
        if (pc + opcode > end) {
            if (error) *error = ScriptError::INVALID_STACK_OPERATION;
            return false;
        }
        if (executing) {
            ctx.stack.emplace_back(pc, pc + opcode);
        }
        pc += opcode;
        return true;
    }

    // Extended push data
    if (opcode == static_cast<uint8_t>(Opcode::OP_PUSHDATA1)) {
        if (pc >= end) {
            if (error) *error = ScriptError::INVALID_STACK_OPERATION;
            return false;
        }
        uint8_t size = *pc++;
        if (pc + size > end) {
            if (error) *error = ScriptError::INVALID_STACK_OPERATION;
            return false;
        }
        if (executing) {
            ctx.stack.emplace_back(pc, pc + size);
        }
        pc += size;
        return true;
    }

    if (opcode == static_cast<uint8_t>(Opcode::OP_PUSHDATA2)) {
        if (pc + 2 > end) {
            if (error) *error = ScriptError::INVALID_STACK_OPERATION;
            return false;
        }
        uint16_t size = pc[0] | (pc[1] << 8);
        pc += 2;
        if (pc + size > end) {
            if (error) *error = ScriptError::INVALID_STACK_OPERATION;
            return false;
        }
        if (executing) {
            ctx.stack.emplace_back(pc, pc + size);
        }
        pc += size;
        return true;
    }

    if (opcode == static_cast<uint8_t>(Opcode::OP_PUSHDATA4)) {
        if (pc + 4 > end) {
            if (error) *error = ScriptError::INVALID_STACK_OPERATION;
            return false;
        }
        uint32_t size = pc[0] | (pc[1] << 8) | (pc[2] << 16) | (pc[3] << 24);
        pc += 4;
        if (pc + size > end || size > MAX_SCRIPT_ELEMENT_SIZE) {
            if (error) *error = ScriptError::PUSH_SIZE;
            return false;
        }
        if (executing) {
            ctx.stack.emplace_back(pc, pc + size);
        }
        pc += size;
        return true;
    }

    // Count non-push opcodes
    if (opcode > static_cast<uint8_t>(Opcode::OP_16)) {
        ctx.op_count++;
        if (ctx.op_count > MAX_OPS_PER_SCRIPT) {
            if (error) *error = ScriptError::OP_COUNT;
            return false;
        }
    }

    // OP_0 (false)
    if (opcode == static_cast<uint8_t>(Opcode::OP_0)) {
        if (executing) {
            ctx.stack.emplace_back();
        }
        return true;
    }

    // OP_1NEGATE
    if (opcode == static_cast<uint8_t>(Opcode::OP_1NEGATE)) {
        if (executing) {
            ctx.stack.push_back(intToStackElement(-1));
        }
        return true;
    }

    // OP_1 - OP_16
    if (opcode >= static_cast<uint8_t>(Opcode::OP_1) &&
        opcode <= static_cast<uint8_t>(Opcode::OP_16)) {
        if (executing) {
            int64_t n = opcode - static_cast<uint8_t>(Opcode::OP_1) + 1;
            ctx.stack.push_back(intToStackElement(n));
        }
        return true;
    }

    // Non-executing branch - only process control flow
    if (!executing) {
        if (opcode == static_cast<uint8_t>(Opcode::OP_IF) ||
            opcode == static_cast<uint8_t>(Opcode::OP_NOTIF)) {
            ctx.exec_stack.push_back(false);
        } else if (opcode == static_cast<uint8_t>(Opcode::OP_ELSE)) {
            if (ctx.exec_stack.empty()) {
                if (error) *error = ScriptError::UNBALANCED_CONDITIONAL;
                return false;
            }
            ctx.exec_stack.back() = !ctx.exec_stack.back();
        } else if (opcode == static_cast<uint8_t>(Opcode::OP_ENDIF)) {
            if (ctx.exec_stack.empty()) {
                if (error) *error = ScriptError::UNBALANCED_CONDITIONAL;
                return false;
            }
            ctx.exec_stack.pop_back();
        }
        return true;
    }

    // Check for disabled opcodes
    if (isOpcodeDisabled(static_cast<Opcode>(opcode))) {
        if (error) *error = ScriptError::DISABLED_OPCODE;
        return false;
    }

    // Execute opcode
    switch (static_cast<Opcode>(opcode)) {
        case Opcode::OP_NOP:
            return true;

        case Opcode::OP_IF:
        case Opcode::OP_NOTIF: {
            bool value = false;
            if (ctx.stack.empty()) {
                if (error) *error = ScriptError::UNBALANCED_CONDITIONAL;
                return false;
            }
            StackElement& elem = ctx.stack.back();

            if (flags & SCRIPT_VERIFY_MINIMALIF) {
                if (elem.size() > 1 || (elem.size() == 1 && elem[0] != 1)) {
                    if (error) *error = ScriptError::MINIMALIF;
                    return false;
                }
            }

            value = stackElementIsTrue(elem);
            ctx.stack.pop_back();

            if (opcode == static_cast<uint8_t>(Opcode::OP_NOTIF)) {
                value = !value;
            }
            ctx.exec_stack.push_back(value);
            return true;
        }

        case Opcode::OP_ELSE:
            if (ctx.exec_stack.empty()) {
                if (error) *error = ScriptError::UNBALANCED_CONDITIONAL;
                return false;
            }
            ctx.exec_stack.back() = !ctx.exec_stack.back();
            return true;

        case Opcode::OP_ENDIF:
            if (ctx.exec_stack.empty()) {
                if (error) *error = ScriptError::UNBALANCED_CONDITIONAL;
                return false;
            }
            ctx.exec_stack.pop_back();
            return true;

        case Opcode::OP_VERIFY: {
            if (ctx.stack.empty()) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            if (!stackElementIsTrue(ctx.stack.back())) {
                if (error) *error = ScriptError::EVAL_FALSE;
                return false;
            }
            ctx.stack.pop_back();
            return true;
        }

        case Opcode::OP_RETURN:
            if (error) *error = ScriptError::OP_RETURN;
            return false;

        // Stack ops
        case Opcode::OP_TOALTSTACK:
            if (ctx.stack.empty()) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            ctx.altstack.push_back(std::move(ctx.stack.back()));
            ctx.stack.pop_back();
            return true;

        case Opcode::OP_FROMALTSTACK:
            if (ctx.altstack.empty()) {
                if (error) *error = ScriptError::INVALID_ALTSTACK_OPERATION;
                return false;
            }
            ctx.stack.push_back(std::move(ctx.altstack.back()));
            ctx.altstack.pop_back();
            return true;

        case Opcode::OP_2DROP:
            if (ctx.stack.size() < 2) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            ctx.stack.pop_back();
            ctx.stack.pop_back();
            return true;

        case Opcode::OP_2DUP:
            if (ctx.stack.size() < 2) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            ctx.stack.push_back(ctx.stack[ctx.stack.size() - 2]);
            ctx.stack.push_back(ctx.stack[ctx.stack.size() - 2]);
            return true;

        case Opcode::OP_3DUP:
            if (ctx.stack.size() < 3) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            ctx.stack.push_back(ctx.stack[ctx.stack.size() - 3]);
            ctx.stack.push_back(ctx.stack[ctx.stack.size() - 3]);
            ctx.stack.push_back(ctx.stack[ctx.stack.size() - 3]);
            return true;

        case Opcode::OP_2OVER:
            if (ctx.stack.size() < 4) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            ctx.stack.push_back(ctx.stack[ctx.stack.size() - 4]);
            ctx.stack.push_back(ctx.stack[ctx.stack.size() - 4]);
            return true;

        case Opcode::OP_2ROT:
            if (ctx.stack.size() < 6) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            {
                auto a = ctx.stack[ctx.stack.size() - 6];
                auto b = ctx.stack[ctx.stack.size() - 5];
                ctx.stack.erase(ctx.stack.end() - 6, ctx.stack.end() - 4);
                ctx.stack.push_back(a);
                ctx.stack.push_back(b);
            }
            return true;

        case Opcode::OP_2SWAP:
            if (ctx.stack.size() < 4) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            std::swap(ctx.stack[ctx.stack.size() - 4], ctx.stack[ctx.stack.size() - 2]);
            std::swap(ctx.stack[ctx.stack.size() - 3], ctx.stack[ctx.stack.size() - 1]);
            return true;

        case Opcode::OP_IFDUP:
            if (ctx.stack.empty()) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            if (stackElementIsTrue(ctx.stack.back())) {
                ctx.stack.push_back(ctx.stack.back());
            }
            return true;

        case Opcode::OP_DEPTH:
            ctx.stack.push_back(intToStackElement(static_cast<int64_t>(ctx.stack.size())));
            return true;

        case Opcode::OP_DROP:
            if (ctx.stack.empty()) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            ctx.stack.pop_back();
            return true;

        case Opcode::OP_DUP:
            if (ctx.stack.empty()) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            ctx.stack.push_back(ctx.stack.back());
            return true;

        case Opcode::OP_NIP:
            if (ctx.stack.size() < 2) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            ctx.stack.erase(ctx.stack.end() - 2);
            return true;

        case Opcode::OP_OVER:
            if (ctx.stack.size() < 2) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            ctx.stack.push_back(ctx.stack[ctx.stack.size() - 2]);
            return true;

        case Opcode::OP_PICK:
        case Opcode::OP_ROLL: {
            if (ctx.stack.empty()) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            int64_t n = stackElementToInt(ctx.stack.back(), flags & SCRIPT_VERIFY_MINIMALDATA);
            ctx.stack.pop_back();
            if (n < 0 || static_cast<size_t>(n) >= ctx.stack.size()) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            auto val = ctx.stack[ctx.stack.size() - n - 1];
            if (opcode == static_cast<uint8_t>(Opcode::OP_ROLL)) {
                ctx.stack.erase(ctx.stack.end() - n - 1);
            }
            ctx.stack.push_back(val);
            return true;
        }

        case Opcode::OP_ROT:
            if (ctx.stack.size() < 3) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            {
                auto a = ctx.stack[ctx.stack.size() - 3];
                ctx.stack.erase(ctx.stack.end() - 3);
                ctx.stack.push_back(a);
            }
            return true;

        case Opcode::OP_SWAP:
            if (ctx.stack.size() < 2) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            std::swap(ctx.stack[ctx.stack.size() - 1], ctx.stack[ctx.stack.size() - 2]);
            return true;

        case Opcode::OP_TUCK:
            if (ctx.stack.size() < 2) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            ctx.stack.insert(ctx.stack.end() - 2, ctx.stack.back());
            return true;

        case Opcode::OP_SIZE:
            if (ctx.stack.empty()) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            ctx.stack.push_back(intToStackElement(static_cast<int64_t>(ctx.stack.back().size())));
            return true;

        // Bitwise
        case Opcode::OP_EQUAL:
        case Opcode::OP_EQUALVERIFY: {
            if (ctx.stack.size() < 2) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            auto& a = ctx.stack[ctx.stack.size() - 2];
            auto& b = ctx.stack[ctx.stack.size() - 1];
            bool equal = (a == b);
            ctx.stack.pop_back();
            ctx.stack.pop_back();
            ctx.stack.push_back(equal ? intToStackElement(1) : StackElement());
            if (opcode == static_cast<uint8_t>(Opcode::OP_EQUALVERIFY)) {
                if (!equal) {
                    if (error) *error = ScriptError::EVAL_FALSE;
                    return false;
                }
                ctx.stack.pop_back();
            }
            return true;
        }

        // Numeric
        case Opcode::OP_1ADD:
        case Opcode::OP_1SUB:
        case Opcode::OP_NEGATE:
        case Opcode::OP_ABS:
        case Opcode::OP_NOT:
        case Opcode::OP_0NOTEQUAL: {
            if (ctx.stack.empty()) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            int64_t n = stackElementToInt(ctx.stack.back(), flags & SCRIPT_VERIFY_MINIMALDATA);
            ctx.stack.pop_back();

            switch (static_cast<Opcode>(opcode)) {
                case Opcode::OP_1ADD: n++; break;
                case Opcode::OP_1SUB: n--; break;
                case Opcode::OP_NEGATE: n = -n; break;
                case Opcode::OP_ABS: n = n < 0 ? -n : n; break;
                case Opcode::OP_NOT: n = (n == 0) ? 1 : 0; break;
                case Opcode::OP_0NOTEQUAL: n = (n != 0) ? 1 : 0; break;
                default: break;
            }

            ctx.stack.push_back(intToStackElement(n));
            return true;
        }

        case Opcode::OP_ADD:
        case Opcode::OP_SUB:
        case Opcode::OP_BOOLAND:
        case Opcode::OP_BOOLOR:
        case Opcode::OP_NUMEQUAL:
        case Opcode::OP_NUMEQUALVERIFY:
        case Opcode::OP_NUMNOTEQUAL:
        case Opcode::OP_LESSTHAN:
        case Opcode::OP_GREATERTHAN:
        case Opcode::OP_LESSTHANOREQUAL:
        case Opcode::OP_GREATERTHANOREQUAL:
        case Opcode::OP_MIN:
        case Opcode::OP_MAX: {
            if (ctx.stack.size() < 2) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            int64_t b = stackElementToInt(ctx.stack.back(), flags & SCRIPT_VERIFY_MINIMALDATA);
            ctx.stack.pop_back();
            int64_t a = stackElementToInt(ctx.stack.back(), flags & SCRIPT_VERIFY_MINIMALDATA);
            ctx.stack.pop_back();

            int64_t result = 0;
            switch (static_cast<Opcode>(opcode)) {
                case Opcode::OP_ADD: result = a + b; break;
                case Opcode::OP_SUB: result = a - b; break;
                case Opcode::OP_BOOLAND: result = (a != 0 && b != 0) ? 1 : 0; break;
                case Opcode::OP_BOOLOR: result = (a != 0 || b != 0) ? 1 : 0; break;
                case Opcode::OP_NUMEQUAL:
                case Opcode::OP_NUMEQUALVERIFY: result = (a == b) ? 1 : 0; break;
                case Opcode::OP_NUMNOTEQUAL: result = (a != b) ? 1 : 0; break;
                case Opcode::OP_LESSTHAN: result = (a < b) ? 1 : 0; break;
                case Opcode::OP_GREATERTHAN: result = (a > b) ? 1 : 0; break;
                case Opcode::OP_LESSTHANOREQUAL: result = (a <= b) ? 1 : 0; break;
                case Opcode::OP_GREATERTHANOREQUAL: result = (a >= b) ? 1 : 0; break;
                case Opcode::OP_MIN: result = std::min(a, b); break;
                case Opcode::OP_MAX: result = std::max(a, b); break;
                default: break;
            }

            ctx.stack.push_back(intToStackElement(result));

            if (opcode == static_cast<uint8_t>(Opcode::OP_NUMEQUALVERIFY)) {
                if (result == 0) {
                    if (error) *error = ScriptError::EVAL_FALSE;
                    return false;
                }
                ctx.stack.pop_back();
            }
            return true;
        }

        case Opcode::OP_WITHIN: {
            if (ctx.stack.size() < 3) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }
            int64_t max_val = stackElementToInt(ctx.stack.back(), flags & SCRIPT_VERIFY_MINIMALDATA);
            ctx.stack.pop_back();
            int64_t min_val = stackElementToInt(ctx.stack.back(), flags & SCRIPT_VERIFY_MINIMALDATA);
            ctx.stack.pop_back();
            int64_t x = stackElementToInt(ctx.stack.back(), flags & SCRIPT_VERIFY_MINIMALDATA);
            ctx.stack.pop_back();

            bool within = (x >= min_val && x < max_val);
            ctx.stack.push_back(within ? intToStackElement(1) : StackElement());
            return true;
        }

        // Crypto
        case Opcode::OP_RIPEMD160:
            return opRipemd160(ctx, error);

        case Opcode::OP_SHA1:
            return opSha1(ctx, error);

        case Opcode::OP_SHA256:
            return opSha256(ctx, error);

        case Opcode::OP_HASH160:
            return opHash160(ctx, error);

        case Opcode::OP_HASH256:
            return opHash256(ctx, error);

        case Opcode::OP_CODESEPARATOR:
            ctx.code_separator = pc;
            return true;

        case Opcode::OP_CHECKSIG:
        case Opcode::OP_CHECKSIGVERIFY: {
            // Get script code from code separator
            Script script_code;
            // For now, use the entire script as script code
            // In full implementation, this should start from code_separator

            if (ctx.stack.size() < 2) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }

            auto pubkey = ctx.stack.back();
            ctx.stack.pop_back();
            auto sig = ctx.stack.back();
            ctx.stack.pop_back();

            // Check encodings
            if (!checkSignatureEncoding(sig, flags, error)) {
                return false;
            }
            if (!checkPubKeyEncoding(pubkey, flags, sigversion, error)) {
                return false;
            }

            bool success = false;
            if (!sig.empty()) {
                success = checker.checkSig(sig, pubkey, script_code, sigversion);
            }

            // NULLFAIL check
            if (!success && (flags & SCRIPT_VERIFY_NULLFAIL) && !sig.empty()) {
                if (error) *error = ScriptError::SIG_NULLFAIL;
                return false;
            }

            ctx.stack.push_back(success ? intToStackElement(1) : StackElement());

            if (opcode == static_cast<uint8_t>(Opcode::OP_CHECKSIGVERIFY)) {
                if (!success) {
                    if (error) *error = ScriptError::SIG_VERIFY;
                    return false;
                }
                ctx.stack.pop_back();
            }
            return true;
        }

        case Opcode::OP_CHECKMULTISIG:
        case Opcode::OP_CHECKMULTISIGVERIFY: {
            // Get script code (simplified)
            Script script_code;

            size_t stack_size = ctx.stack.size();
            if (stack_size < 1) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }

            int64_t keys_count = stackElementToInt(ctx.stack.back(), flags & SCRIPT_VERIFY_MINIMALDATA);
            ctx.stack.pop_back();

            if (keys_count < 0 || keys_count > MAX_PUBKEYS_PER_MULTISIG) {
                if (error) *error = ScriptError::PUBKEY_COUNT;
                return false;
            }

            ctx.op_count += keys_count;
            if (ctx.op_count > MAX_OPS_PER_SCRIPT) {
                if (error) *error = ScriptError::OP_COUNT;
                return false;
            }

            if (ctx.stack.size() < static_cast<size_t>(keys_count)) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }

            std::vector<std::vector<uint8_t>> pubkeys;
            for (int64_t i = 0; i < keys_count; i++) {
                pubkeys.push_back(ctx.stack.back());
                ctx.stack.pop_back();
            }

            if (ctx.stack.empty()) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }

            int64_t sigs_count = stackElementToInt(ctx.stack.back(), flags & SCRIPT_VERIFY_MINIMALDATA);
            ctx.stack.pop_back();

            if (sigs_count < 0 || sigs_count > keys_count) {
                if (error) *error = ScriptError::SIG_COUNT;
                return false;
            }

            if (ctx.stack.size() < static_cast<size_t>(sigs_count)) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }

            std::vector<std::vector<uint8_t>> sigs;
            for (int64_t i = 0; i < sigs_count; i++) {
                sigs.push_back(ctx.stack.back());
                ctx.stack.pop_back();
            }

            // Dummy element (must be empty for NULLDUMMY)
            if (ctx.stack.empty()) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }

            auto& dummy = ctx.stack.back();
            if ((flags & SCRIPT_VERIFY_NULLDUMMY) && !dummy.empty()) {
                if (error) *error = ScriptError::SIG_NULLDUMMY;
                return false;
            }
            ctx.stack.pop_back();

            // Verify signatures
            bool success = true;
            size_t key_idx = 0;
            size_t sig_idx = 0;

            while (sig_idx < sigs.size() && success) {
                auto& sig = sigs[sig_idx];
                auto& pubkey = pubkeys[key_idx];

                if (!checkSignatureEncoding(sig, flags, error)) {
                    return false;
                }
                if (!checkPubKeyEncoding(pubkey, flags, sigversion, error)) {
                    return false;
                }

                bool valid = false;
                if (!sig.empty()) {
                    valid = checker.checkSig(sig, pubkey, script_code, sigversion);
                }

                if (valid) {
                    sig_idx++;
                }
                key_idx++;

                // Not enough keys left to satisfy remaining sigs
                if (sigs.size() - sig_idx > pubkeys.size() - key_idx) {
                    success = false;
                }
            }

            // NULLFAIL check
            if (!success && (flags & SCRIPT_VERIFY_NULLFAIL)) {
                for (const auto& sig : sigs) {
                    if (!sig.empty()) {
                        if (error) *error = ScriptError::SIG_NULLFAIL;
                        return false;
                    }
                }
            }

            ctx.stack.push_back(success ? intToStackElement(1) : StackElement());

            if (opcode == static_cast<uint8_t>(Opcode::OP_CHECKMULTISIGVERIFY)) {
                if (!success) {
                    if (error) *error = ScriptError::MULTISIG_VERIFY;
                    return false;
                }
                ctx.stack.pop_back();
            }
            return true;
        }

        case Opcode::OP_CHECKLOCKTIMEVERIFY: {
            if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
                // Treat as NOP2
                return true;
            }

            if (ctx.stack.empty()) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }

            int64_t locktime = stackElementToInt(ctx.stack.back(), flags & SCRIPT_VERIFY_MINIMALDATA, 5);
            if (locktime < 0) {
                if (error) *error = ScriptError::NEGATIVE_LOCKTIME;
                return false;
            }

            if (!checker.checkLockTime(locktime)) {
                if (error) *error = ScriptError::UNSATISFIED_LOCKTIME;
                return false;
            }
            return true;
        }

        case Opcode::OP_CHECKSEQUENCEVERIFY: {
            if (!(flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
                // Treat as NOP3
                return true;
            }

            if (ctx.stack.empty()) {
                if (error) *error = ScriptError::INVALID_STACK_OPERATION;
                return false;
            }

            int64_t sequence = stackElementToInt(ctx.stack.back(), flags & SCRIPT_VERIFY_MINIMALDATA, 5);
            if (sequence < 0) {
                if (error) *error = ScriptError::NEGATIVE_LOCKTIME;
                return false;
            }

            // Sequence disable flag check
            if ((sequence & (1 << 31)) == 0) {
                if (!checker.checkSequence(sequence)) {
                    if (error) *error = ScriptError::UNSATISFIED_SEQUENCE;
                    return false;
                }
            }
            return true;
        }

        case Opcode::OP_NOP1:
        case Opcode::OP_NOP4:
        case Opcode::OP_NOP5:
        case Opcode::OP_NOP6:
        case Opcode::OP_NOP7:
        case Opcode::OP_NOP8:
        case Opcode::OP_NOP9:
        case Opcode::OP_NOP10:
            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                if (error) *error = ScriptError::INVALID_OPCODE;
                return false;
            }
            return true;

        default:
            if (error) *error = ScriptError::INVALID_OPCODE;
            return false;
    }
}

//-----------------------------------------------------------------------------
// Crypto operations
//-----------------------------------------------------------------------------

bool Interpreter::opHash160(ScriptExecutionContext& ctx, ScriptError* error) const {
    if (ctx.stack.empty()) {
        if (error) *error = ScriptError::INVALID_STACK_OPERATION;
        return false;
    }

    auto& elem = ctx.stack.back();

    // RIPEMD160(SHA256(x)) - but we use Keccak256 instead of SHA256
    auto sha_hash = crypto::keccak256(elem.data(), elem.size());

    // For HASH160 we need RIPEMD160 of the Keccak256 result
    // Since we don't have RIPEMD160 in our crypto module, we use
    // a double Keccak256 and take the first 20 bytes
    auto ripe_hash = crypto::keccak256(sha_hash.data(), sha_hash.size());

    ctx.stack.pop_back();
    ctx.stack.emplace_back(ripe_hash.begin(), ripe_hash.begin() + 20);
    return true;
}

bool Interpreter::opHash256(ScriptExecutionContext& ctx, ScriptError* error) const {
    if (ctx.stack.empty()) {
        if (error) *error = ScriptError::INVALID_STACK_OPERATION;
        return false;
    }

    auto& elem = ctx.stack.back();

    // Double Keccak256
    auto hash1 = crypto::keccak256(elem.data(), elem.size());
    auto hash2 = crypto::keccak256(hash1.data(), hash1.size());

    ctx.stack.pop_back();
    ctx.stack.push_back(std::vector<uint8_t>(hash2.begin(), hash2.end()));
    return true;
}

bool Interpreter::opSha256(ScriptExecutionContext& ctx, ScriptError* error) const {
    if (ctx.stack.empty()) {
        if (error) *error = ScriptError::INVALID_STACK_OPERATION;
        return false;
    }

    auto& elem = ctx.stack.back();

    // We use Keccak256 instead of SHA256
    auto hash = crypto::keccak256(elem.data(), elem.size());

    ctx.stack.pop_back();
    ctx.stack.push_back(std::vector<uint8_t>(hash.begin(), hash.end()));
    return true;
}

bool Interpreter::opRipemd160(ScriptExecutionContext& ctx, ScriptError* error) const {
    if (ctx.stack.empty()) {
        if (error) *error = ScriptError::INVALID_STACK_OPERATION;
        return false;
    }

    auto& elem = ctx.stack.back();

    // We use truncated Keccak256 instead of RIPEMD160
    auto hash = crypto::keccak256(elem.data(), elem.size());

    ctx.stack.pop_back();
    ctx.stack.emplace_back(hash.begin(), hash.begin() + 20);
    return true;
}

bool Interpreter::opSha1(ScriptExecutionContext& ctx, ScriptError* error) const {
    if (ctx.stack.empty()) {
        if (error) *error = ScriptError::INVALID_STACK_OPERATION;
        return false;
    }

    auto& elem = ctx.stack.back();

    // We use truncated Keccak256 instead of SHA1
    auto hash = crypto::keccak256(elem.data(), elem.size());

    ctx.stack.pop_back();
    ctx.stack.emplace_back(hash.begin(), hash.begin() + 20);
    return true;
}

//-----------------------------------------------------------------------------
// Signature/pubkey validation
//-----------------------------------------------------------------------------

bool Interpreter::checkSignatureEncoding(const std::vector<uint8_t>& sig,
                                          uint32_t flags,
                                          ScriptError* error) const {
    if (sig.empty()) return true;

    if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) &&
        !isValidSignatureEncoding(sig)) {
        if (error) *error = ScriptError::SIG_DER;
        return false;
    }

    if ((flags & SCRIPT_VERIFY_LOW_S) && !hasLowS(sig)) {
        if (error) *error = ScriptError::SIG_HIGH_S;
        return false;
    }

    if (flags & SCRIPT_VERIFY_STRICTENC) {
        uint8_t hash_type = sig.back() & ~SIGHASH_ANYONECANPAY;
        if (hash_type < SIGHASH_ALL || hash_type > SIGHASH_SINGLE) {
            if (error) *error = ScriptError::SIG_HASHTYPE;
            return false;
        }
    }

    return true;
}

bool Interpreter::checkPubKeyEncoding(const std::vector<uint8_t>& pubkey,
                                       uint32_t flags,
                                       SigVersion sigversion,
                                       ScriptError* error) const {
    if ((flags & SCRIPT_VERIFY_STRICTENC) && !isValidPubKey(pubkey)) {
        if (error) *error = ScriptError::PUBKEYTYPE;
        return false;
    }

    if ((flags & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) &&
        sigversion == SigVersion::WITNESS_V0 &&
        !isCompressedPubKey(pubkey)) {
        if (error) *error = ScriptError::WITNESS_PUBKEYTYPE;
        return false;
    }

    return true;
}

//-----------------------------------------------------------------------------
// Script verification
//-----------------------------------------------------------------------------

bool Interpreter::verifyScript(const Script& scriptSig,
                                const Script& scriptPubKey,
                                const std::vector<std::vector<uint8_t>>* witness,
                                uint32_t flags,
                                const BaseSignatureChecker& checker,
                                ScriptError* error) const {
    // Check scriptSig is push-only
    if ((flags & SCRIPT_VERIFY_SIGPUSHONLY) && !scriptSig.isPushOnly()) {
        if (error) *error = ScriptError::SIG_PUSHONLY;
        return false;
    }

    std::vector<StackElement> stack;
    std::vector<StackElement> stack_copy;

    // Evaluate scriptSig
    if (!evalScript(scriptSig, flags, checker, SigVersion::BASE, error, &stack)) {
        return false;
    }

    // Copy stack for P2SH
    if (flags & SCRIPT_VERIFY_P2SH) {
        stack_copy = stack;
    }

    // Evaluate scriptPubKey
    if (!evalScript(scriptPubKey, flags, checker, SigVersion::BASE, error, &stack)) {
        return false;
    }

    // Check result
    if (stack.empty() || !stackElementIsTrue(stack.back())) {
        if (error) *error = ScriptError::EVAL_FALSE;
        return false;
    }

    // P2WSH / P2WPKH
    int witness_version = -1;
    std::vector<uint8_t> witness_program;
    if (flags & SCRIPT_VERIFY_WITNESS) {
        if (scriptPubKey.isWitnessProgram(witness_version, witness_program)) {
            if (!scriptSig.empty()) {
                if (error) *error = ScriptError::WITNESS_MALLEATED;
                return false;
            }

            if (!witness || witness->empty()) {
                if (error) *error = ScriptError::WITNESS_PROGRAM_WITNESS_EMPTY;
                return false;
            }

            if (!verifyWitnessProgram(witness_program, witness_version, *witness, flags, checker, error)) {
                return false;
            }

            // Witness scripts clean stack
            stack.resize(1);
        }
    }

    // P2SH
    if ((flags & SCRIPT_VERIFY_P2SH) && scriptPubKey.isPayToScriptHash()) {
        if (!scriptSig.isPushOnly()) {
            if (error) *error = ScriptError::SIG_PUSHONLY;
            return false;
        }

        if (stack_copy.empty()) {
            if (error) *error = ScriptError::EVAL_FALSE;
            return false;
        }

        Script redeem_script(stack_copy.back());
        stack_copy.pop_back();

        if (!evalScript(redeem_script, flags, checker, SigVersion::BASE, error, &stack_copy)) {
            return false;
        }

        if (stack_copy.empty() || !stackElementIsTrue(stack_copy.back())) {
            if (error) *error = ScriptError::EVAL_FALSE;
            return false;
        }

        // P2SH-wrapped witness
        if ((flags & SCRIPT_VERIFY_WITNESS) &&
            redeem_script.isWitnessProgram(witness_version, witness_program)) {
            if (scriptSig.size() != redeem_script.size() + 2) {
                if (error) *error = ScriptError::WITNESS_MALLEATED_P2SH;
                return false;
            }

            if (!witness || witness->empty()) {
                if (error) *error = ScriptError::WITNESS_PROGRAM_WITNESS_EMPTY;
                return false;
            }

            if (!verifyWitnessProgram(witness_program, witness_version, *witness, flags, checker, error)) {
                return false;
            }

            stack_copy.resize(1);
        }

        stack = stack_copy;
    }

    // Clean stack check
    if ((flags & SCRIPT_VERIFY_CLEANSTACK) && stack.size() != 1) {
        if (error) *error = ScriptError::CLEANSTACK;
        return false;
    }

    return true;
}

bool Interpreter::verifyWitnessProgram(const std::vector<uint8_t>& witness_program,
                                        int witness_version,
                                        const std::vector<std::vector<uint8_t>>& witness,
                                        uint32_t flags,
                                        const BaseSignatureChecker& checker,
                                        ScriptError* error) const {
    if (witness_version == 0) {
        if (witness_program.size() == 20) {
            // P2WPKH
            if (witness.size() != 2) {
                if (error) *error = ScriptError::WITNESS_PROGRAM_MISMATCH;
                return false;
            }

            // Construct P2PKH script: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
            Script script_code = Script::createP2PKH(witness_program);

            std::vector<StackElement> stack(witness.begin(), witness.end());
            if (!evalScript(script_code, flags, checker, SigVersion::WITNESS_V0, error, &stack)) {
                return false;
            }

            if (stack.size() != 1 || !stackElementIsTrue(stack.back())) {
                if (error) *error = ScriptError::EVAL_FALSE;
                return false;
            }

            return true;
        } else if (witness_program.size() == 32) {
            // P2WSH
            if (witness.empty()) {
                if (error) *error = ScriptError::WITNESS_PROGRAM_WITNESS_EMPTY;
                return false;
            }

            // Witness script is the last item
            Script witness_script(witness.back());

            // Verify script hash
            auto script_hash = crypto::keccak256(witness_script.data().data(),
                                                  witness_script.data().size());
            if (witness_program.size() != 32 ||
                !std::equal(script_hash.begin(), script_hash.end(), witness_program.begin())) {
                if (error) *error = ScriptError::WITNESS_PROGRAM_MISMATCH;
                return false;
            }

            // Execute witness script with witness stack (minus script)
            std::vector<StackElement> stack(witness.begin(), witness.end() - 1);
            if (!evalScript(witness_script, flags, checker, SigVersion::WITNESS_V0, error, &stack)) {
                return false;
            }

            if (stack.size() != 1 || !stackElementIsTrue(stack.back())) {
                if (error) *error = ScriptError::EVAL_FALSE;
                return false;
            }

            return true;
        } else {
            if (error) *error = ScriptError::WITNESS_PROGRAM_WRONG_LENGTH;
            return false;
        }
    } else if (witness_version == 1 && witness_program.size() == 32) {
        // Taproot (v1)
        // TODO: Implement Taproot verification
        if (error) *error = ScriptError::UNKNOWN_ERROR;
        return false;
    } else {
        // Unknown witness version - succeed for forward compatibility
        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
            if (error) *error = ScriptError::UNKNOWN_ERROR;
            return false;
        }
        return true;
    }
}

} // namespace script
} // namespace ftc
