#ifndef FTC_SCRIPT_INTERPRETER_H
#define FTC_SCRIPT_INTERPRETER_H

#include "script/script.h"
#include "chain/transaction.h"
#include <vector>
#include <functional>
#include <memory>
#include <mutex>
#include <map>

namespace ftc {
namespace script {

// Maximum sizes
constexpr size_t MAX_SCRIPT_SIZE = 10000;
constexpr size_t MAX_STACK_SIZE = 1000;
constexpr size_t MAX_OPS_PER_SCRIPT = 201;
constexpr size_t MAX_PUBKEYS_PER_MULTISIG = 20;
constexpr size_t MAX_SCRIPT_ELEMENT_SIZE = 520;

// Signature hash cache for performance
class SignatureCache {
public:
    static SignatureCache& instance();

    // Check if signature verification is cached
    bool get(const std::vector<uint8_t>& hash, bool& valid) const;

    // Cache signature verification result
    void set(const std::vector<uint8_t>& hash, bool valid);

    // Clear cache
    void clear();

    // Set maximum entries
    void setMaxEntries(size_t max) { max_entries_ = max; }

private:
    SignatureCache() : max_entries_(100000) {}

    mutable std::mutex mutex_;
    std::map<std::vector<uint8_t>, bool> cache_;
    size_t max_entries_;
};

// Pre-computed signature hash for signing/verification
struct PrecomputedTransactionData {
    // BIP143 (SegWit v0) precomputed data
    std::vector<uint8_t> hash_prevouts;      // SHA256d of all prevouts
    std::vector<uint8_t> hash_sequence;      // SHA256d of all sequences
    std::vector<uint8_t> hash_outputs;       // SHA256d of all outputs

    // BIP341 (Taproot) precomputed data
    std::vector<uint8_t> hash_amounts;       // SHA256 of all input amounts
    std::vector<uint8_t> hash_script_pubkeys; // SHA256 of all scriptPubKeys
    std::vector<uint8_t> spend_type;

    bool ready = false;

    // Initialize from transaction
    void init(const chain::Transaction& tx,
              const std::vector<chain::TxOutput>& spent_outputs);
};

// Signature version for different script types (must be before BaseSignatureChecker)
enum class SigVersion {
    BASE,        // Legacy (pre-SegWit)
    WITNESS_V0,  // SegWit v0 (P2WPKH, P2WSH)
    TAPROOT,     // Taproot key path
    TAPSCRIPT    // Taproot script path
};

// Signature checker - verifies signatures against transaction
class BaseSignatureChecker {
public:
    virtual ~BaseSignatureChecker() = default;

    // Check ECDSA signature
    virtual bool checkSig(const std::vector<uint8_t>& sig,
                          const std::vector<uint8_t>& pubkey,
                          const Script& script_code,
                          SigVersion sigversion) const = 0;

    // Check Schnorr signature (Taproot)
    virtual bool checkSchnorrSig(const std::vector<uint8_t>& sig,
                                  const std::vector<uint8_t>& pubkey,
                                  SigVersion sigversion,
                                  ScriptError* error) const {
        return false;
    }

    // Check locktime
    virtual bool checkLockTime(int64_t locktime) const { return false; }

    // Check sequence
    virtual bool checkSequence(int64_t sequence) const { return false; }
};

// Transaction signature checker
class TransactionSignatureChecker : public BaseSignatureChecker {
public:
    TransactionSignatureChecker(const chain::Transaction* tx,
                                 unsigned int input_index,
                                 uint64_t amount,
                                 const PrecomputedTransactionData* precomputed = nullptr);

    bool checkSig(const std::vector<uint8_t>& sig,
                  const std::vector<uint8_t>& pubkey,
                  const Script& script_code,
                  SigVersion sigversion) const override;

    bool checkSchnorrSig(const std::vector<uint8_t>& sig,
                          const std::vector<uint8_t>& pubkey,
                          SigVersion sigversion,
                          ScriptError* error) const override;

    bool checkLockTime(int64_t locktime) const override;
    bool checkSequence(int64_t sequence) const override;

private:
    const chain::Transaction* tx_;
    unsigned int input_index_;
    uint64_t amount_;
    const PrecomputedTransactionData* precomputed_;
};

// Dummy signature checker for signature counting
class DummySignatureChecker : public BaseSignatureChecker {
public:
    bool checkSig(const std::vector<uint8_t>&,
                  const std::vector<uint8_t>&,
                  const Script&,
                  SigVersion) const override { return true; }
};

// Script execution context
struct ScriptExecutionContext {
    // Main stack
    std::vector<StackElement> stack;

    // Alt stack (for OP_TOALTSTACK / OP_FROMALTSTACK)
    std::vector<StackElement> altstack;

    // Conditional execution stack
    std::vector<bool> exec_stack;

    // Current opcode count
    size_t op_count = 0;

    // Code separator position
    const uint8_t* code_separator = nullptr;

    // Are we executing (not in disabled branch)?
    bool executing() const {
        for (bool v : exec_stack) {
            if (!v) return false;
        }
        return true;
    }
};

/**
 * Script Interpreter - executes Bitcoin-style scripts
 *
 * The interpreter implements a stack-based virtual machine that executes
 * scripts to validate transactions. Scripts consist of opcodes that:
 * - Push data onto the stack
 * - Perform stack manipulation
 * - Perform cryptographic operations
 * - Control flow
 *
 * Transaction validation requires evaluating:
 * 1. scriptSig (unlocking script from input)
 * 2. scriptPubKey (locking script from output being spent)
 * 3. For P2SH: serialized script from scriptSig
 * 4. For SegWit: witness data
 */
class Interpreter {
public:
    Interpreter() = default;

    /**
     * Evaluate a script
     *
     * @param script Script to execute
     * @param flags Verification flags
     * @param checker Signature checker for transaction context
     * @param sigversion Script type (legacy, segwit, taproot)
     * @param error Output error code if verification fails
     * @param stack Initial stack (modified in place)
     * @return true if script execution succeeds
     */
    bool evalScript(const Script& script,
                    uint32_t flags,
                    const BaseSignatureChecker& checker,
                    SigVersion sigversion,
                    ScriptError* error,
                    std::vector<StackElement>* stack) const;

    /**
     * Verify a complete script (scriptSig + scriptPubKey)
     *
     * @param scriptSig Unlocking script
     * @param scriptPubKey Locking script
     * @param witness Witness data (for SegWit)
     * @param flags Verification flags
     * @param checker Signature checker
     * @param error Output error code
     * @return true if script verifies successfully
     */
    bool verifyScript(const Script& scriptSig,
                      const Script& scriptPubKey,
                      const std::vector<std::vector<uint8_t>>* witness,
                      uint32_t flags,
                      const BaseSignatureChecker& checker,
                      ScriptError* error) const;

private:
    // Execute a single opcode
    bool executeOpcode(uint8_t opcode,
                       const uint8_t*& pc,
                       const uint8_t* end,
                       uint32_t flags,
                       const BaseSignatureChecker& checker,
                       SigVersion sigversion,
                       ScriptExecutionContext& ctx,
                       ScriptError* error) const;

    // Read push data from script
    bool readPushData(const uint8_t*& pc, const uint8_t* end,
                      std::vector<uint8_t>& data, ScriptError* error) const;

    // Crypto operations
    bool opHash160(ScriptExecutionContext& ctx, ScriptError* error) const;
    bool opHash256(ScriptExecutionContext& ctx, ScriptError* error) const;
    bool opSha256(ScriptExecutionContext& ctx, ScriptError* error) const;
    bool opRipemd160(ScriptExecutionContext& ctx, ScriptError* error) const;
    bool opSha1(ScriptExecutionContext& ctx, ScriptError* error) const;

    // Signature operations
    bool opCheckSig(const BaseSignatureChecker& checker,
                    const Script& script_code,
                    SigVersion sigversion,
                    uint32_t flags,
                    ScriptExecutionContext& ctx,
                    ScriptError* error) const;

    bool opCheckMultisig(const BaseSignatureChecker& checker,
                         const Script& script_code,
                         SigVersion sigversion,
                         uint32_t flags,
                         ScriptExecutionContext& ctx,
                         ScriptError* error) const;

    // SegWit verification
    bool verifyWitnessProgram(const std::vector<uint8_t>& witness_program,
                               int witness_version,
                               const std::vector<std::vector<uint8_t>>& witness,
                               uint32_t flags,
                               const BaseSignatureChecker& checker,
                               ScriptError* error) const;

    // Helper to check signature encoding
    bool checkSignatureEncoding(const std::vector<uint8_t>& sig,
                                 uint32_t flags,
                                 ScriptError* error) const;

    // Helper to check pubkey encoding
    bool checkPubKeyEncoding(const std::vector<uint8_t>& pubkey,
                              uint32_t flags,
                              SigVersion sigversion,
                              ScriptError* error) const;

    // Check minimal push
    bool checkMinimalPush(const std::vector<uint8_t>& data,
                           uint8_t opcode) const;
};

// Compute signature hash for signing/verification
std::vector<uint8_t> signatureHash(const chain::Transaction& tx,
                                    unsigned int input_index,
                                    const Script& script_code,
                                    uint8_t hash_type,
                                    uint64_t amount,
                                    SigVersion sigversion,
                                    const PrecomputedTransactionData* precomputed = nullptr);

// BIP143 signature hash (SegWit v0)
std::vector<uint8_t> signatureHashWitness(const chain::Transaction& tx,
                                           unsigned int input_index,
                                           const Script& script_code,
                                           uint8_t hash_type,
                                           uint64_t amount,
                                           const PrecomputedTransactionData* precomputed);

// Legacy signature hash
std::vector<uint8_t> signatureHashLegacy(const chain::Transaction& tx,
                                          unsigned int input_index,
                                          const Script& script_code,
                                          uint8_t hash_type);

// Verify ECDSA signature
bool verifySignature(const std::vector<uint8_t>& sig,
                      const std::vector<uint8_t>& pubkey,
                      const std::vector<uint8_t>& hash);

// Verify Schnorr signature (BIP340)
bool verifySchnorrSignature(const std::vector<uint8_t>& sig,
                             const std::vector<uint8_t>& pubkey,
                             const std::vector<uint8_t>& hash);

// Check if signature has low S value (BIP62)
bool hasLowS(const std::vector<uint8_t>& sig);

// Check if signature is valid DER
bool isValidSignatureEncoding(const std::vector<uint8_t>& sig);

// Check if pubkey is valid
bool isValidPubKey(const std::vector<uint8_t>& pubkey);

// Check if pubkey is compressed
bool isCompressedPubKey(const std::vector<uint8_t>& pubkey);

// Extract hash type from signature
uint8_t getHashType(const std::vector<uint8_t>& sig);

// Count signature operations in script
unsigned int countSigOps(const Script& script, bool accurate = false);

// Count signature operations including P2SH
unsigned int countP2SHSigOps(const Script& scriptSig, const Script& scriptPubKey);

// Count witness signature operations
unsigned int countWitnessSigOps(int witness_version,
                                 const std::vector<uint8_t>& witness_program,
                                 const std::vector<std::vector<uint8_t>>& witness);

} // namespace script
} // namespace ftc

#endif // FTC_SCRIPT_INTERPRETER_H
