#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Coinbase transaction construction for FTC mining.
//
// Creates the coinbase transaction that pays the block reward (subsidy +
// collected fees) to the miner's address. Includes:
//   - BIP34 block height encoding in the scriptSig
//   - Extra nonce for additional hash-space
//   - Miner identification tag
//   - Optional witness commitment (BIP141) in a second output
// ---------------------------------------------------------------------------

#include "core/error.h"
#include "core/types.h"
#include "primitives/address.h"
#include "primitives/amount.h"
#include "primitives/transaction.h"

#include <cstdint>
#include <string>
#include <vector>

namespace miner {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of confirmations required before coinbase outputs can be spent.
static constexpr int COINBASE_MATURITY = 100;

/// Default miner identification tag embedded in the coinbase scriptSig.
static constexpr const char* MINER_TAG = "FTC Miner v1.0";

/// Maximum size of the coinbase scriptSig in bytes.
static constexpr size_t MAX_COINBASE_SCRIPTSIG_SIZE = 100;

/// Witness commitment header (4 bytes) as defined by BIP141.
/// 0xaa21a9ed is the commitment header.
static constexpr uint8_t WITNESS_COMMITMENT_HEADER[4] = {
    0xaa, 0x21, 0xa9, 0xed
};

// ---------------------------------------------------------------------------
// Coinbase script construction
// ---------------------------------------------------------------------------

/// Encode a block height as a BIP34 script number push.
///
/// BIP34 requires the block height to be the first item pushed onto the
/// stack in the coinbase scriptSig. The height is encoded as a
/// CScriptNum (signed, little-endian, minimal encoding).
///
/// @param height  The block height to encode (must be >= 0).
/// @returns       The serialized script bytes for the height push.
[[nodiscard]] std::vector<uint8_t> encode_height(int height);

/// Build the coinbase scriptSig.
///
/// Format: [height_push] [extra_nonce_push] [tag_string]
///
/// @param height       Block height (BIP34).
/// @param extra_nonce  Extra nonce value for additional randomness.
/// @returns            The complete coinbase scriptSig bytes.
[[nodiscard]] std::vector<uint8_t> build_coinbase_script(
    int height,
    uint64_t extra_nonce);

// ---------------------------------------------------------------------------
// Witness commitment
// ---------------------------------------------------------------------------

/// Compute the witness commitment hash for segwit blocks.
///
/// The witness commitment is:
///   keccak256d(witness_merkle_root || witness_reserved_value)
///
/// where witness_reserved_value is 32 zero bytes and the witness merkle
/// root is computed from all wtxids (with the coinbase wtxid replaced by
/// 32 zero bytes).
///
/// @param witness_merkle_root  The witness merkle root of the block.
/// @returns                    The 32-byte witness commitment hash.
[[nodiscard]] core::uint256 compute_witness_commitment(
    const core::uint256& witness_merkle_root);

/// Build the witness commitment output script.
///
/// Format: OP_RETURN [commitment_header (4 bytes) || commitment_hash (32 bytes)]
///
/// @param witness_merkle_root  The witness merkle root.
/// @returns                    The scriptPubKey for the witness commitment output.
[[nodiscard]] std::vector<uint8_t> build_witness_commitment_script(
    const core::uint256& witness_merkle_root);

// ---------------------------------------------------------------------------
// Coinbase transaction creation
// ---------------------------------------------------------------------------

/// Create a complete coinbase transaction.
///
/// The coinbase transaction has:
///   - One input with a null outpoint (txid=0, n=0xFFFFFFFF) and the
///     BIP34 scriptSig encoding the block height.
///   - First output: pays (subsidy + fees) to the miner's address script.
///   - Optional second output: witness commitment (OP_RETURN) if the block
///     contains segwit transactions.
///
/// @param height         The height of the block being mined.
/// @param coinbase_addr  The miner's payout address.
/// @param fees           Total fees from all transactions in the block.
/// @param subsidy        The block subsidy (newly created coins).
/// @param extra_nonce    Extra nonce for hash-space expansion.
/// @param include_witness  Whether to include the witness commitment output.
/// @param witness_merkle_root  The witness merkle root (only used if
///                             include_witness is true).
/// @returns              The complete coinbase Transaction, or an error.
[[nodiscard]] core::Result<primitives::Transaction> create_coinbase(
    int height,
    const primitives::Address& coinbase_addr,
    primitives::Amount fees,
    primitives::Amount subsidy,
    uint64_t extra_nonce = 0,
    bool include_witness = false,
    const core::uint256& witness_merkle_root = core::uint256{});

/// Validate that a coinbase transaction is well-formed.
///
/// Checks:
///   - Exactly one input with a null outpoint.
///   - scriptSig size is within [2, MAX_COINBASE_SCRIPTSIG_SIZE].
///   - At least one output.
///   - Total output value does not exceed (subsidy + fees).
///
/// @param tx       The transaction to validate.
/// @param height   Expected block height.
/// @param subsidy  Expected block subsidy.
/// @param fees     Expected total fees.
/// @returns        core::make_ok() on success, or an error.
[[nodiscard]] core::Result<void> validate_coinbase(
    const primitives::Transaction& tx,
    int height,
    primitives::Amount subsidy,
    primitives::Amount fees);

} // namespace miner
