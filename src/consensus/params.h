#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// ConsensusParams -- central consensus parameters for the FTC protocol
// ---------------------------------------------------------------------------
// Defines all chain-level constants: proof-of-work limits, block timing,
// subsidy schedule, activation heights, network identifiers, and weight /
// fee policy values.
// ---------------------------------------------------------------------------

#include "core/types.h"
#include "primitives/amount.h"
#include "primitives/block_header.h"
#include "primitives/transaction.h"

#include <cstdint>
#include <string>

namespace consensus {

/// All tuneable consensus parameters for a given network (mainnet, testnet,
/// regtest).  An instance is typically obtained via one of the static
/// factory methods and then held by reference throughout the node lifetime.
struct ConsensusParams {

    // -- Proof-of-work ------------------------------------------------------

    /// Maximum proof-of-work target (minimum difficulty).
    core::uint256 pow_limit;

    /// Target spacing between blocks, in seconds (10 minutes).
    int64_t pow_target_spacing = 600;

    /// Target timespan over which difficulty is recalculated.
    /// 2016 blocks * 600 seconds = 1,209,600 seconds (~2 weeks).
    int64_t pow_target_timespan = 2016 * 600;

    /// Number of blocks between difficulty adjustments.
    [[nodiscard]] int64_t difficulty_adjustment_interval() const noexcept {
        return pow_target_timespan / pow_target_spacing;
    }

    // -- Subsidy schedule ---------------------------------------------------

    /// Number of blocks between subsidy halvings.
    int subsidy_halving_interval = 210'000;

    // -- Deployment activation heights (all genesis-active for FTC) ----------

    /// BIP34: require block height in coinbase scriptSig.
    int bip34_height = 0;

    /// BIP65: OP_CHECKLOCKTIMEVERIFY.
    int bip65_height = 0;

    /// BIP66: strict DER signature encoding.
    int bip66_height = 0;

    /// Segregated witness activation height.
    int segwit_height = 0;

    // -- Genesis block ------------------------------------------------------

    /// The genesis block header.
    primitives::BlockHeader genesis_block;

    /// The genesis coinbase message embedded in the scriptSig.
    std::string genesis_message = "Pilatovich Kristian 20091227";

    /// Reconstruct the full genesis coinbase transaction.
    [[nodiscard]] primitives::Transaction create_genesis_coinbase() const;

    // -- BIP9 versionbits ---------------------------------------------------

    /// Minimum number of blocks signalling support within a
    /// miner_confirmation_window for a softfork to lock in.
    int rule_change_activation_threshold = 1916;

    /// Size of the miner signalling window (same as difficulty period).
    int miner_confirmation_window = 2016;

    // -- Block weight / size limits -----------------------------------------

    /// Maximum block weight in weight units (4 MWU).
    uint32_t max_block_weight = 4'000'000;

    /// Maximum serialized block size in bytes.
    uint32_t max_block_serialized_size = 4'000'000;

    /// Witness scale factor (non-witness bytes count 4x).
    int witness_scale_factor = 4;

    // -- Maturity -----------------------------------------------------------

    /// Number of confirmations before a coinbase output may be spent.
    int coinbase_maturity = 100;

    // -- Fee policy ---------------------------------------------------------

    /// Minimum transaction relay fee in satoshis.
    int64_t min_tx_fee = 1'000;

    /// Dust relay fee threshold in satoshis.
    int64_t dust_relay_fee = 3'000;

    // -- Network identification ---------------------------------------------

    /// Default P2P listen port.
    uint16_t default_port = 9333;

    /// Default JSON-RPC port.
    uint16_t rpc_port = 9332;

    /// Network magic bytes (wire protocol message prefix).
    uint32_t magic_bytes = 0x46544321;

    // -- Static factory methods ---------------------------------------------

    /// Returns the consensus parameters for mainnet.
    static const ConsensusParams& mainnet_params();

    /// Returns the consensus parameters for the public test network.
    static const ConsensusParams& testnet_params();

    /// Returns the consensus parameters for the local regression-test mode.
    static const ConsensusParams& regtest_params();
};

} // namespace consensus
