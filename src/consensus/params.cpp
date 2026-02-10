// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/params.h"
#include "consensus/subsidy.h"

#include "crypto/keccak.h"
#include "primitives/outpoint.h"
#include "primitives/txin.h"
#include "primitives/txout.h"
#include "primitives/script/script.h"

#include <cstring>
#include <span>

namespace consensus {

// ---------------------------------------------------------------------------
// Genesis coinbase reconstruction
// ---------------------------------------------------------------------------

primitives::Transaction ConsensusParams::create_genesis_coinbase() const {
    // Build scriptSig: [BIP34 height=0] [bits LE] [message]
    primitives::script::Script script;
    script.push_int(0);

    uint32_t bits_val = genesis_block.bits;
    uint8_t bits_bytes[4];
    std::memcpy(bits_bytes, &bits_val, 4);
    script.push_data(std::span<const uint8_t>(bits_bytes, 4));

    std::vector<uint8_t> msg_bytes(genesis_message.begin(), genesis_message.end());
    script.push_data(std::span<const uint8_t>(msg_bytes.data(), msg_bytes.size()));

    // Coinbase input (null outpoint)
    primitives::TxInput coinbase_in;
    coinbase_in.prevout = primitives::OutPoint{};
    coinbase_in.script_sig = script.data();
    coinbase_in.sequence = primitives::TxInput::SEQUENCE_FINAL;

    // Coinbase output: 50 FTC to unspendable address (hash160 of message)
    auto msg_hash = crypto::hash160(
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(genesis_message.data()),
            genesis_message.size()));
    auto output_script = primitives::script::Script::p2pkh(msg_hash);

    primitives::TxOutput coinbase_out;
    coinbase_out.amount = get_block_subsidy(0, *this);
    coinbase_out.script_pubkey = output_script.data();

    return primitives::Transaction(
        std::vector<primitives::TxInput>{coinbase_in},
        std::vector<primitives::TxOutput>{coinbase_out}, 1, 0);
}

// ---------------------------------------------------------------------------
// Mainnet parameters
// ---------------------------------------------------------------------------
const ConsensusParams& ConsensusParams::mainnet_params() {
    static const ConsensusParams params = [] {
        ConsensusParams p;

        // Proof-of-work limit (minimum difficulty target).
        // Top 13 bits are zero, giving ~8192 nonces per solution on average.
        // target_to_bits(pow_limit) == 0x1f07ffff.
        p.pow_limit = core::uint256::from_hex(
            "0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        p.pow_target_spacing  = 600;          // 10 minutes
        p.pow_target_timespan = 2016 * 600;   // ~2 weeks (1,209,600 s)

        // Subsidy
        p.subsidy_halving_interval = 210'000;

        // All soft-forks active from genesis
        p.bip34_height  = 0;
        p.bip65_height  = 0;
        p.bip66_height  = 0;
        p.segwit_height = 0;

        // Genesis block header
        // Message: "Pilatovich Kristian 20091227"
        // Hash: 0000451ca7b54fd5e3d96f6b07b9ee74d9dd9abebd8b8ae4e9b78f2c740c2bb7
        p.genesis_block.version     = 1;
        p.genesis_block.prev_hash   = core::uint256{};  // all zeros
        p.genesis_block.merkle_root = core::uint256::from_hex(
            "25ebc8574565ffc8640590e0b0d3aba5da8cccd6cf9e99cd263b8ab064c8849d");
        p.genesis_block.timestamp   = 1738540800;        // 2026-02-03 00:00:00 UTC
        p.genesis_block.bits        = 0x1f07ffff;        // target_to_bits(pow_limit)
        p.genesis_block.nonce       = 4737;

        // BIP9 versionbits
        p.rule_change_activation_threshold = 1916;
        p.miner_confirmation_window        = 2016;

        // Block weight / size
        p.max_block_weight          = 4'000'000;
        p.max_block_serialized_size = 4'000'000;
        p.witness_scale_factor      = 4;

        // Maturity
        p.coinbase_maturity = 100;

        // Fee policy
        p.min_tx_fee      = 1'000;   // satoshis
        p.dust_relay_fee  = 3'000;   // satoshis

        // Network
        p.default_port = 9333;
        p.rpc_port     = 9332;
        p.magic_bytes  = 0x46544321;

        return p;
    }();

    return params;
}

// ---------------------------------------------------------------------------
// Testnet parameters
// ---------------------------------------------------------------------------
const ConsensusParams& ConsensusParams::testnet_params() {
    static const ConsensusParams params = [] {
        // Start from mainnet and override what differs.
        ConsensusParams p = mainnet_params();

        // Higher pow_limit for testnet to allow easy CPU mining.
        p.pow_limit = core::uint256::from_hex(
            "07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        p.genesis_block.bits = 0x2007ffff;   // target_to_bits(pow_limit)

        // Faster retargeting on testnet: same interval count but the
        // target spacing is unchanged (the testnet special rule that allows
        // min-difficulty blocks after 20 minutes is enforced at the
        // validation layer, not here).

        // All soft-forks still active from genesis on testnet.
        p.bip34_height  = 0;
        p.bip65_height  = 0;
        p.bip66_height  = 0;
        p.segwit_height = 0;

        // BIP9 -- lower threshold for testnet to ease deployment testing.
        p.rule_change_activation_threshold = 1512;

        // Different genesis timestamp
        p.genesis_block.timestamp = 1296688602;
        p.genesis_block.nonce     = 0;

        // Distinct ports so mainnet and testnet can coexist.
        p.default_port = 19333;
        p.rpc_port     = 19332;

        // Distinct magic bytes for the test network.
        p.magic_bytes = 0x46544354;  // "FTCT"

        return p;
    }();

    return params;
}

// ---------------------------------------------------------------------------
// Regtest parameters
// ---------------------------------------------------------------------------
const ConsensusParams& ConsensusParams::regtest_params() {
    static const ConsensusParams params = [] {
        ConsensusParams p;

        // Trivially easy difficulty so blocks can be mined instantly.
        p.pow_limit = core::uint256::from_hex(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        p.pow_target_spacing  = 600;
        p.pow_target_timespan = 2016 * 600;

        // Halve every 150 blocks for quick testing.
        p.subsidy_halving_interval = 150;

        p.bip34_height  = 0;
        p.bip65_height  = 0;
        p.bip66_height  = 0;
        p.segwit_height = 0;

        p.genesis_block.version     = 1;
        p.genesis_block.prev_hash   = core::uint256{};
        p.genesis_block.merkle_root = core::uint256{};
        p.genesis_block.timestamp   = 1296688602;
        p.genesis_block.bits        = 0x207fffff;       // compact form of regtest pow_limit
        p.genesis_block.nonce       = 0;

        // Activate immediately with a single signal.
        p.rule_change_activation_threshold = 108;
        p.miner_confirmation_window        = 144;

        p.max_block_weight          = 4'000'000;
        p.max_block_serialized_size = 4'000'000;
        p.witness_scale_factor      = 4;

        p.coinbase_maturity = 100;

        p.min_tx_fee     = 1'000;
        p.dust_relay_fee = 3'000;

        p.default_port = 18444;
        p.rpc_port     = 18443;
        p.magic_bytes  = 0x46544352;  // "FTCR"

        return p;
    }();

    return params;
}

} // namespace consensus
