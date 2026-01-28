/**
 * Mining Routes - /mining/*
 * Kristian Pilatovich 20091227 - First Real P2P
 */

#include "routes.h"
#include "api/handlers.h"
#include "chain/block.h"
#include "chain/transaction.h"
#include "p2pool/sharechain.h"
#include "util/logging.h"
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstring>
#include <iostream>

namespace ftc {
namespace api {
namespace routes {

void setupMiningRoutes(RouteContext& ctx) {
    auto* server = ctx.server;
    auto* chain = ctx.chain;
    auto* mempool = ctx.mempool;
    auto* peer_manager = ctx.peer_manager;

    // Mining template
    server->get("/mining/template", [server, chain, mempool](const HttpRequest& req, HttpResponse& res) {
        if (!chain || !mempool) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Chain or mempool not available");
            return;
        }

        auto* p2pool = server->getP2Pool();
        std::string payout_address = req.getQueryParam("address");

        auto tmpl = mempool->getBlockTemplate(
            chain->getParams().max_block_size,
            chain->getParams().max_block_sigops
        );

        auto tip = chain->getTip();
        if (!tip) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "No chain tip");
            return;
        }

        int32_t height = tip->height + 1;
        uint64_t reward = chain->getBlockReward(height);
        uint32_t block_bits = chain->getNextWorkRequired(tip);
        // Fallback: if bits is 0 (corrupted), use genesis difficulty
        if (block_bits == 0) {
            block_bits = 0x1d00ffff;
        }

        // Block header MUST use block_bits for valid blocks
        // Share difficulty is communicated separately for P2Pool
        uint32_t bits = block_bits;
        uint32_t share_bits = block_bits;  // Default: same as block

        if (p2pool && p2pool->isRunning()) {
            auto* sharechain = p2pool->getSharechain();
            if (sharechain) {
                share_bits = sharechain->getNextShareDifficulty();
            }

            // Validate share_bits: must be valid (>= 10) and EASIER than block difficulty
            // In bits format: higher value = easier difficulty (higher target)
            // So share_bits should be > block_bits (strictly easier)
            // If invalid or not easier, use default: 256x easier than block
            if (share_bits < 10 || share_bits <= block_bits) {
                uint32_t exp = (block_bits >> 24) & 0xFF;
                uint32_t mantissa = block_bits & 0x00FFFFFF;
                share_bits = ((exp + 1) << 24) | mantissa;  // 256x easier
            }
        }

        // Timestamp must be > median time past (MTP) to be valid
        // This is critical when blocks are found faster than 1 per second
        int64_t mtp = chain->getMedianTimePast(tip);
        uint32_t now = static_cast<uint32_t>(std::time(nullptr));
        uint32_t timestamp = static_cast<uint32_t>(std::max(static_cast<int64_t>(now), mtp + 1));

        // Build coinbase transaction
        chain::Transaction coinbase;
        coinbase.version = 1;
        coinbase.locktime = 0;

        chain::TxInput cb_input;
        cb_input.prevout.txid = crypto::Hash256{};
        cb_input.prevout.index = 0xFFFFFFFF;
        cb_input.sequence = 0xFFFFFFFF;

        // Script with height (BIP34)
        std::vector<uint8_t> height_script;
        if (height < 17) {
            height_script.push_back(0x50 + height);
        } else if (height < 128) {
            height_script.push_back(0x01);
            height_script.push_back(static_cast<uint8_t>(height));
        } else if (height < 32768) {
            height_script.push_back(0x02);
            height_script.push_back(height & 0xFF);
            height_script.push_back((height >> 8) & 0xFF);
        } else {
            height_script.push_back(0x03);
            height_script.push_back(height & 0xFF);
            height_script.push_back((height >> 8) & 0xFF);
            height_script.push_back((height >> 16) & 0xFF);
        }

        height_script.push_back(0x08);  // Push 8 bytes extra nonce
        for (int i = 0; i < 8; i++) {
            height_script.push_back(0x00);
        }

        cb_input.script_sig = height_script;
        coinbase.inputs.push_back(cb_input);

        uint64_t total_reward = reward + tmpl.total_fee;

        // Track miner activity for P2Pool stats
        if (p2pool && !payout_address.empty()) {
            auto miner_script = chain::script::createP2PKHFromAddress(payout_address);
            if (!miner_script.empty()) {
                p2pool->registerMinerShare(miner_script);
            }
        }

        // P2Pool is the only mining mode - PPLNS payouts always used
        std::map<std::vector<uint8_t>, uint64_t> payouts;

        if (p2pool && p2pool->isRunning()) {
            try {
                payouts = p2pool->getPayouts();
            } catch (const std::exception& e) {
                payouts.clear();
            }
        }

        if (!payouts.empty()) {
            // Distribute reward according to PPLNS shares
            for (const auto& [script, amount] : payouts) {
                if (amount > 0) {
                    chain::TxOutput cb_output;
                    cb_output.value = amount;
                    cb_output.script_pubkey = script;
                    coinbase.outputs.push_back(cb_output);
                }
            }
        } else {
            // No shares yet - pay to miner's address (bootstrap phase)
            chain::TxOutput cb_output;
            cb_output.value = total_reward;
            if (!payout_address.empty()) {
                cb_output.script_pubkey = chain::script::createP2PKHFromAddress(payout_address);
            } else {
                // No address provided - use OP_RETURN (unspendable)
                cb_output.script_pubkey = {0x6a, 0x07, 'F', 'T', 'C', 'P', 'O', 'O', 'L'};
            }
            coinbase.outputs.push_back(cb_output);
        }

        std::vector<uint8_t> coinbase_data = coinbase.serialize();

        // Build merkle tree
        std::vector<crypto::Hash256> tx_hashes;
        tx_hashes.push_back(coinbase.getTxId());
        for (const auto& tx : tmpl.transactions) {
            tx_hashes.push_back(tx.getTxId());
        }

        crypto::Hash256 merkle_root;
        if (tx_hashes.size() == 1) {
            merkle_root = tx_hashes[0];
        } else {
            while (tx_hashes.size() > 1) {
                std::vector<crypto::Hash256> new_level;
                for (size_t i = 0; i < tx_hashes.size(); i += 2) {
                    crypto::Hash256 left = tx_hashes[i];
                    crypto::Hash256 right = (i + 1 < tx_hashes.size()) ? tx_hashes[i + 1] : left;
                    std::vector<uint8_t> combined(64);
                    std::memcpy(combined.data(), left.data(), 32);
                    std::memcpy(combined.data() + 32, right.data(), 32);
                    new_level.push_back(crypto::keccak256(combined));
                }
                tx_hashes = std::move(new_level);
            }
            merkle_root = tx_hashes[0];
        }

        JsonBuilder json;
        json.beginObject()
            .key("version").value(static_cast<int64_t>(1))
            .key("height").value(static_cast<int64_t>(height))
            .key("prev_hash").value(hashToHex(tip->hash))
            .key("merkle_root").value(hashToHex(merkle_root))
            .key("timestamp").value(static_cast<int64_t>(timestamp))
            .key("bits").value(static_cast<uint64_t>(bits))
            .key("block_bits").value(static_cast<uint64_t>(block_bits))
            .key("share_bits").value(static_cast<uint64_t>(share_bits))
            .key("coinbase").value(bytesToHex(coinbase_data))
            .key("coinbase_value").value(reward + tmpl.total_fee)
            .key("block_reward").value(reward)
            .key("total_fees").value(tmpl.total_fee)
            .key("tx_count").value(static_cast<uint64_t>(tmpl.transactions.size()));

        json.key("transactions").beginArray();
        for (const auto& tx : tmpl.transactions) {
            json.value(bytesToHex(tx.serialize()));
        }
        json.endArray();

        // Add P2Pool sharechain info for proper share construction
        if (p2pool && p2pool->isRunning()) {
            auto* sharechain = p2pool->getSharechain();
            if (sharechain) {
                json.key("sharechain_tip").value(hashToHex(sharechain->getTipHash()));
                json.key("sharechain_height").value(static_cast<int64_t>(sharechain->getHeight()));
            }
        }

        json.endObject();
        res.success(json.build());
    });

    // Submit mined block/share
    server->post("/mining/submit", [server, chain, mempool, peer_manager](const HttpRequest& req, HttpResponse& res) {
        if (!chain) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Chain not available");
            return;
        }

        JsonParser parser(req.body);
        if (!parser.parse() || !parser.isObject()) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid JSON body");
            return;
        }

        std::string hex = parser.getString("hex");
        if (hex.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "Missing 'hex' field (raw block)");
            return;
        }

        // Parse optional solutions_found (total solutions found by miner)
        uint64_t solutions_found = parser.getUint("solutions_found");

        // Parse optional share_only flag (for stale blocks - count for hashrate but don't process as block)
        bool share_only = parser.getBool("share_only");

        std::vector<uint8_t> raw_block;
        raw_block.reserve(hex.size() / 2);
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            int byte;
            std::istringstream iss(hex.substr(i, 2));
            if (!(iss >> std::hex >> byte)) {
                res.error(HttpStatus::BAD_REQUEST, "Invalid hex encoding");
                return;
            }
            raw_block.push_back(static_cast<uint8_t>(byte));
        }

        auto block_opt = chain::Block::deserialize(raw_block);
        if (!block_opt) {
            res.error(HttpStatus::BAD_REQUEST, "Failed to decode block");
            return;
        }
        chain::Block& block = *block_opt;

        // Get current difficulty targets
        auto tip = chain->getTip();
        if (!tip) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "No chain tip");
            return;
        }

        uint32_t block_bits = chain->getNextWorkRequired(tip);
        if (block_bits == 0) block_bits = 0x1d00ffff;

        // Calculate block hash
        crypto::Hash256 block_hash = block.getHash();

        // Helper to check if hash meets difficulty target
        auto meetsTarget = [](const crypto::Hash256& hash, uint32_t bits) {
            crypto::Hash256 target = chain::BlockHeader::bitsToTarget(bits);
            // Compare hash to target (hash must be <= target)
            // Use big-endian comparison: byte[0] = MSB, byte[31] = LSB
            return crypto::Keccak256::compare(hash, target) <= 0;
        };

        // Check P2Pool share difficulty first
        auto* p2pool = server->getP2Pool();
        bool share_accepted = false;
        bool is_block = false;

        if (p2pool && p2pool->isRunning()) {
            // Calculate share_bits the same way as in template route
            uint32_t share_bits = block_bits;  // Default: same as block
            auto* sharechain = p2pool->getSharechain();
            if (sharechain) {
                share_bits = sharechain->getNextShareDifficulty();
            }

            // Validate share_bits: must be valid (>= 10) and EASIER than block difficulty
            // In bits format: higher value = easier difficulty (higher target)
            if (share_bits < 10 || share_bits <= block_bits) {
                uint32_t exp = (block_bits >> 24) & 0xFF;
                uint32_t mantissa = block_bits & 0x00FFFFFF;
                share_bits = ((exp + 1) << 24) | mantissa;  // 256x easier
            }

            // Check if meets share difficulty (easier target for P2Pool shares)
            if (meetsTarget(block_hash, share_bits) && sharechain) {
                // Create actual P2Pool Share object
                p2pool::Share share;
                share.header.version = 1;
                share.header.prev_share = sharechain->getTipHash();
                share.header.timestamp = block.header.timestamp;
                share.header.bits = share_bits;
                share.header.nonce = block.header.nonce;
                share.header.block_prev_hash = block.header.prev_hash;
                share.header.block_height = static_cast<uint32_t>(tip->height + 1);
                share.header.block_bits = block_bits;

                // Calculate share merkle root from payouts
                share.header.merkle_root = block.header.merkle_root;

                // Store block hash for PoW verification (already validated)
                share.block_hash = block_hash;

                // Add payout info from coinbase
                if (!block.transactions.empty()) {
                    auto& coinbase = block.transactions[0];
                    share.generation_tx = coinbase;

                    for (const auto& output : coinbase.outputs) {
                        if (!output.script_pubkey.empty()) {
                            p2pool::Share::PayoutEntry payout;
                            payout.script_pubkey = output.script_pubkey;
                            payout.weight = 1;  // Equal weight per share
                            share.payouts.push_back(payout);
                        }
                    }

                    // Register miner activity
                    if (!coinbase.outputs.empty()) {
                        p2pool->registerMinerShare(coinbase.outputs[0].script_pubkey);

                        // Register ALL shares that meet difficulty for accurate hashrate
                        // (including stale shares - they still represent real work)
                        p2pool->registerMinerShareSubmission(
                            coinbase.outputs[0].script_pubkey,
                            share_bits
                        );

                        // If miner reports solutions_found, use that for most accurate hashrate
                        if (solutions_found > 0) {
                            p2pool->registerMinerSolutionsFound(
                                coinbase.outputs[0].script_pubkey,
                                solutions_found,
                                share_bits
                            );
                        }
                    }
                }

                // Submit share to sharechain
                std::string error;
                if (sharechain->processShare(share, error)) {
                    share_accepted = true;
                } else {
                    // Share rejected by sharechain (e.g., orphan, duplicate, stale)
                    // Still counted for hashrate above
                }
            }

            // Check if also meets block difficulty (harder target for actual blocks)
            // Don't process as block if share_only=true (stale blocks - only count for hashrate)
            if (meetsTarget(block_hash, block_bits) && !share_only) {
                is_block = true;
            }
        } else {
            // P2Pool not running - reject mining attempts
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "P2Pool not running - mining requires P2Pool");
            return;
        }

        if (is_block) {
            // Process as main chain block
            LOG_NOTICE("Block submission: height={} timestamp={} prev={}",
                      tip->height + 1, block.header.timestamp,
                      hashToHex(block.header.prev_hash).substr(0, 16));
            auto result = chain->processBlock(block);

            if (result == chain::ValidationResult::VALID) {
                LOG_NOTICE("BLOCK ACCEPTED at height {}", tip->height + 1);
                if (mempool) {
                    mempool->removeForBlock(block.transactions);
                }

                // Broadcast block to peers
                if (peer_manager) {
                    peer_manager->broadcastBlock(block.getHash(), block);
                }

                JsonBuilder json;
                json.beginObject()
                    .key("hash").value(hashToHex(block.getHash()))
                    .key("accepted").value(true)
                    .key("is_block").value(true)
                    .key("share_accepted").value(share_accepted)
                    .endObject();
                res.success(json.build());
            } else {
                std::string reason;
                switch (result) {
                    case chain::ValidationResult::INVALID_BLOCK_HEADER: reason = "Invalid header"; break;
                    case chain::ValidationResult::INVALID_POW: reason = "Invalid proof of work"; break;
                    case chain::ValidationResult::INVALID_TIMESTAMP: reason = "Invalid timestamp"; break;
                    case chain::ValidationResult::INVALID_MERKLE_ROOT: reason = "Invalid merkle root"; break;
                    case chain::ValidationResult::INVALID_TX: reason = "Invalid transaction"; break;
                    case chain::ValidationResult::INVALID_COINBASE: reason = "Invalid coinbase"; break;
                    case chain::ValidationResult::DUPLICATE_TX: reason = "Duplicate block"; break;
                    case chain::ValidationResult::BLOCK_MISSING_PREV: reason = "Orphan block"; break;
                    default: reason = "Unknown error"; break;
                }
                LOG_WARN("BLOCK REJECTED at height {}: {}", tip->height + 1, reason);
                res.error(HttpStatus::BAD_REQUEST, reason);
            }
        } else if (share_accepted) {
            // Share accepted but not a block
            JsonBuilder json;
            json.beginObject()
                .key("hash").value(hashToHex(block.getHash()))
                .key("accepted").value(true)
                .key("is_block").value(false)
                .key("share_accepted").value(true)
                .endObject();
            res.success(json.build());
        } else {
            // Doesn't meet share difficulty
            res.error(HttpStatus::BAD_REQUEST, "Does not meet share difficulty");
        }
    });

    // Mining info
    server->get("/mining/info", [chain](const HttpRequest& req, HttpResponse& res) {
        if (!chain) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Chain not available");
            return;
        }

        auto tip = chain->getTip();
        int32_t height = tip ? tip->height : -1;
        uint32_t bits = tip ? chain->getNextWorkRequired(tip) : 0x1d00ffff;
        // Fallback: if bits is 0 (corrupted), use genesis difficulty
        if (bits == 0) {
            bits = 0x1d00ffff;
        }

        const auto& params = chain->getParams();

        JsonBuilder json;
        json.beginObject()
            .key("height").value(static_cast<int64_t>(height + 1))
            .key("difficulty_bits").value(static_cast<uint64_t>(bits))
            .key("block_reward").value(chain->getBlockReward(height + 1))
            .key("block_time_target").value(static_cast<uint64_t>(params.block_time))
            .key("difficulty_algorithm").value("classic-2016")
            .key("difficulty_adjustment_interval").value(static_cast<uint64_t>(params.difficulty_adjustment_interval))
            .endObject();
        res.success(json.build());
    });

    // Generate blocks (CPU mining for testing)
    server->get("/mining/generate", [chain, mempool, peer_manager](const HttpRequest& req, HttpResponse& res) {
        if (!chain || !mempool) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Chain or mempool not available");
            return;
        }

        int num_blocks = 1;
        std::string blocks_str = req.getQueryParam("blocks");
        if (!blocks_str.empty()) {
            num_blocks = std::stoi(blocks_str);
            if (num_blocks < 1 || num_blocks > 100) {
                res.error(HttpStatus::BAD_REQUEST, "blocks must be 1-100");
                return;
            }
        }

        std::string payout_address = req.getQueryParam("address");
        std::vector<uint8_t> payout_script;
        if (!payout_address.empty()) {
            payout_script = decodeAddress(payout_address);
            if (payout_script.empty()) {
                res.error(HttpStatus::BAD_REQUEST, "Invalid payout address");
                return;
            }
        } else {
            payout_script = {0x6a};  // OP_RETURN
        }

        std::vector<std::string> block_hashes;

        for (int i = 0; i < num_blocks; i++) {
            auto tip = chain->getTip();
            if (!tip) {
                res.error(HttpStatus::SERVICE_UNAVAILABLE, "No chain tip");
                return;
            }

            int32_t height = tip->height + 1;
            uint64_t reward = chain->getBlockReward(height);
            uint32_t bits = chain->getNextWorkRequired(tip);
            // Fallback: if bits is 0 (corrupted), use genesis difficulty
            if (bits == 0) {
                bits = 0x1d00ffff;
            }
            uint32_t min_timestamp = tip->timestamp + 1;
            uint32_t now = static_cast<uint32_t>(std::time(nullptr));
            uint32_t timestamp = std::max(min_timestamp, now);

            chain::Transaction coinbase;
            coinbase.version = 1;
            coinbase.locktime = 0;

            chain::TxInput cb_input;
            cb_input.prevout.txid = crypto::Hash256{};
            cb_input.prevout.index = 0xFFFFFFFF;
            cb_input.sequence = 0xFFFFFFFF;
            std::vector<uint8_t> height_script;
            height_script.push_back(0x01);
            height_script.push_back(static_cast<uint8_t>(height & 0xFF));
            cb_input.script_sig = height_script;
            coinbase.inputs.push_back(cb_input);

            chain::TxOutput cb_output;
            cb_output.value = reward;
            cb_output.script_pubkey = payout_script;
            coinbase.outputs.push_back(cb_output);

            chain::Block block;
            block.header.version = 1;
            block.header.prev_hash = tip->hash;
            block.header.timestamp = timestamp;
            block.header.bits = bits;
            block.header.nonce = 0;
            block.transactions.push_back(coinbase);

            block.header.merkle_root = block.calculateMerkleRoot();

            crypto::Hash256 target = chain::BlockHeader::bitsToTarget(bits);

            bool found = false;
            for (uint32_t nonce = 0; nonce < 0xFFFFFFFF && !found; nonce++) {
                block.header.nonce = nonce;
                crypto::Hash256 hash = block.getHash();
                if (crypto::Keccak256::compare(hash, target) <= 0) {
                    found = true;
                }
                if (nonce % 1000000 == 0 && nonce > 0) {
                    block.header.timestamp = static_cast<uint32_t>(std::time(nullptr));
                }
            }

            if (!found) {
                res.error(HttpStatus::INTERNAL_ERROR, "Failed to mine block");
                return;
            }

            auto result = chain->processBlock(block);
            if (result != chain::ValidationResult::VALID) {
                res.error(HttpStatus::INTERNAL_ERROR, "Block validation failed");
                return;
            }

            crypto::Hash256 block_hash = block.getHash();
            if (peer_manager) {
                peer_manager->broadcastBlock(block_hash, block);
            }

            block_hashes.push_back(crypto::Keccak256::toHex(block.getHash()));
        }

        JsonBuilder json;
        json.beginObject();
        json.key("blocks_mined").value(static_cast<int64_t>(num_blocks));
        json.key("hashes").beginArray();
        for (const auto& hash : block_hashes) {
            json.value(hash);
        }
        json.endArray();
        json.endObject();
        res.success(json.build());
    });
}

} // namespace routes
} // namespace api
} // namespace ftc
