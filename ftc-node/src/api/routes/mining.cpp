/**
 * Mining Routes - /mining/*
 * Kristian Pilatovich 20091227 - First Real P2P
 */

#include "routes.h"
#include "api/handlers.h"
#include "chain/block.h"
#include "chain/transaction.h"
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstring>

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
        uint32_t bits = chain->getNextWorkRequired(tip);
        uint32_t timestamp = static_cast<uint32_t>(std::time(nullptr));

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

        // Check if P2Pool payouts are enabled
        bool use_p2pool_payouts = false;
        std::map<std::vector<uint8_t>, uint64_t> payouts;

        if (p2pool && p2pool->isRunning() && !payout_address.empty()) {
            try {
                payouts = p2pool->getPayouts();
                if (!payouts.empty()) {
                    use_p2pool_payouts = true;
                }
            } catch (const std::exception& e) {
                use_p2pool_payouts = false;
                payouts.clear();
            }
        }

        if (use_p2pool_payouts) {
            for (const auto& [script, amount] : payouts) {
                if (amount > 0) {
                    chain::TxOutput cb_output;
                    cb_output.value = amount;
                    cb_output.script_pubkey = script;
                    coinbase.outputs.push_back(cb_output);
                }
            }
        } else {
            chain::TxOutput cb_output;
            cb_output.value = total_reward;
            if (!payout_address.empty()) {
                cb_output.script_pubkey = chain::script::createP2PKHFromAddress(payout_address);
            } else {
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

        json.endObject();
        res.success(json.build());
    });

    // Submit mined block
    server->post("/mining/submit", [chain, mempool](const HttpRequest& req, HttpResponse& res) {
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

        auto result = chain->processBlock(block);

        if (result == chain::ValidationResult::VALID) {
            if (mempool) {
                mempool->removeForBlock(block.transactions);
            }

            JsonBuilder json;
            json.beginObject()
                .key("hash").value(hashToHex(block.getHash()))
                .key("accepted").value(true)
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
            res.error(HttpStatus::BAD_REQUEST, reason);
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
        uint32_t bits = tip ? chain->getNextWorkRequired(tip) : 0;

        JsonBuilder json;
        json.beginObject()
            .key("height").value(static_cast<int64_t>(height + 1))
            .key("difficulty_bits").value(static_cast<uint64_t>(bits))
            .key("block_reward").value(chain->getBlockReward(height + 1))
            .key("block_time_target").value(static_cast<uint64_t>(chain->getParams().block_time))
            .key("difficulty_adjustment_interval").value(
                static_cast<uint64_t>(chain->getParams().difficulty_adjustment_interval))
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
