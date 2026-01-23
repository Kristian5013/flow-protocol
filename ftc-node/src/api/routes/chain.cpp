/**
 * Chain Routes - /block, /tx, /mempool
 * Kristian Pilatovich 20091227 - First Real P2P
 */

#include "routes.h"
#include "chain/transaction.h"
#include <sstream>
#include <iomanip>

namespace ftc {
namespace api {
namespace routes {

void setupChainRoutes(RouteContext& ctx) {
    auto* server = ctx.server;
    auto* chain = ctx.chain;
    auto* mempool = ctx.mempool;

    // Get block by hash or height
    server->get("/block/:id", [chain](const HttpRequest& req, HttpResponse& res) {
        if (!chain) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Chain not available");
            return;
        }

        std::string id = req.getPathParam("id");
        std::optional<chain::Block> block;

        // Try as height first
        try {
            int32_t height = std::stoi(id);
            block = chain->getBlock(height);
        } catch (...) {
            // Try as hash
            crypto::Hash256 hash;
            if (hexToHash(id, hash)) {
                block = chain->getBlock(hash);
            }
        }

        if (!block) {
            res.error(HttpStatus::NOT_FOUND, "Block not found");
            return;
        }

        JsonBuilder json;
        json.beginObject()
            .key("hash").value(hashToHex(block->getHash()))
            .key("version").value(static_cast<int64_t>(block->header.version))
            .key("prev_hash").value(hashToHex(block->header.prev_hash))
            .key("merkle_root").value(hashToHex(block->header.merkle_root))
            .key("timestamp").value(static_cast<uint64_t>(block->header.timestamp))
            .key("bits").value(static_cast<uint64_t>(block->header.bits))
            .key("nonce").value(static_cast<uint64_t>(block->header.nonce))
            .key("tx_count").value(static_cast<uint64_t>(block->transactions.size()))
            .key("transactions").beginArray();

        for (const auto& tx : block->transactions) {
            json.value(hashToHex(tx.getTxId()));
        }

        json.endArray().endObject();
        res.success(json.build());
    });

    // Get transaction by txid
    server->get("/tx/:txid", [chain, mempool](const HttpRequest& req, HttpResponse& res) {
        std::string txid_str = req.getPathParam("txid");

        crypto::Hash256 txid;
        if (!hexToHash(txid_str, txid)) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid txid format");
            return;
        }

        // Check mempool first
        if (mempool) {
            auto tx = mempool->getTransaction(txid);
            if (tx) {
                JsonBuilder json;
                json.beginObject()
                    .key("txid").value(hashToHex(tx->getTxId()))
                    .key("version").value(static_cast<int64_t>(tx->version))
                    .key("locktime").value(static_cast<uint64_t>(tx->locktime))
                    .key("confirmations").value(static_cast<int64_t>(0))
                    .key("in_mempool").value(true)
                    .key("input_count").value(static_cast<uint64_t>(tx->inputs.size()))
                    .key("output_count").value(static_cast<uint64_t>(tx->outputs.size()))
                    .endObject();
                res.success(json.build());
                return;
            }
        }

        // Search in confirmed transactions
        if (chain) {
            auto tx = chain->getTx(txid);
            if (tx) {
                auto tip = chain->getTip();
                int64_t confirmations = 1;  // At least 1 if in chain

                JsonBuilder json;
                json.beginObject()
                    .key("txid").value(hashToHex(tx->getTxId()))
                    .key("version").value(static_cast<int64_t>(tx->version))
                    .key("locktime").value(static_cast<uint64_t>(tx->locktime))
                    .key("confirmations").value(confirmations)
                    .key("in_mempool").value(false)
                    .key("input_count").value(static_cast<uint64_t>(tx->inputs.size()))
                    .key("output_count").value(static_cast<uint64_t>(tx->outputs.size()))
                    .endObject();
                res.success(json.build());
                return;
            }
        }

        res.error(HttpStatus::NOT_FOUND, "Transaction not found");
    });

    // Broadcast transaction
    server->post("/tx", [chain, mempool](const HttpRequest& req, HttpResponse& res) {
        if (!mempool) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Mempool not available");
            return;
        }

        JsonParser parser(req.body);
        if (!parser.parse() || !parser.isObject()) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid JSON body");
            return;
        }

        std::string hex = parser.getString("hex");
        if (hex.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "Missing 'hex' field (raw transaction)");
            return;
        }

        // Decode hex to transaction
        std::vector<uint8_t> raw_tx;
        raw_tx.reserve(hex.size() / 2);
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            int byte;
            std::istringstream iss(hex.substr(i, 2));
            if (!(iss >> std::hex >> byte)) {
                res.error(HttpStatus::BAD_REQUEST, "Invalid hex encoding");
                return;
            }
            raw_tx.push_back(static_cast<uint8_t>(byte));
        }

        // Deserialize transaction
        auto tx_opt = chain::Transaction::deserialize(raw_tx);
        if (!tx_opt) {
            res.error(HttpStatus::BAD_REQUEST, "Failed to decode transaction");
            return;
        }
        chain::Transaction& tx = *tx_opt;

        // Add to mempool
        int32_t current_height = chain ? chain->getHeight() : 0;
        auto result = mempool->addTransaction(tx, current_height);

        if (result == chain::MempoolReject::VALID) {
            JsonBuilder json;
            json.beginObject()
                .key("txid").value(hashToHex(tx.getTxId()))
                .key("accepted").value(true)
                .endObject();
            res.success(json.build());
        } else {
            std::string reason;
            switch (result) {
                case chain::MempoolReject::SCRIPT_ERROR: reason = "Invalid transaction (script error)"; break;
                case chain::MempoolReject::DOUBLE_SPEND: reason = "Double spend detected"; break;
                case chain::MempoolReject::INSUFFICIENT_FEE: reason = "Insufficient fee"; break;
                case chain::MempoolReject::MEMPOOL_FULL: reason = "Mempool full"; break;
                case chain::MempoolReject::ALREADY_IN_MEMPOOL: reason = "Already in mempool"; break;
                case chain::MempoolReject::MISSING_INPUTS: reason = "Missing inputs"; break;
                case chain::MempoolReject::IMMATURE_COINBASE: reason = "Immature coinbase (requires 100 confirmations)"; break;
                case chain::MempoolReject::NEGATIVE_FEE: reason = "Negative fee (outputs exceed inputs)"; break;
                case chain::MempoolReject::TOO_LARGE: reason = "Transaction too large"; break;
                case chain::MempoolReject::ALREADY_IN_CHAIN: reason = "Already in blockchain"; break;
                case chain::MempoolReject::ANCESTOR_LIMIT: reason = "Ancestor limit exceeded"; break;
                case chain::MempoolReject::DESCENDANT_LIMIT: reason = "Descendant limit exceeded"; break;
                default: reason = "Unknown error"; break;
            }
            res.error(HttpStatus::BAD_REQUEST, reason);
        }
    });

    // Mempool info
    server->get("/mempool", [mempool](const HttpRequest& req, HttpResponse& res) {
        if (!mempool) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Mempool not available");
            return;
        }

        auto stats = mempool->getStats();

        JsonBuilder json;
        json.beginObject()
            .key("size").value(static_cast<uint64_t>(stats.tx_count))
            .key("bytes").value(stats.total_size)
            .key("total_fees").value(stats.total_fee)
            .key("min_fee_rate").value(stats.min_fee_rate)
            .endObject();
        res.success(json.build());
    });

    // Mempool transaction IDs
    server->get("/mempool/txids", [mempool](const HttpRequest& req, HttpResponse& res) {
        if (!mempool) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Mempool not available");
            return;
        }

        auto txids = mempool->getAllTxids();

        JsonBuilder json;
        json.beginObject()
            .key("count").value(static_cast<uint64_t>(txids.size()))
            .key("txids").beginArray();

        for (const auto& txid : txids) {
            json.value(hashToHex(txid));
        }

        json.endArray().endObject();
        res.success(json.build());
    });
}

} // namespace routes
} // namespace api
} // namespace ftc
