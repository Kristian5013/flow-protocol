/**
 * Status Routes - /, /status, /health, /genesis
 * Kristian Pilatovich 20091227 - First Real P2P
 */

#include "routes.h"
#include "chain/genesis.h"

namespace ftc {
namespace api {
namespace routes {

void setupStatusRoutes(RouteContext& ctx) {
    auto* server = ctx.server;
    auto* chain = ctx.chain;
    auto* mempool = ctx.mempool;
    auto* peer_manager = ctx.peer_manager;

    // Root endpoint - API info
    server->get("/", [](const HttpRequest& req, HttpResponse& res) {
        JsonBuilder json;
        json.beginObject()
            .key("name").value("FTC Node API")
            .key("version").value("1.0.0")
            .key("endpoints").beginArray()
                .value("/status")
                .value("/block/:id")
                .value("/tx/:txid")
                .value("/mempool")
                .value("/balance/:address")
                .value("/utxo/:address")
                .value("/address/:addr/history")
                .value("/peers")
                .value("/wallet/new")
                .value("/wallet/send")
                .value("/mining/template")
                .value("/p2pool/status")
            .endArray()
        .endObject();
        res.success(json.build());
    });

    // Status endpoint - node status
    server->get("/status", [chain, mempool, peer_manager](const HttpRequest& req, HttpResponse& res) {
        JsonBuilder json;
        json.beginObject()
            .key("node").value("FTC Node")
            .key("version").value("1.0.0")
            .key("network").value("mainnet")
            .key("running").value(true);

        if (chain) {
            json.key("chain").beginObject()
                .key("height").value(static_cast<int64_t>(chain->getHeight()))
                .key("best_hash").value(hashToHex(chain->getBestHash()))
                .endObject();
        }

        if (mempool) {
            auto stats = mempool->getStats();
            json.key("mempool").beginObject()
                .key("size").value(static_cast<uint64_t>(stats.tx_count))
                .key("bytes").value(stats.total_size)
                .key("fees").value(stats.total_fee)
                .endObject();
        }

        if (peer_manager) {
            json.key("peers").beginObject()
                .key("nodes").value(static_cast<uint64_t>(peer_manager->getPeerCount()))
                .key("connections").value(static_cast<uint64_t>(peer_manager->getConnectionCount()))
                .key("inbound").value(static_cast<uint64_t>(peer_manager->getInboundCount()))
                .key("outbound").value(static_cast<uint64_t>(peer_manager->getOutboundCount()))
                .key("known_addresses").value(static_cast<uint64_t>(peer_manager->getAddressCount()))
                .endObject();
        }

        json.endObject();
        res.success(json.build());
    });

    // Health check endpoint for monitoring
    server->get("/health", [chain, peer_manager](const HttpRequest& req, HttpResponse& res) {
        bool healthy = true;
        std::string status = "healthy";

        if (!chain) {
            healthy = false;
            status = "chain unavailable";
        }

        int peer_count = peer_manager ? peer_manager->getPeerCount() : 0;

        JsonBuilder json;
        json.beginObject()
            .key("status").value(status)
            .key("healthy").value(healthy)
            .key("peers").value(static_cast<int64_t>(peer_count))
            .key("height").value(chain ? static_cast<int64_t>(chain->getHeight()) : 0)
            .endObject();

        if (healthy) {
            res.success(json.build());
        } else {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, json.build());
        }
    });

    // Genesis block info - for verification
    server->get("/genesis", [chain](const HttpRequest& req, HttpResponse& res) {
        crypto::Hash256 genesis_hash{};
        if (chain) {
            auto genesis_block = chain->getBlock(0);
            if (genesis_block) {
                genesis_hash = genesis_block->getHash();
            }
        }

        JsonBuilder json;
        json.beginObject()
            .key("message").value(chain::genesis::GENESIS_MESSAGE)
            .key("timestamp").value(static_cast<int64_t>(chain::genesis::GENESIS_TIME))
            .key("timestamp_utc").value("2026-01-20 00:00:00 UTC")
            .key("hash").value(hashToHex(genesis_hash))
            .key("version").value(static_cast<int64_t>(chain::genesis::GENESIS_VERSION))
            .key("bits").value(static_cast<int64_t>(chain::genesis::GENESIS_BITS))
            .key("nonce").value(static_cast<int64_t>(chain::genesis::GENESIS_NONCE))
            .endObject();

        res.success(json.build());
    });
}

} // namespace routes
} // namespace api
} // namespace ftc
