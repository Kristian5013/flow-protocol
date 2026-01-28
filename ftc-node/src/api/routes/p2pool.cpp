/**
 * P2Pool Routes - /p2pool/*
 * Kristian Pilatovich 20091227 - First Real P2P
 */

#include "routes.h"
#include "api/handlers.h"
#include <sstream>
#include <iomanip>

namespace ftc {
namespace api {
namespace routes {

void setupP2PoolRoutes(RouteContext& ctx) {
    auto* server = ctx.server;
    auto* chain = ctx.chain;

    // P2Pool status - fetch p2pool dynamically from server
    server->get("/p2pool/status", [server](const HttpRequest& req, HttpResponse& res) {
        auto* p2pool = server->getP2Pool();
        if (!p2pool) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "P2Pool not available");
            return;
        }

        auto stats = p2pool->getStats();

        JsonBuilder json;
        json.beginObject()
            .key("enabled").value(true)
            .key("running").value(p2pool->isRunning())
            .key("sharechain_height").value(static_cast<int64_t>(stats.sharechain_height))
            .key("sharechain_tip").value(hashToHex(stats.sharechain_tip))
            .key("active_miners").value(static_cast<int64_t>(stats.active_miners))
            .key("total_shares").value(stats.total_shares)
            .key("total_blocks").value(stats.total_blocks)
            .key("shares_per_minute").value(stats.shares_per_minute)
            .key("peer_count").value(static_cast<int64_t>(stats.peer_count))
            .key("total_hashrate").value(stats.total_hashrate)
            .endObject();
        res.success(json.build());
    });

    // Get P2Pool share template for mining
    server->get("/p2pool/template", [server, chain](const HttpRequest& req, HttpResponse& res) {
        auto* p2pool = server->getP2Pool();
        if (!p2pool || !chain) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "P2Pool or chain not available");
            return;
        }

        std::string payout_address = req.getQueryParam("address");
        if (payout_address.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "Missing 'address' query parameter");
            return;
        }

        std::vector<uint8_t> payout_script = decodeAddress(payout_address);
        if (payout_script.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid payout address");
            return;
        }

        auto share = p2pool->getWorkTemplate(payout_script);

        auto tip = chain->getTip();
        if (!tip) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "No chain tip");
            return;
        }

        JsonBuilder json;
        json.beginObject()
            .key("share_version").value(static_cast<int64_t>(share.header.version))
            .key("share_target_bits").value(static_cast<uint64_t>(share.header.bits))
            .key("prev_share").value(hashToHex(share.header.prev_share))
            .key("block_prev_hash").value(hashToHex(share.header.block_prev_hash))
            .key("block_height").value(static_cast<int64_t>(share.header.block_height))
            .key("block_bits").value(static_cast<uint64_t>(share.header.block_bits))
            .key("timestamp").value(static_cast<int64_t>(share.header.timestamp))
            .key("merkle_root").value(hashToHex(share.header.merkle_root))
            .key("generation_tx").value(bytesToHex(share.generation_tx.serialize()))
            .key("main_chain_height").value(static_cast<int64_t>(tip->height))
            .key("main_chain_tip").value(hashToHex(tip->hash))
            .endObject();
        res.success(json.build());
    });

    // Submit share to P2Pool
    server->post("/p2pool/submit", [server](const HttpRequest& req, HttpResponse& res) {
        auto* p2pool = server->getP2Pool();
        if (!p2pool) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "P2Pool not available");
            return;
        }

        JsonParser parser(req.body);
        if (!parser.parse() || !parser.isObject()) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid JSON body");
            return;
        }

        uint32_t nonce = static_cast<uint32_t>(parser.getInt("nonce"));
        std::string extra_nonce_hex = parser.getString("extra_nonce");

        std::vector<uint8_t> extra_nonce;
        if (!extra_nonce_hex.empty()) {
            for (size_t i = 0; i + 1 < extra_nonce_hex.size(); i += 2) {
                int byte;
                std::istringstream iss(extra_nonce_hex.substr(i, 2));
                if (iss >> std::hex >> byte) {
                    extra_nonce.push_back(static_cast<uint8_t>(byte));
                }
            }
        }

        if (p2pool->submitWork(nonce, extra_nonce)) {
            JsonBuilder json;
            json.beginObject()
                .key("accepted").value(true)
                .key("message").value("Share submitted to P2Pool")
                .endObject();
            res.success(json.build());
        } else {
            res.error(HttpStatus::BAD_REQUEST, "Share rejected");
        }
    });

    // Get P2Pool payouts estimate
    server->get("/p2pool/payouts", [server](const HttpRequest& req, HttpResponse& res) {
        auto* p2pool = server->getP2Pool();
        if (!p2pool) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "P2Pool not available");
            return;
        }

        auto payouts = p2pool->getEstimatedPayouts();

        JsonBuilder json;
        json.beginObject();
        json.key("payouts").beginArray();

        for (const auto& [script, amount] : payouts) {
            json.beginObject()
                .key("script").value(bytesToHex(script))
                .key("amount").value(amount)
                .endObject();
        }

        json.endArray();
        json.endObject();
        res.success(json.build());
    });
}

} // namespace routes
} // namespace api
} // namespace ftc
