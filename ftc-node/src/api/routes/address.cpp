/**
 * Address Routes - /balance, /utxo, /address/history, /peers
 * Kristian Pilatovich 20091227 - First Real P2P
 */

#include "routes.h"
#include "api/handlers.h"

namespace ftc {
namespace api {
namespace routes {

void setupAddressRoutes(RouteContext& ctx) {
    auto* server = ctx.server;
    auto* chain = ctx.chain;
    auto* utxo_set = ctx.utxo_set;
    auto* peer_manager = ctx.peer_manager;

    // Get balance for address
    server->get("/balance/:address", [utxo_set](const HttpRequest& req, HttpResponse& res) {
        if (!utxo_set) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "UTXO set not available");
            return;
        }

        std::string address = req.getPathParam("address");

        std::vector<uint8_t> script_pubkey = decodeAddress(address);
        if (script_pubkey.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid address format");
            return;
        }

        auto balance = utxo_set->getBalance(script_pubkey);

        JsonBuilder json;
        json.beginObject()
            .key("address").value(address)
            .key("confirmed").value(balance.confirmed)
            .key("unconfirmed").value(balance.unconfirmed)
            .key("total").value(balance.confirmed + balance.unconfirmed)
            .key("utxo_count").value(static_cast<uint64_t>(balance.utxos.size()))
            .endObject();
        res.success(json.build());
    });

    // Get UTXOs for address
    server->get("/utxo/:address", [utxo_set](const HttpRequest& req, HttpResponse& res) {
        if (!utxo_set) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "UTXO set not available");
            return;
        }

        std::string address = req.getPathParam("address");

        std::vector<uint8_t> script_pubkey = decodeAddress(address);
        if (script_pubkey.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid address format");
            return;
        }

        auto utxos = utxo_set->getUTXOs(script_pubkey);

        JsonBuilder json;
        json.beginObject()
            .key("address").value(address)
            .key("count").value(static_cast<uint64_t>(utxos.size()))
            .key("utxos").beginArray();

        for (const auto& utxo : utxos) {
            json.beginObject()
                .key("txid").value(hashToHex(utxo.outpoint.txid))
                .key("vout").value(static_cast<uint64_t>(utxo.outpoint.index))
                .key("amount").value(utxo.value)
                .key("height").value(static_cast<int64_t>(utxo.height))
                .key("coinbase").value(utxo.coinbase)
                .endObject();
        }

        json.endArray().endObject();
        res.success(json.build());
    });

    // Get transaction history for address
    server->get("/address/:addr/history", [chain, utxo_set](const HttpRequest& req, HttpResponse& res) {
        if (!utxo_set || !chain) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "UTXO set or chain not available");
            return;
        }

        std::string address = req.getPathParam("addr");

        std::vector<uint8_t> script_pubkey = decodeAddress(address);
        if (script_pubkey.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid address format");
            return;
        }

        auto utxos = utxo_set->getUTXOs(script_pubkey);
        uint32_t current_height = chain->getHeight();

        JsonBuilder json;
        json.beginObject()
            .key("address").value(address)
            .key("count").value(static_cast<uint64_t>(utxos.size()))
            .key("transactions").beginArray();

        for (const auto& utxo : utxos) {
            uint32_t confirmations = (utxo.height <= current_height) ? (current_height - utxo.height + 1) : 0;

            json.beginObject()
                .key("txid").value(hashToHex(utxo.outpoint.txid))
                .key("type").value("receive")
                .key("amount").value(utxo.value)
                .key("height").value(static_cast<int64_t>(utxo.height))
                .key("confirmations").value(static_cast<int64_t>(confirmations))
                .key("coinbase").value(utxo.coinbase)
                .endObject();
        }

        json.endArray().endObject();
        res.success(json.build());
    });

    // Get peers
    server->get("/peers", [peer_manager](const HttpRequest& req, HttpResponse& res) {
        if (!peer_manager) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Peer manager not available");
            return;
        }

        auto peers = peer_manager->getPeerInfo();

        JsonBuilder json;
        json.beginObject()
            .key("count").value(static_cast<uint64_t>(peers.size()))
            .key("peers").beginArray();

        for (const auto& peer : peers) {
            // Map reachability status to string
            const char* reachability_str = "unknown";
            switch (peer.reachability) {
                case p2p::ReachabilityStatus::UNKNOWN: reachability_str = "unknown"; break;
                case p2p::ReachabilityStatus::CHECKING: reachability_str = "checking"; break;
                case p2p::ReachabilityStatus::REACHABLE: reachability_str = "reachable"; break;
                case p2p::ReachabilityStatus::UNREACHABLE: reachability_str = "unreachable"; break;
            }

            json.beginObject()
                .key("id").value(static_cast<uint64_t>(peer.id))
                .key("address").value(peer.addr.toString())
                .key("version").value(static_cast<int64_t>(peer.version))
                .key("user_agent").value(peer.user_agent)
                .key("height").value(static_cast<int64_t>(peer.best_height))
                .key("inbound").value(peer.direction == p2p::ConnectionDir::INBOUND)
                .key("reachability").value(reachability_str)
                .key("ping_ms").value(peer.ping_usec / 1000)
                .key("bytes_sent").value(peer.bytes_sent)
                .key("bytes_recv").value(peer.bytes_recv)
                .endObject();
        }

        json.endArray().endObject();
        res.success(json.build());
    });

    // Banned peers
    server->get("/peers/banned", [peer_manager](const HttpRequest& req, HttpResponse& res) {
        if (!peer_manager) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Peer manager not available");
            return;
        }

        auto bans = peer_manager->getBanList();

        JsonBuilder json;
        json.beginObject()
            .key("count").value(static_cast<uint64_t>(bans.size()))
            .key("banned").beginArray();

        for (const auto& ban : bans) {
            json.beginObject()
                .key("address").value(ban.addr.toString())
                .key("reason").value(ban.reason)
                .key("ban_time").value(static_cast<int64_t>(ban.ban_time))
                .key("unban_time").value(static_cast<int64_t>(ban.unban_time))
                .endObject();
        }

        json.endArray().endObject();
        res.success(json.build());
    });
}

} // namespace routes
} // namespace api
} // namespace ftc
