/**
 * Status Routes - /, /status, /health, /genesis, /snapshot
 * Kristian Pilatovich 20091227 - First Real P2P
 */

#include "routes.h"
#include "chain/genesis.h"
#include "chain/snapshot.h"
#include "chain/consensus.h"
#include "ftc/version.h"
#include <chrono>
#include <filesystem>
#include <fstream>

namespace ftc {
namespace api {
namespace routes {

void setupStatusRoutes(RouteContext& ctx) {
    auto* server = ctx.server;
    auto* chain = ctx.chain;
    auto* mempool = ctx.mempool;
    auto* peer_manager = ctx.peer_manager;
    auto* dht = ctx.dht;

    // Root endpoint - API info
    server->get("/", [](const HttpRequest& req, HttpResponse& res) {
        JsonBuilder json;
        json.beginObject()
            .key("name").value("FTC Node API")
            .key("version").value(FTC_VERSION)
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
                .value("/snapshot")
            .endArray()
        .endObject();
        res.success(json.build());
    });

    // Status endpoint - node status (flat format for web UI)
    static auto start_time = std::chrono::steady_clock::now();
    server->get("/status", [server, chain, mempool, peer_manager](const HttpRequest& req, HttpResponse& res) {
        // Get DHT at runtime (it's set after routes are registered)
        auto* dht = server->getDHT();
        JsonBuilder json;
        json.beginObject()
            .key("node").value("FTC Node")
            .key("version").value(FTC_VERSION)
            .key("network").value("mainnet")
            .key("running").value(true);

        // Uptime
        auto now = std::chrono::steady_clock::now();
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        json.key("uptime").value(static_cast<int64_t>(uptime));

        // Chain info (flat)
        int64_t height = chain ? static_cast<int64_t>(chain->getHeight()) : 0;
        json.key("chain_height").value(height);
        if (chain) {
            json.key("best_hash").value(hashToHex(chain->getBestHash()));
        }
        json.key("sync_progress").value(1.0);  // Always synced for now

        // Mempool info (flat)
        if (mempool) {
            auto stats = mempool->getStats();
            json.key("mempool_size").value(static_cast<uint64_t>(stats.tx_count));
            json.key("mempool_bytes").value(stats.total_size);
        } else {
            json.key("mempool_size").value(static_cast<uint64_t>(0));
            json.key("mempool_bytes").value(static_cast<uint64_t>(0));
        }

        // Peer info (flat)
        if (peer_manager) {
            json.key("peer_count").value(static_cast<uint64_t>(peer_manager->getPeerCount()));
            json.key("connections").value(static_cast<uint64_t>(peer_manager->getConnectionCount()));
            json.key("inbound").value(static_cast<uint64_t>(peer_manager->getInboundCount()));
            json.key("outbound").value(static_cast<uint64_t>(peer_manager->getOutboundCount()));
            json.key("reachable_peers").value(static_cast<uint64_t>(peer_manager->getReachableCount()));
            json.key("unreachable_peers").value(static_cast<uint64_t>(peer_manager->getUnreachableCount()));
            json.key("known_addresses").value(static_cast<uint64_t>(peer_manager->getAddressCount()));
        } else {
            json.key("peer_count").value(static_cast<uint64_t>(0));
            json.key("connections").value(static_cast<uint64_t>(0));
            json.key("known_addresses").value(static_cast<uint64_t>(0));
        }

        // DHT info
        if (dht) {
            json.key("dht_running").value(dht->isRunning());
            json.key("dht_nodes").value(static_cast<uint64_t>(dht->getRoutingTableSize()));
            json.key("dht_nodes_ipv4").value(static_cast<uint64_t>(dht->getIPv4NodeCount()));
            json.key("dht_nodes_ipv6").value(static_cast<uint64_t>(dht->getIPv6NodeCount()));
        } else {
            json.key("dht_running").value(false);
            json.key("dht_nodes").value(static_cast<uint64_t>(0));
            json.key("dht_nodes_ipv4").value(static_cast<uint64_t>(0));
            json.key("dht_nodes_ipv6").value(static_cast<uint64_t>(0));
        }

        // Network hashrate - calculated from actual miner share submissions
        // This is accurate per-miner tracking, not blockchain-based estimate
        uint64_t network_hashrate = 0;
        auto* p2pool = server->getP2Pool();
        if (p2pool && p2pool->isRunning()) {
            network_hashrate = p2pool->getTotalMinerHashrate();
        }
        json.key("network_hashrate").value(network_hashrate);

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

    // Sync status - detailed sync statistics
    auto* message_handler = ctx.message_handler;
    server->get("/sync", [message_handler, chain](const HttpRequest& req, HttpResponse& res) {
        JsonBuilder json;
        json.beginObject();

        if (message_handler) {
            auto stats = message_handler->getSyncStats();

            // State as string
            const char* state_str = "unknown";
            switch (stats.state) {
                case p2p::SyncState::IDLE: state_str = "idle"; break;
                case p2p::SyncState::HEADERS: state_str = "headers"; break;
                case p2p::SyncState::BLOCKS: state_str = "blocks"; break;
                case p2p::SyncState::COMPLETE: state_str = "complete"; break;
            }

            json.key("state").value(state_str)
                .key("current_height").value(static_cast<int64_t>(stats.current_height))
                .key("target_height").value(static_cast<int64_t>(stats.target_height))
                .key("progress").value(stats.progress)
                .key("blocks_per_second").value(stats.blocks_per_second)
                .key("blocks_in_flight").value(static_cast<int64_t>(stats.blocks_in_flight))
                .key("blocks_in_queue").value(static_cast<int64_t>(stats.blocks_in_queue))
                .key("active_peers").value(static_cast<int64_t>(stats.active_peers))
                .key("total_downloaded").value(static_cast<int64_t>(stats.total_downloaded))
                .key("eta_seconds").value(static_cast<int64_t>(stats.eta.count()));
        } else {
            json.key("state").value("unavailable")
                .key("current_height").value(chain ? static_cast<int64_t>(chain->getHeight()) : 0)
                .key("progress").value(1.0);
        }

        json.endObject();
        res.success(json.build());
    });

    // ==========================================================================
    // Snapshot endpoints - UTXO state snapshots for fast sync
    // ==========================================================================

    auto* utxo_set = ctx.utxo_set;

    // GET /snapshot - Get snapshot info (existing file or current state)
    server->get("/snapshot", [chain, utxo_set](const HttpRequest& req, HttpResponse& res) {
        JsonBuilder json;
        json.beginObject();

        // Check for existing snapshot file
        std::string snapshot_path = "snapshot.dat";
        if (!std::filesystem::exists(snapshot_path)) {
            snapshot_path = "./data/snapshot.dat";
        }

        if (std::filesystem::exists(snapshot_path)) {
            auto info = chain::Snapshot::getInfo(snapshot_path);
            if (info.valid) {
                json.key("exists").value(true)
                    .key("file").value(snapshot_path)
                    .key("size").value(static_cast<uint64_t>(info.file_size))
                    .key("height").value(static_cast<int64_t>(info.header.height))
                    .key("block_hash").value(hashToHex(info.header.block_hash))
                    .key("utxo_count").value(info.header.utxo_count)
                    .key("total_value").value(info.header.total_value);
            } else {
                json.key("exists").value(false)
                    .key("error").value(info.error);
            }
        } else {
            json.key("exists").value(false);
        }

        // Current chain state for comparison
        if (chain && utxo_set) {
            json.key("current_height").value(static_cast<int64_t>(chain->getHeight()))
                .key("current_utxos").value(static_cast<uint64_t>(utxo_set->size()));
        }

        json.endObject();
        res.success(json.build());
    });

    // POST /snapshot - Create/export a new snapshot
    server->post("/snapshot", [chain, utxo_set](const HttpRequest& req, HttpResponse& res) {
        if (!chain || !utxo_set) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Chain or UTXO set not available");
            return;
        }

        auto tip = chain->getTip();
        if (!tip) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "No chain tip available");
            return;
        }

        std::string snapshot_path = "./data/snapshot.dat";

        // Create data directory if needed
        std::filesystem::create_directories("./data");

        auto start = std::chrono::steady_clock::now();

        if (!chain::Snapshot::exportToFile(*utxo_set, tip->height, tip->hash, snapshot_path, nullptr)) {
            res.error(HttpStatus::INTERNAL_ERROR, "Failed to export snapshot");
            return;
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();

        // Get file size
        auto file_size = std::filesystem::file_size(snapshot_path);

        JsonBuilder json;
        json.beginObject()
            .key("success").value(true)
            .key("file").value(snapshot_path)
            .key("height").value(static_cast<int64_t>(tip->height))
            .key("block_hash").value(hashToHex(tip->hash))
            .key("utxo_count").value(static_cast<uint64_t>(utxo_set->size()))
            .key("size").value(static_cast<uint64_t>(file_size))
            .key("time_ms").value(static_cast<int64_t>(elapsed))
            .endObject();

        res.success(json.build());
    });

    // GET /snapshot/download - Download snapshot file (binary)
    server->get("/snapshot/download", [](const HttpRequest& req, HttpResponse& res) {
        std::string snapshot_path = "snapshot.dat";
        if (!std::filesystem::exists(snapshot_path)) {
            snapshot_path = "./data/snapshot.dat";
        }

        if (!std::filesystem::exists(snapshot_path)) {
            res.error(HttpStatus::NOT_FOUND, "No snapshot file available");
            return;
        }

        // Read file
        std::ifstream file(snapshot_path, std::ios::binary);
        if (!file) {
            res.error(HttpStatus::INTERNAL_ERROR, "Failed to open snapshot file");
            return;
        }

        // Read entire file into buffer
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::string data(size, '\0');
        file.read(&data[0], size);

        // Set response headers for binary download
        res.headers["Content-Type"] = "application/octet-stream";
        res.headers["Content-Disposition"] = "attachment; filename=\"snapshot.dat\"";
        res.headers["Content-Length"] = std::to_string(size);
        res.body = std::move(data);
        res.status = HttpStatus::OK;
    });
}

} // namespace routes
} // namespace api
} // namespace ftc
