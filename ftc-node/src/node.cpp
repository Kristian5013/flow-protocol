/**
 * FTC Node - Full Integration
 *
 * Coordinates all components:
 * - P2P Network (TCP block/tx propagation)
 * - Blockchain (validation, storage)
 * - Mempool (pending transactions)
 * - Localhost API (wallet/miner interface)
 *
 * Peer discovery: BitTorrent DHT (IPv6 only)
 * "Kristian Pilatovich 20091227 - First Real P2P"
 */

#include "node.h"
#include "util/logging.h"
#include "util/time.h"
#include "crypto/keccak256.h"
#include "chain/genesis.h"

#include <cstring>
#include <random>
#include <filesystem>
#include <fstream>
#include <csignal>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <algorithm>
#include <set>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace ftc {

// Import toHex function for convenience
using crypto::toHex;

// Global node pointer for signal handling
static Node* g_node = nullptr;

static void signalHandler(int signal) {
    if (g_node) {
        LOG_NOTICE("Received signal {}, shutting down...", signal);
        g_node->requestShutdown();
    }
}

Node::Node(const util::Config& config)
    : config_(config) {
    g_node = this;

#ifdef _WIN32
    // Enable ANSI escape codes in Windows console
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    if (GetConsoleMode(hOut, &dwMode)) {
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }
#endif
}

Node::~Node() {
    stop();
    g_node = nullptr;
}

void Node::generateNodeId() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    uint64_t r1 = dis(gen);
    uint64_t r2 = dis(gen);
    uint64_t r3 = dis(gen);

    std::memcpy(node_id_, &r1, 8);
    std::memcpy(node_id_ + 8, &r2, 8);
    std::memcpy(node_id_ + 16, &r3, 4);

    // Hash for extra randomness using Keccak-256
    auto hash = crypto::keccak256(node_id_, 20);
    std::memcpy(node_id_, hash.data(), 20);
}

bool Node::initDataDir() {
    try {
        std::filesystem::create_directories(config_.data_dir);
        std::filesystem::create_directories(config_.data_dir + "/blocks");
        std::filesystem::create_directories(config_.data_dir + "/chainstate");
        std::filesystem::create_directories(config_.data_dir + "/peers");
        std::filesystem::create_directories(config_.data_dir + "/p2pool");
        std::filesystem::create_directories(config_.data_dir + "/p2pool/sharechain");
        LOG_DEBUG("Data directory initialized: {}", config_.data_dir);
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to create data directory: {}", e.what());
        return false;
    }
}

bool Node::initConsensus() {
    // Initialize consensus with mainnet parameters
    chain::ConsensusParams params;  // Default = mainnet

    consensus_ = std::make_unique<chain::Consensus>(params);
    LOG_DEBUG("Consensus initialized (target_spacing={}s, halving_interval={})",
              params.target_spacing, params.halving_interval);
    return true;
}

bool Node::initUTXOSet() {
    std::string utxo_path = config_.data_dir + "/chainstate";

    chain::UTXOSet::Config utxo_config;
    utxo_config.db_path = utxo_path;
    utxo_config.cache_size = config_.utxo_cache_mb * 1024 * 1024;

    utxo_set_ = std::make_unique<chain::UTXOSet>(utxo_config);

    if (!utxo_set_->open()) {
        LOG_ERROR("Failed to open UTXO database");
        return false;
    }

    LOG_DEBUG("UTXO set initialized ({} entries)", utxo_set_->size());
    return true;
}

bool Node::initChain() {
    std::string blocks_path = config_.data_dir + "/blocks";

    chain::Chain::Config chain_config;
    chain_config.data_dir = blocks_path;
    chain_config.max_reorg_depth = 100;

    chain_ = std::make_unique<chain::Chain>(chain_config, consensus_.get(), utxo_set_.get());

    // Set chain callbacks
    chain_->setNewTipCallback([this](const chain::BlockIndex* tip) {
        onNewTip(tip);
    });

    chain_->setBlockConnectedCallback([this](const chain::Block& block, const chain::BlockIndex* index) {
        onBlockConnected(block, index);
    });

    chain_->setBlockDisconnectedCallback([this](const chain::Block& block, const chain::BlockIndex* index) {
        onBlockDisconnected(block, index);
    });

    // Initialize chain (loads from disk or creates genesis)
    if (!chain_->initialize()) {
        LOG_ERROR("Failed to initialize blockchain");
        return false;
    }

    auto tip = chain_->getTip();
    LOG_NOTICE("Blockchain initialized: height={}, tip={}",
               tip ? tip->height : 0,
               tip ? toHex(tip->hash).substr(0, 16) : "genesis");

    return true;
}

bool Node::initMempool() {
    chain::Mempool::Config mp_config;
    mp_config.max_size = config_.mempool_max_mb * 1024 * 1024;
    mp_config.min_relay_fee = config_.min_relay_fee;
    mp_config.max_ancestors = 25;
    mp_config.max_descendants = 25;

    mempool_ = std::make_unique<chain::Mempool>(mp_config);
    mempool_->setUTXOSet(utxo_set_.get());

    // Set callbacks
    mempool_->setOnTxAdded([this](const chain::Transaction& tx) {
        onTxAdded(tx);
    });

    mempool_->setOnTxRemoved([this](const crypto::Hash256& txid, const std::string& reason) {
        onTxRemoved(txid, reason);
    });

    LOG_DEBUG("Mempool initialized (max_size={}MB)", config_.mempool_max_mb);
    return true;
}

bool Node::checkExternalAccessibility() {
    LOG_NOTICE("Checking external accessibility...");

#ifdef _WIN32
    // Get external IP using WinHTTP
    std::string external_ip;

    HINTERNET session = WinHttpOpen(
        L"FTC-Node/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!session) {
        LOG_ERROR("Failed to create WinHTTP session");
        return false;
    }

    HINTERNET connect = WinHttpConnect(session, L"api.ipify.org", 443, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        LOG_ERROR("Failed to connect to IP lookup service");
        return false;
    }

    HINTERNET request = WinHttpOpenRequest(
        connect,
        L"GET",
        L"/",
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );

    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        LOG_ERROR("Failed to create HTTP request");
        return false;
    }

    // Set timeout (5 seconds)
    DWORD timeout = 5000;
    WinHttpSetOption(request, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(request, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request, NULL)) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        LOG_ERROR("Failed to get external IP from api.ipify.org");
        return false;
    }

    char buffer[256];
    DWORD bytes_read = 0;
    if (WinHttpReadData(request, buffer, sizeof(buffer) - 1, &bytes_read) && bytes_read > 0) {
        buffer[bytes_read] = '\0';
        external_ip = buffer;
        // Trim whitespace
        while (!external_ip.empty() && (external_ip.back() == '\n' || external_ip.back() == '\r' || external_ip.back() == ' ')) {
            external_ip.pop_back();
        }
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    if (external_ip.empty()) {
        LOG_ERROR("Failed to determine external IP address");
        return false;
    }

    LOG_NOTICE("External IP: {}", external_ip);

    // Try to connect to ourselves at external IP:p2p_port
    LOG_NOTICE("Testing accessibility at {}:{}...", external_ip, config_.p2p_port);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        LOG_ERROR("Failed to create test socket");
        return false;
    }

    // Set short timeout for connect
    DWORD sock_timeout = 3000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&sock_timeout, sizeof(sock_timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&sock_timeout, sizeof(sock_timeout));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.p2p_port);

    if (inet_pton(AF_INET, external_ip.c_str(), &addr.sin_addr) != 1) {
        closesocket(sock);
        LOG_ERROR("Invalid external IP format: {}", external_ip);
        return false;
    }

    int result = ::connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    closesocket(sock);

    if (result == 0) {
        LOG_NOTICE("Node is externally accessible at {}:{}", external_ip, config_.p2p_port);
        return true;
    } else {
        LOG_ERROR("Node is NOT accessible from external IP {}:{}", external_ip, config_.p2p_port);
        LOG_ERROR("Please ensure:");
        LOG_ERROR("  1. Port {} is open in your firewall", config_.p2p_port);
        LOG_ERROR("  2. Port {} is forwarded on your router to this machine", config_.p2p_port);
        LOG_ERROR("Node will NOT connect to P2P network (not accessible from outside)");
        return false;
    }

#else
    // Linux/Unix implementation using curl or direct socket
    // Get external IP
    std::string external_ip;

    FILE* fp = popen("curl -s --connect-timeout 5 https://api.ipify.org", "r");
    if (fp) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), fp)) {
            external_ip = buffer;
            while (!external_ip.empty() && (external_ip.back() == '\n' || external_ip.back() == '\r')) {
                external_ip.pop_back();
            }
        }
        pclose(fp);
    }

    if (external_ip.empty()) {
        LOG_ERROR("Failed to determine external IP address");
        return false;
    }

    LOG_NOTICE("External IP: {}", external_ip);
    LOG_NOTICE("Testing accessibility at {}:{}...", external_ip, config_.p2p_port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG_ERROR("Failed to create test socket");
        return false;
    }

    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.p2p_port);

    if (inet_pton(AF_INET, external_ip.c_str(), &addr.sin_addr) != 1) {
        close(sock);
        LOG_ERROR("Invalid external IP format: {}", external_ip);
        return false;
    }

    int result = ::connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);

    if (result == 0) {
        LOG_NOTICE("Node is externally accessible at {}:{}", external_ip, config_.p2p_port);
        return true;
    } else {
        LOG_ERROR("Node is NOT accessible from external IP {}:{}", external_ip, config_.p2p_port);
        LOG_ERROR("Please ensure:");
        LOG_ERROR("  1. Port {} is open in your firewall", config_.p2p_port);
        LOG_ERROR("  2. Port {} is forwarded on your router to this machine", config_.p2p_port);
        LOG_ERROR("Node will NOT connect to P2P network (not accessible from outside)");
        return false;
    }
#endif
}

bool Node::initP2P() {
    // Initialize peer manager
    p2p::PeerManager::Config pm_config;
    pm_config.listen_port = config_.p2p_port;
    pm_config.max_inbound = config_.max_inbound;
    pm_config.max_outbound = config_.max_outbound;
    pm_config.target_outbound = config_.target_outbound;

    peer_manager_ = std::make_unique<p2p::PeerManager>(pm_config);

    // Set our node info
    peer_manager_->setOurVersion(70015);  // Protocol version
    peer_manager_->setOurServices(1);      // NODE_NETWORK
    peer_manager_->setOurUserAgent("/FTC:1.0.0/");
    peer_manager_->setOurNodeId(node_id_);  // Unique node ID for peer deduplication

    auto tip = chain_->getTip();
    peer_manager_->setOurHeight(tip ? tip->height : 0);

    // Set peer callbacks
    peer_manager_->setOnNewPeer([this](p2p::Connection::Id id) {
        onNewPeer(id);
    });

    peer_manager_->setOnPeerDisconnect([this](p2p::Connection::Id id, const std::string& reason) {
        onPeerDisconnect(id, reason);
    });

    peer_manager_->setOnMessage([this](p2p::Connection::Id id, const p2p::Message& msg) {
        onP2PMessage(id, msg);
    });

    // Initialize message handler
    p2p::MessageHandler::Config mh_config;
    mh_config.max_blocks_in_flight = 128;  // Higher for faster initial sync
    mh_config.relay_txs = true;
    mh_config.relay_blocks = true;

    message_handler_ = std::make_unique<p2p::MessageHandler>(
        chain_.get(),
        mempool_.get(),
        utxo_set_.get(),
        peer_manager_.get(),
        mh_config
    );

    // Set message handler callbacks
    message_handler_->setBlockCallback([this](const chain::Block& block, bool accepted) {
        if (accepted) {
            LOG_INFO("Block accepted: {}", toHex(block.getHash()).substr(0, 16));
        }
    });

    message_handler_->setTxCallback([this](const chain::Transaction& tx, bool accepted) {
        if (accepted) {
            LOG_DEBUG("Transaction accepted: {}", toHex(tx.getTxId()).substr(0, 16));
        }
    });

    // Start peer manager
    if (!peer_manager_->start()) {
        LOG_ERROR("Failed to start peer manager");
        return false;
    }

    // Start message handler
    if (!message_handler_->start()) {
        LOG_ERROR("Failed to start message handler");
        return false;
    }

    LOG_DEBUG("P2P network started (port={})", config_.p2p_port);
    return true;
}

// Helper to parse IPv6 address string and add to peer manager
bool Node::addPeerAddress(const std::string& addr_str, const std::string& source) {
    std::string host;
    uint16_t port = 17318;

    std::string line = addr_str;

    // Trim whitespace
    while (!line.empty() && (line.back() == ' ' || line.back() == '\t' ||
                              line.back() == '\r' || line.back() == '\n')) {
        line.pop_back();
    }
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
        line.erase(0, 1);
    }

    if (line.empty()) return false;

    // Parse [ipv6]:port or host:port format
    if (line.front() == '[') {
        // IPv6 format: [addr]:port
        size_t bracket_end = line.find(']');
        if (bracket_end != std::string::npos) {
            host = line.substr(1, bracket_end - 1);
            if (bracket_end + 1 < line.size() && line[bracket_end + 1] == ':') {
                try {
                    port = static_cast<uint16_t>(std::stoi(line.substr(bracket_end + 2)));
                } catch (...) {}
            }
        }
    } else {
        // Check if it's a bare IPv6 (contains ::)
        if (line.find("::") != std::string::npos || std::count(line.begin(), line.end(), ':') > 1) {
            // Bare IPv6 without brackets - find last : that's followed by digits only
            size_t last_colon = line.rfind(':');
            if (last_colon != std::string::npos) {
                std::string after = line.substr(last_colon + 1);
                bool is_port = !after.empty() && std::all_of(after.begin(), after.end(), ::isdigit);
                if (is_port && std::stoi(after) < 65536) {
                    host = line.substr(0, last_colon);
                    port = static_cast<uint16_t>(std::stoi(after));
                } else {
                    host = line;  // No port specified
                }
            } else {
                host = line;
            }
        } else {
            // Invalid format (not [IPv6]:port)
            host = line;
        }
    }

    if (host.empty()) return false;

    // Convert to NetAddr (IPv6 only)
    p2p::NetAddr addr;
    addr.port = port;
    addr.services = 1;

    // Parse IPv6 address (IPv6 only network)
    struct in6_addr ipv6;
    if (inet_pton(AF_INET6, host.c_str(), &ipv6) == 1) {
        std::memcpy(addr.ip, &ipv6, 16);
        peer_manager_->addAddress(addr, source);
        return true;
    }

    LOG_DEBUG("[Peers] Invalid IPv6 address: {}", host);
    return false;
}

// Note: loadPeers() and savePeers() removed - DHT handles peer discovery now

bool Node::initAPI() {
    api::Server::Config api_config;
    api_config.host = config_.api_bind;  // Default: :: (all interfaces)
    api_config.port = config_.api_port;
    api_config.enable_cors = config_.api_cors;  // Enable CORS for browser wallets

    api_server_ = std::make_unique<api::Server>(api_config);

    // Wire up dependencies
    api_server_->setChain(chain_.get());
    api_server_->setMempool(mempool_.get());
    api_server_->setUTXOSet(utxo_set_.get());
    api_server_->setPeerManager(peer_manager_.get());
    api_server_->setMessageHandler(message_handler_.get());

    if (!api_server_->start()) {
        LOG_ERROR("Failed to start API server");
        return false;
    }

    LOG_DEBUG("API server started: http://[::]:{}", config_.api_port);
    return true;
}

bool Node::initP2Pool() {
    // P2Pool configuration
    p2pool::P2Pool::Config p2pool_config;
    p2pool_config.data_dir = config_.data_dir + "/p2pool";
    p2pool_config.port = 17320;  // P2Pool P2P port
    p2pool_config.enabled = true;

    // Set default payout address if configured
    if (!config_.mining_address.empty()) {
        // Decode address to script pubkey
        // For now, use empty script - miners will provide their own addresses
    }

    // Create P2Pool instance
    p2pool_ = std::make_unique<p2pool::P2Pool>(chain_.get(), p2pool_config);

    // Set callback when P2Pool finds a block that meets main chain target
    p2pool_->setBlockFoundCallback([this](const chain::Block& block) {
        auto tip = chain_->getTip();
        int32_t expected_height = tip ? tip->height + 1 : 0;

        LOG_NOTICE("P2Pool found main chain block! Height={} Hash={}",
                   expected_height,
                   toHex(block.getHash()).substr(0, 16) + "...");

        // Validate and add block to chain
        auto result = chain_->processBlock(block);
        if (result == chain::ValidationResult::VALID) {
            LOG_NOTICE("Block accepted into main chain!");

            // Broadcast to peers
            if (peer_manager_) {
                peer_manager_->broadcastBlock(block.getHash(), block);
            }
        } else {
            LOG_ERROR("P2Pool block rejected (validation result: {})", static_cast<int>(result));
        }
    });

    // Start P2Pool
    if (!p2pool_->start()) {
        LOG_ERROR("Failed to start P2Pool");
        return false;
    }

    LOG_DEBUG("P2Pool started: tcp://0.0.0.0:{}", p2pool_config.port);
    return true;
}

bool Node::initDHT() {
    // Initialize BitTorrent DHT for peer discovery
    // Always use mainnet (FTC doesn't have testnet mode currently)
    dht_ = std::make_unique<dht::DHT>(17321, true);

    // Set logging callback
    dht_->setLogCallback([](const std::string& msg, bool is_error) {
        if (is_error) {
            LOG_ERROR("{}", msg);
        } else {
            LOG_NOTICE("{}", msg);
        }
    });

    // Set peer found callback - add discovered FTC nodes to peer manager
    dht_->setOnPeerFound([this](const std::string& ip, uint16_t port) {
        if (!peer_manager_) return;

        // Construct address string for P2P port (peers announce their P2P port)
        std::string addr_str = "[" + ip + "]:" + std::to_string(port);

        LOG_DEBUG("[DHT] Discovered FTC peer: {}", addr_str);

        // Add to peer manager
        if (addPeerAddress(addr_str, "dht")) {
            // Try to connect if we need more peers
            if (peer_manager_->getOutboundCount() < static_cast<size_t>(config_.target_outbound)) {
                auto addrs = peer_manager_->getAddresses(1);
                if (!addrs.empty()) {
                    peer_manager_->connectTo(addrs[0]);
                }
            }
        }
    });

    // Add local IPs to DHT to filter self-discovery
    if (peer_manager_) {
        for (const auto& ip : peer_manager_->getLocalIPs()) {
            dht_->addLocalIP(ip);
        }
    }

    // Start DHT
    if (!dht_->start()) {
        LOG_ERROR("Failed to start DHT");
        return false;
    }

    // Announce our P2P port on DHT
    dht_->announce(config_.p2p_port);

    LOG_NOTICE("[DHT] Started on UDP port 17321 (routing table: {} nodes)", dht_->getRoutingTableSize());
    return true;
}

bool Node::reindexUTXO() {
    LOG_NOTICE("Starting UTXO reindex...");

    if (!chain_) {
        LOG_ERROR("Cannot reindex: chain not initialized");
        return false;
    }

    if (!utxo_set_) {
        LOG_ERROR("Cannot reindex: UTXO set not initialized");
        return false;
    }

    // Get current chain height
    auto tip = chain_->getTip();
    if (!tip) {
        LOG_NOTICE("No blocks to reindex - chain is empty");
        return true;
    }

    int32_t height = tip->height;
    LOG_NOTICE("Reindexing {} blocks...", height + 1);

    // Clear existing UTXO set
    // We do this by closing and reopening with a fresh database
    utxo_set_->close();

    // Remove existing UTXO data
    std::string utxo_path = config_.data_dir + "/chainstate/utxo.dat";
    if (std::filesystem::exists(utxo_path)) {
        std::filesystem::remove(utxo_path);
        LOG_INFO("Removed old UTXO database");
    }

    // Reopen UTXO set
    if (!utxo_set_->open()) {
        LOG_ERROR("Failed to reopen UTXO set after clearing");
        return false;
    }

    // Walk through all blocks from genesis to tip
    auto start_time = std::chrono::steady_clock::now();
    int last_progress = -1;

    for (int32_t h = 0; h <= height; ++h) {
        auto block_opt = chain_->getBlock(h);
        if (!block_opt) {
            LOG_ERROR("Failed to load block at height {}", h);
            return false;
        }

        const chain::Block& block = *block_opt;

        // Apply block to UTXO set (no need to save undo data during reindex)
        if (!utxo_set_->connectBlock(block.transactions, h)) {
            LOG_ERROR("Failed to apply block {} to UTXO set", h);
            return false;
        }

        // Progress reporting
        int progress = (h * 100) / (height + 1);
        if (progress != last_progress && progress % 10 == 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start_time).count();
            LOG_NOTICE("Reindex progress: {}% ({}/{} blocks, {}s elapsed)",
                      progress, h + 1, height + 1, elapsed);
            last_progress = progress;
        }
    }

    // Flush UTXO set to disk
    utxo_set_->flush();

    auto total_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - start_time).count();

    LOG_NOTICE("Reindex complete: {} blocks processed in {}s, {} UTXOs",
               height + 1, total_time, utxo_set_->size());

    return true;
}

std::string Node::getSnapshotPath() const {
    // Check current directory first
    if (std::filesystem::exists("snapshot.dat")) {
        return "snapshot.dat";
    }
    // Fall back to data directory
    return config_.data_dir + "/snapshot.dat";
}

bool Node::loadSnapshot() {
    std::string snapshot_path = getSnapshotPath();

    if (!std::filesystem::exists(snapshot_path)) {
        LOG_DEBUG("No snapshot file found at {}", snapshot_path);
        return false;
    }

    // Get snapshot info
    auto info = chain::Snapshot::getInfo(snapshot_path);
    if (!info.valid) {
        LOG_WARN("Invalid snapshot file: {}", info.error);
        return false;
    }

    LOG_NOTICE("Found UTXO snapshot: height={}, utxos={}, size={}",
               info.header.height, info.header.utxo_count, info.file_size);

    // Verify snapshot before loading
    if (!chain::Snapshot::verify(snapshot_path)) {
        LOG_ERROR("Snapshot checksum verification failed");
        return false;
    }

    // Import snapshot
    auto start_time = std::chrono::steady_clock::now();

    if (!chain::Snapshot::importFromFile(*utxo_set_, snapshot_path,
        [](uint64_t processed, uint64_t total) {
            if (processed % 100000 == 0) {
                LOG_INFO("Snapshot import: {}/{} UTXOs", processed, total);
            }
        })) {
        LOG_ERROR("Failed to import snapshot");
        return false;
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();

    LOG_NOTICE("Snapshot loaded in {}ms: {} UTXOs at height {}",
               elapsed, utxo_set_->size(), info.header.height);

    return true;
}

bool Node::exportSnapshot() {
    if (!chain_ || !utxo_set_) {
        LOG_ERROR("Cannot export snapshot: node not initialized");
        return false;
    }

    auto tip = chain_->getTip();
    if (!tip) {
        LOG_ERROR("Cannot export snapshot: no chain tip");
        return false;
    }

    std::string snapshot_path = config_.data_dir + "/snapshot.dat";

    LOG_NOTICE("Exporting UTXO snapshot at height {}", tip->height);

    auto start_time = std::chrono::steady_clock::now();

    if (!chain::Snapshot::exportToFile(*utxo_set_, tip->height, tip->hash, snapshot_path,
        [](uint64_t processed, uint64_t total) {
            if (processed % 100000 == 0) {
                LOG_INFO("Snapshot export: {}/{} UTXOs", processed, total);
            }
        })) {
        LOG_ERROR("Failed to export snapshot");
        return false;
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();

    LOG_NOTICE("Snapshot exported in {}ms: {} UTXOs, file={}",
               elapsed, utxo_set_->size(), snapshot_path);

    return true;
}

bool Node::start() {
    start_time_ = std::chrono::steady_clock::now();

    // Initialize all components (daemon mode - no output)
    generateNodeId();
    if (!initDataDir()) return false;
    if (!initConsensus()) return false;
    if (!initUTXOSet()) return false;

    // Try to load snapshot if UTXO set is empty (fresh install)
    if (utxo_set_->size() == 0 && !config_.reindex) {
        if (loadSnapshot()) {
            LOG_NOTICE("Using UTXO snapshot for fast sync");
        }
    }

    if (!initChain()) return false;
    if (!initMempool()) return false;

    // Reindex if requested OR if UTXO set is empty but blocks exist
    bool need_reindex = config_.reindex;
    if (!need_reindex && utxo_set_->size() == 0) {
        auto tip = chain_->getTip();
        if (tip && tip->height > 0) {
            LOG_NOTICE("UTXO set is empty but {} blocks exist - auto-reindexing...", tip->height + 1);
            need_reindex = true;
        }
    }

    if (need_reindex && !reindexUTXO()) {
        LOG_ERROR("Reindex failed");
        return false;
    }

    // Start P2P network
    if (!initP2P()) return false;

    // TODO: Fix checkExternalAccessibility() to use IPv6 instead of IPv4
    // For now, skip this check as our network is IPv6-only
    LOG_NOTICE("Skipping external accessibility check (IPv6-only network)");

    // NOTE: Don't call startSync() here - peers haven't completed VERSION handshake yet.
    // Sync will be triggered by onPeerConnect() when a peer with higher height is established.

    // Start API server
    if (!initAPI()) return false;

    // Start P2Pool
    initP2Pool();
    if (p2pool_ && api_server_) {
        api_server_->setP2Pool(p2pool_.get());
    }

    // Start DHT for automatic peer discovery (finds peers via BitTorrent network)
    initDHT();

    // Install signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    running_ = true;

    // Start heartbeat thread for periodic status logging
    heartbeat_thread_ = std::thread(&Node::heartbeatLoop, this);

    return true;
}

void Node::stop() {
    if (!running_.load()) return;
    running_ = false;

    // Wait for heartbeat thread to finish
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }

    // Stop all components
    if (dht_) dht_->stop();
    if (p2pool_) p2pool_->stop();
    if (api_server_) api_server_->stop();
    if (message_handler_) message_handler_->stop();
    if (peer_manager_) peer_manager_->stop();
    if (chain_) chain_->flush();
    if (utxo_set_) utxo_set_->flush();
}

void Node::waitForShutdown() {
    std::unique_lock<std::mutex> lock(shutdown_mutex_);
    shutdown_cv_.wait(lock, [this] { return shutdown_requested_; });
    stop();
}

void Node::requestShutdown() {
    {
        std::lock_guard<std::mutex> lock(shutdown_mutex_);
        shutdown_requested_ = true;
    }
    shutdown_cv_.notify_all();
}

Node::Stats Node::getStats() const {
    Stats stats{};

    auto now = std::chrono::steady_clock::now();
    stats.uptime_seconds = std::chrono::duration_cast<std::chrono::seconds>(
        now - start_time_).count();

    if (chain_) {
        auto tip = chain_->getTip();
        stats.chain_height = tip ? tip->height : 0;
    }

    if (peer_manager_) {
        stats.peer_count = peer_manager_->getPeerCount();
        stats.known_addresses = peer_manager_->getAddressCount();
    }

    if (mempool_) {
        auto mp_stats = mempool_->getStats();
        stats.mempool_size = mp_stats.tx_count;
        stats.mempool_bytes = mp_stats.total_size;
    }

    if (message_handler_) {
        auto mh_stats = message_handler_->getStats();
        stats.blocks_received = mh_stats.blocks_received;
        stats.txs_received = mh_stats.txs_received;
    }

    // Sync progress from message handler
    if (message_handler_) {
        auto sync_stats = message_handler_->getSyncStats();
        stats.sync_progress = sync_stats.progress;
    } else {
        stats.sync_progress = 1.0;  // Assume synced if no handler
    }

    // Bandwidth (calculated in heartbeat loop)
    stats.bandwidth_in = 0.0;
    stats.bandwidth_out = 0.0;

    return stats;
}

// ═══════════════════════════════════════════════════════════════════════════
// Heartbeat - Periodic status logging (Tor-style)
// ═══════════════════════════════════════════════════════════════════════════

void Node::heartbeatLoop() {
    constexpr int HEARTBEAT_INTERVAL_SEC = 300;  // Log heartbeat every 5 minutes (daemon mode)
    constexpr int FIRST_HEARTBEAT_SEC = 10;      // First heartbeat after 10 seconds
    constexpr int UTXO_FLUSH_INTERVAL_SEC = 300; // Flush UTXOs every 5 minutes

    last_bandwidth_check_ = std::chrono::steady_clock::now();
    last_bytes_in_ = bytes_in_.load();
    last_bytes_out_ = bytes_out_.load();

    auto last_utxo_flush = std::chrono::steady_clock::now();
    bool first_heartbeat = true;

    while (running_.load()) {
        // First heartbeat comes faster, then regular interval
        int wait_sec = first_heartbeat ? FIRST_HEARTBEAT_SEC : HEARTBEAT_INTERVAL_SEC;

        // Sleep in small increments to allow quick shutdown
        for (int i = 0; i < wait_sec * 10 && running_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (!running_.load()) break;
        first_heartbeat = false;

        // Calculate bandwidth since last check
        auto now = std::chrono::steady_clock::now();
        double elapsed_sec = std::chrono::duration<double>(now - last_bandwidth_check_).count();

        uint64_t current_in = bytes_in_.load();
        uint64_t current_out = bytes_out_.load();

        double bw_in = (current_in - last_bytes_in_) / elapsed_sec;
        double bw_out = (current_out - last_bytes_out_) / elapsed_sec;

        last_bytes_in_ = current_in;
        last_bytes_out_ = current_out;
        last_bandwidth_check_ = now;

        // Get current stats
        auto tip = chain_ ? chain_->getTip() : nullptr;
        int32_t height = tip ? tip->height : 0;
        uint64_t peers = peer_manager_ ? peer_manager_->getPeerCount() : 0;
        uint64_t known_addrs = peer_manager_ ? peer_manager_->getAddressCount() : 0;

        uint64_t mempool_txs = 0;
        uint64_t mempool_bytes = 0;
        if (mempool_) {
            auto mp_stats = mempool_->getStats();
            mempool_txs = mp_stats.tx_count;
            mempool_bytes = mp_stats.total_size;
        }

        double sync_progress = 1.0;
        uint64_t blocks_received = 0;
        uint64_t txs_received = 0;
        if (message_handler_) {
            auto sync_stats = message_handler_->getSyncStats();
            sync_progress = sync_stats.progress;

            auto mh_stats = message_handler_->getStats();
            blocks_received = mh_stats.blocks_received;
            txs_received = mh_stats.txs_received;
        }

        auto uptime_sec = std::chrono::duration_cast<std::chrono::seconds>(
            now - start_time_).count();

        // Log heartbeat (full or simple based on sync state)
        if (sync_progress < 1.0) {
            // Still syncing - use simple format
            log::heartbeat_simple(height, peers, sync_progress);
        } else {
            // Fully synced - use detailed format
            log::heartbeat(
                uptime_sec,
                height,
                peers,
                known_addrs,
                mempool_txs,
                mempool_bytes,
                sync_progress,
                blocks_received,
                txs_received,
                bw_in,
                bw_out
            );
        }

        // Periodic UTXO flush to prevent data loss on crash
        auto utxo_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - last_utxo_flush).count();
        if (utxo_elapsed >= UTXO_FLUSH_INTERVAL_SEC && utxo_set_) {
            utxo_set_->flush();
            last_utxo_flush = now;
            LOG_DEBUG("UTXO set flushed to disk ({} entries)", utxo_set_->size());
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Status Display
// ═══════════════════════════════════════════════════════════════════════════

void Node::printStatusLine() {
    auto tip = chain_ ? chain_->getTip() : nullptr;
    uint32_t height = tip ? tip->height : 0;
    size_t peers = peer_manager_ ? peer_manager_->getPeerCount() : 0;
    size_t known_addrs = peer_manager_ ? peer_manager_->getAddressCount() : 0;
    size_t mempool_size = mempool_ ? mempool_->size() : 0;
    size_t active_miners = 0;

    if (p2pool_ && p2pool_->isRunning()) {
        active_miners = p2pool_->getMinerCount();
    }

    // Calculate uptime
    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_).count();
    int hours = uptime / 3600;
    int mins = (uptime % 3600) / 60;
    int secs = uptime % 60;

    // Use carriage return to update in place, \033[K clears to end of line
    std::cout << "\r\033[K"
              << "Height: " << height
              << " | Peers: " << peers
              << " | Known: " << known_addrs
              << " | Miners: " << active_miners
              << " | Mempool: " << mempool_size << " txs"
              << " | Uptime: ";

    if (hours > 0) {
        std::cout << hours << "h " << mins << "m";
    } else if (mins > 0) {
        std::cout << mins << "m " << secs << "s";
    } else {
        std::cout << secs << "s";
    }

    std::cout << std::flush;
}

// ═══════════════════════════════════════════════════════════════════════════
// Event Handlers
// ═══════════════════════════════════════════════════════════════════════════

void Node::onNewPeer(p2p::Connection::Id peer_id) {
    int32_t peer_height = 0;
    auto info = peer_manager_->getPeerInfo();
    for (const auto& peer : info) {
        if (peer.id == peer_id) {
            peer_height = peer.best_height;
            LOG_INFO("P2P: new peer {} \"{}\" (height: {})",
                     peer.addr.toString(), peer.user_agent, peer.best_height);
            break;
        }
    }

    // Update our advertised height
    auto tip = chain_->getTip();
    if (tip) {
        peer_manager_->setOurHeight(tip->height);

        // If the new peer has a higher height, trigger sync
        if (peer_height > tip->height) {
            LOG_INFO("New peer has higher height ({} > {}), triggering sync",
                     peer_height, tip->height);
            message_handler_->startSync();
        }
    }

}

void Node::onPeerDisconnect(p2p::Connection::Id peer_id, const std::string& reason) {
    LOG_INFO("P2P: peer {} disconnected: {}", peer_id, reason);
}

void Node::onP2PMessage(p2p::Connection::Id peer_id, const p2p::Message& msg) {
    // Forward to message handler
    if (message_handler_) {
        message_handler_->processMessage(peer_id, msg);
    }
}

void Node::onNewTip(const chain::BlockIndex* tip) {
    LOG_INFO("New tip: height={} hash={}",
             tip->height, toHex(tip->hash).substr(0, 16));

    // Update peer manager height
    if (peer_manager_) {
        peer_manager_->setOurHeight(tip->height);
    }

    // Remove confirmed transactions from mempool
    auto block = chain_->getBlock(tip->hash);
    if (block && mempool_) {
        mempool_->removeForBlock(block->transactions);
    }
}

void Node::onBlockConnected(const chain::Block& block, const chain::BlockIndex* index) {
    LOG_DEBUG("Block connected: height={} txs={}",
              index->height, block.transactions.size());

    // CRITICAL: Update UTXO set - spend inputs, create outputs
    if (utxo_set_) {
        // Generate undo data BEFORE modifying UTXO set
        // This saves the UTXOs that will be spent, so we can restore them on reorg
        chain::CoinViewDelta undo_data = utxo_set_->generateUndoData(block.transactions);

        // Apply block to UTXO set
        if (!utxo_set_->connectBlock(block.transactions, index->height)) {
            LOG_ERROR("Failed to update UTXO set for block at height {}", index->height);
        }

        // Save undo data to disk for chain reorganization support
        if (!undo_data.added.empty()) {
            std::string undo_path = config_.data_dir + "/blocks/undo_" + std::to_string(index->height) + ".dat";
            std::ofstream undo_file(undo_path, std::ios::binary);
            if (undo_file) {
                // Serialize undo data: count + entries
                uint32_t count = static_cast<uint32_t>(undo_data.added.size());
                undo_file.write(reinterpret_cast<const char*>(&count), sizeof(count));

                for (const auto& [outpoint, entry] : undo_data.added) {
                    // Write outpoint
                    undo_file.write(reinterpret_cast<const char*>(outpoint.txid.data()), 32);
                    undo_file.write(reinterpret_cast<const char*>(&outpoint.index), sizeof(outpoint.index));

                    // Write entry
                    auto entry_data = entry.serialize();
                    uint32_t entry_size = static_cast<uint32_t>(entry_data.size());
                    undo_file.write(reinterpret_cast<const char*>(&entry_size), sizeof(entry_size));
                    undo_file.write(reinterpret_cast<const char*>(entry_data.data()), entry_data.size());
                }
                LOG_DEBUG("Saved undo data for height {}: {} entries", index->height, count);
            } else {
                LOG_WARN("Failed to save undo data for height {}", index->height);
            }
        }
    }

    // Announce to peers
    if (message_handler_) {
        message_handler_->announceBlock(block);
    }
}

void Node::onBlockDisconnected(const chain::Block& block, const chain::BlockIndex* index) {
    LOG_DEBUG("Block disconnected: height={}", index->height);

    // Load undo data from disk to restore spent UTXOs
    if (utxo_set_) {
        chain::CoinViewDelta undo_data;
        std::string undo_path = config_.data_dir + "/blocks/undo_" + std::to_string(index->height) + ".dat";
        std::ifstream undo_file(undo_path, std::ios::binary);

        if (undo_file) {
            uint32_t count = 0;
            undo_file.read(reinterpret_cast<char*>(&count), sizeof(count));

            for (uint32_t i = 0; i < count; ++i) {
                // Read outpoint
                chain::Outpoint outpoint;
                undo_file.read(reinterpret_cast<char*>(outpoint.txid.data()), 32);
                undo_file.read(reinterpret_cast<char*>(&outpoint.index), sizeof(outpoint.index));

                // Read entry size and data
                uint32_t entry_size = 0;
                undo_file.read(reinterpret_cast<char*>(&entry_size), sizeof(entry_size));

                std::vector<uint8_t> entry_data(entry_size);
                undo_file.read(reinterpret_cast<char*>(entry_data.data()), entry_size);

                chain::UTXOEntry entry;
                if (entry.deserialize(entry_data.data(), entry_data.size())) {
                    undo_data.added[outpoint] = entry;
                }
            }

            LOG_DEBUG("Loaded undo data for height {}: {} entries", index->height, count);

            // Apply undo data to UTXO set
            if (!utxo_set_->disconnectBlock(block.transactions, index->height, undo_data)) {
                LOG_ERROR("Failed to disconnect UTXO set for block at height {}", index->height);
            }

            // Remove undo file after successful use
            std::filesystem::remove(undo_path);
        } else {
            LOG_ERROR("No undo data found for height {} - UTXO set may be inconsistent!", index->height);
            LOG_ERROR("Consider running --reindex to rebuild the UTXO set from blocks");
        }
    }

    // Return transactions to mempool (except coinbase)
    if (mempool_) {
        for (size_t i = 1; i < block.transactions.size(); ++i) {
            mempool_->addTransaction(block.transactions[i], index->height);
        }
    }
}

void Node::onTxAdded(const chain::Transaction& tx) {
    LOG_DEBUG("Mempool: tx added {}", toHex(tx.getTxId()).substr(0, 16));

    // Announce to peers
    if (message_handler_) {
        message_handler_->announceTx(tx);
    }
}

void Node::onTxRemoved(const crypto::Hash256& txid, const std::string& reason) {
    LOG_DEBUG("Mempool: tx removed {} ({})", toHex(txid).substr(0, 16), reason);
}

} // namespace ftc
