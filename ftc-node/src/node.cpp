/**
 * FTC Node - Full Integration
 *
 * Coordinates all components:
 * - P2P Network (TCP block/tx propagation)
 * - Blockchain (validation, storage)
 * - Mempool (pending transactions)
 * - Localhost API (wallet/miner interface)
 *
 * Peer discovery via --addnode and peers.dat
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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
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
    // Initialize consensus with network parameters
    chain::ConsensusParams params;
    if (config_.testnet) {
        params = chain::ConsensusParams::testnet();
    } else {
        // Default constructor sets mainnet parameters
        params = chain::ConsensusParams();
    }

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
    mh_config.max_blocks_in_flight = 16;
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

bool Node::initAPI() {
    api::Server::Config api_config;
    api_config.host = "127.0.0.1";  // SECURITY: localhost only
    api_config.port = config_.api_port;
    api_config.enable_cors = config_.api_cors;  // Enable CORS for browser wallets

    api_server_ = std::make_unique<api::Server>(api_config);

    // Wire up dependencies
    api_server_->setChain(chain_.get());
    api_server_->setMempool(mempool_.get());
    api_server_->setUTXOSet(utxo_set_.get());
    api_server_->setPeerManager(peer_manager_.get());

    if (!api_server_->start()) {
        LOG_ERROR("Failed to start API server");
        return false;
    }

    LOG_DEBUG("API server started: http://[::]:{} (IPv4+IPv6)", config_.api_port);
    return true;
}

bool Node::initStratum() {
    stratum_server_ = std::make_unique<stratum::StratumServer>(config_.stratum_port);

    // Set payout address for solo mining
    if (!config_.mining_address.empty()) {
        stratum_server_->setPayoutAddress(config_.mining_address);
    }

    // Set callback for getting mining work
    stratum_server_->setGetWorkCallback([this](const std::string& payout_address, stratum::Job& job) -> bool {
        auto tip = chain_->getTip();
        if (!tip) return false;

        // Get bits (difficulty target)
        auto getHeader = [this](uint64_t height) -> chain::BlockHeader {
            auto blk = chain_->getBlock(static_cast<int32_t>(height));
            if (!blk) return chain::BlockHeader{};
            return blk->header;
        };
        auto tipBlock = chain_->getBlock(tip->hash);
        if (!tipBlock) return false;
        uint32_t bits = consensus_->getNextWorkRequired(tip->height, tipBlock->header, getHeader);

        // New block height
        uint32_t height = tip->height + 1;

        // Create timestamp
        uint32_t timestamp = static_cast<uint32_t>(std::time(nullptr));

        // Build block template with coinbase
        chain::Block block_template;
        block_template.header.version = 1;
        block_template.header.prev_hash = tip->hash;
        block_template.header.timestamp = timestamp;
        block_template.header.bits = bits;
        block_template.header.nonce = 0;

        // Create coinbase transaction
        chain::Transaction coinbase_tx;
        coinbase_tx.version = 1;
        coinbase_tx.locktime = 0;

        // Coinbase input (no previous output)
        chain::TxInput coinbase_input;
        std::memset(coinbase_input.prevout.txid.data(), 0, 32);
        coinbase_input.prevout.index = 0xFFFFFFFF;
        coinbase_input.sequence = 0xFFFFFFFF;

        // Coinbase script: height (BIP34) + arbitrary data
        std::vector<uint8_t> coinbase_script;
        // Encode height as minimal push
        if (height < 17) {
            coinbase_script.push_back(static_cast<uint8_t>(0x50 + height));  // OP_1 to OP_16
        } else if (height <= 0x7F) {
            coinbase_script.push_back(1);
            coinbase_script.push_back(static_cast<uint8_t>(height));
        } else if (height <= 0x7FFF) {
            coinbase_script.push_back(2);
            coinbase_script.push_back(static_cast<uint8_t>(height & 0xFF));
            coinbase_script.push_back(static_cast<uint8_t>((height >> 8) & 0xFF));
        } else {
            coinbase_script.push_back(3);
            coinbase_script.push_back(static_cast<uint8_t>(height & 0xFF));
            coinbase_script.push_back(static_cast<uint8_t>((height >> 8) & 0xFF));
            coinbase_script.push_back(static_cast<uint8_t>((height >> 16) & 0xFF));
        }
        // Add miner identifier
        const char* miner_tag = "/FTC/Stratum/";
        coinbase_script.insert(coinbase_script.end(), miner_tag, miner_tag + std::strlen(miner_tag));
        coinbase_input.script_sig = coinbase_script;

        coinbase_tx.inputs.push_back(coinbase_input);

        // Coinbase output with block reward + fees
        uint64_t block_reward = consensus_->params().getBlockReward(height);
        uint64_t fees = 0;  // TODO: Calculate fees from mempool transactions
        uint64_t total_reward = block_reward + fees;

        // Check if P2Pool is enabled and has shares - use PPLNS payouts
        bool use_p2pool_payouts = false;
        std::map<std::vector<uint8_t>, uint64_t> payouts;

        if (p2pool_ && p2pool_->isRunning()) {
            // Register this miner's share for PPLNS
            auto miner_script = chain::script::createP2PKHFromAddress(payout_address);
            if (!miner_script.empty()) {
                p2pool_->registerMinerShare(miner_script);
            }

            // Get PPLNS payouts
            payouts = p2pool_->getPayouts();
            if (!payouts.empty()) {
                use_p2pool_payouts = true;
            }
        }

        if (use_p2pool_payouts) {
            // Create multiple outputs for P2Pool PPLNS participants
            for (const auto& [script, amount] : payouts) {
                if (amount > 0) {
                    chain::TxOutput output;
                    output.value = amount;
                    output.script_pubkey = script;
                    coinbase_tx.outputs.push_back(output);
                }
            }
        } else {
            // Solo mining fallback - single output to miner
            chain::TxOutput coinbase_output;
            coinbase_output.value = total_reward;

            // Create output script from payout address
            if (!payout_address.empty()) {
                coinbase_output.script_pubkey = chain::script::createP2PKHFromAddress(payout_address);
            } else if (!config_.mining_address.empty()) {
                coinbase_output.script_pubkey = chain::script::createP2PKHFromAddress(config_.mining_address);
            } else {
                // No payout address configured - this shouldn't happen
                LOG_ERROR("[Stratum] No payout address configured for mining");
                return false;
            }

            coinbase_tx.outputs.push_back(coinbase_output);
        }
        block_template.transactions.push_back(coinbase_tx);

        // Add mempool transactions (simplified - just coinbase for now)
        // TODO: Add fee-prioritized mempool transactions

        // Calculate merkle root
        block_template.updateMerkleRoot();

        // Store block template for later submission
        {
            std::lock_guard<std::mutex> lock(mining_work_mutex_);
            current_mining_work_.block_template = block_template;
            current_mining_work_.prev_hash = tip->hash;
            current_mining_work_.height = height;
            current_mining_work_.bits = bits;
            current_mining_work_.valid = true;
        }

        // Build job data for Stratum protocol
        job.height = height;

        // Version in little-endian hex
        std::stringstream ver_ss;
        uint32_t ver_le = block_template.header.version;
        ver_ss << std::hex << std::setfill('0') << std::setw(8) << ver_le;
        job.version = ver_ss.str();

        // prev_hash in internal byte order
        std::stringstream prev_ss;
        prev_ss << std::hex << std::setfill('0');
        for (int i = 0; i < 32; ++i) {
            prev_ss << std::setw(2) << static_cast<int>(tip->hash[i]);
        }
        job.prev_hash = prev_ss.str();

        // ntime
        std::stringstream ntime_ss;
        ntime_ss << std::hex << std::setfill('0') << std::setw(8) << timestamp;
        job.ntime = ntime_ss.str();

        // nbits
        std::stringstream nbits_ss;
        nbits_ss << std::hex << std::setfill('0') << std::setw(8) << bits;
        job.nbits = nbits_ss.str();

        // Serialize coinbase for the miner
        auto coinbase_data = coinbase_tx.serialize();
        std::stringstream cb1_ss, cb2_ss;
        cb1_ss << std::hex << std::setfill('0');
        for (auto b : coinbase_data) {
            cb1_ss << std::setw(2) << static_cast<int>(b);
        }
        job.coinbase1 = cb1_ss.str();
        job.coinbase2 = "";  // Extranonce goes after coinbase1 in our simple scheme

        // Merkle branch (empty for single coinbase)
        job.merkle_branch.clear();

        LOG_DEBUG("[Stratum] New work: height={} bits={:08x} prev={}...",
                  height, bits, toHex(tip->hash).substr(0, 16));

        return true;
    });

    // Set callback for block submission
    stratum_server_->setBlockFoundCallback([this](const std::vector<uint8_t>& header_data, uint32_t nonce,
                                                   const std::vector<uint8_t>& coinbase) -> bool {
        MiningWork work;
        {
            std::lock_guard<std::mutex> lock(mining_work_mutex_);
            if (!current_mining_work_.valid) {
                LOG_WARN("[Stratum] Block submission rejected: no valid work template");
                return false;
            }
            work = current_mining_work_;
        }

        // Update the block with the found nonce
        chain::Block block = work.block_template;
        block.header.nonce = nonce;

        // Verify the header matches what we sent (prev_hash, bits)
        auto tip = chain_->getTip();
        if (!tip || tip->hash != work.prev_hash) {
            LOG_WARN("[Stratum] Block submission rejected: chain tip changed");
            return false;
        }

        // Check proof of work
        crypto::Hash256 block_hash = block.header.getHash();
        if (!consensus_->checkProofOfWork(block_hash, block.header.bits)) {
            LOG_WARN("[Stratum] Block submission rejected: PoW check failed");
            return false;
        }

        LOG_NOTICE("[Stratum] Valid block found! height={} hash={}",
                   work.height, toHex(block_hash).substr(0, 16) + "...");

        // Submit to chain
        auto result = chain_->processBlock(block);
        if (result != chain::ValidationResult::VALID) {
            LOG_ERROR("[Stratum] Block rejected by chain: result={}", static_cast<int>(result));
            return false;
        }

        LOG_NOTICE("[Stratum] Block accepted into main chain! height={}", work.height);

        // Broadcast to peers
        if (peer_manager_) {
            peer_manager_->broadcastBlock(block_hash, block);
            LOG_INFO("[Stratum] Block broadcast to {} peers", peer_manager_->getPeerCount());
        }

        // Invalidate current work (new work needed)
        {
            std::lock_guard<std::mutex> lock(mining_work_mutex_);
            current_mining_work_.valid = false;
        }

        // Notify stratum server to send new work to miners
        if (stratum_server_) {
            stratum_server_->notifyNewBlock();
        }

        return true;
    });

    if (!stratum_server_->start()) {
        LOG_ERROR("Failed to start Stratum server");
        return false;
    }

    LOG_DEBUG("Stratum server started: stratum+tcp://0.0.0.0:{}", config_.stratum_port);
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

    // Set callback for getting connected miner count from Stratum server
    p2pool_->setGetConnectedMinersCallback([this]() -> size_t {
        if (stratum_server_) {
            return stratum_server_->getConnectedMiners();
        }
        return 0;
    });

    // Start P2Pool
    if (!p2pool_->start()) {
        LOG_ERROR("Failed to start P2Pool");
        return false;
    }

    LOG_DEBUG("P2Pool started: tcp://0.0.0.0:{}", p2pool_config.port);
    return true;
}

// Parse IP:PORT string to NetAddr
static bool parseAddress(const std::string& str, p2p::NetAddr& addr) {
    std::string host;
    uint16_t port = 17318;  // Default port

    // Handle IPv6 format: [2001:db8::1]:port
    if (!str.empty() && str[0] == '[') {
        size_t close = str.find(']');
        if (close == std::string::npos) return false;
        host = str.substr(1, close - 1);
        if (close + 1 < str.size() && str[close + 1] == ':') {
            port = static_cast<uint16_t>(std::stoi(str.substr(close + 2)));
        }
    } else {
        // IPv4 format: 1.2.3.4:port
        size_t colon = str.rfind(':');
        if (colon != std::string::npos) {
            host = str.substr(0, colon);
            port = static_cast<uint16_t>(std::stoi(str.substr(colon + 1)));
        } else {
            host = str;
        }
    }

    addr.port = port;
    addr.services = 1;  // NODE_NETWORK

    // Try IPv4 first
    struct in_addr ipv4;
    if (inet_pton(AF_INET, host.c_str(), &ipv4) == 1) {
        // Convert to IPv6-mapped address
        std::memset(addr.ip, 0, 10);
        addr.ip[10] = 0xff;
        addr.ip[11] = 0xff;
        std::memcpy(addr.ip + 12, &ipv4, 4);
        return true;
    }

    // Try IPv6
    struct in6_addr ipv6;
    if (inet_pton(AF_INET6, host.c_str(), &ipv6) == 1) {
        std::memcpy(addr.ip, &ipv6, 16);
        return true;
    }

    return false;
}

void Node::connectToInitialPeers() {
    for (const auto& node_str : config_.addnodes) {
        p2p::NetAddr addr;
        if (parseAddress(node_str, addr)) {
            LOG_INFO("Connecting to --addnode peer: {}", addr.toString());
            peer_manager_->connectTo(addr);
        } else {
            LOG_WARN("Invalid --addnode address: {}", node_str);
        }
    }
}

bool Node::loadPeers() {
    std::string peers_file = config_.data_dir + "/peers/peers.dat";

    std::ifstream f(peers_file);
    if (!f.is_open()) {
        LOG_DEBUG("No peers.dat found, starting fresh");
        return true;  // Not an error, just no saved peers
    }

    int loaded = 0;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;

        p2p::NetAddr addr;
        if (parseAddress(line, addr)) {
            peer_manager_->addAddress(addr, "peers.dat");
            loaded++;
        }
    }

    LOG_INFO("Loaded {} addresses from peers.dat", loaded);
    return true;
}

bool Node::savePeers() {
    std::string peers_file = config_.data_dir + "/peers/peers.dat";

    std::ofstream f(peers_file, std::ios::trunc);
    if (!f.is_open()) {
        LOG_WARN("Failed to open peers.dat for writing");
        return false;
    }

    f << "# FTC peers.dat - known peer addresses\n";
    f << "# Format: IP:PORT (one per line)\n";

    auto addrs = peer_manager_->getAddresses(1000);
    int saved = 0;
    for (const auto& a : addrs) {
        p2p::NetAddr addr;
        std::memcpy(addr.ip, a.ip, 16);
        addr.port = a.port;
        addr.services = a.services;

        f << addr.toString() << "\n";
        saved++;
    }

    LOG_DEBUG("Saved {} addresses to peers.dat", saved);
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

bool Node::start() {
    start_time_ = std::chrono::steady_clock::now();

    LOG_NOTICE("FTC Node starting...");
    LOG_NOTICE("Data directory: {}", config_.data_dir);
    LOG_NOTICE("Network: {}", config_.testnet ? "testnet" : "mainnet");

    // ═══════════════════════════════════════════════════════════════════════
    // Phase 0: Basic Initialization
    // ═══════════════════════════════════════════════════════════════════════
    LOG_BOOTSTRAP(0, "starting", "Starting");

    generateNodeId();
    LOG_INFO("Node ID: {}...", toHex(node_id_, 20).substr(0, 16));

    if (!initDataDir()) {
        return false;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Phase 1: Consensus & Storage
    // ═══════════════════════════════════════════════════════════════════════
    LOG_BOOTSTRAP(10, "init_consensus", "Initializing consensus rules");

    if (!initConsensus()) {
        return false;
    }

    LOG_BOOTSTRAP(20, "init_utxo", "Initializing UTXO set");

    if (!initUTXOSet()) {
        return false;
    }

    LOG_BOOTSTRAP(30, "init_chain", "Initializing blockchain");

    if (!initChain()) {
        return false;
    }

    LOG_BOOTSTRAP(40, "init_mempool", "Initializing mempool");

    if (!initMempool()) {
        return false;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Phase 1.5: Reindex (if requested)
    // ═══════════════════════════════════════════════════════════════════════
    if (config_.reindex) {
        LOG_BOOTSTRAP(45, "reindexing", "Rebuilding UTXO set from blocks");

        if (!reindexUTXO()) {
            LOG_ERROR("Reindex failed!");
            return false;
        }

        LOG_NOTICE("Reindex completed successfully");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Phase 2: P2P Network
    // ═══════════════════════════════════════════════════════════════════════
    LOG_BOOTSTRAP(50, "p2p_start", "Starting P2P network");

    if (!initP2P()) {
        return false;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Phase 3: Load Peers & Connect
    // ═══════════════════════════════════════════════════════════════════════
    LOG_BOOTSTRAP(60, "load_peers", "Loading peer database");

    loadPeers();

    // Connect to initial nodes from command line
    if (!config_.addnodes.empty()) {
        LOG_BOOTSTRAP(65, "connecting", "Connecting to initial peers");
        connectToInitialPeers();

        // Wait briefly for at least one connection
        auto wait_start = std::chrono::steady_clock::now();
        while (peer_manager_->getPeerCount() == 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - wait_start).count();

            if (elapsed > 30) {
                LOG_WARN("Could not connect to any initial peers, continuing anyway");
                break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            if (shutdown_requested_) {
                return false;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Phase 4: Chain Synchronization
    // ═══════════════════════════════════════════════════════════════════════
    if (peer_manager_->getPeerCount() > 0) {
        LOG_BOOTSTRAP(70, "sync_start", "Starting chain synchronization");

        message_handler_->startSync();

        // Wait for initial sync (with timeout)
        auto sync_start = std::chrono::steady_clock::now();
        while (message_handler_->isSyncing()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - sync_start).count();

            if (elapsed > 300) {  // 5 minutes max for initial sync
                LOG_WARN("Initial sync taking too long, continuing in background");
                break;
            }

            double progress = message_handler_->getSyncProgress();
            int bootstrap_progress = static_cast<int>(70 + progress * 20);  // 70-90 during sync

            auto tip = chain_->getTip();
            LOG_BOOTSTRAP(bootstrap_progress, "syncing",
                "Syncing... height={} progress={:.1f}%%",
                tip ? tip->height : 0, progress * 100);

            std::this_thread::sleep_for(std::chrono::seconds(2));

            LOG_DEBUG("Sync loop: woke up from sleep, shutdown_requested={}, isSyncing={}",
                      shutdown_requested_, message_handler_->isSyncing());

            if (shutdown_requested_) {
                LOG_DEBUG("Sync loop: exiting due to shutdown_requested");
                return false;
            }
        }

        LOG_DEBUG("Sync loop: exited normally, proceeding to sync_done");
        LOG_BOOTSTRAP(90, "sync_done", "Chain synchronized");
    } else {
        LOG_BOOTSTRAP(90, "first_node", "First node - waiting for peers to connect");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Phase 5: API Server
    // ═══════════════════════════════════════════════════════════════════════
    LOG_BOOTSTRAP(95, "api_start", "Starting API server");

    if (!initAPI()) {
        return false;
    }

    // Start Stratum server for GPU miners
    if (config_.stratum_enabled) {
        LOG_BOOTSTRAP(97, "stratum_start", "Starting Stratum server");

        if (!initStratum()) {
            LOG_WARN("Failed to start Stratum server, GPU mining unavailable");
        }
    }

    // Start P2Pool - decentralized mining pool
    LOG_BOOTSTRAP(98, "p2pool_start", "Starting P2Pool");
    if (!initP2Pool()) {
        LOG_WARN("Failed to start P2Pool, decentralized mining unavailable");
    }

    // Wire P2Pool to API server (after P2Pool is initialized)
    if (p2pool_ && api_server_) {
        api_server_->setP2Pool(p2pool_.get());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Phase 6: Ready
    // ═══════════════════════════════════════════════════════════════════════
    LOG_BOOTSTRAP(100, "done", "Ready");

    auto tip = chain_->getTip();
    LOG_NOTICE("========================================================");
    LOG_NOTICE("FTC Node Ready");
    LOG_NOTICE("========================================================");
    LOG_NOTICE("Chain height: {}", tip ? tip->height : 0);
    LOG_NOTICE("Best block:   {}", tip ? toHex(tip->hash).substr(0, 32) + "..." : "genesis");
    LOG_NOTICE("Peers:        {}", peer_manager_->getPeerCount());
    LOG_NOTICE("Known addrs:  {}", peer_manager_->getAddressCount());
    LOG_NOTICE("Mempool:      {} txs", mempool_->size());
    LOG_NOTICE("P2P:          tcp://[::]:{} (IPv4+IPv6)", config_.p2p_port);
    LOG_NOTICE("API:          http://[::]:{} (IPv4+IPv6)", config_.api_port);
    if (stratum_server_ && stratum_server_->isRunning()) {
        LOG_NOTICE("Stratum:      stratum+tcp://[::]:{} (IPv4+IPv6)", config_.stratum_port);
    }
    if (p2pool_ && p2pool_->isRunning()) {
        LOG_NOTICE("P2Pool:       tcp://[::]:{} (decentralized pool)", 17320);
    }
    LOG_NOTICE("========================================================");

    if (config_.addnodes.empty() && peer_manager_->getPeerCount() == 0) {
        LOG_NOTICE("");
        LOG_NOTICE("This is the first node. Share your IP address:");
        LOG_NOTICE("  Other nodes can connect using: --addnode=YOUR_IP:{}", config_.p2p_port);
        LOG_NOTICE("");
    }

    // Install signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    running_ = true;
    return true;
}

void Node::stop() {
    if (!running_.load()) return;

    LOG_NOTICE("Shutting down FTC Node...");

    running_ = false;

    // Save peers before shutdown
    savePeers();

    // Stop in reverse order of initialization

    if (p2pool_) {
        LOG_DEBUG("Stopping P2Pool...");
        p2pool_->stop();
    }

    if (stratum_server_) {
        LOG_DEBUG("Stopping Stratum server...");
        stratum_server_->stop();
    }

    if (api_server_) {
        LOG_DEBUG("Stopping API server...");
        api_server_->stop();
    }

    if (message_handler_) {
        LOG_DEBUG("Stopping message handler...");
        message_handler_->stop();
    }

    if (peer_manager_) {
        LOG_DEBUG("Stopping peer manager...");
        peer_manager_->stop();
    }

    if (chain_) {
        LOG_DEBUG("Flushing blockchain...");
        chain_->flush();
    }

    if (utxo_set_) {
        LOG_DEBUG("Flushing UTXO set...");
        utxo_set_->flush();
    }

    LOG_NOTICE("Shutdown complete");
}

void Node::waitForShutdown() {
    std::unique_lock<std::mutex> lock(shutdown_mutex_);

    // Periodically save peers and print status while waiting for shutdown
    while (!shutdown_requested_) {
        // Wait for 30 seconds or until shutdown is requested
        if (shutdown_cv_.wait_for(lock, std::chrono::seconds(30), [this] { return shutdown_requested_; })) {
            break;  // Shutdown requested
        }

        lock.unlock();

        // Save peers
        savePeers();

        // Print status update
        auto tip = chain_ ? chain_->getTip() : nullptr;
        uint32_t height = tip ? tip->height : 0;
        size_t peers = peer_manager_ ? peer_manager_->getPeerCount() : 0;
        size_t mempool_size = mempool_ ? mempool_->size() : 0;
        size_t active_miners = 0;
        if (p2pool_ && p2pool_->isRunning()) {
            active_miners = p2pool_->getMinerCount();
        }

        LOG_NOTICE("[Status] Height: {} | Peers: {} | Miners: {} | Mempool: {} txs",
                   height, peers, active_miners, mempool_size);

        lock.lock();
    }

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
    Stats stats;

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

    return stats;
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
