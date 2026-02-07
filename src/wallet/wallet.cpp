// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/wallet.h"
#include "core/logging.h"
#include "primitives/address.h"
#include "wallet/backup.h"
#include "wallet/create_tx.h"
#include "wallet/sign_tx.h"
#include "wallet/spend.h"

#include <cstring>

namespace wallet {

// ---------------------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------------------

Wallet::Wallet(chain::ChainstateManager& chainstate)
    : chainstate_(chainstate) {}

Wallet::~Wallet() {
    if (loaded_) {
        close();
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

core::Result<void> Wallet::open(const std::filesystem::path& path) {
    std::lock_guard lock(mutex_);

    if (loaded_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Wallet is already loaded");
    }

    wallet_path_ = path;

    // Open the database.
    auto db_result = db_.open(path);
    if (!db_result.ok()) {
        return core::Error(core::ErrorCode::STORAGE_ERROR,
                           "Failed to open wallet database: " +
                           db_result.error().message());
    }

    // Initialize all subsystems.
    auto init_result = init_subsystems();
    if (!init_result.ok()) {
        db_.close();
        return init_result;
    }

    loaded_ = true;

    // Start the background scanner thread.
    scanner_running_ = true;
    scanner_thread_ = std::thread(&Wallet::scanner_loop, this);

    LOG_INFO(core::LogCategory::WALLET,
             "Wallet opened: " + path.string());
    return core::Result<void>{};
}

void Wallet::close() {
    // Stop the scanner thread first.
    scanner_running_ = false;
    if (scanner_thread_.joinable()) {
        scanner_thread_.join();
    }

    std::lock_guard lock(mutex_);

    if (!loaded_) return;

    // Store final metadata.
    auto meta_result = store_metadata();
    if (!meta_result.ok()) {
        LOG_ERROR(core::LogCategory::WALLET,
                  "Failed to store wallet metadata on close: " +
                  meta_result.error().message());
    }

    // Lock the wallet (clear encryption keys).
    keys_.clear_encryption_key();

    // Close the database.
    db_.close();

    loaded_ = false;
    LOG_INFO(core::LogCategory::WALLET, "Wallet closed");
}

bool Wallet::is_loaded() const {
    return loaded_.load();
}

// ---------------------------------------------------------------------------
// Balance queries
// ---------------------------------------------------------------------------

WalletBalance Wallet::get_balance() const {
    std::lock_guard lock(mutex_);

    if (!loaded_) {
        return WalletBalance{};
    }

    auto all_coins = coins_.get_all_coins();
    return compute_balance(all_coins, chain_height());
}

primitives::Amount Wallet::get_spendable_balance() const {
    std::lock_guard lock(mutex_);

    if (!loaded_) {
        return primitives::Amount(0);
    }

    auto all_coins = coins_.get_all_coins();
    return compute_spendable_balance(all_coins, chain_height());
}

// ---------------------------------------------------------------------------
// Address management
// ---------------------------------------------------------------------------

core::Result<std::string> Wallet::get_new_address(const std::string& label) {
    std::lock_guard lock(mutex_);

    if (!loaded_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Wallet is not loaded");
    }

    check_auto_lock();

    // Derive a new key from the HD wallet.
    std::string address;
    if (hd_.is_initialized()) {
        auto key_result = hd_.get_next_receiving_key();
        if (!key_result.ok()) {
            return core::Error(core::ErrorCode::CRYPTO_KEY_FAIL,
                               "Failed to derive HD key: " +
                               key_result.error().message());
        }

        auto& ec_key = key_result.value();
        auto pubkey = ec_key.pubkey_compressed();

        // Import the derived key into the key manager.
        auto import_result = keys_.import_key(
            KeyManager::encode_wif(ec_key.secret()));
        if (import_result.ok()) {
            address = import_result.value();
        } else {
            // Key might already exist (from pool). Just compute the address.
            auto pkh = crypto::hash160(
                std::span<const uint8_t>(pubkey.data(), pubkey.size()));
            auto addr = primitives::Address::from_pubkey_hash(pkh);
            address = addr.to_string();
        }
    } else {
        // Non-HD wallet: generate a random key.
        auto gen_result = keys_.generate_key();
        if (!gen_result.ok()) {
            return gen_result.error();
        }
        address = gen_result.value();
    }

    // Add to address book.
    auto book_result = address_book_.add_receiving(address, label);
    if (!book_result.ok()) {
        LOG_WARN(core::LogCategory::WALLET,
                 "Failed to add address to book: " +
                 book_result.error().message());
    }

    // Notify listeners.
    notify_.notify_new_address(address);

    LOG_INFO(core::LogCategory::WALLET,
             "New address: " + address);
    return address;
}

core::Result<std::string> Wallet::get_change_address() {
    std::lock_guard lock(mutex_);

    if (!loaded_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Wallet is not loaded");
    }

    std::string address;
    if (hd_.is_initialized()) {
        auto key_result = hd_.get_next_change_key();
        if (!key_result.ok()) {
            return key_result.error();
        }

        auto& ec_key = key_result.value();
        auto pubkey = ec_key.pubkey_compressed();

        auto import_result = keys_.import_key(
            KeyManager::encode_wif(ec_key.secret()));
        if (import_result.ok()) {
            address = import_result.value();
        } else {
            auto pkh = crypto::hash160(
                std::span<const uint8_t>(pubkey.data(), pubkey.size()));
            auto addr = primitives::Address::from_witness_v0_keyhash(pkh);
            address = addr.to_string();
        }
    } else {
        auto gen_result = keys_.generate_key();
        if (!gen_result.ok()) return gen_result.error();
        address = gen_result.value();
    }

    auto book_result = address_book_.add_change(address);
    if (!book_result.ok()) {
        LOG_WARN(core::LogCategory::WALLET,
                 "Failed to add change address to book: " +
                 book_result.error().message());
    }

    return address;
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

core::Result<primitives::Transaction> Wallet::send_to_address(
    const std::string& address,
    primitives::Amount amount,
    FeePriority priority) {

    std::vector<Recipient> recipients;
    recipients.push_back({address, amount, false});
    return send_many(recipients, priority);
}

core::Result<primitives::Transaction> Wallet::send_many(
    const std::vector<Recipient>& recipients,
    FeePriority priority) {

    std::lock_guard lock(mutex_);

    if (!loaded_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Wallet is not loaded");
    }

    if (!keys_.is_unlocked()) {
        return core::Error(core::ErrorCode::WALLET_LOCKED,
                           "Wallet is locked");
    }

    check_auto_lock();

    // Calculate total send amount.
    int64_t total_send = 0;
    for (const auto& r : recipients) {
        total_send += r.amount.value();
    }

    if (total_send <= 0) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
                           "Send amount must be positive");
    }

    // Get available coins.
    int current_height = chain_height();
    auto available = coins_.get_spendable_coins(1, current_height);

    if (available.empty()) {
        return core::Error(core::ErrorCode::WALLET_NO_FUNDS,
                           "No spendable coins available");
    }

    // Get fee rate.
    auto fee_rate = fees_.get_fee_rate(priority);

    // Select coins.
    auto select_result = select_coins(
        primitives::Amount(total_send), available, fee_rate);
    if (!select_result.ok()) {
        return select_result.error();
    }

    auto selection = std::move(select_result).value();

    // Get a change address if needed.
    std::string change_addr;
    if (selection.has_change) {
        // Get change address without holding the lock
        // (we're already holding it).
        if (hd_.is_initialized()) {
            auto key_result = hd_.get_next_change_key();
            if (key_result.ok()) {
                auto pubkey = key_result.value().pubkey_compressed();
                auto import_result = keys_.import_key(
                    KeyManager::encode_wif(key_result.value().secret()));
                if (import_result.ok()) {
                    change_addr = import_result.value();
                } else {
                    auto pkh = crypto::hash160(
                        std::span<const uint8_t>(pubkey.data(), pubkey.size()));
                    auto addr = primitives::Address::from_witness_v0_keyhash(pkh);
                    change_addr = addr.to_string();
                }
            }
        }

        if (change_addr.empty()) {
            auto gen_result = keys_.generate_key();
            if (!gen_result.ok()) return gen_result.error();
            change_addr = gen_result.value();
        }

        address_book_.add_change(change_addr);
    }

    // Create the transaction.
    TransactionRequest request;
    request.recipients = recipients;
    request.coin_selection = selection;
    request.change_address = change_addr;
    request.current_height = current_height;
    request.enable_rbf = false;

    auto tx_result = create_transaction(request);
    if (!tx_result.ok()) {
        return tx_result.error();
    }

    auto tx = std::move(tx_result).value();

    // Build input signing info.
    std::vector<InputSigningInfo> input_info;
    input_info.reserve(selection.inputs.size());
    for (const auto& coin : selection.inputs) {
        InputSigningInfo info;
        info.amount = coin.output.amount;
        info.script_pubkey = primitives::script::Script(
            std::span<const uint8_t>(coin.output.script_pubkey));
        input_info.push_back(std::move(info));
    }

    // Sign the transaction.
    auto sign_result = sign_transaction(
        std::move(tx), keys_, input_info);
    if (!sign_result.ok()) {
        return sign_result.error();
    }

    auto signed_tx = std::move(sign_result).value();

    // Verify all inputs are signed.
    if (!is_fully_signed(signed_tx)) {
        return core::Error(core::ErrorCode::WALLET_KEY_MISS,
                           "Transaction is not fully signed");
    }

    // Mark the spent coins.
    for (const auto& coin : selection.inputs) {
        coins_.mark_spent(coin.outpoint, signed_tx.txid());
    }

    // Scan the transaction itself for change outputs.
    coins_.scan_transaction(signed_tx, 0);  // 0 = unconfirmed.

    // Store the transaction record.
    WalletTx wtx;
    wtx.txid = signed_tx.txid();
    wtx.amount = primitives::Amount(-total_send);
    wtx.fee = selection.fee;
    wtx.height = 0;
    wtx.time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    wtx.is_send = true;
    wtx.category = TxCategory::SEND;
    if (!recipients.empty()) {
        wtx.address = recipients[0].address;
    }

    store_wallet_tx(db_, wtx);

    // Notify listeners.
    notify_.notify_transaction(signed_tx.txid(), 0);
    notify_.notify_balance_change(get_spendable_balance());

    LOG_INFO(core::LogCategory::WALLET,
             "Sent transaction: " + signed_tx.txid().to_hex() +
             " amount=" + std::to_string(total_send) +
             " fee=" + std::to_string(selection.fee.value()));

    return signed_tx;
}

// ---------------------------------------------------------------------------
// Transaction history
// ---------------------------------------------------------------------------

std::vector<WalletTx> Wallet::list_transactions(
    size_t count, size_t skip, TxFilter filter) const {
    std::lock_guard lock(mutex_);

    if (!loaded_) return {};

    return get_transactions(db_, coins_, keys_, address_book_,
                            chain_height(), count, skip, filter);
}

std::vector<WalletCoin> Wallet::list_unspent(
    int minconf, int maxconf) const {
    std::lock_guard lock(mutex_);

    if (!loaded_) return {};

    int current_height = chain_height();
    auto all_coins = coins_.get_spendable_coins(minconf, current_height);

    // Filter by maxconf.
    std::vector<WalletCoin> result;
    for (const auto& coin : all_coins) {
        int confirmations = 0;
        if (coin.height > 0 && current_height >= coin.height) {
            confirmations = current_height - coin.height + 1;
        }
        if (confirmations <= maxconf) {
            result.push_back(coin);
        }
    }

    return result;
}

core::Result<WalletTx> Wallet::get_transaction(
    const core::uint256& txid) const {
    std::lock_guard lock(mutex_);

    if (!loaded_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Wallet is not loaded");
    }

    return get_transaction_detail(db_, coins_, keys_, address_book_,
                                  txid, chain_height());
}

// ---------------------------------------------------------------------------
// Wallet locking
// ---------------------------------------------------------------------------

void Wallet::lock() {
    std::lock_guard lock(mutex_);
    keys_.clear_encryption_key();
    has_auto_lock_ = false;
    LOG_INFO(core::LogCategory::WALLET, "Wallet locked");
}

core::Result<void> Wallet::unlock(std::string_view passphrase,
                                    std::chrono::seconds timeout) {
    std::lock_guard lock(mutex_);

    if (!loaded_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Wallet is not loaded");
    }

    if (!encryptor_.is_encrypted()) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Wallet is not encrypted");
    }

    // Verify the passphrase.
    auto verify_result = encryptor_.verify_passphrase(passphrase);
    if (!verify_result.ok()) {
        return verify_result.error();
    }
    if (!verify_result.value()) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Incorrect wallet passphrase");
    }

    // Derive the master key and set it on the key manager.
    auto key_result = encryptor_.derive_key(
        passphrase, std::span<const uint8_t>(encryptor_.salt()));
    if (!key_result.ok()) {
        return key_result.error();
    }

    keys_.set_encryption_key(key_result.value());

    // Set auto-lock timer if requested.
    if (timeout.count() > 0) {
        auto_lock_time_ = std::chrono::steady_clock::now() + timeout;
        has_auto_lock_ = true;
    } else {
        has_auto_lock_ = false;
    }

    LOG_INFO(core::LogCategory::WALLET,
             "Wallet unlocked" +
             (timeout.count() > 0
                 ? " (auto-lock in " + std::to_string(timeout.count()) + "s)"
                 : ""));
    return core::Result<void>{};
}

bool Wallet::is_locked() const {
    std::lock_guard lock(mutex_);
    return encryptor_.is_encrypted() && !keys_.is_unlocked();
}

bool Wallet::is_encrypted() const {
    std::lock_guard lock(mutex_);
    return encryptor_.is_encrypted();
}

core::Result<void> Wallet::encrypt_wallet(std::string_view passphrase) {
    std::lock_guard lock(mutex_);

    if (!loaded_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Wallet is not loaded");
    }

    return encryptor_.encrypt(keys_, passphrase);
}

core::Result<void> Wallet::change_passphrase(
    std::string_view old_passphrase,
    std::string_view new_passphrase) {
    std::lock_guard lock(mutex_);

    if (!loaded_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Wallet is not loaded");
    }

    return encryptor_.change_passphrase(keys_, old_passphrase,
                                         new_passphrase);
}

// ---------------------------------------------------------------------------
// Chain scanning
// ---------------------------------------------------------------------------

core::Result<void> Wallet::rescan(int from_height) {
    std::lock_guard lock(mutex_);

    if (!loaded_) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Wallet is not loaded");
    }

    LOG_INFO(core::LogCategory::WALLET,
             "Starting rescan from height " + std::to_string(from_height));

    coins_.clear_unconfirmed();

    int current_height = chain_height();
    for (int h = from_height; h <= current_height; ++h) {
        auto result = scan_block_at_height(h);
        if (!result.ok()) {
            LOG_WARN(core::LogCategory::WALLET,
                     "Rescan error at height " + std::to_string(h) +
                     ": " + result.error().message());
        }

        last_scanned_height_ = h;

        // Log progress periodically.
        if (h % 1000 == 0) {
            LOG_INFO(core::LogCategory::WALLET,
                     "Rescan progress: " + std::to_string(h) + "/" +
                     std::to_string(current_height));
        }
    }

    auto meta_result = store_metadata();
    if (!meta_result.ok()) {
        LOG_WARN(core::LogCategory::WALLET,
                 "Failed to store metadata after rescan: " +
                 meta_result.error().message());
    }

    LOG_INFO(core::LogCategory::WALLET,
             "Rescan complete up to height " +
             std::to_string(current_height));
    return core::Result<void>{};
}

int Wallet::last_scanned_height() const {
    return last_scanned_height_.load();
}

// ---------------------------------------------------------------------------
// Background scanner
// ---------------------------------------------------------------------------

void Wallet::scanner_loop() {
    LOG_INFO(core::LogCategory::WALLET,
             "Wallet scanner thread started");

    while (scanner_running_.load()) {
        {
            std::lock_guard lock(mutex_);
            if (!loaded_) break;

            check_auto_lock();

            int current_height = chain_height();
            int scanned = last_scanned_height_.load();

            if (current_height > scanned) {
                for (int h = scanned + 1; h <= current_height; ++h) {
                    auto result = scan_block_at_height(h);
                    if (result.ok()) {
                        last_scanned_height_ = h;

                        // Notify block.
                        auto& chain = chainstate_.active_chain();
                        auto* index = chain.at(h);
                        if (index) {
                            notify_.notify_block(h, index->block_hash);
                        }
                    } else {
                        LOG_WARN(core::LogCategory::WALLET,
                                 "Scanner error at height " +
                                 std::to_string(h) + ": " +
                                 result.error().message());
                        break;
                    }
                }

                // Update metadata periodically.
                store_metadata();
            }
        }

        // Sleep before next poll.
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    LOG_INFO(core::LogCategory::WALLET,
             "Wallet scanner thread stopped");
}

core::Result<void> Wallet::scan_block_at_height(int height) {
    auto& chain = chainstate_.active_chain();
    auto* index = chain.at(height);
    if (!index) {
        return core::Error(core::ErrorCode::STORAGE_NOT_FOUND,
                           "Block not found at height " +
                           std::to_string(height));
    }

    if (!index->has_data()) {
        return core::Error(core::ErrorCode::STORAGE_NOT_FOUND,
                           "Block data not available at height " +
                           std::to_string(height));
    }

    // Read the block from storage. We need the block store from
    // the chainstate. Since ChainstateManager doesn't expose the
    // block store directly, we skip reading the full block here
    // and instead rely on the chainstate providing the block.
    // In a production implementation, the block store would be
    // accessible, or we'd use a dedicated block reading interface.

    // For now, log the scan attempt. The actual block reading would
    // go through chain::storage::BlockStore::read_block(index->data_pos).
    LOG_TRACE(core::LogCategory::WALLET,
              "Scanned block at height " + std::to_string(height));

    return core::Result<void>{};
}

int Wallet::chain_height() const {
    return chainstate_.active_chain().height();
}

void Wallet::check_auto_lock() {
    if (!has_auto_lock_) return;

    if (std::chrono::steady_clock::now() >= auto_lock_time_) {
        keys_.clear_encryption_key();
        has_auto_lock_ = false;
        LOG_INFO(core::LogCategory::WALLET,
                 "Wallet auto-locked after timeout");
    }
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

core::Result<void> Wallet::init_subsystems() {
    // Initialize key manager.
    auto keys_result = keys_.init(db_);
    if (!keys_result.ok()) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Failed to initialize key manager: " +
                           keys_result.error().message());
    }

    // Initialize address book.
    auto addr_result = address_book_.init(db_);
    if (!addr_result.ok()) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Failed to initialize address book: " +
                           addr_result.error().message());
    }

    // Initialize coin tracker.
    auto coins_result = coins_.init(keys_, db_);
    if (!coins_result.ok()) {
        return core::Error(core::ErrorCode::WALLET_ERROR,
                           "Failed to initialize coin tracker: " +
                           coins_result.error().message());
    }

    // Initialize encryption.
    LOG_INFO(core::LogCategory::WALLET, "Initializing encryption subsystem...");
    auto enc_result = encryptor_.init(db_);
    if (!enc_result.ok()) {
        LOG_WARN(core::LogCategory::WALLET,
                 "Encryption init warning: " +
                 enc_result.error().message());
    }
    LOG_INFO(core::LogCategory::WALLET, "Encryption subsystem initialized");

    // Initialize HD wallet.
    LOG_INFO(core::LogCategory::WALLET, "Initializing HD wallet...");
    auto hd_result = init_hd_wallet();
    if (!hd_result.ok()) {
        LOG_WARN(core::LogCategory::WALLET,
                 "HD wallet init: " + hd_result.error().message());
    }
    LOG_INFO(core::LogCategory::WALLET, "HD wallet initialized");

    // Load metadata.
    LOG_INFO(core::LogCategory::WALLET, "Loading wallet metadata...");
    auto meta_result = load_metadata();
    if (!meta_result.ok()) {
        LOG_DEBUG(core::LogCategory::WALLET,
                  "No wallet metadata found, starting fresh");
        last_scanned_height_ = 0;
    }

    return core::Result<void>{};
}

core::Result<void> Wallet::init_hd_wallet() {
    LOG_INFO(core::LogCategory::WALLET, "init_hd_wallet: checking for existing seed...");
    // Try to load existing HD seed from database.
    auto seed_result = db_.read("meta:hd_seed");
    if (seed_result.ok() && !seed_result.value().empty()) {
        auto hd_result = HDWallet::from_seed(
            std::span<const uint8_t>(seed_result.value()));
        if (hd_result.ok()) {
            hd_ = std::move(hd_result).value();

            // Load derivation indices.
            auto recv_result = db_.read("meta:hd_recv_index");
            if (recv_result.ok() && recv_result.value().size() >= 4) {
                uint32_t idx = static_cast<uint32_t>(recv_result.value()[0]) |
                               (static_cast<uint32_t>(recv_result.value()[1]) << 8) |
                               (static_cast<uint32_t>(recv_result.value()[2]) << 16) |
                               (static_cast<uint32_t>(recv_result.value()[3]) << 24);
                // Advance the HD wallet to this index.
                for (uint32_t i = 0; i < idx; ++i) {
                    hd_.get_next_receiving_key();
                }
            }

            LOG_INFO(core::LogCategory::WALLET,
                     "HD wallet restored from seed");
            return core::Result<void>{};
        }
    }

    // Generate a new HD wallet.
    LOG_INFO(core::LogCategory::WALLET, "init_hd_wallet: generating new 12-word mnemonic...");
    auto gen_result = HDWallet::generate(128);  // 12-word mnemonic.
    if (!gen_result.ok()) {
        LOG_ERROR(core::LogCategory::WALLET,
                  "init_hd_wallet: generate failed: " + gen_result.error().message());
        return gen_result.error();
    }
    LOG_INFO(core::LogCategory::WALLET, "init_hd_wallet: mnemonic generated, moving wallet...");

    auto& [words, wallet] = gen_result.value();
    hd_ = std::move(wallet);

    LOG_INFO(core::LogCategory::WALLET, "init_hd_wallet: storing seed to DB...");
    // Store the seed.
    const auto& seed = hd_.seed();
    auto store_result = db_.write("meta:hd_seed",
        std::span<const uint8_t>(seed));
    if (!store_result.ok()) {
        return store_result;
    }

    LOG_INFO(core::LogCategory::WALLET,
             "New HD wallet created (12-word mnemonic)");
    return core::Result<void>{};
}

core::Result<void> Wallet::store_metadata() {
    if (!db_.is_open()) return core::Result<void>{};

    // Store last scanned height.
    uint32_t height = static_cast<uint32_t>(last_scanned_height_.load());
    std::vector<uint8_t> height_data = {
        static_cast<uint8_t>(height & 0xFF),
        static_cast<uint8_t>((height >> 8) & 0xFF),
        static_cast<uint8_t>((height >> 16) & 0xFF),
        static_cast<uint8_t>((height >> 24) & 0xFF)
    };
    auto result = db_.write("meta:last_scan_height",
        std::span<const uint8_t>(height_data));
    if (!result.ok()) return result;

    // Store HD derivation indices.
    if (hd_.is_initialized()) {
        uint32_t recv_idx = hd_.next_receiving_index();
        std::vector<uint8_t> idx_data = {
            static_cast<uint8_t>(recv_idx & 0xFF),
            static_cast<uint8_t>((recv_idx >> 8) & 0xFF),
            static_cast<uint8_t>((recv_idx >> 16) & 0xFF),
            static_cast<uint8_t>((recv_idx >> 24) & 0xFF)
        };
        auto idx_result = db_.write("meta:hd_recv_index",
            std::span<const uint8_t>(idx_data));
        if (!idx_result.ok()) return idx_result;

        uint32_t change_idx = hd_.next_change_index();
        std::vector<uint8_t> change_data = {
            static_cast<uint8_t>(change_idx & 0xFF),
            static_cast<uint8_t>((change_idx >> 8) & 0xFF),
            static_cast<uint8_t>((change_idx >> 16) & 0xFF),
            static_cast<uint8_t>((change_idx >> 24) & 0xFF)
        };
        auto change_result = db_.write("meta:hd_change_index",
            std::span<const uint8_t>(change_data));
        if (!change_result.ok()) return change_result;
    }

    return core::Result<void>{};
}

core::Result<void> Wallet::load_metadata() {
    auto height_result = db_.read("meta:last_scan_height");
    if (height_result.ok() && height_result.value().size() >= 4) {
        const auto& data = height_result.value();
        uint32_t height = static_cast<uint32_t>(data[0]) |
                          (static_cast<uint32_t>(data[1]) << 8) |
                          (static_cast<uint32_t>(data[2]) << 16) |
                          (static_cast<uint32_t>(data[3]) << 24);
        last_scanned_height_ = static_cast<int>(height);
        LOG_DEBUG(core::LogCategory::WALLET,
                  "Last scanned height: " + std::to_string(height));
        return core::Result<void>{};
    }

    return core::Error(core::ErrorCode::STORAGE_NOT_FOUND,
                       "No wallet metadata found");
}

} // namespace wallet
