// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// ftc-wallet — standalone FTC wallet CLI
//
// Manages private keys locally and connects to an FTC node via JSON-RPC
// for UTXO queries and transaction broadcasting.
//
// Usage:
//   ftc-wallet [options] <command> [args...]
//
// Commands:
//   newaddress          Generate a new address
//   importkey <WIF>     Import a private key (WIF format)
//   addresses           List all wallet addresses
//   balance             Show total balance
//   listunspent         List unspent outputs
//   send <addr> <amt>   Send FTC to an address
//
// Options:
//   --rpc-host=HOST     RPC server host (default: 127.0.0.1)
//   --rpc-port=PORT     RPC server port (default: 9332)
//   --wallet=FILE       Wallet key file (default: wallet.keys)
// ---------------------------------------------------------------------------

#include "core/base58.h"
#include "core/hex.h"
#include "core/stream.h"
#include "core/types.h"
#include "crypto/keccak.h"
#include "crypto/secp256k1.h"
#include "primitives/address.h"
#include "primitives/amount.h"
#include "primitives/outpoint.h"
#include "primitives/script/script.h"
#include "primitives/script/sign.h"
#include "primitives/transaction.h"
#include "primitives/txin.h"
#include "primitives/txout.h"
#include "rpc/request.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Platform-specific socket includes
// ---------------------------------------------------------------------------
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    using sock_t = SOCKET;
    static constexpr sock_t BAD_SOCK = INVALID_SOCKET;
    inline void close_sock(sock_t s) { closesocket(s); }
#else
    #include <netdb.h>
    #include <sys/socket.h>
    #include <unistd.h>
    using sock_t = int;
    static constexpr sock_t BAD_SOCK = -1;
    inline void close_sock(sock_t s) { ::close(s); }
#endif

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
static constexpr uint8_t WIF_VERSION = 0x80;
static constexpr int64_t MIN_FEE = 1000;           // 0.00001000 FTC
static constexpr int64_t COIN = 100'000'000;        // 1 FTC in satoshis
static constexpr int COINBASE_MATURITY = 100;

// ---------------------------------------------------------------------------
// Wallet key entry
// ---------------------------------------------------------------------------
struct WalletKey {
    std::array<uint8_t, 32> secret;
    std::array<uint8_t, 33> pubkey;
    std::string address;   // P2PKH address string
    std::string wif;       // WIF-encoded private key
};

// ---------------------------------------------------------------------------
// UTXO entry from scantxoutset
// ---------------------------------------------------------------------------
struct Utxo {
    std::string txid;
    int64_t vout = 0;
    int64_t amount = 0;       // satoshis
    int64_t height = 0;
    bool coinbase = false;
    std::string script_pubkey; // hex
};

// ---------------------------------------------------------------------------
// HTTP POST (minimal client, same as miner)
// ---------------------------------------------------------------------------
static std::string http_post(const std::string& host, uint16_t port,
                             const std::string& body) {
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result) != 0) {
        return {};
    }

    sock_t sock = socket(result->ai_family, result->ai_socktype,
                         result->ai_protocol);
    if (sock == BAD_SOCK) {
        freeaddrinfo(result);
        return {};
    }

    if (connect(sock, result->ai_addr,
                static_cast<int>(result->ai_addrlen)) != 0) {
        close_sock(sock);
        freeaddrinfo(result);
        return {};
    }
    freeaddrinfo(result);

    std::string request =
        "POST / HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Connection: close\r\n"
        "\r\n" + body;

    int total_sent = 0;
    int req_len = static_cast<int>(request.size());
    while (total_sent < req_len) {
        int n = send(sock, request.c_str() + total_sent,
                     req_len - total_sent, 0);
        if (n <= 0) { close_sock(sock); return {}; }
        total_sent += n;
    }

    std::string response;
    char buf[4096];
    for (;;) {
        int n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        response.append(buf, n);
    }
    close_sock(sock);

    auto pos = response.find("\r\n\r\n");
    if (pos != std::string::npos) {
        return response.substr(pos + 4);
    }
    return response;
}

// ---------------------------------------------------------------------------
// JSON-RPC call
// ---------------------------------------------------------------------------
static std::string rpc_call(const std::string& host, uint16_t port,
                            const std::string& method,
                            const std::string& params_json) {
    std::string body = "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"" +
                       method + "\",\"params\":" + params_json + "}";
    return http_post(host, port, body);
}

// ---------------------------------------------------------------------------
// Parse satoshi amount from string like "50.00000000"
// ---------------------------------------------------------------------------
static int64_t parse_amount_str(const std::string& s) {
    // Find decimal point
    auto dot = s.find('.');
    if (dot == std::string::npos) {
        return std::stoll(s) * COIN;
    }
    std::string whole = s.substr(0, dot);
    std::string frac = s.substr(dot + 1);
    // Pad or truncate to 8 decimal places
    while (frac.size() < 8) frac += '0';
    if (frac.size() > 8) frac = frac.substr(0, 8);
    return std::stoll(whole) * COIN + std::stoll(frac);
}

// ---------------------------------------------------------------------------
// Format satoshis as FTC string
// ---------------------------------------------------------------------------
static std::string format_ftc(int64_t satoshis) {
    bool neg = satoshis < 0;
    if (neg) satoshis = -satoshis;
    int64_t whole = satoshis / COIN;
    int64_t frac = satoshis % COIN;
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s%lld.%08lld",
                  neg ? "-" : "",
                  static_cast<long long>(whole),
                  static_cast<long long>(frac));
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// WIF encoding / decoding
// ---------------------------------------------------------------------------
static std::string wif_encode(const std::array<uint8_t, 32>& secret) {
    std::vector<uint8_t> payload(secret.begin(), secret.end());
    payload.push_back(0x01); // compressed flag
    return core::encode_with_version(WIF_VERSION,
        std::span<const uint8_t>(payload.data(), payload.size()));
}

static bool wif_decode(const std::string& wif,
                       std::array<uint8_t, 32>& secret_out) {
    auto decoded = core::decode_with_version(wif);
    if (!decoded) return false;
    auto& [version, payload] = *decoded;
    if (version != WIF_VERSION) return false;
    if (payload.size() != 32 && payload.size() != 33) return false;
    // 33 bytes = 32-byte secret + 0x01 compressed flag
    std::copy_n(payload.begin(), 32, secret_out.begin());
    return true;
}

// ---------------------------------------------------------------------------
// Derive WalletKey from secret bytes
// ---------------------------------------------------------------------------
static WalletKey derive_key(const std::array<uint8_t, 32>& secret) {
    WalletKey wk;
    wk.secret = secret;

    auto key_result = crypto::ECKey::from_secret(
        std::span<const uint8_t, 32>(secret.data(), 32));
    if (!key_result.ok()) {
        std::cerr << "Error: invalid private key" << std::endl;
        std::exit(1);
    }
    auto key = std::move(key_result).value();

    wk.pubkey = key.pubkey_compressed();
    auto addr = primitives::Address::from_pubkey(
        std::span<const uint8_t>(wk.pubkey.data(), wk.pubkey.size()),
        primitives::AddressType::P2PKH);
    wk.address = addr.to_string();
    wk.wif = wif_encode(secret);
    return wk;
}

// ---------------------------------------------------------------------------
// Load / save wallet
// ---------------------------------------------------------------------------
static std::vector<WalletKey> load_wallet(const std::string& path) {
    std::vector<WalletKey> keys;
    std::ifstream in(path);
    if (!in.is_open()) return keys;

    std::string line;
    while (std::getline(in, line)) {
        // Trim whitespace
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'
               || line.back() == ' '))
            line.pop_back();
        if (line.empty() || line[0] == '#') continue;

        std::array<uint8_t, 32> secret;
        if (wif_decode(line, secret)) {
            keys.push_back(derive_key(secret));
        } else {
            std::cerr << "Warning: skipping invalid key line" << std::endl;
        }
    }
    return keys;
}

static void save_key(const std::string& path, const std::string& wif) {
    std::ofstream out(path, std::ios::app);
    if (!out.is_open()) {
        std::cerr << "Error: cannot open wallet file: " << path << std::endl;
        std::exit(1);
    }
    out << wif << "\n";
}

// ---------------------------------------------------------------------------
// Command-line argument parsing
// ---------------------------------------------------------------------------
static std::string get_arg(int argc, char* argv[], const std::string& name,
                           const std::string& default_val = "") {
    std::string prefix = "--" + name + "=";
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg.rfind(prefix, 0) == 0) {
            return arg.substr(prefix.size());
        }
    }
    return default_val;
}

static std::string get_command(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg[0] != '-') return arg;
    }
    return "";
}

static std::string get_positional(int argc, char* argv[], int pos) {
    int count = 0;
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg[0] != '-') {
            if (count == pos) return arg;
            ++count;
        }
    }
    return "";
}

// ---------------------------------------------------------------------------
// JSON escape helper
// ---------------------------------------------------------------------------
static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out += '"';
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else out += c;
    }
    out += '"';
    return out;
}

// ===========================================================================
// Commands
// ===========================================================================

// ---------------------------------------------------------------------------
// newaddress
// ---------------------------------------------------------------------------
static void cmd_newaddress(const std::string& wallet_file) {
    auto key = crypto::ECKey::generate();
    auto secret = key.secret();
    auto wk = derive_key(secret);

    save_key(wallet_file, wk.wif);

    std::cout << "New address:  " << wk.address << std::endl;
    std::cout << "Private key:  " << wk.wif << std::endl;
    std::cout << "Saved to:     " << wallet_file << std::endl;
}

// ---------------------------------------------------------------------------
// importkey
// ---------------------------------------------------------------------------
static void cmd_importkey(const std::string& wallet_file,
                          const std::string& wif) {
    std::array<uint8_t, 32> secret;
    if (!wif_decode(wif, secret)) {
        std::cerr << "Error: invalid WIF key" << std::endl;
        std::exit(1);
    }

    auto wk = derive_key(secret);
    save_key(wallet_file, wk.wif);

    std::cout << "Imported:     " << wk.address << std::endl;
    std::cout << "Saved to:     " << wallet_file << std::endl;
}

// ---------------------------------------------------------------------------
// addresses
// ---------------------------------------------------------------------------
static void cmd_addresses(const std::string& wallet_file) {
    auto keys = load_wallet(wallet_file);
    if (keys.empty()) {
        std::cout << "No keys in wallet. Use 'newaddress' to create one."
                  << std::endl;
        return;
    }

    std::cout << "Wallet addresses (" << keys.size() << "):" << std::endl;
    for (size_t i = 0; i < keys.size(); ++i) {
        std::cout << "  [" << i << "] " << keys[i].address << std::endl;
    }
}

// ---------------------------------------------------------------------------
// Fetch UTXOs for all wallet addresses
// ---------------------------------------------------------------------------
static std::vector<Utxo> fetch_utxos(
    const std::string& host, uint16_t port,
    const std::vector<WalletKey>& keys) {

    if (keys.empty()) return {};

    // Build scan descriptors JSON
    std::string descriptors = "[";
    for (size_t i = 0; i < keys.size(); ++i) {
        if (i > 0) descriptors += ",";
        descriptors += json_escape(keys[i].address);
    }
    descriptors += "]";

    std::string resp = rpc_call(host, port, "scantxoutset",
                                "[\"start\"," + descriptors + "]");
    if (resp.empty()) {
        std::cerr << "Error: cannot connect to node at "
                  << host << ":" << port << std::endl;
        return {};
    }

    rpc::JsonValue json;
    try {
        json = rpc::parse_json(resp);
    } catch (const std::exception& e) {
        std::cerr << "Error parsing response: " << e.what() << std::endl;
        return {};
    }

    if (!json["result"].is_object()) {
        std::cerr << "RPC error: "
                  << rpc::json_serialize(json["error"]) << std::endl;
        return {};
    }

    // Get current blockchain height for maturity check
    std::string height_resp = rpc_call(host, port, "getblockcount", "[]");
    int64_t chain_height = 0;
    if (!height_resp.empty()) {
        try {
            auto hj = rpc::parse_json(height_resp);
            if (hj["result"].is_int()) {
                chain_height = hj["result"].get_int();
            }
        } catch (...) {}
    }

    auto& result = json["result"];
    std::vector<Utxo> utxos;

    if (result["unspents"].is_array()) {
        for (const auto& u : result["unspents"].get_array()) {
            Utxo utxo;
            utxo.txid = u["txid"].get_string();
            utxo.vout = u["vout"].get_int();
            utxo.amount = parse_amount_str(u["amount"].get_string());
            utxo.height = u["height"].get_int();
            utxo.coinbase = u["coinbase"].is_bool()
                            ? u["coinbase"].get_bool() : false;
            utxo.script_pubkey = u["scriptPubKey"].get_string();

            // Skip immature coinbase outputs
            if (utxo.coinbase &&
                (chain_height - utxo.height) < COINBASE_MATURITY) {
                continue;
            }

            utxos.push_back(std::move(utxo));
        }
    }

    return utxos;
}

// ---------------------------------------------------------------------------
// balance
// ---------------------------------------------------------------------------
static void cmd_balance(const std::string& wallet_file,
                        const std::string& host, uint16_t port) {
    auto keys = load_wallet(wallet_file);
    if (keys.empty()) {
        std::cout << "No keys in wallet. Use 'newaddress' to create one."
                  << std::endl;
        return;
    }

    auto utxos = fetch_utxos(host, port, keys);

    int64_t total = 0;
    for (const auto& u : utxos) {
        total += u.amount;
    }

    std::cout << "Balance: " << format_ftc(total) << " FTC"
              << "  (" << utxos.size() << " UTXOs)" << std::endl;
}

// ---------------------------------------------------------------------------
// listunspent
// ---------------------------------------------------------------------------
static void cmd_listunspent(const std::string& wallet_file,
                            const std::string& host, uint16_t port) {
    auto keys = load_wallet(wallet_file);
    if (keys.empty()) {
        std::cout << "No keys in wallet." << std::endl;
        return;
    }

    auto utxos = fetch_utxos(host, port, keys);
    if (utxos.empty()) {
        std::cout << "No unspent outputs." << std::endl;
        return;
    }

    std::cout << "Unspent outputs (" << utxos.size() << "):" << std::endl;
    int64_t total = 0;
    for (const auto& u : utxos) {
        std::cout << "  " << u.txid << ":" << u.vout
                  << "  " << format_ftc(u.amount) << " FTC"
                  << "  height=" << u.height
                  << (u.coinbase ? " [coinbase]" : "")
                  << std::endl;
        total += u.amount;
    }
    std::cout << "Total: " << format_ftc(total) << " FTC" << std::endl;
}

// ---------------------------------------------------------------------------
// send
// ---------------------------------------------------------------------------
static void cmd_send(const std::string& wallet_file,
                     const std::string& host, uint16_t port,
                     const std::string& dest_addr_str,
                     const std::string& amount_str) {
    // Parse amount
    int64_t send_amount = parse_amount_str(amount_str);
    if (send_amount <= 0) {
        std::cerr << "Error: invalid amount" << std::endl;
        std::exit(1);
    }

    // Validate destination address
    auto dest_result = primitives::Address::from_string(dest_addr_str);
    if (!dest_result.ok()) {
        std::cerr << "Error: invalid destination address: "
                  << dest_addr_str << std::endl;
        std::exit(1);
    }
    auto dest_addr = dest_result.value();
    auto dest_script = dest_addr.to_script();

    // Load wallet
    auto keys = load_wallet(wallet_file);
    if (keys.empty()) {
        std::cerr << "Error: no keys in wallet" << std::endl;
        std::exit(1);
    }

    // Fetch UTXOs
    auto utxos = fetch_utxos(host, port, keys);
    if (utxos.empty()) {
        std::cerr << "Error: no spendable UTXOs" << std::endl;
        std::exit(1);
    }

    // Select UTXOs (simple greedy: pick until we have enough)
    int64_t fee = MIN_FEE;
    int64_t needed = send_amount + fee;
    int64_t selected_total = 0;
    std::vector<Utxo> selected;

    for (const auto& u : utxos) {
        selected.push_back(u);
        selected_total += u.amount;
        if (selected_total >= needed) break;
    }

    if (selected_total < needed) {
        std::cerr << "Error: insufficient funds. Have "
                  << format_ftc(selected_total) << " FTC, need "
                  << format_ftc(needed) << " FTC (incl. fee)" << std::endl;
        std::exit(1);
    }

    int64_t change = selected_total - send_amount - fee;

    // Build signing provider
    primitives::script::SimpleSigningProvider provider;
    for (const auto& wk : keys) {
        auto key_result = crypto::ECKey::from_secret(
            std::span<const uint8_t, 32>(wk.secret.data(), 32));
        if (key_result.ok()) {
            provider.add_key(key_result.value());
        }
    }

    // Build inputs
    std::vector<primitives::TxInput> vin;
    for (const auto& u : selected) {
        primitives::TxInput input;
        input.prevout = primitives::OutPoint(
            core::uint256::from_hex(u.txid),
            static_cast<uint32_t>(u.vout));
        input.sequence = 0xFFFFFFFF;
        vin.push_back(std::move(input));
    }

    // Build outputs
    std::vector<primitives::TxOutput> vout;

    // Destination output
    primitives::TxOutput dest_out;
    dest_out.amount = primitives::Amount(send_amount);
    dest_out.script_pubkey = dest_script.data();
    vout.push_back(std::move(dest_out));

    // Change output (back to first wallet address)
    if (change > 0) {
        auto change_addr = primitives::Address::from_string(keys[0].address);
        if (change_addr.ok()) {
            primitives::TxOutput change_out;
            change_out.amount = primitives::Amount(change);
            change_out.script_pubkey = change_addr.value().to_script().data();
            vout.push_back(std::move(change_out));
        }
    }

    // Create transaction
    primitives::Transaction tx(std::move(vin), std::move(vout), 2, 0);

    // Sign each input
    for (size_t i = 0; i < selected.size(); ++i) {
        auto script_hex = selected[i].script_pubkey;
        auto script_bytes_opt = core::from_hex(script_hex);
        if (!script_bytes_opt) {
            std::cerr << "Error: invalid scriptPubKey hex for input "
                      << i << std::endl;
            std::exit(1);
        }
        primitives::script::Script prev_script(
            std::move(*script_bytes_opt));

        bool signed_ok = primitives::script::sign_input(
            provider, tx, i, prev_script,
            primitives::Amount(selected[i].amount));

        if (!signed_ok) {
            std::cerr << "Error: failed to sign input " << i << std::endl;
            std::exit(1);
        }
    }

    // Serialize
    auto tx_bytes = tx.serialize();
    std::string tx_hex = core::to_hex(
        std::span<const uint8_t>(tx_bytes.data(), tx_bytes.size()));

    std::cout << "Transaction built:" << std::endl;
    std::cout << "  TXID:    " << tx.txid().to_hex() << std::endl;
    std::cout << "  Size:    " << tx_bytes.size() << " bytes" << std::endl;
    std::cout << "  Inputs:  " << selected.size() << std::endl;
    std::cout << "  Amount:  " << format_ftc(send_amount) << " FTC"
              << std::endl;
    std::cout << "  Fee:     " << format_ftc(fee) << " FTC" << std::endl;
    if (change > 0) {
        std::cout << "  Change:  " << format_ftc(change) << " FTC"
                  << std::endl;
    }
    std::cout << std::endl;

    // Broadcast via sendrawtransaction
    std::cout << "Broadcasting..." << std::flush;

    std::string resp = rpc_call(host, port, "sendrawtransaction",
                                "[" + json_escape(tx_hex) + "]");
    if (resp.empty()) {
        std::cerr << "\nError: cannot connect to node" << std::endl;
        std::exit(1);
    }

    rpc::JsonValue json;
    try {
        json = rpc::parse_json(resp);
    } catch (const std::exception& e) {
        std::cerr << "\nError parsing response: " << e.what() << std::endl;
        std::exit(1);
    }

    if (json["result"].is_string()) {
        std::cout << " OK" << std::endl;
        std::cout << "TXID: " << json["result"].get_string() << std::endl;
    } else {
        std::cerr << "\nTransaction rejected: "
                  << rpc::json_serialize(json["error"]) << std::endl;
        std::exit(1);
    }
}

// ===========================================================================
// Main
// ===========================================================================
int main(int argc, char* argv[]) {
#ifdef _WIN32
    {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
#endif

    if (argc < 2 || get_command(argc, argv).empty()) {
        std::cout << "FTC Wallet v1.0\n\n"
                  << "Usage: ftc-wallet [options] <command> [args...]\n\n"
                  << "Commands:\n"
                  << "  newaddress          Generate a new address\n"
                  << "  importkey <WIF>     Import a private key\n"
                  << "  addresses           List all wallet addresses\n"
                  << "  balance             Show total balance\n"
                  << "  listunspent         List unspent outputs\n"
                  << "  send <addr> <amt>   Send FTC to an address\n\n"
                  << "Options:\n"
                  << "  --rpc-host=HOST     Node RPC host (default: 127.0.0.1)\n"
                  << "  --rpc-port=PORT     Node RPC port (default: 9332)\n"
                  << "  --wallet=FILE       Wallet file (default: wallet.keys)\n\n"
                  << "Examples:\n"
                  << "  ftc-wallet newaddress\n"
                  << "  ftc-wallet --rpc-host=3.35.208.160 balance\n"
                  << "  ftc-wallet --rpc-host=3.35.208.160 send 1A73... 0.001\n";
        return 0;
    }

    std::string rpc_host    = get_arg(argc, argv, "rpc-host", "127.0.0.1");
    uint16_t rpc_port       = static_cast<uint16_t>(
        std::atoi(get_arg(argc, argv, "rpc-port", "9332").c_str()));
    std::string wallet_file = get_arg(argc, argv, "wallet", "wallet.keys");

    std::string command = get_command(argc, argv);

    if (command == "newaddress") {
        cmd_newaddress(wallet_file);
    }
    else if (command == "importkey") {
        std::string wif = get_positional(argc, argv, 1);
        if (wif.empty()) {
            std::cerr << "Usage: ftc-wallet importkey <WIF>" << std::endl;
            return 1;
        }
        cmd_importkey(wallet_file, wif);
    }
    else if (command == "addresses") {
        cmd_addresses(wallet_file);
    }
    else if (command == "balance") {
        cmd_balance(wallet_file, rpc_host, rpc_port);
    }
    else if (command == "listunspent") {
        cmd_listunspent(wallet_file, rpc_host, rpc_port);
    }
    else if (command == "send") {
        std::string dest = get_positional(argc, argv, 1);
        std::string amt  = get_positional(argc, argv, 2);
        if (dest.empty() || amt.empty()) {
            std::cerr << "Usage: ftc-wallet send <address> <amount>"
                      << std::endl;
            return 1;
        }
        cmd_send(wallet_file, rpc_host, rpc_port, dest, amt);
    }
    else {
        std::cerr << "Unknown command: " << command << std::endl;
        std::cerr << "Run 'ftc-wallet' without arguments for help."
                  << std::endl;
        return 1;
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
