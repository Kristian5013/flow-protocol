/**
 * Wallet Routes - /wallet/new, /wallet/send
 * Kristian Pilatovich 20091227 - First Real P2P
 */

#include "routes.h"
#include "api/handlers.h"
#include "chain/transaction.h"
#include <algorithm>

namespace ftc {
namespace api {
namespace routes {

void setupWalletRoutes(RouteContext& ctx) {
    auto* server = ctx.server;
    auto* chain = ctx.chain;
    auto* mempool = ctx.mempool;
    auto* utxo_set = ctx.utxo_set;

    // Generate new wallet keypair
    server->get("/wallet/new", [](const HttpRequest& req, HttpResponse& res) {
        crypto::PrivateKey privkey;
        crypto::PublicKey pubkey;

        if (!crypto::generateKeyPair(privkey, pubkey)) {
            res.error(HttpStatus::INTERNAL_ERROR, "Failed to generate keypair");
            return;
        }

        // Compute pubkey hash: keccak256(keccak256(pubkey))[0:20]
        auto hash1 = crypto::keccak256(pubkey.data(), pubkey.size());
        auto hash2 = crypto::keccak256(hash1.data(), hash1.size());

        // Create address from pubkey hash (mainnet)
        std::string address = crypto::bech32::addressFromPubKeyHash(hash2.data(), false);

        // Convert keys to hex
        std::string privkey_hex = crypto::Secp256k1::toHex(privkey);
        std::string pubkey_hex = crypto::Secp256k1::toHex(pubkey);

        JsonBuilder json;
        json.beginObject()
            .key("address").value(address)
            .key("private_key").value(privkey_hex)
            .key("public_key").value(pubkey_hex)
            .endObject();

        res.success(json.build());
    });

    // Send transaction (build, sign, broadcast)
    server->post("/wallet/send", [chain, mempool, utxo_set](const HttpRequest& req, HttpResponse& res) {
        if (!utxo_set || !mempool || !chain) {
            res.error(HttpStatus::SERVICE_UNAVAILABLE, "Node services not available");
            return;
        }

        JsonParser parser(req.body);
        if (!parser.parse() || !parser.isObject()) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid JSON body");
            return;
        }

        std::string privkey_hex = parser.getString("private_key");
        std::string to_address = parser.getString("to");
        int64_t amount_satoshis = parser.getInt("amount");
        int64_t fee_satoshis = parser.getInt("fee");

        if (privkey_hex.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "Missing 'private_key' field");
            return;
        }
        if (to_address.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "Missing 'to' field (recipient address)");
            return;
        }
        if (amount_satoshis <= 0) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid 'amount' (must be positive satoshis)");
            return;
        }

        // Default fee: 1000 satoshis (0.00001 FTC)
        if (fee_satoshis <= 0) {
            fee_satoshis = 1000;
        }

        // Parse private key
        auto privkey_opt = crypto::Secp256k1::privateKeyFromHex(privkey_hex);
        if (!privkey_opt) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid private key format");
            return;
        }
        crypto::PrivateKey privkey = *privkey_opt;

        // Derive public key
        crypto::PublicKey pubkey;
        if (!crypto::Secp256k1::instance().derivePublicKey(privkey, pubkey)) {
            res.error(HttpStatus::BAD_REQUEST, "Failed to derive public key");
            return;
        }

        // Compute pubkey hash: keccak256(keccak256(pubkey))[0:20]
        auto hash1 = crypto::keccak256(pubkey.data(), pubkey.size());
        auto hash2 = crypto::keccak256(hash1.data(), hash1.size());

        // Create from_address
        std::string from_address = crypto::bech32::addressFromPubKeyHash(hash2.data(), false);

        // Get UTXOs for sender
        std::vector<uint8_t> from_script = decodeAddress(from_address);
        if (from_script.empty()) {
            res.error(HttpStatus::INTERNAL_ERROR, "Failed to create sender script");
            return;
        }

        // Validate recipient address
        std::vector<uint8_t> to_script = decodeAddress(to_address);
        if (to_script.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "Invalid recipient address");
            return;
        }

        auto utxos = utxo_set->getUTXOs(from_script);
        if (utxos.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "No UTXOs available for sender address");
            return;
        }

        // Filter mature UTXOs (coinbase requires 100 confirmations)
        int32_t current_height = chain->getHeight();
        std::vector<chain::AddressUTXO> mature_utxos;
        for (const auto& utxo : utxos) {
            if (utxo.coinbase) {
                int32_t confirmations = current_height - utxo.height;
                if (confirmations < 100) {
                    continue;  // Skip immature coinbase
                }
            }
            mature_utxos.push_back(utxo);
        }

        // Sort by height (oldest first for coin age)
        std::sort(mature_utxos.begin(), mature_utxos.end(),
            [](const chain::AddressUTXO& a, const chain::AddressUTXO& b) {
                return a.height < b.height;
            });

        if (mature_utxos.empty()) {
            res.error(HttpStatus::BAD_REQUEST, "No mature UTXOs (coinbase requires 100 confirmations)");
            return;
        }

        // Calculate total available
        uint64_t total_available = 0;
        for (const auto& utxo : mature_utxos) {
            total_available += utxo.value;
        }

        uint64_t amount = static_cast<uint64_t>(amount_satoshis);
        uint64_t fee = static_cast<uint64_t>(fee_satoshis);

        if (total_available < amount + fee) {
            res.error(HttpStatus::BAD_REQUEST, "Insufficient funds. Available: " +
                std::to_string(total_available) + " satoshis");
            return;
        }

        // Select UTXOs (oldest first)
        std::vector<chain::AddressUTXO> selected_utxos;
        uint64_t selected_amount = 0;
        for (const auto& utxo : mature_utxos) {
            selected_utxos.push_back(utxo);
            selected_amount += utxo.value;
            if (selected_amount >= amount + fee) break;
        }

        uint64_t change = selected_amount - amount - fee;

        // Build transaction
        chain::Transaction tx;
        tx.version = 1;
        tx.locktime = 0;

        // Add inputs
        for (const auto& utxo : selected_utxos) {
            chain::TxInput input;
            input.prevout = utxo.outpoint;
            input.sequence = 0xFFFFFFFF;
            tx.inputs.push_back(input);
        }

        // Add output: recipient
        chain::TxOutput out_recipient;
        out_recipient.value = amount;
        out_recipient.script_pubkey = to_script;
        tx.outputs.push_back(out_recipient);

        // Add output: change (if any)
        if (change > 0) {
            chain::TxOutput out_change;
            out_change.value = change;
            out_change.script_pubkey = from_script;
            tx.outputs.push_back(out_change);
        }

        // Sign each input
        auto& secp = crypto::Secp256k1::instance();
        for (size_t i = 0; i < tx.inputs.size(); i++) {
            auto sighash = tx.getSignatureHash(i, from_script, 1);  // SIGHASH_ALL

            crypto::Signature sig;
            if (!secp.sign(sighash.data(), privkey, sig)) {
                res.error(HttpStatus::INTERNAL_ERROR, "Failed to sign input " + std::to_string(i));
                return;
            }

            auto der = secp.signatureToDER(sig);
            der.push_back(0x01);  // SIGHASH_ALL

            // Build scriptSig: <sig> <pubkey>
            std::vector<uint8_t> script_sig;
            script_sig.push_back(static_cast<uint8_t>(der.size()));
            script_sig.insert(script_sig.end(), der.begin(), der.end());
            script_sig.push_back(static_cast<uint8_t>(pubkey.size()));
            script_sig.insert(script_sig.end(), pubkey.begin(), pubkey.end());

            tx.inputs[i].script_sig = script_sig;
        }

        // Add to mempool
        auto result = mempool->addTransaction(tx, current_height);

        if (result == chain::MempoolReject::VALID) {
            auto txid = tx.getTxId();
            JsonBuilder json;
            json.beginObject()
                .key("txid").value(hashToHex(txid))
                .key("from").value(from_address)
                .key("to").value(to_address)
                .key("amount").value(amount)
                .key("fee").value(fee)
                .key("change").value(change)
                .key("inputs_used").value(static_cast<uint64_t>(selected_utxos.size()))
                .endObject();
            res.success(json.build());
        } else {
            std::string reason;
            switch (result) {
                case chain::MempoolReject::SCRIPT_ERROR: reason = "Script verification failed"; break;
                case chain::MempoolReject::DOUBLE_SPEND: reason = "Double spend detected"; break;
                case chain::MempoolReject::INSUFFICIENT_FEE: reason = "Insufficient fee"; break;
                case chain::MempoolReject::MISSING_INPUTS: reason = "Missing inputs"; break;
                case chain::MempoolReject::IMMATURE_COINBASE: reason = "Immature coinbase"; break;
                case chain::MempoolReject::NEGATIVE_FEE: reason = "Outputs exceed inputs"; break;
                default: reason = "Transaction rejected"; break;
            }
            res.error(HttpStatus::BAD_REQUEST, reason);
        }
    });
}

} // namespace routes
} // namespace api
} // namespace ftc
