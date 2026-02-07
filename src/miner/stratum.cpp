// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner/stratum.h"

#include "core/hex.h"
#include "core/logging.h"
#include "crypto/keccak.h"
#include "miner/difficulty.h"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace miner {

// ---------------------------------------------------------------------------
// Minimal JSON helpers (avoid pulling in a full JSON library)
// ---------------------------------------------------------------------------
namespace {

/// Extract a string value for a key from a simple JSON object.
/// This is a basic parser for the Stratum protocol's simple JSON messages.
std::string json_get_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return {};

    // Find the colon after the key.
    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return {};

    // Skip whitespace.
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) {
        ++pos;
    }

    if (pos >= json.size()) return {};

    // If the value is a string (starts with "), extract it.
    if (json[pos] == '"') {
        ++pos;
        auto end = json.find('"', pos);
        if (end == std::string::npos) return {};
        return json.substr(pos, end - pos);
    }

    // Otherwise, extract until the next comma, }, or end.
    auto end = json.find_first_of(",]}", pos);
    if (end == std::string::npos) end = json.size();
    std::string val = json.substr(pos, end - pos);

    // Trim whitespace.
    while (!val.empty() && (val.back() == ' ' || val.back() == '\t' ||
                             val.back() == '\n' || val.back() == '\r')) {
        val.pop_back();
    }

    return val;
}

/// Extract an integer value for a key.
uint64_t json_get_uint(const std::string& json, const std::string& key) {
    std::string val = json_get_string(json, key);
    if (val.empty()) return 0;
    // Remove "null" checks.
    if (val == "null") return 0;
    try {
        return std::stoull(val);
    } catch (...) {
        return 0;
    }
}

/// Extract the method name from a Stratum JSON-RPC request.
std::string json_get_method(const std::string& json) {
    return json_get_string(json, "method");
}

/// Extract the "params" array as a raw string for further parsing.
std::string json_get_params(const std::string& json) {
    auto pos = json.find("\"params\"");
    if (pos == std::string::npos) return "[]";

    pos = json.find('[', pos);
    if (pos == std::string::npos) return "[]";

    int depth = 0;
    size_t start = pos;
    for (size_t i = pos; i < json.size(); ++i) {
        if (json[i] == '[') ++depth;
        else if (json[i] == ']') --depth;
        if (depth == 0) {
            return json.substr(start, i - start + 1);
        }
    }
    return "[]";
}

/// Parse a params array to extract string elements.
/// Simple parser for ["str1", "str2", ...] arrays.
std::vector<std::string> parse_string_array(const std::string& params) {
    std::vector<std::string> result;
    size_t pos = 0;

    while (pos < params.size()) {
        auto quote_start = params.find('"', pos);
        if (quote_start == std::string::npos) break;

        auto quote_end = params.find('"', quote_start + 1);
        if (quote_end == std::string::npos) break;

        result.push_back(params.substr(quote_start + 1,
                                        quote_end - quote_start - 1));
        pos = quote_end + 1;
    }

    return result;
}

/// Build a JSON-RPC response.
std::string json_response(uint64_t id, const std::string& result_val,
                          const std::string& error_val = "null") {
    return "{\"id\":" + std::to_string(id) +
           ",\"result\":" + result_val +
           ",\"error\":" + error_val + "}\n";
}

/// Build a JSON-RPC notification (no id).
std::string json_notification(const std::string& method,
                               const std::string& params) {
    return "{\"id\":null,\"method\":\"" + method +
           "\",\"params\":" + params + "}\n";
}

/// Convert bytes to hex string.
std::string bytes_to_hex(const uint8_t* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result.push_back(hex_chars[(data[i] >> 4) & 0x0F]);
        result.push_back(hex_chars[data[i] & 0x0F]);
    }
    return result;
}

/// Convert hex string to bytes.
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        uint8_t high = 0, low = 0;
        if (hex[i] >= '0' && hex[i] <= '9') high = hex[i] - '0';
        else if (hex[i] >= 'a' && hex[i] <= 'f') high = hex[i] - 'a' + 10;
        else if (hex[i] >= 'A' && hex[i] <= 'F') high = hex[i] - 'A' + 10;

        if (hex[i+1] >= '0' && hex[i+1] <= '9') low = hex[i+1] - '0';
        else if (hex[i+1] >= 'a' && hex[i+1] <= 'f') low = hex[i+1] - 'a' + 10;
        else if (hex[i+1] >= 'A' && hex[i+1] <= 'F') low = hex[i+1] - 'A' + 10;

        result.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return result;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// StratumServer construction / destruction
// ---------------------------------------------------------------------------

StratumServer::StratumServer() = default;

StratumServer::~StratumServer() {
    if (running_.load(std::memory_order_relaxed)) {
        stop();
    }
}

// ---------------------------------------------------------------------------
// start
// ---------------------------------------------------------------------------

core::Result<void> StratumServer::start(uint16_t port) {
    if (running_.load(std::memory_order_relaxed)) {
        return core::Error(core::ErrorCode::INTERNAL_ERROR,
            "Stratum server is already running");
    }

    // Bind and listen on the specified port.
    auto bind_result = listen_socket_.bind_listen("0.0.0.0", port);
    if (!bind_result.ok()) {
        return core::Error(core::ErrorCode::NETWORK_ERROR,
            "Failed to bind Stratum server on port " +
            std::to_string(port) + ": " + bind_result.error().message());
    }

    stopping_.store(false, std::memory_order_relaxed);
    running_.store(true, std::memory_order_relaxed);

    LOG_INFO(core::LogCategory::MINING,
        "Stratum server started on port " + std::to_string(port));

    // Start the accept thread.
    accept_thread_ = std::thread([this] { accept_loop(); });

    return core::Result<void>{};
}

// ---------------------------------------------------------------------------
// stop
// ---------------------------------------------------------------------------

void StratumServer::stop() {
    if (!running_.load(std::memory_order_relaxed)) {
        return;
    }

    LOG_INFO(core::LogCategory::MINING, "Stopping Stratum server");

    stopping_.store(true, std::memory_order_relaxed);
    running_.store(false, std::memory_order_relaxed);

    // Close the listening socket to unblock accept().
    listen_socket_.close();

    // Close all client sockets.
    {
        std::lock_guard lock(clients_mutex_);
        for (auto& [id, client] : clients_) {
            client->socket.close();
        }
    }

    // Join the accept thread.
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }

    // Join all client handler threads.
    for (auto& t : client_threads_) {
        if (t.joinable()) {
            t.join();
        }
    }
    client_threads_.clear();

    // Clear all clients.
    {
        std::lock_guard lock(clients_mutex_);
        clients_.clear();
    }

    LOG_INFO(core::LogCategory::MINING, "Stratum server stopped");
}

// ---------------------------------------------------------------------------
// accept_loop
// ---------------------------------------------------------------------------

void StratumServer::accept_loop() {
    while (!stopping_.load(std::memory_order_relaxed)) {
        auto accept_result = listen_socket_.accept();
        if (!accept_result.ok()) {
            if (stopping_.load(std::memory_order_relaxed)) {
                break;
            }
            LOG_WARN(core::LogCategory::MINING,
                "Stratum accept error: " + accept_result.error().message());
            continue;
        }

        auto client_socket = std::move(accept_result.value());

        // Check client limit.
        {
            std::lock_guard lock(clients_mutex_);
            if (clients_.size() >= MAX_STRATUM_CLIENTS) {
                LOG_WARN(core::LogCategory::MINING,
                    "Stratum server at max clients, rejecting connection");
                client_socket.close();
                continue;
            }
        }

        // Create a new client.
        uint64_t client_id = next_client_id_.fetch_add(1,
            std::memory_order_relaxed);

        auto client = std::make_unique<StratumClient>();
        client->id = client_id;
        client->remote_addr = client_socket.remote_address();
        client->difficulty = default_difficulty_.load(
            std::memory_order_relaxed);
        client->socket = std::move(client_socket);

        // Set socket options.
        client->socket.set_nodelay(true);
        client->socket.set_recv_timeout(STRATUM_READ_TIMEOUT_MS);

        LOG_INFO(core::LogCategory::MINING,
            "Stratum client " + std::to_string(client_id) +
            " connected from " + client->remote_addr);

        {
            std::lock_guard lock(clients_mutex_);
            clients_[client_id] = std::move(client);
        }

        // Spawn a handler thread for this client.
        client_threads_.emplace_back(
            [this, client_id] { client_handler(client_id); });
    }
}

// ---------------------------------------------------------------------------
// client_handler
// ---------------------------------------------------------------------------

void StratumServer::client_handler(uint64_t client_id) {
    std::array<uint8_t, 4096> read_buf{};

    while (!stopping_.load(std::memory_order_relaxed)) {
        // Read data from the client.
        net::Socket* sock = nullptr;

        {
            std::lock_guard lock(clients_mutex_);
            auto it = clients_.find(client_id);
            if (it == clients_.end()) break;
            sock = &it->second->socket;
        }

        auto recv_result = sock->recv(
            std::span<uint8_t>(read_buf.data(), read_buf.size()));

        if (!recv_result.ok()) {
            LOG_DEBUG(core::LogCategory::MINING,
                "Stratum client " + std::to_string(client_id) +
                " read error: " + recv_result.error().message());
            break;
        }

        size_t bytes_read = recv_result.value();
        if (bytes_read == 0) {
            // Client disconnected.
            LOG_INFO(core::LogCategory::MINING,
                "Stratum client " + std::to_string(client_id) +
                " disconnected");
            break;
        }

        // Append to the client's receive buffer.
        {
            std::lock_guard lock(clients_mutex_);
            auto it = clients_.find(client_id);
            if (it == clients_.end()) break;
            it->second->recv_buffer.append(
                reinterpret_cast<const char*>(read_buf.data()), bytes_read);
        }

        // Process complete lines (Stratum messages are newline-delimited).
        while (true) {
            std::string line;

            {
                std::lock_guard lock(clients_mutex_);
                auto it = clients_.find(client_id);
                if (it == clients_.end()) break;

                auto& buf = it->second->recv_buffer;
                auto newline_pos = buf.find('\n');
                if (newline_pos == std::string::npos) break;

                line = buf.substr(0, newline_pos);
                buf.erase(0, newline_pos + 1);

                // Guard against excessive buffer size.
                if (buf.size() > MAX_STRATUM_LINE_LENGTH) {
                    LOG_WARN(core::LogCategory::MINING,
                        "Stratum client " + std::to_string(client_id) +
                        " buffer overflow, disconnecting");
                    break;
                }
            }

            // Strip trailing CR.
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            if (!line.empty()) {
                process_message(client_id, line);
            }
        }
    }

    remove_client(client_id);
}

// ---------------------------------------------------------------------------
// process_message
// ---------------------------------------------------------------------------

void StratumServer::process_message(uint64_t client_id,
                                     const std::string& line) {
    LOG_TRACE(core::LogCategory::MINING,
        "Stratum recv from client " + std::to_string(client_id) +
        ": " + line);

    std::string method = json_get_method(line);
    uint64_t msg_id = json_get_uint(line, "id");
    std::string params = json_get_params(line);

    if (method == "mining.subscribe") {
        handle_subscribe(client_id, msg_id);
    } else if (method == "mining.authorize") {
        auto param_list = parse_string_array(params);
        std::string worker_name = param_list.size() > 0 ? param_list[0] : "";
        std::string worker_pass = param_list.size() > 1 ? param_list[1] : "";
        handle_authorize(client_id, msg_id, worker_name, worker_pass);
    } else if (method == "mining.submit") {
        auto param_list = parse_string_array(params);
        StratumShare share;
        share.worker_name = param_list.size() > 0 ? param_list[0] : "";
        share.job_id = param_list.size() > 1 ? param_list[1] : "";

        // Parse nonce (hex string).
        if (param_list.size() > 2) {
            try {
                share.nonce = static_cast<uint32_t>(
                    std::stoul(param_list[2], nullptr, 16));
            } catch (...) {
                share.nonce = 0;
            }
        }

        // Parse solution (hex string).
        if (param_list.size() > 3) {
            share.solution = hex_to_bytes(param_list[3]);
        }

        // Parse time (hex string).
        if (param_list.size() > 4) {
            try {
                share.time = static_cast<uint32_t>(
                    std::stoul(param_list[4], nullptr, 16));
            } catch (...) {
                share.time = 0;
            }
        }

        handle_submit(client_id, msg_id, share);
    } else {
        // Unknown method. Send an error response.
        std::string response = json_response(msg_id, "null",
            "[20, \"Unknown method: " + method + "\", null]");
        send_to_client(client_id, response);
    }
}

// ---------------------------------------------------------------------------
// handle_subscribe
// ---------------------------------------------------------------------------

void StratumServer::handle_subscribe(uint64_t client_id, uint64_t msg_id) {
    // Generate an extra nonce for this client.
    uint32_t extra_nonce = generate_extra_nonce();
    std::string extra_nonce_hex = bytes_to_hex(
        reinterpret_cast<const uint8_t*>(&extra_nonce), 4);

    {
        std::lock_guard lock(clients_mutex_);
        auto it = clients_.find(client_id);
        if (it != clients_.end()) {
            it->second->subscribed = true;
        }
    }

    // Response: [[["mining.notify", subscription_id]], extranonce1, extranonce2_size]
    std::string result = "[[[\""
        "mining.notify\",\"" + std::to_string(client_id) +
        "\"]],\"" + extra_nonce_hex + "\",4]";

    std::string response = json_response(msg_id, result);
    send_to_client(client_id, response);

    LOG_DEBUG(core::LogCategory::MINING,
        "Stratum client " + std::to_string(client_id) +
        " subscribed, extra_nonce=" + extra_nonce_hex);

    // Send initial difficulty.
    double difficulty = default_difficulty_.load(std::memory_order_relaxed);
    std::string diff_msg = build_set_difficulty_message(difficulty);
    send_to_client(client_id, diff_msg);

    // Send current job if available.
    std::lock_guard lock(template_mutex_);
    if (current_template_) {
        std::string notify_msg = build_notify_message(*current_template_);
        send_to_client(client_id, notify_msg);
    }
}

// ---------------------------------------------------------------------------
// handle_authorize
// ---------------------------------------------------------------------------

void StratumServer::handle_authorize(
    uint64_t client_id, uint64_t msg_id,
    const std::string& worker_name,
    const std::string& worker_pass) {

    // For FTC, we accept all workers (no actual authentication needed
    // for a solo-mining or development pool).
    {
        std::lock_guard lock(clients_mutex_);
        auto it = clients_.find(client_id);
        if (it != clients_.end()) {
            it->second->authorized = true;
            it->second->worker_name = worker_name;
            it->second->worker_pass = worker_pass;
        }
    }

    std::string response = json_response(msg_id, "true");
    send_to_client(client_id, response);

    LOG_INFO(core::LogCategory::MINING,
        "Stratum client " + std::to_string(client_id) +
        " authorized as '" + worker_name + "'");
}

// ---------------------------------------------------------------------------
// handle_submit
// ---------------------------------------------------------------------------

void StratumServer::handle_submit(
    uint64_t client_id, uint64_t msg_id,
    const StratumShare& share) {

    // Verify the share against the current template.
    BlockTemplate* tmpl = nullptr;
    {
        std::lock_guard lock(template_mutex_);
        tmpl = current_template_.get();
    }

    if (tmpl == nullptr) {
        std::string response = json_response(msg_id, "null",
            "[21, \"No current job\", null]");
        send_to_client(client_id, response);
        total_invalid_shares_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Check that the job ID matches.
    std::string expected_job_id = std::to_string(
        current_job_id_.load(std::memory_order_relaxed));
    if (share.job_id != expected_job_id) {
        std::string response = json_response(msg_id, "null",
            "[21, \"Stale job\", null]");
        send_to_client(client_id, response);
        total_invalid_shares_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Build the header with the submitted nonce and time.
    primitives::BlockHeader header = tmpl->header;
    header.nonce = share.nonce;
    if (share.time != 0) {
        header.timestamp = share.time;
    }

    // Verify the Equihash solution.
    if (!verifier_.verify_solution(header, share.solution)) {
        std::string response = json_response(msg_id, "null",
            "[23, \"Invalid solution\", null]");
        send_to_client(client_id, response);
        total_invalid_shares_.fetch_add(1, std::memory_order_relaxed);

        {
            std::lock_guard lock(clients_mutex_);
            auto it = clients_.find(client_id);
            if (it != clients_.end()) {
                it->second->invalid_shares++;
            }
        }

        LOG_DEBUG(core::LogCategory::MINING,
            "Invalid share from client " + std::to_string(client_id));
        return;
    }

    // Valid share. Check if it meets the network target (block-level).
    auto serialized = EquihashSolver::serialize_header(header);
    std::vector<uint8_t> block_data;
    block_data.reserve(serialized.size() + share.solution.size());
    block_data.insert(block_data.end(), serialized.begin(), serialized.end());
    block_data.insert(block_data.end(),
        share.solution.begin(), share.solution.end());

    core::uint256 block_hash = crypto::keccak256d(
        std::span<const uint8_t>(block_data.data(), block_data.size()));

    bool meets_network_target = (block_hash <= tmpl->target);

    // Accept the share.
    std::string response = json_response(msg_id, "true");
    send_to_client(client_id, response);
    total_valid_shares_.fetch_add(1, std::memory_order_relaxed);

    {
        std::lock_guard lock(clients_mutex_);
        auto it = clients_.find(client_id);
        if (it != clients_.end()) {
            it->second->valid_shares++;
        }
    }

    LOG_DEBUG(core::LogCategory::MINING,
        "Valid share from client " + std::to_string(client_id) +
        " worker=" + share.worker_name +
        (meets_network_target ? " *** BLOCK FOUND ***" : ""));

    // If the share also meets the network target, it's a block!
    if (meets_network_target && share_callback_) {
        share_callback_(header, share.solution);
    }
}

// ---------------------------------------------------------------------------
// notify_new_job
// ---------------------------------------------------------------------------

void StratumServer::notify_new_job(const BlockTemplate& tmpl) {
    // Update the current template.
    {
        std::lock_guard lock(template_mutex_);
        current_template_ = std::make_unique<BlockTemplate>(tmpl);
    }

    uint64_t job_id = current_job_id_.fetch_add(1, std::memory_order_relaxed);

    std::string notify_msg = build_notify_message(tmpl);
    broadcast(notify_msg);

    LOG_DEBUG(core::LogCategory::MINING,
        "Sent new Stratum job " + std::to_string(job_id) +
        " to " + std::to_string(client_count()) + " clients");
}

// ---------------------------------------------------------------------------
// set_difficulty
// ---------------------------------------------------------------------------

void StratumServer::set_difficulty(double difficulty) {
    default_difficulty_.store(difficulty, std::memory_order_relaxed);

    std::string msg = build_set_difficulty_message(difficulty);
    broadcast(msg);

    // Update difficulty for all existing clients.
    {
        std::lock_guard lock(clients_mutex_);
        for (auto& [id, client] : clients_) {
            client->difficulty = difficulty;
        }
    }
}

// ---------------------------------------------------------------------------
// set_share_callback
// ---------------------------------------------------------------------------

void StratumServer::set_share_callback(ShareCallback callback) {
    share_callback_ = std::move(callback);
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

size_t StratumServer::client_count() const {
    std::lock_guard lock(clients_mutex_);
    return clients_.size();
}

uint64_t StratumServer::total_valid_shares() const {
    return total_valid_shares_.load(std::memory_order_relaxed);
}

uint64_t StratumServer::total_invalid_shares() const {
    return total_invalid_shares_.load(std::memory_order_relaxed);
}

// ---------------------------------------------------------------------------
// send_to_client
// ---------------------------------------------------------------------------

bool StratumServer::send_to_client(uint64_t client_id,
                                    const std::string& json_line) {
    std::lock_guard lock(clients_mutex_);
    auto it = clients_.find(client_id);
    if (it == clients_.end()) return false;

    auto& socket = it->second->socket;
    if (!socket.is_open()) return false;

    auto data = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(json_line.data()),
        json_line.size());

    auto result = socket.send_all(data);
    if (!result.ok()) {
        LOG_DEBUG(core::LogCategory::MINING,
            "Failed to send to Stratum client " +
            std::to_string(client_id));
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// broadcast
// ---------------------------------------------------------------------------

void StratumServer::broadcast(const std::string& json_line) {
    std::lock_guard lock(clients_mutex_);
    for (auto& [id, client] : clients_) {
        if (!client->authorized) continue;
        if (!client->socket.is_open()) continue;

        auto data = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(json_line.data()),
            json_line.size());

        auto result = client->socket.send_all(data);
        if (!result.ok()) {
            LOG_DEBUG(core::LogCategory::MINING,
                "Failed to broadcast to client " + std::to_string(id));
        }
    }
}

// ---------------------------------------------------------------------------
// build_notify_message
// ---------------------------------------------------------------------------

std::string StratumServer::build_notify_message(
    const BlockTemplate& tmpl) const {

    uint64_t job_id = current_job_id_.load(std::memory_order_relaxed);

    // mining.notify parameters:
    //   [job_id, prev_hash, coinbase1, coinbase2, merkle_branches,
    //    version, nbits, ntime, clean_jobs]
    //
    // For Equihash, we simplify: send the full header info.

    std::string prev_hash = tmpl.header.prev_hash.to_hex();
    std::string merkle_root = tmpl.header.merkle_root.to_hex();

    // Version, bits, and time as hex.
    char version_hex[9], bits_hex[9], time_hex[9];
    snprintf(version_hex, sizeof(version_hex), "%08x",
             static_cast<uint32_t>(tmpl.header.version));
    snprintf(bits_hex, sizeof(bits_hex), "%08x", tmpl.header.bits);
    snprintf(time_hex, sizeof(time_hex), "%08x", tmpl.header.timestamp);

    // Build the params array.
    std::string params = "[\"" + std::to_string(job_id) + "\","
        "\"" + prev_hash + "\","
        "\"" + merkle_root + "\","
        "\"" + std::string(version_hex) + "\","
        "\"" + std::string(bits_hex) + "\","
        "\"" + std::string(time_hex) + "\","
        "true]";  // clean_jobs = true

    return json_notification("mining.notify", params);
}

// ---------------------------------------------------------------------------
// build_set_difficulty_message
// ---------------------------------------------------------------------------

std::string StratumServer::build_set_difficulty_message(
    double difficulty) const {

    std::ostringstream oss;
    oss << "[" << difficulty << "]";
    return json_notification("mining.set_difficulty", oss.str());
}

// ---------------------------------------------------------------------------
// remove_client
// ---------------------------------------------------------------------------

void StratumServer::remove_client(uint64_t client_id) {
    std::lock_guard lock(clients_mutex_);
    auto it = clients_.find(client_id);
    if (it != clients_.end()) {
        it->second->socket.close();
        clients_.erase(it);

        LOG_DEBUG(core::LogCategory::MINING,
            "Removed Stratum client " + std::to_string(client_id));
    }
}

// ---------------------------------------------------------------------------
// generate_extra_nonce
// ---------------------------------------------------------------------------

uint32_t StratumServer::generate_extra_nonce() {
    return next_extra_nonce_.fetch_add(1, std::memory_order_relaxed);
}

} // namespace miner
