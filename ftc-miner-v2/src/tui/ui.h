#ifndef FTC_MINER_TUI_UI_H
#define FTC_MINER_TUI_UI_H

#include "terminal.h"
#include "widgets.h"
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <chrono>

namespace tui {

// Device mining statistics
struct DeviceStats {
    int id = 0;
    std::string name;
    std::string type = "GPU";       // "CPU" or "GPU"
    double hashrate = 0.0;
    double temperature = 0.0;
    double power = 0.0;
    int fan_percent = 0;
    double efficiency = 0.0;      // H/W
    uint64_t accepted = 0;
    uint64_t rejected = 0;
    bool enabled = true;
    int intensity = 20;
    int worksize = 256;
    int threads = 0;

    // Hashrate history for sparkline
    std::vector<double> hashrate_history;
};

// Global mining statistics
struct MiningStats {
    // Hashrate
    double total_hashrate = 0.0;
    double avg_hashrate_1m = 0.0;
    double avg_hashrate_5m = 0.0;
    double avg_hashrate_15m = 0.0;
    double peak_hashrate = 0.0;

    // Shares
    uint64_t shares_accepted = 0;
    uint64_t shares_rejected = 0;
    uint64_t shares_stale = 0;

    // Blocks
    uint64_t blocks_found = 0;
    uint64_t block_reward = 0;

    // Network (blockchain)
    double difficulty = 1.0;           // Calculated difficulty (not raw bits)
    int32_t block_height = 0;
    bool connected = false;
    uint32_t node_count = 0;           // FTC nodes (not DHT peers)
    double network_hashrate = 0.0;     // Total network hashrate (H/s)

    // P2Pool statistics
    bool p2pool_enabled = false;       // P2Pool available
    bool p2pool_running = false;       // P2Pool active
    uint32_t active_miners = 0;        // Miners in P2Pool
    uint64_t sharechain_height = 0;    // P2Pool sharechain height
    double pool_hashrate = 0.0;        // P2Pool total hashrate
    uint64_t pool_total_shares = 0;    // Total shares in pool
    uint64_t pool_total_blocks = 0;    // Blocks found by pool
    double shares_per_minute = 0.0;    // Pool share rate
    uint32_t p2pool_peers = 0;         // P2Pool network peers

    // Time
    std::chrono::steady_clock::time_point start_time;
    int64_t uptime_seconds = 0;

    // Auto-tune
    bool autotune_active = false;
    int autotune_progress = 0;
    std::string autotune_status;
};

// Main UI class
class MinerUI {
public:
    MinerUI();
    ~MinerUI();

    // Initialize/cleanup
    bool init();
    void cleanup();

    // Main render loop (call periodically)
    void render();

    // Update data
    void setStats(const MiningStats& stats);
    void setDevices(const std::vector<DeviceStats>& devices);
    void addLogMessage(const std::string& message, Color color = Color::White);

    // User input
    bool handleInput();  // Returns false if quit requested

    // Control
    void showAutotunePanel(bool show);
    void setAutotuneProgress(int progress, const std::string& status);

private:
    void renderHeader();
    void renderStats();
    void renderDevices();
    void renderHashrateGraph();
    void renderLog();
    void renderFooter();
    void renderAutotunePanel();

    int width_;
    int height_;
    bool initialized_;

    MiningStats stats_;
    std::vector<DeviceStats> devices_;
    std::vector<std::pair<std::string, Color>> log_messages_;
    std::mutex data_mutex_;

    // Sparkline for total hashrate
    Sparkline hashrate_sparkline_;

    // Animation frame
    int anim_frame_;
    std::chrono::steady_clock::time_point last_render_;

    // UI state
    bool show_autotune_panel_;
    int selected_device_;

    // Log max lines
    static constexpr int MAX_LOG_LINES = 100;
};

} // namespace tui

#endif // FTC_MINER_TUI_UI_H
