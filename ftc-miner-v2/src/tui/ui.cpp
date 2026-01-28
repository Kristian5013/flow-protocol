#include "ui.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace tui {

MinerUI::MinerUI()
    : width_(120)
    , height_(40)
    , prev_width_(0)
    , prev_height_(0)
    , initialized_(false)
    , hashrate_sparkline_(40)
    , anim_frame_(0)
    , show_autotune_panel_(false)
    , selected_device_(0)
{
    stats_ = {};
    stats_.start_time = std::chrono::steady_clock::now();
}

MinerUI::~MinerUI() {
    cleanup();
}

bool MinerUI::init() {
    if (initialized_) return true;

    Terminal::init();
    Terminal::getSize(width_, height_);
    Terminal::hideCursor();
    Terminal::clear();

    hashrate_sparkline_.setColor(Color::Cyan);

    last_render_ = std::chrono::steady_clock::now();
    initialized_ = true;

    return true;
}

void MinerUI::cleanup() {
    if (!initialized_) return;

    Terminal::showCursor();
    Terminal::cleanup();
    initialized_ = false;
}

void MinerUI::render() {
    if (!initialized_) return;

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_render_);
    if (elapsed.count() < 100) return;  // Max 10 FPS
    last_render_ = now;

    // Update animation frame
    anim_frame_ = (anim_frame_ + 1) % 10;

    // Get terminal size (may have changed)
    Terminal::getSize(width_, height_);

    // Detect resize - clear screen to prevent artifacts
    bool resized = (width_ != prev_width_ || height_ != prev_height_);
    if (resized) {
        std::cout << "\033[H\033[2J";  // Clear entire screen on resize
        prev_width_ = width_;
        prev_height_ = height_;
    }

    // Ensure minimum terminal size
    if (width_ < 80 || height_ < 30) {
        std::cout << "\033[H\033[2J";  // Clear and home
        std::cout << "Terminal too small. Minimum 80x30 required.\n";
        std::cout << "Current: " << width_ << "x" << height_ << std::endl;
        return;
    }

    // Move cursor to home (no clear - prevents flicker)
    std::cout << "\033[H";

    std::lock_guard<std::mutex> lock(data_mutex_);

    // Update uptime
    stats_.uptime_seconds = std::chrono::duration_cast<std::chrono::seconds>(
        now - stats_.start_time).count();

    renderHeader();
    renderStats();
    renderDevices();
    renderHashrateGraph();
    renderLog();
    renderFooter();

    if (show_autotune_panel_) {
        renderAutotunePanel();
    }

    std::cout << std::flush;
}

void MinerUI::renderHeader() {
    // Simple text header (no ASCII art)
    Terminal::moveTo(2, 1);
    std::cout << Terminal::style(Style::Bold) << Terminal::fg(Color::Cyan)
              << "FTC Miner v2.0.0" << Terminal::reset()
              << Terminal::fg(Color::BrightBlack)
              << " | Keccak-256 | P2Pool Mining"
              << Terminal::reset();

    // Connection status on right
    Terminal::moveTo(width_ - 15, 1);
    if (stats_.connected) {
        std::cout << Terminal::fg(Color::Green) << "[Connected]" << Terminal::reset();
    } else {
        std::cout << Terminal::fg(Color::Red) << "[Offline]" << Terminal::reset();
    }
    std::cout << "\033[K";  // Clear to end of line

    // Separator
    Terminal::moveTo(1, 2);
    std::cout << Terminal::fg(Color::BrightBlack);
    for (int i = 0; i < width_ - 1; ++i) std::cout << "-";
    std::cout << "\033[K" << Terminal::reset();
}

void MinerUI::renderStats() {
    int y = 4;

    // Stats header
    Terminal::moveTo(2, y);
    std::cout << Terminal::fg(Color::Cyan) << "Mining Statistics" << "\033[K" << Terminal::reset();

    // Row 1: Hashrate
    Terminal::moveTo(4, y + 1);
    std::cout << Terminal::fg(Color::White) << "Hashrate: "
              << Terminal::style(Style::Bold) << Terminal::fg(Color::Green)
              << formatHashrate(stats_.total_hashrate)
              << Terminal::reset()
              << Terminal::fg(Color::BrightBlack) << "  │  "
              << "1m: " << formatHashrate(stats_.avg_hashrate_1m) << "  "
              << "5m: " << formatHashrate(stats_.avg_hashrate_5m) << "  "
              << "15m: " << formatHashrate(stats_.avg_hashrate_15m)
              << "\033[K" << Terminal::reset();

    // Row 2: Shares and blocks
    Terminal::moveTo(4, y + 2);
    std::cout << Terminal::fg(Color::White) << "Shares:   "
              << Terminal::fg(Color::Green) << stats_.shares_accepted << " accepted"
              << Terminal::fg(Color::BrightBlack) << "  │  "
              << Terminal::fg(Color::Red) << stats_.shares_rejected << " rejected"
              << Terminal::fg(Color::BrightBlack) << "  │  "
              << Terminal::fg(Color::Yellow) << stats_.shares_stale << " stale"
              << Terminal::fg(Color::BrightBlack) << "  │  "
              << Terminal::fg(Color::White) << "Blocks: "
              << Terminal::fg(Color::Yellow) << stats_.blocks_found
              << "\033[K" << Terminal::reset();

    // Row 3: Pool info (miners, your share, est. daily)
    Terminal::moveTo(4, y + 3);
    double your_pct = 100.0;
    if (stats_.active_miners > 1 && stats_.pool_hashrate > 0) {
        your_pct = (stats_.total_hashrate / stats_.pool_hashrate) * 100.0;
        if (your_pct > 100.0) your_pct = 100.0;
    }
    std::cout << Terminal::fg(Color::White) << "Pool:     "
              << Terminal::fg(Color::Cyan) << stats_.active_miners << " miners"
              << Terminal::fg(Color::BrightBlack) << "  │  "
              << Terminal::fg(Color::White) << "Your share: "
              << Terminal::fg(Color::Magenta) << formatNumber(your_pct, 1) << "%"
              << Terminal::fg(Color::BrightBlack) << "  │  "
              << Terminal::fg(Color::White) << "Est. daily: "
              << Terminal::fg(Color::Yellow)
              << formatNumber(1440.0 * (your_pct / 100.0) * 50.0, 1) << " FTC"
              << "\033[K" << Terminal::reset();

    // Row 4: Chain info
    Terminal::moveTo(4, y + 4);
    std::cout << Terminal::fg(Color::White) << "Chain:    "
              << "Height: " << Terminal::fg(Color::Cyan) << stats_.block_height
              << Terminal::fg(Color::BrightBlack) << " │ "
              << Terminal::fg(Color::White) << "Diff: "
              << Terminal::fg(Color::Yellow) << formatNumber(stats_.difficulty, stats_.difficulty >= 100 ? 0 : 2)
              << Terminal::fg(Color::BrightBlack) << " │ "
              << Terminal::fg(Color::White) << "Nodes: "
              << Terminal::fg(Color::Green) << stats_.node_count
              << "\033[K" << Terminal::reset();

    // Row 5: Uptime
    Terminal::moveTo(4, y + 5);
    std::cout << Terminal::fg(Color::White) << "Uptime:   "
              << Terminal::fg(Color::BrightBlack) << formatDuration(stats_.uptime_seconds);

    // Auto-tune status (right side)
    if (stats_.autotune_active) {
        Terminal::moveTo(width_ - 40, y + 5);
        StatusIndicator status;
        status.setState(StatusIndicator::State::Running);
        status.setText("Auto-tune: " + stats_.autotune_status);
        status.setAnimated(true);
        status.tick();
        std::cout << status.render();
    }
    std::cout << "\033[K" << Terminal::reset();
}

void MinerUI::renderDevices() {
    int y = 11;  // After header (2) + stats (6) + margin
    int boxHeight = std::max(5, static_cast<int>(devices_.size()) + 3);

    Box devBox(2, y, width_ - 3, boxHeight, Box::Style::Single);
    devBox.setTitle("Devices");
    devBox.setTitleColor(Color::Cyan);
    devBox.setBorderColor(Color::BrightBlack);
    devBox.render();

    // Header
    Terminal::moveTo(4, y + 1);
    std::cout << Terminal::style(Style::Bold) << Terminal::fg(Color::Cyan)
              << leftAlign("ID", 4)
              << leftAlign("Device", 25)
              << leftAlign("Hashrate", 14)
              << leftAlign("Temp", 8)
              << leftAlign("Fan", 6)
              << leftAlign("Power", 10)
              << leftAlign("Eff.", 12)
              << leftAlign("A/R", 10)
              << Terminal::reset();

    // Separator
    Terminal::moveTo(4, y + 2);
    std::cout << Terminal::fg(Color::BrightBlack);
    for (int i = 0; i < width_ - 8; ++i) std::cout << "─";
    std::cout << Terminal::reset();

    // Devices
    for (size_t i = 0; i < devices_.size() && i < static_cast<size_t>(boxHeight - 4); ++i) {
        const auto& dev = devices_[i];
        Terminal::moveTo(4, y + 3 + static_cast<int>(i));

        // Highlight selected device
        if (static_cast<int>(i) == selected_device_) {
            std::cout << Terminal::bg(Color::BrightBlack);
        }

        // ID
        std::cout << Terminal::fg(dev.enabled ? Color::White : Color::BrightBlack)
                  << leftAlign(std::to_string(dev.id), 4);

        // Name
        std::cout << Terminal::fg(dev.type == "GPU" ? Color::Green : Color::Cyan)
                  << leftAlign(truncate(dev.name, 24), 25);

        // Hashrate with mini sparkline
        std::cout << Terminal::fg(Color::Green)
                  << leftAlign(formatHashrate(dev.hashrate), 14);

        // Temperature with color coding
        Color tempColor = Color::Green;
        if (dev.temperature >= 80) tempColor = Color::Red;
        else if (dev.temperature >= 70) tempColor = Color::Yellow;
        std::cout << Terminal::fg(tempColor)
                  << leftAlign(formatNumber(dev.temperature, 0) + "C", 8);

        // Fan
        std::cout << Terminal::fg(Color::Cyan)
                  << leftAlign(std::to_string(dev.fan_percent) + "%", 6);

        // Power
        std::cout << Terminal::fg(Color::Yellow)
                  << leftAlign(formatNumber(dev.power, 0) + "W", 10);

        // Efficiency
        std::cout << Terminal::fg(Color::Magenta)
                  << leftAlign(formatNumber(dev.efficiency, 2) + " H/W", 12);

        // Accepted/Rejected
        std::cout << Terminal::fg(Color::Green) << dev.accepted
                  << Terminal::fg(Color::BrightBlack) << "/"
                  << Terminal::fg(Color::Red) << dev.rejected
                  << "\033[K";  // Clear to end of line

        std::cout << Terminal::reset();
    }
}

void MinerUI::renderHashrateGraph() {
    int deviceBoxHeight = std::max(5, static_cast<int>(devices_.size()) + 3);
    int y = 11 + deviceBoxHeight + 1;  // After devices box
    int graphHeight = 4;

    Box graphBox(2, y, width_ - 3, graphHeight, Box::Style::Single);
    graphBox.setTitle("Hashrate History");
    graphBox.setTitleColor(Color::Cyan);
    graphBox.setBorderColor(Color::BrightBlack);
    graphBox.render();

    // Sparkline
    Terminal::moveTo(4, y + 2);
    std::cout << hashrate_sparkline_.render();

    // Min/Max labels
    Terminal::moveTo(width_ - 25, y + 1);
    double peak = stats_.peak_hashrate > 0 ? stats_.peak_hashrate : stats_.total_hashrate;
    std::cout << Terminal::fg(Color::BrightBlack) << "Peak: "
              << Terminal::fg(Color::Green) << formatHashrate(peak)
              << "\033[K";
}

void MinerUI::renderLog() {
    int deviceBoxHeight = std::max(5, static_cast<int>(devices_.size()) + 3);
    int graphHeight = 4;
    int y = 11 + deviceBoxHeight + graphHeight + 2;  // After all boxes
    int logHeight = height_ - y - 2;

    if (logHeight < 5) return;

    Box logBox(2, y, width_ - 3, logHeight, Box::Style::Single);
    logBox.setTitle("Log");
    logBox.setTitleColor(Color::Cyan);
    logBox.setBorderColor(Color::BrightBlack);
    logBox.render();

    // Show recent log messages
    int maxLines = logHeight - 2;
    int startIdx = std::max(0, static_cast<int>(log_messages_.size()) - maxLines);

    for (int i = 0; i < maxLines && startIdx + i < static_cast<int>(log_messages_.size()); ++i) {
        const auto& [msg, color] = log_messages_[startIdx + i];
        Terminal::moveTo(4, y + 1 + i);
        std::cout << Terminal::fg(color)
                  << truncate(msg, width_ - 8)
                  << "\033[K" << Terminal::reset();
    }
}

void MinerUI::renderFooter() {
    Terminal::moveTo(1, height_ - 1);
    std::cout << Terminal::fg(Color::BrightBlack);
    for (int i = 0; i < width_; ++i) std::cout << "─";

    Terminal::moveTo(2, height_);
    std::cout << Terminal::fg(Color::Cyan) << "[Q]" << Terminal::fg(Color::White) << "uit  "
              << Terminal::fg(Color::Cyan) << "[A]" << Terminal::fg(Color::White) << "uto-tune  "
              << Terminal::fg(Color::Cyan) << "[P]" << Terminal::fg(Color::White) << "ause  "
              << Terminal::fg(Color::Cyan) << "[+/-]" << Terminal::fg(Color::White) << " Intensity  "
              << Terminal::fg(Color::Cyan) << "[R]" << Terminal::fg(Color::White) << "eset Stats"
              << Terminal::reset();
}

void MinerUI::renderAutotunePanel() {
    int panelW = 50;
    int panelH = 10;
    int x = (width_ - panelW) / 2;
    int y = (height_ - panelH) / 2;

    Box panel(x, y, panelW, panelH, Box::Style::Double);
    panel.setTitle("AI Auto-Tune");
    panel.setTitleColor(Color::Yellow);
    panel.setBorderColor(Color::Yellow);
    panel.render();

    // Clear inside
    for (int i = 1; i < panelH - 1; ++i) {
        Terminal::moveTo(x + 1, y + i);
        std::cout << std::string(panelW - 2, ' ');
    }

    // Status
    Terminal::moveTo(x + 3, y + 2);
    StatusIndicator status;
    status.setState(StatusIndicator::State::Running);
    status.setText(stats_.autotune_status);
    status.setAnimated(true);
    std::cout << status.render();

    // Progress bar
    Terminal::moveTo(x + 3, y + 4);
    ProgressBar bar(panelW - 8);
    bar.setValue(stats_.autotune_progress / 100.0);
    bar.setColors(Color::Yellow, Color::BrightBlack);
    std::cout << bar.render() << " " << stats_.autotune_progress << "%";

    // Instructions
    Terminal::moveTo(x + 3, y + 6);
    std::cout << Terminal::fg(Color::BrightBlack)
              << "Optimizing parameters for your hardware..."
              << Terminal::reset();

    Terminal::moveTo(x + 3, y + 8);
    std::cout << Terminal::fg(Color::Cyan) << "[ESC]"
              << Terminal::fg(Color::White) << " Cancel"
              << Terminal::reset();
}

void MinerUI::setStats(const MiningStats& stats) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    stats_ = stats;
    hashrate_sparkline_.addValue(stats.total_hashrate);
}

void MinerUI::setDevices(const std::vector<DeviceStats>& devices) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    devices_ = devices;
}

void MinerUI::addLogMessage(const std::string& message, Color color) {
    std::lock_guard<std::mutex> lock(data_mutex_);

    // Add timestamp
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&time);

    std::ostringstream ss;
    ss << std::put_time(&tm, "%H:%M:%S") << " " << message;

    log_messages_.emplace_back(ss.str(), color);

    // Keep log size bounded
    while (log_messages_.size() > MAX_LOG_LINES) {
        log_messages_.erase(log_messages_.begin());
    }
}

bool MinerUI::handleInput() {
    if (!Terminal::kbhit()) return true;

    int ch = Terminal::getch();

    switch (ch) {
        case 'q':
        case 'Q':
            return false;

        case 'a':
        case 'A':
            show_autotune_panel_ = !show_autotune_panel_;
            break;

        case 'p':
        case 'P':
            addLogMessage("Mining paused/resumed", Color::Yellow);
            break;

        case '+':
        case '=':
            addLogMessage("Intensity increased", Color::Cyan);
            break;

        case '-':
        case '_':
            addLogMessage("Intensity decreased", Color::Cyan);
            break;

        case 'r':
        case 'R':
            addLogMessage("Statistics reset", Color::Yellow);
            break;

        case 27:  // ESC
            if (show_autotune_panel_) {
                show_autotune_panel_ = false;
                addLogMessage("Auto-tune cancelled", Color::Yellow);
            }
            break;
    }

    return true;
}

void MinerUI::showAutotunePanel(bool show) {
    show_autotune_panel_ = show;
}

void MinerUI::setAutotuneProgress(int progress, const std::string& status) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    stats_.autotune_progress = progress;
    stats_.autotune_status = status;
}

} // namespace tui
