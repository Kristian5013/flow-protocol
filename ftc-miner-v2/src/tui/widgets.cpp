#include "widgets.h"
#include <sstream>
#include <iomanip>
#include <cmath>
#include <algorithm>
#include <iostream>

namespace tui {

// ============================================================================
// ProgressBar
// ============================================================================

ProgressBar::ProgressBar(int width)
    : width_(width)
    , value_(0.0)
    , fg_color_(Color::Green)
    , bg_color_(Color::BrightBlack)
    , smooth_(true)
{}

void ProgressBar::setValue(double value) {
    value_ = std::clamp(value, 0.0, 1.0);
}

void ProgressBar::setColors(Color fg, Color bg) {
    fg_color_ = fg;
    bg_color_ = bg;
}

void ProgressBar::setStyle(bool smooth) {
    smooth_ = smooth;
}

std::string ProgressBar::render() const {
    std::ostringstream ss;

    double filled = value_ * width_;
    int full_blocks = static_cast<int>(filled);
    double frac = filled - full_blocks;

    ss << Terminal::fg(fg_color_);

    // Full blocks
    for (int i = 0; i < full_blocks && i < width_; ++i) {
        ss << Terminal::BLOCK_FULL;
    }

    // Partial block
    if (full_blocks < width_ && smooth_) {
        if (frac >= 0.875) ss << Terminal::BLOCK_7_8;
        else if (frac >= 0.75) ss << Terminal::BLOCK_3_4;
        else if (frac >= 0.625) ss << Terminal::BLOCK_5_8;
        else if (frac >= 0.5) ss << Terminal::BLOCK_1_2;
        else if (frac >= 0.375) ss << Terminal::BLOCK_3_8;
        else if (frac >= 0.25) ss << Terminal::BLOCK_1_4;
        else if (frac >= 0.125) ss << Terminal::BLOCK_1_8;
        else ss << Terminal::fg(bg_color_) << Terminal::BLOCK_FULL;
        full_blocks++;
    }

    // Empty blocks
    ss << Terminal::fg(bg_color_);
    for (int i = full_blocks; i < width_; ++i) {
        ss << Terminal::BLOCK_FULL;
    }

    ss << Terminal::reset();
    return ss.str();
}

// ============================================================================
// Sparkline
// ============================================================================

Sparkline::Sparkline(int width)
    : width_(width)
    , min_val_(0.0)
    , max_val_(1.0)
    , auto_range_(true)
    , color_(Color::Cyan)
{}

void Sparkline::addValue(double value) {
    values_.push_back(value);
    if (static_cast<int>(values_.size()) > width_) {
        values_.erase(values_.begin());
    }

    if (auto_range_ && !values_.empty()) {
        auto [minIt, maxIt] = std::minmax_element(values_.begin(), values_.end());
        min_val_ = *minIt;
        max_val_ = *maxIt;
        if (max_val_ == min_val_) max_val_ = min_val_ + 1.0;
    }
}

void Sparkline::setRange(double min, double max) {
    min_val_ = min;
    max_val_ = max;
    auto_range_ = false;
}

void Sparkline::setColor(Color color) {
    color_ = color;
}

std::string Sparkline::render() const {
    std::ostringstream ss;
    ss << Terminal::fg(color_);

    for (size_t i = 0; i < static_cast<size_t>(width_); ++i) {
        if (i < values_.size()) {
            double normalized = (values_[i] - min_val_) / (max_val_ - min_val_);
            normalized = std::clamp(normalized, 0.0, 1.0);
            int idx = static_cast<int>(normalized * 8);
            idx = std::clamp(idx, 0, 8);
            ss << BLOCKS[idx];
        } else {
            ss << " ";
        }
    }

    ss << Terminal::reset();
    return ss.str();
}

// ============================================================================
// Box
// ============================================================================

Box::Box(int x, int y, int width, int height, Style style)
    : x_(x), y_(y), width_(width), height_(height)
    , style_(style)
    , title_color_(Color::White)
    , border_color_(Color::White)
{}

void Box::setTitle(const std::string& title) {
    title_ = title;
}

void Box::setTitleColor(Color color) {
    title_color_ = color;
}

void Box::setBorderColor(Color color) {
    border_color_ = color;
}

void Box::render() const {
    const char *tl, *tr, *bl, *br, *h, *v;

    switch (style_) {
        case Style::Double:
            tl = Terminal::DBOX_TL; tr = Terminal::DBOX_TR;
            bl = Terminal::DBOX_BL; br = Terminal::DBOX_BR;
            h = Terminal::DBOX_H; v = Terminal::DBOX_V;
            break;
        case Style::Single:
        default:
            tl = Terminal::BOX_TL; tr = Terminal::BOX_TR;
            bl = Terminal::BOX_BL; br = Terminal::BOX_BR;
            h = Terminal::BOX_H; v = Terminal::BOX_V;
            break;
    }

    std::string border_col = Terminal::fg(border_color_);
    std::string title_col = Terminal::fg(title_color_);
    std::string reset = Terminal::reset();

    // Top border with title
    Terminal::moveTo(x_, y_);
    std::cout << border_col << tl;

    if (!title_.empty()) {
        std::cout << h << title_col << " " << title_ << " " << border_col;
        for (int i = static_cast<int>(title_.size()) + 4; i < width_ - 1; ++i) {
            std::cout << h;
        }
    } else {
        for (int i = 1; i < width_ - 1; ++i) std::cout << h;
    }
    std::cout << tr << reset;

    // Sides
    for (int row = 1; row < height_ - 1; ++row) {
        Terminal::moveTo(x_, y_ + row);
        std::cout << border_col << v << reset;
        Terminal::moveTo(x_ + width_ - 1, y_ + row);
        std::cout << border_col << v << reset;
    }

    // Bottom border
    Terminal::moveTo(x_, y_ + height_ - 1);
    std::cout << border_col << bl;
    for (int i = 1; i < width_ - 1; ++i) std::cout << h;
    std::cout << br << reset;

    std::cout << std::flush;
}

void Box::clear() const {
    std::string spaces(contentWidth(), ' ');
    for (int row = 0; row < contentHeight(); ++row) {
        Terminal::moveTo(contentX(), contentY() + row);
        std::cout << spaces;
    }
    std::cout << std::flush;
}

// ============================================================================
// Table
// ============================================================================

Table::Table(const std::vector<std::string>& headers, const std::vector<int>& widths)
    : headers_(headers)
    , widths_(widths)
    , header_color_(Color::Cyan)
    , odd_row_color_(Color::White)
    , even_row_color_(Color::BrightBlack)
{}

void Table::addRow(const std::vector<std::string>& row) {
    rows_.push_back(row);
}

void Table::clearRows() {
    rows_.clear();
}

void Table::setHeaderColor(Color color) {
    header_color_ = color;
}

void Table::setRowColors(Color odd, Color even) {
    odd_row_color_ = odd;
    even_row_color_ = even;
}

std::vector<std::string> Table::render() const {
    std::vector<std::string> lines;
    std::ostringstream ss;

    // Header
    ss << Terminal::style(Style::Bold) << Terminal::fg(header_color_);
    for (size_t i = 0; i < headers_.size(); ++i) {
        ss << leftAlign(headers_[i], widths_[i]);
        if (i < headers_.size() - 1) ss << " ";
    }
    ss << Terminal::reset();
    lines.push_back(ss.str());

    // Separator
    ss.str("");
    ss << Terminal::fg(Color::BrightBlack);
    for (size_t i = 0; i < widths_.size(); ++i) {
        for (int j = 0; j < widths_[i]; ++j) ss << "─";
        if (i < widths_.size() - 1) ss << " ";
    }
    ss << Terminal::reset();
    lines.push_back(ss.str());

    // Rows
    for (size_t r = 0; r < rows_.size(); ++r) {
        ss.str("");
        Color color = (r % 2 == 0) ? odd_row_color_ : even_row_color_;
        ss << Terminal::fg(color);

        for (size_t i = 0; i < rows_[r].size() && i < widths_.size(); ++i) {
            ss << leftAlign(rows_[r][i], widths_[i]);
            if (i < rows_[r].size() - 1) ss << " ";
        }
        ss << Terminal::reset();
        lines.push_back(ss.str());
    }

    return lines;
}

// ============================================================================
// StatusIndicator
// ============================================================================

StatusIndicator::StatusIndicator()
    : state_(State::Idle)
    , animated_(false)
    , frame_(0)
{}

void StatusIndicator::setState(State state) {
    state_ = state;
    frame_ = 0;
}

void StatusIndicator::setText(const std::string& text) {
    text_ = text;
}

void StatusIndicator::setAnimated(bool animated) {
    animated_ = animated;
}

void StatusIndicator::tick() {
    frame_ = (frame_ + 1) % 10;
}

std::string StatusIndicator::render() const {
    std::ostringstream ss;

    switch (state_) {
        case State::Idle:
            ss << Terminal::fg(Color::BrightBlack) << Terminal::SYM_CIRCLE;
            break;
        case State::Running:
            if (animated_) {
                ss << Terminal::fg(Color::Cyan) << SPINNER[frame_];
            } else {
                ss << Terminal::fg(Color::Cyan) << Terminal::SYM_BULLET;
            }
            break;
        case State::Success:
            ss << Terminal::fg(Color::Green) << Terminal::SYM_CHECK;
            break;
        case State::Warning:
            ss << Terminal::fg(Color::Yellow) << "!";
            break;
        case State::Error:
            ss << Terminal::fg(Color::Red) << Terminal::SYM_CROSS;
            break;
    }

    ss << " " << Terminal::reset() << text_;
    return ss.str();
}

// ============================================================================
// Gauge
// ============================================================================

Gauge::Gauge(const std::string& label, int width)
    : label_(label)
    , width_(width)
    , value_(0.0)
    , max_(100.0)
    , warning_threshold_(0.7)
    , critical_threshold_(0.9)
    , normal_color_(Color::Green)
    , warning_color_(Color::Yellow)
    , critical_color_(Color::Red)
{}

void Gauge::setValue(double value, double max) {
    value_ = value;
    max_ = max;
}

void Gauge::setUnit(const std::string& unit) {
    unit_ = unit;
}

void Gauge::setThresholds(double warning, double critical) {
    warning_threshold_ = warning;
    critical_threshold_ = critical;
}

void Gauge::setColors(Color normal, Color warning, Color critical) {
    normal_color_ = normal;
    warning_color_ = warning;
    critical_color_ = critical;
}

std::string Gauge::render() const {
    std::ostringstream ss;

    double ratio = max_ > 0 ? value_ / max_ : 0.0;
    Color color = normal_color_;
    if (ratio >= critical_threshold_) color = critical_color_;
    else if (ratio >= warning_threshold_) color = warning_color_;

    ss << label_ << " ";

    ProgressBar bar(width_);
    bar.setValue(ratio);
    bar.setColors(color, Color::BrightBlack);
    ss << bar.render();

    ss << " " << Terminal::fg(color)
       << formatNumber(value_, 1) << "/" << formatNumber(max_, 1) << unit_
       << Terminal::reset();

    return ss.str();
}

// ============================================================================
// HashrateAverager
// ============================================================================

HashrateAverager::HashrateAverager()
    : peak_hashrate_(0.0)
{}

void HashrateAverager::addSample(double hashrate) {
    auto now = std::chrono::steady_clock::now();

    // Track peak
    if (hashrate > peak_hashrate_) {
        peak_hashrate_ = hashrate;
    }

    // Add sample
    samples_.push_back({hashrate, now});

    // Remove old samples (older than 15 minutes)
    auto cutoff = now - std::chrono::seconds(900);
    while (!samples_.empty() && samples_.front().timestamp < cutoff) {
        samples_.erase(samples_.begin());
    }

    // Also limit by count
    while (samples_.size() > MAX_SAMPLES) {
        samples_.erase(samples_.begin());
    }
}

double HashrateAverager::getCurrent() const {
    if (samples_.empty()) return 0.0;
    return samples_.back().hashrate;
}

double HashrateAverager::getAverage1m() const {
    return calculateAverage(60);
}

double HashrateAverager::getAverage5m() const {
    return calculateAverage(300);
}

double HashrateAverager::getAverage15m() const {
    return calculateAverage(900);
}

double HashrateAverager::calculateAverage(int seconds) const {
    if (samples_.empty()) return 0.0;

    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::seconds(seconds);

    double sum = 0.0;
    int count = 0;

    for (auto it = samples_.rbegin(); it != samples_.rend(); ++it) {
        if (it->timestamp >= cutoff) {
            sum += it->hashrate;
            count++;
        } else {
            break;  // Samples are ordered by time
        }
    }

    return count > 0 ? sum / count : 0.0;
}

void HashrateAverager::reset() {
    samples_.clear();
    peak_hashrate_ = 0.0;
}

// ============================================================================
// Helper Functions
// ============================================================================

std::string centerText(const std::string& text, int width) {
    if (static_cast<int>(text.size()) >= width) return text.substr(0, width);
    int padding = (width - static_cast<int>(text.size())) / 2;
    return std::string(padding, ' ') + text + std::string(width - padding - text.size(), ' ');
}

std::string leftAlign(const std::string& text, int width) {
    if (static_cast<int>(text.size()) >= width) return text.substr(0, width);
    return text + std::string(width - text.size(), ' ');
}

std::string rightAlign(const std::string& text, int width) {
    if (static_cast<int>(text.size()) >= width) return text.substr(0, width);
    return std::string(width - text.size(), ' ') + text;
}

std::string truncate(const std::string& text, int maxWidth) {
    if (static_cast<int>(text.size()) <= maxWidth) return text;
    if (maxWidth <= 3) return text.substr(0, maxWidth);
    return text.substr(0, maxWidth - 3) + "...";
}

std::string formatNumber(double value, int precision) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(precision) << value;
    return ss.str();
}

std::string formatHashrate(double hashrate) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2);

    if (hashrate >= 1e15) {
        ss << (hashrate / 1e15) << " PH/s";
    } else if (hashrate >= 1e12) {
        ss << (hashrate / 1e12) << " TH/s";
    } else if (hashrate >= 1e9) {
        ss << (hashrate / 1e9) << " GH/s";
    } else if (hashrate >= 1e6) {
        ss << (hashrate / 1e6) << " MH/s";
    } else if (hashrate >= 1e3) {
        ss << (hashrate / 1e3) << " KH/s";
    } else {
        ss << hashrate << " H/s";
    }

    return ss.str();
}

std::string formatDuration(int64_t seconds) {
    std::ostringstream ss;

    if (seconds < 60) {
        ss << seconds << "s";
    } else if (seconds < 3600) {
        ss << (seconds / 60) << "m " << (seconds % 60) << "s";
    } else if (seconds < 86400) {
        ss << (seconds / 3600) << "h " << ((seconds % 3600) / 60) << "m";
    } else {
        ss << (seconds / 86400) << "d " << ((seconds % 86400) / 3600) << "h";
    }

    return ss.str();
}

std::string formatSize(uint64_t bytes) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1);

    if (bytes >= 1ULL << 40) {
        ss << static_cast<double>(bytes) / (1ULL << 40) << " TB";
    } else if (bytes >= 1ULL << 30) {
        ss << static_cast<double>(bytes) / (1ULL << 30) << " GB";
    } else if (bytes >= 1ULL << 20) {
        ss << static_cast<double>(bytes) / (1ULL << 20) << " MB";
    } else if (bytes >= 1ULL << 10) {
        ss << static_cast<double>(bytes) / (1ULL << 10) << " KB";
    } else {
        ss << bytes << " B";
    }

    return ss.str();
}

} // namespace tui
