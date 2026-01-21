#ifndef FTC_MINER_TUI_WIDGETS_H
#define FTC_MINER_TUI_WIDGETS_H

#include "terminal.h"
#include <string>
#include <vector>
#include <functional>

namespace tui {

// Progress bar widget
class ProgressBar {
public:
    ProgressBar(int width = 30);

    void setValue(double value);  // 0.0 to 1.0
    void setColors(Color fg, Color bg);
    void setStyle(bool smooth);   // Smooth = use fractional blocks

    std::string render() const;

private:
    int width_;
    double value_;
    Color fg_color_;
    Color bg_color_;
    bool smooth_;
};

// Sparkline - mini graph
class Sparkline {
public:
    Sparkline(int width = 20);

    void addValue(double value);
    void setRange(double min, double max);
    void setColor(Color color);

    std::string render() const;

private:
    int width_;
    std::vector<double> values_;
    double min_val_;
    double max_val_;
    bool auto_range_;
    Color color_;

    static constexpr const char* BLOCKS[] = {" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
};

// Box widget
class Box {
public:
    enum class Style { Single, Double, Rounded, Heavy };

    Box(int x, int y, int width, int height, Style style = Style::Single);

    void setTitle(const std::string& title);
    void setTitleColor(Color color);
    void setBorderColor(Color color);

    void render() const;
    void clear() const;

    // Content area coordinates
    int contentX() const { return x_ + 1; }
    int contentY() const { return y_ + 1; }
    int contentWidth() const { return width_ - 2; }
    int contentHeight() const { return height_ - 2; }

private:
    int x_, y_, width_, height_;
    Style style_;
    std::string title_;
    Color title_color_;
    Color border_color_;
};

// Table widget
class Table {
public:
    Table(const std::vector<std::string>& headers, const std::vector<int>& widths);

    void addRow(const std::vector<std::string>& row);
    void clearRows();
    void setHeaderColor(Color color);
    void setRowColors(Color odd, Color even);

    std::vector<std::string> render() const;

private:
    std::vector<std::string> headers_;
    std::vector<int> widths_;
    std::vector<std::vector<std::string>> rows_;
    Color header_color_;
    Color odd_row_color_;
    Color even_row_color_;
};

// Status indicator
class StatusIndicator {
public:
    enum class State { Idle, Running, Success, Warning, Error };

    StatusIndicator();

    void setState(State state);
    void setText(const std::string& text);
    void setAnimated(bool animated);
    void tick();  // Advance animation frame

    std::string render() const;

private:
    State state_;
    std::string text_;
    bool animated_;
    int frame_;
    static constexpr const char* SPINNER[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
};

// Gauge/meter widget
class Gauge {
public:
    Gauge(const std::string& label, int width = 20);

    void setValue(double value, double max);
    void setUnit(const std::string& unit);
    void setThresholds(double warning, double critical);
    void setColors(Color normal, Color warning, Color critical);

    std::string render() const;

private:
    std::string label_;
    int width_;
    double value_;
    double max_;
    std::string unit_;
    double warning_threshold_;
    double critical_threshold_;
    Color normal_color_;
    Color warning_color_;
    Color critical_color_;
};

// Helper functions
std::string centerText(const std::string& text, int width);
std::string leftAlign(const std::string& text, int width);
std::string rightAlign(const std::string& text, int width);
std::string truncate(const std::string& text, int maxWidth);
std::string formatNumber(double value, int precision = 2);
std::string formatHashrate(double hashrate);
std::string formatDuration(int64_t seconds);
std::string formatSize(uint64_t bytes);

} // namespace tui

#endif // FTC_MINER_TUI_WIDGETS_H
