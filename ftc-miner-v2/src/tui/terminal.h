#ifndef FTC_MINER_TUI_TERMINAL_H
#define FTC_MINER_TUI_TERMINAL_H

#include <string>
#include <cstdint>

namespace tui {

// ANSI Color codes
enum class Color : uint8_t {
    Black = 0,
    Red = 1,
    Green = 2,
    Yellow = 3,
    Blue = 4,
    Magenta = 5,
    Cyan = 6,
    White = 7,
    BrightBlack = 8,
    BrightRed = 9,
    BrightGreen = 10,
    BrightYellow = 11,
    BrightBlue = 12,
    BrightMagenta = 13,
    BrightCyan = 14,
    BrightWhite = 15,
    Default = 255
};

// Text style
enum class Style : uint8_t {
    Normal = 0,
    Bold = 1,
    Dim = 2,
    Italic = 3,
    Underline = 4,
    Blink = 5,
    Reverse = 7,
    Hidden = 8
};

// Terminal control class
class Terminal {
public:
    static void init();
    static void cleanup();

    // Screen control
    static void clear();
    static void clearLine();
    static void getSize(int& width, int& height);

    // Cursor control
    static void moveTo(int x, int y);
    static void moveUp(int n = 1);
    static void moveDown(int n = 1);
    static void moveLeft(int n = 1);
    static void moveRight(int n = 1);
    static void saveCursor();
    static void restoreCursor();
    static void hideCursor();
    static void showCursor();

    // Colors and styles
    static std::string fg(Color color);
    static std::string bg(Color color);
    static std::string style(Style s);
    static std::string reset();

    // RGB colors (true color)
    static std::string fgRGB(uint8_t r, uint8_t g, uint8_t b);
    static std::string bgRGB(uint8_t r, uint8_t g, uint8_t b);

    // Box drawing characters (Unicode)
    static constexpr const char* BOX_TL = "┌";  // Top-left
    static constexpr const char* BOX_TR = "┐";  // Top-right
    static constexpr const char* BOX_BL = "└";  // Bottom-left
    static constexpr const char* BOX_BR = "┘";  // Bottom-right
    static constexpr const char* BOX_H  = "─";  // Horizontal
    static constexpr const char* BOX_V  = "│";  // Vertical
    static constexpr const char* BOX_LT = "├";  // Left-T
    static constexpr const char* BOX_RT = "┤";  // Right-T
    static constexpr const char* BOX_TT = "┬";  // Top-T
    static constexpr const char* BOX_BT = "┴";  // Bottom-T
    static constexpr const char* BOX_X  = "┼";  // Cross

    // Double-line box
    static constexpr const char* DBOX_TL = "╔";
    static constexpr const char* DBOX_TR = "╗";
    static constexpr const char* DBOX_BL = "╚";
    static constexpr const char* DBOX_BR = "╝";
    static constexpr const char* DBOX_H  = "═";
    static constexpr const char* DBOX_V  = "║";

    // Block characters for progress bars
    static constexpr const char* BLOCK_FULL   = "█";
    static constexpr const char* BLOCK_7_8    = "▉";
    static constexpr const char* BLOCK_3_4    = "▊";
    static constexpr const char* BLOCK_5_8    = "▋";
    static constexpr const char* BLOCK_1_2    = "▌";
    static constexpr const char* BLOCK_3_8    = "▍";
    static constexpr const char* BLOCK_1_4    = "▎";
    static constexpr const char* BLOCK_1_8    = "▏";
    static constexpr const char* BLOCK_EMPTY  = " ";

    // Symbols
    static constexpr const char* SYM_CHECK    = "✓";
    static constexpr const char* SYM_CROSS    = "✗";
    static constexpr const char* SYM_BULLET   = "●";
    static constexpr const char* SYM_CIRCLE   = "○";
    static constexpr const char* SYM_ARROW_R  = "→";
    static constexpr const char* SYM_ARROW_L  = "←";
    static constexpr const char* SYM_ARROW_U  = "↑";
    static constexpr const char* SYM_ARROW_D  = "↓";
    static constexpr const char* SYM_DIAMOND  = "◆";
    static constexpr const char* SYM_STAR     = "★";

    // Input handling
    static bool kbhit();
    static int getch();

private:
    static bool initialized_;
#ifdef _WIN32
    static void* original_mode_;
#endif
};

} // namespace tui

#endif // FTC_MINER_TUI_TERMINAL_H
