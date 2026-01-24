#include "terminal.h"
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#endif

namespace tui {

bool Terminal::initialized_ = false;

#ifdef _WIN32
void* Terminal::original_mode_ = nullptr;

void Terminal::init() {
    if (initialized_) return;

    // Enable ANSI escape codes on Windows 10+
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hOut, &mode);
    original_mode_ = reinterpret_cast<void*>(static_cast<uintptr_t>(mode));

    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, mode);

    // Set console to UTF-8
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    initialized_ = true;
}

void Terminal::cleanup() {
    if (!initialized_) return;

    // Restore original console mode
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = static_cast<DWORD>(reinterpret_cast<uintptr_t>(original_mode_));
    SetConsoleMode(hOut, mode);

    showCursor();
    std::cout << reset();

    initialized_ = false;
}

void Terminal::getSize(int& width, int& height) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
    width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    height = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
}

bool Terminal::kbhit() {
    return _kbhit() != 0;
}

int Terminal::getch() {
    return _getch();
}

#else // POSIX

void Terminal::init() {
    if (initialized_) return;
    initialized_ = true;
}

void Terminal::cleanup() {
    if (!initialized_) return;
    showCursor();
    std::cout << reset();
    initialized_ = false;
}

void Terminal::getSize(int& width, int& height) {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    width = w.ws_col;
    height = w.ws_row;
}

bool Terminal::kbhit() {
    struct termios oldt, newt;
    int ch;
    int oldf;

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);

    ch = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fcntl(STDIN_FILENO, F_SETFL, oldf);

    if (ch != EOF) {
        ungetc(ch, stdin);
        return true;
    }

    return false;
}

int Terminal::getch() {
    struct termios oldt, newt;
    int ch;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return ch;
}

#endif

void Terminal::clear() {
    std::cout << "\033[2J\033[H";
}

void Terminal::clearLine() {
    std::cout << "\033[2K";
}

void Terminal::moveTo(int x, int y) {
    std::cout << "\033[" << y << ";" << x << "H";
}

void Terminal::moveUp(int n) {
    std::cout << "\033[" << n << "A";
}

void Terminal::moveDown(int n) {
    std::cout << "\033[" << n << "B";
}

void Terminal::moveRight(int n) {
    std::cout << "\033[" << n << "C";
}

void Terminal::moveLeft(int n) {
    std::cout << "\033[" << n << "D";
}

void Terminal::saveCursor() {
    std::cout << "\033[s";
}

void Terminal::restoreCursor() {
    std::cout << "\033[u";
}

void Terminal::hideCursor() {
    std::cout << "\033[?25l";
}

void Terminal::showCursor() {
    std::cout << "\033[?25h";
}

std::string Terminal::fg(Color color) {
    if (color == Color::Default) return "\033[39m";
    int code = static_cast<int>(color);
    if (code < 8) {
        return "\033[" + std::to_string(30 + code) + "m";
    } else {
        return "\033[" + std::to_string(82 + code) + "m";  // 90-97 for bright
    }
}

std::string Terminal::bg(Color color) {
    if (color == Color::Default) return "\033[49m";
    int code = static_cast<int>(color);
    if (code < 8) {
        return "\033[" + std::to_string(40 + code) + "m";
    } else {
        return "\033[" + std::to_string(92 + code) + "m";  // 100-107 for bright
    }
}

std::string Terminal::style(Style s) {
    return "\033[" + std::to_string(static_cast<int>(s)) + "m";
}

std::string Terminal::reset() {
    return "\033[0m";
}

std::string Terminal::fgRGB(uint8_t r, uint8_t g, uint8_t b) {
    std::ostringstream ss;
    ss << "\033[38;2;" << static_cast<int>(r) << ";"
       << static_cast<int>(g) << ";" << static_cast<int>(b) << "m";
    return ss.str();
}

std::string Terminal::bgRGB(uint8_t r, uint8_t g, uint8_t b) {
    std::ostringstream ss;
    ss << "\033[48;2;" << static_cast<int>(r) << ";"
       << static_cast<int>(g) << ";" << static_cast<int>(b) << "m";
    return ss.str();
}

} // namespace tui
