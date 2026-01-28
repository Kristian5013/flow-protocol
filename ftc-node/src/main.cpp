/**
 * FTC Node - Flow Token Chain
 * Background node daemon with HTTP API.
 *
 * HTTP API: http://localhost:17319
 *
 * Author: Kristian Pilatovich
 * Genesis: "Kristian Pilatovich 20091227 - First Real P2P"
 */

#include "node.h"
#include "util/config.h"
#include "util/logging.h"

#include <fstream>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>
#else
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

// ============================================================================
// Windows System Tray
// ============================================================================

#ifdef _WIN32
#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_EXIT 1001
#define ID_TRAY_STATUS 1002

static NOTIFYICONDATAW g_nid = {};
static HWND g_hwnd = nullptr;
static HMENU g_menu = nullptr;
#endif

// ============================================================================
// Globals
// ============================================================================

static ftc::Node* g_node = nullptr;

// ============================================================================
// Signal Handlers
// ============================================================================

#ifdef _WIN32
static BOOL WINAPI consoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) {
        if (g_node) {
            g_node->requestShutdown();
        }
        return TRUE;
    }
    return FALSE;
}

static LRESULT CALLBACK TrayWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_TRAYICON:
            if (lParam == WM_RBUTTONUP || lParam == WM_LBUTTONUP) {
                POINT pt;
                GetCursorPos(&pt);
                SetForegroundWindow(hwnd);
                TrackPopupMenu(g_menu, TPM_RIGHTALIGN | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hwnd, NULL);
                PostMessage(hwnd, WM_NULL, 0, 0);
            }
            return 0;

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_TRAY_EXIT:
                    if (g_node) {
                        g_node->requestShutdown();
                    }
                    return 0;
            }
            break;

        case WM_DESTROY:
            Shell_NotifyIconW(NIM_DELETE, &g_nid);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

static void createTrayIcon(HINSTANCE hInstance) {
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = TrayWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"FTCNodeTray";
    RegisterClassExW(&wc);

    g_hwnd = CreateWindowExW(0, L"FTCNodeTray", L"FTC Node", 0,
                              0, 0, 0, 0, HWND_MESSAGE, NULL, hInstance, NULL);

    g_menu = CreatePopupMenu();
    AppendMenuW(g_menu, MF_STRING | MF_GRAYED, ID_TRAY_STATUS, L"FTC Node Running");
    AppendMenuW(g_menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(g_menu, MF_STRING, ID_TRAY_EXIT, L"Stop Node && Exit");

    g_nid.cbSize = sizeof(NOTIFYICONDATAW);
    g_nid.hWnd = g_hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcscpy_s(g_nid.szTip, L"FTC Node - Running");

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(exePath, L'\\');
    if (lastSlash) {
        wcscpy_s(lastSlash + 1, MAX_PATH - (lastSlash - exePath + 1), L"ftc-node.ico");
        HICON customIcon = (HICON)LoadImageW(NULL, exePath, IMAGE_ICON, 0, 0, LR_LOADFROMFILE);
        if (customIcon) {
            g_nid.hIcon = customIcon;
        }
    }

    Shell_NotifyIconW(NIM_ADD, &g_nid);
}

static void removeTrayIcon() {
    if (g_nid.hWnd) {
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
    }
    if (g_menu) {
        DestroyMenu(g_menu);
        g_menu = nullptr;
    }
    if (g_hwnd) {
        DestroyWindow(g_hwnd);
        g_hwnd = nullptr;
    }
}

static void processTrayMessages() {
    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

#else
static void signalHandler(int sig) {
    (void)sig;
    if (g_node) {
        g_node->requestShutdown();
    }
}
#endif

// ============================================================================
// PID File Management
// ============================================================================

static std::string getPidFilePath(const std::string& data_dir) {
#ifdef _WIN32
    return data_dir + "\\ftc.pid";
#else
    return data_dir + "/ftc.pid";
#endif
}

static bool writePidFile(const std::string& path, uint32_t pid) {
    std::ofstream f(path);
    if (!f) return false;
    f << pid;
    return f.good();
}

static uint32_t readPidFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) return 0;
    uint32_t pid = 0;
    f >> pid;
    return pid;
}

static void removePidFile(const std::string& path) {
    std::remove(path.c_str());
}

static bool isProcessRunning(uint32_t pid) {
    if (pid == 0) return false;
#ifdef _WIN32
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process) {
        DWORD exitCode;
        bool running = GetExitCodeProcess(process, &exitCode) && exitCode == STILL_ACTIVE;
        CloseHandle(process);
        return running;
    }
    return false;
#else
    return kill(pid, 0) == 0;
#endif
}

// ============================================================================
// Run Node
// ============================================================================

#ifdef _WIN32
static int runNode(const std::string& data_dir, HINSTANCE hInstance) {
#else
static int runNode(const std::string& data_dir) {
#endif
    ftc::util::Config config;
    config.data_dir = data_dir;

#ifdef _WIN32
    CreateDirectoryA(config.data_dir.c_str(), NULL);
    config.log_file = config.data_dir + "\\debug.log";
#else
    mkdir(config.data_dir.c_str(), 0755);
    config.log_file = config.data_dir + "/debug.log";
#endif

    ftc::log::init(config.log_level, config.log_file);

    std::string pid_path = getPidFilePath(config.data_dir);
#ifdef _WIN32
    writePidFile(pid_path, GetCurrentProcessId());
#else
    writePidFile(pid_path, getpid());
#endif

    ftc::Node node(config);
    g_node = &node;

#ifdef _WIN32
    SetConsoleCtrlHandler(consoleHandler, TRUE);
#else
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGPIPE, SIG_IGN);
#endif

    if (!node.start()) {
        removePidFile(pid_path);
        return 1;
    }

#ifdef _WIN32
    createTrayIcon(hInstance);
    while (!node.isShutdownRequested()) {
        processTrayMessages();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    removeTrayIcon();
#else
    node.waitForShutdown();
#endif

    node.stop();
    g_node = nullptr;
    removePidFile(pid_path);

    return 0;
}

// ============================================================================
// Entry Point
// ============================================================================

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;

    std::string data_dir = ftc::util::Config::getDefaultDataDir();
    std::string pid_path = getPidFilePath(data_dir);
    uint32_t existing_pid = readPidFile(pid_path);

    if (existing_pid && isProcessRunning(existing_pid)) {
        return 0; // Already running
    }
    if (existing_pid) {
        removePidFile(pid_path);
    }

    return runNode(data_dir, hInstance);
}

#else
// Linux/Unix
int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    std::string data_dir = ftc::util::Config::getDefaultDataDir();
    std::string pid_path = getPidFilePath(data_dir);
    uint32_t existing_pid = readPidFile(pid_path);

    if (existing_pid && isProcessRunning(existing_pid)) {
        return 0; // Already running
    }
    if (existing_pid) {
        removePidFile(pid_path);
    }

    // Fork to background
    pid_t pid = fork();
    if (pid < 0) return 1;
    if (pid > 0) return 0;

    setsid();
    // Redirect standard streams to /dev/null for daemon mode
    if (!freopen("/dev/null", "r", stdin)) { /* ignore */ }
    if (!freopen("/dev/null", "w", stdout)) { /* ignore */ }
    if (!freopen("/dev/null", "w", stderr)) { /* ignore */ }

    return runNode(data_dir);
}
#endif
