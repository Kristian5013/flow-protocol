/**
 * FTC Full - Combined Node + Miner Launcher
 *
 * Kristian Pilatovich 20091227 - First Real P2P
 *
 * Cross-platform launcher for Windows and Linux:
 * 1. Starts ftc-node in background
 * 2. Waits for node to be ready
 * 3. Starts ftc-miner connected to local node
 */

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstring>
#include <csignal>
#include <atomic>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#endif

static std::atomic<bool> g_shutdown{false};

#ifdef _WIN32
static HANDLE g_node_process = NULL;
static HANDLE g_miner_process = NULL;
#else
static pid_t g_node_pid = 0;
static pid_t g_miner_pid = 0;
#endif

void signalHandler(int sig) {
    g_shutdown = true;
}

// ============================================================================
// Platform-specific implementations
// ============================================================================

#ifdef _WIN32

bool isNodeReady() {
    HINTERNET session = WinHttpOpen(L"FTC-Full/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return false;

    HINTERNET connect = WinHttpConnect(session, L"127.0.0.1", 17319, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        return false;
    }

    HINTERNET request = WinHttpOpenRequest(connect, L"GET", L"/status", NULL,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }

    WinHttpSetTimeouts(request, 2000, 2000, 2000, 2000);
    BOOL result = WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                     WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (result) result = WinHttpReceiveResponse(request, NULL);

    bool ready = false;
    if (result) {
        DWORD status = 0;
        DWORD size = sizeof(status);
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX);
        ready = (status == 200);
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return ready;
}

std::string getExeDir() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string dir = path;
    size_t pos = dir.find_last_of("\\/");
    if (pos != std::string::npos) dir = dir.substr(0, pos);
    return dir;
}

bool startNode(const std::string& exe_dir) {
    std::string exe = exe_dir + "\\ftc-node.exe";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    char cmd[512];
    strcpy(cmd, exe.c_str());

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        return false;
    }

    CloseHandle(pi.hThread);
    g_node_process = pi.hProcess;
    return true;
}

bool startMiner(const std::string& exe_dir, const std::string& args) {
    std::string exe = exe_dir + "\\ftc-miner.exe";
    std::string cmdLine = exe + " " + args;

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    char* cmd = new char[cmdLine.size() + 1];
    strcpy(cmd, cmdLine.c_str());

    BOOL result = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    delete[] cmd;

    if (!result) return false;

    CloseHandle(pi.hThread);
    g_miner_process = pi.hProcess;
    return true;
}

bool isNodeRunning() {
    if (!g_node_process) return false;
    DWORD exit_code;
    return GetExitCodeProcess(g_node_process, &exit_code) && exit_code == STILL_ACTIVE;
}

void waitForMiner() {
    if (g_miner_process) {
        WaitForSingleObject(g_miner_process, INFINITE);
        CloseHandle(g_miner_process);
        g_miner_process = NULL;
    }
}

void stopNode() {
    if (g_node_process) {
        TerminateProcess(g_node_process, 0);
        CloseHandle(g_node_process);
        g_node_process = NULL;
    }
}

#else // Linux

bool isNodeReady() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(17319);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return false;
    }

    const char* request = "GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    send(sock, request, strlen(request), 0);

    char buffer[1024];
    int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    close(sock);

    if (received <= 0) return false;
    buffer[received] = '\0';

    return strstr(buffer, "200 OK") != nullptr;
}

std::string getExeDir() {
    char path[1024];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len <= 0) return ".";
    path[len] = '\0';

    std::string dir = path;
    size_t pos = dir.find_last_of('/');
    if (pos != std::string::npos) dir = dir.substr(0, pos);
    return dir;
}

bool startNode(const std::string& exe_dir) {
    std::string exe = exe_dir + "/ftc-node";

    pid_t pid = fork();
    if (pid < 0) return false;

    if (pid == 0) {
        // Child process
        setsid();  // Create new session
        execl(exe.c_str(), "ftc-node", nullptr);
        _exit(1);
    }

    g_node_pid = pid;
    return true;
}

bool startMiner(const std::string& exe_dir, const std::string& args) {
    std::string exe = exe_dir + "/ftc-miner";

    pid_t pid = fork();
    if (pid < 0) return false;

    if (pid == 0) {
        // Child process - parse args and exec
        // Simple arg parsing for common cases
        std::vector<const char*> argv;
        argv.push_back("ftc-miner");

        // Parse args string into tokens
        std::string args_copy = args;
        char* token = strtok(&args_copy[0], " ");
        std::vector<std::string> arg_storage;

        while (token) {
            arg_storage.push_back(token);
            token = strtok(nullptr, " ");
        }

        for (const auto& arg : arg_storage) {
            argv.push_back(arg.c_str());
        }
        argv.push_back(nullptr);

        execv(exe.c_str(), const_cast<char* const*>(argv.data()));
        _exit(1);
    }

    g_miner_pid = pid;
    return true;
}

bool isNodeRunning() {
    if (g_node_pid <= 0) return false;
    return kill(g_node_pid, 0) == 0;
}

void waitForMiner() {
    if (g_miner_pid > 0) {
        int status;
        waitpid(g_miner_pid, &status, 0);
        g_miner_pid = 0;
    }
}

void stopNode() {
    if (g_node_pid > 0) {
        kill(g_node_pid, SIGTERM);
        std::this_thread::sleep_for(std::chrono::seconds(1));
        kill(g_node_pid, SIGKILL);
        waitpid(g_node_pid, nullptr, WNOHANG);
        g_node_pid = 0;
    }
}

#endif

// ============================================================================
// Common code
// ============================================================================

void printBanner() {
    std::cout << R"(
    ______________________
   / ____/_  __/ ____/    |
  / /_    / / / /   / /| |
 / __/   / / / /___/ ___ |
/_/     /_/  \____/_/  |_|  FULL

    Node + Miner Combined
    Kristian Pilatovich

)" << std::endl;
}

void printUsage() {
    std::cout << R"(
Usage: ftc-full -a <address> [options]

Required:
  -a, --address ADDR   Mining wallet address (ftc1q...)

Options:
  --node-only          Start only the node (no mining)
  --miner-only         Start only the miner (requires running node)
  -I, --intensity N    GPU intensity 8-31 (default: auto)
  --autotune           Enable AI auto-tune
  --no-tui             Disable TUI

Examples:
  ftc-full -a ftc1qwfk0r2r9f6352ad9m4nph5mh9xhrf9yukv6pap
  ftc-full -a ftc1q... --autotune

)" << std::endl;
}

int main(int argc, char** argv) {
    printBanner();

    // Install signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    // Parse arguments
    std::string wallet_address;
    std::string miner_args;
    bool node_only = false;
    bool miner_only = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-a" || arg == "--address") {
            if (i + 1 < argc) {
                wallet_address = argv[++i];
                miner_args += " -a " + wallet_address;
            }
        } else if (arg == "--node-only") {
            node_only = true;
        } else if (arg == "--miner-only") {
            miner_only = true;
        } else if (arg == "-h" || arg == "--help") {
            printUsage();
            return 0;
        } else if (arg == "-I" || arg == "--intensity") {
            if (i + 1 < argc) {
                miner_args += " -I " + std::string(argv[++i]);
            }
        } else if (arg == "--autotune") {
            miner_args += " --autotune";
        } else if (arg == "--no-tui") {
            miner_args += " --no-tui";
        }
    }

    // Validate
    if (!node_only && wallet_address.empty()) {
        std::cerr << "Error: Mining address required (-a <ftc1q...>)\n";
        printUsage();
        return 1;
    }

    if (!node_only && wallet_address.substr(0, 4) != "ftc1") {
        std::cerr << "Error: Invalid wallet address format (must start with ftc1)\n";
        return 1;
    }

    std::string exe_dir = getExeDir();

    // Start node (unless miner-only)
    if (!miner_only) {
        std::cout << "[+] Starting FTC Node...\n";

        if (isNodeReady()) {
            std::cout << "[+] Node already running on port 17319\n";
        } else {
            if (!startNode(exe_dir)) {
                std::cerr << "[-] Failed to start ftc-node\n";
                std::cerr << "    Make sure ftc-node is in the same directory\n";
                return 1;
            }

            std::cout << "[+] Waiting for node to initialize...\n";

            int wait_count = 0;
            while (!isNodeReady() && wait_count < 60 && !g_shutdown) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                wait_count++;

                if (!isNodeRunning()) {
                    std::cerr << "[-] Node exited unexpectedly\n";
                    return 1;
                }
            }

            if (!isNodeReady()) {
                std::cerr << "[-] Node failed to start within 30 seconds\n";
                stopNode();
                return 1;
            }

            std::cout << "[+] Node is ready!\n";
        }
    }

    // Start miner (unless node-only)
    if (!node_only && !g_shutdown) {
        std::cout << "[+] Starting FTC Miner...\n";

        miner_args = "-o 127.0.0.1:17319" + miner_args;

        if (!startMiner(exe_dir, miner_args)) {
            std::cerr << "[-] Failed to start ftc-miner\n";
            std::cerr << "    Make sure ftc-miner is in the same directory\n";
            stopNode();
            return 1;
        }

        std::cout << "[+] Miner started!\n";
        std::cout << "\n[*] Press Ctrl+C to stop\n\n";
    }

    // Wait for miner or shutdown
    if (!node_only) {
        waitForMiner();
    } else {
        // Node-only mode: wait for shutdown signal
        std::cout << "[*] Node running. Press Ctrl+C to stop.\n";
        while (!g_shutdown) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    // Cleanup
    if (!miner_only) {
        std::cout << "\n[*] Stopping node...\n";
        stopNode();
    }

    std::cout << "[+] Done.\n";
    return 0;
}
