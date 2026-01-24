#include "https_client.h"
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

namespace net {

static bool parseUrl(const std::string& url, std::wstring& host, std::wstring& path, INTERNET_PORT& port, bool& https) {
    https = false;
    port = 80;

    std::string clean_url = url;

    // Check protocol
    if (clean_url.substr(0, 8) == "https://") {
        https = true;
        port = 443;
        clean_url = clean_url.substr(8);
    } else if (clean_url.substr(0, 7) == "http://") {
        clean_url = clean_url.substr(7);
    }

    // Split host and path
    size_t path_start = clean_url.find('/');
    std::string host_part;
    std::string path_part = "/";

    if (path_start != std::string::npos) {
        host_part = clean_url.substr(0, path_start);
        path_part = clean_url.substr(path_start);
    } else {
        host_part = clean_url;
    }

    // Check for port in host
    size_t port_pos = host_part.rfind(':');
    if (port_pos != std::string::npos) {
        port = static_cast<INTERNET_PORT>(std::stoi(host_part.substr(port_pos + 1)));
        host_part = host_part.substr(0, port_pos);
    }

    // Convert to wide strings
    host = std::wstring(host_part.begin(), host_part.end());
    path = std::wstring(path_part.begin(), path_part.end());

    return !host.empty();
}

HttpsClient::Response HttpsClient::get(const std::string& url) {
    Response response;

    std::wstring host, path;
    INTERNET_PORT port;
    bool https;

    if (!parseUrl(url, host, path, port, https)) {
        response.error = "Invalid URL";
        return response;
    }

    // Open WinHTTP session
    HINTERNET session = WinHttpOpen(
        L"FTC-Miner/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!session) {
        response.error = "Failed to open WinHTTP session";
        return response;
    }

    // Connect to server
    HINTERNET connect = WinHttpConnect(session, host.c_str(), port, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        response.error = "Failed to connect to " + std::string(host.begin(), host.end());
        return response;
    }

    // Open request
    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(
        connect,
        L"GET",
        path.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags
    );

    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        response.error = "Failed to open request";
        return response;
    }

    // Set timeouts (10 seconds)
    WinHttpSetTimeouts(request, 10000, 10000, 10000, 10000);

    // Send request
    BOOL result = WinHttpSendRequest(
        request,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0
    );

    if (!result) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        response.error = "Failed to send request";
        return response;
    }

    // Receive response
    result = WinHttpReceiveResponse(request, NULL);
    if (!result) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        response.error = "Failed to receive response";
        return response;
    }

    // Get status code
    DWORD status_code = 0;
    DWORD size = sizeof(status_code);
    WinHttpQueryHeaders(
        request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &status_code,
        &size,
        WINHTTP_NO_HEADER_INDEX
    );
    response.status_code = static_cast<int>(status_code);

    // Read body
    DWORD bytes_available = 0;
    do {
        bytes_available = 0;
        WinHttpQueryDataAvailable(request, &bytes_available);

        if (bytes_available > 0) {
            char* buffer = new char[bytes_available + 1];
            DWORD bytes_read = 0;

            if (WinHttpReadData(request, buffer, bytes_available, &bytes_read)) {
                buffer[bytes_read] = '\0';
                response.body.append(buffer, bytes_read);
            }

            delete[] buffer;
        }
    } while (bytes_available > 0);

    // Cleanup
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    return response;
}

HttpsClient::Response HttpsClient::post(const std::string& url, const std::string& body,
                                        const std::string& content_type) {
    Response response;

    std::wstring host, path;
    INTERNET_PORT port;
    bool https;

    if (!parseUrl(url, host, path, port, https)) {
        response.error = "Invalid URL";
        return response;
    }

    HINTERNET session = WinHttpOpen(
        L"FTC-Miner/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!session) {
        response.error = "Failed to open WinHTTP session";
        return response;
    }

    HINTERNET connect = WinHttpConnect(session, host.c_str(), port, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        response.error = "Failed to connect";
        return response;
    }

    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(
        connect,
        L"POST",
        path.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags
    );

    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        response.error = "Failed to open request";
        return response;
    }

    WinHttpSetTimeouts(request, 10000, 10000, 10000, 10000);

    // Set Content-Type header
    std::wstring headers = L"Content-Type: " + std::wstring(content_type.begin(), content_type.end());

    BOOL result = WinHttpSendRequest(
        request,
        headers.c_str(),
        static_cast<DWORD>(headers.length()),
        (LPVOID)body.c_str(),
        static_cast<DWORD>(body.length()),
        static_cast<DWORD>(body.length()),
        0
    );

    if (!result) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        response.error = "Failed to send request";
        return response;
    }

    result = WinHttpReceiveResponse(request, NULL);
    if (!result) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        response.error = "Failed to receive response";
        return response;
    }

    DWORD status_code = 0;
    DWORD size = sizeof(status_code);
    WinHttpQueryHeaders(
        request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &status_code,
        &size,
        WINHTTP_NO_HEADER_INDEX
    );
    response.status_code = static_cast<int>(status_code);

    DWORD bytes_available = 0;
    do {
        bytes_available = 0;
        WinHttpQueryDataAvailable(request, &bytes_available);

        if (bytes_available > 0) {
            char* buffer = new char[bytes_available + 1];
            DWORD bytes_read = 0;

            if (WinHttpReadData(request, buffer, bytes_available, &bytes_read)) {
                buffer[bytes_read] = '\0';
                response.body.append(buffer, bytes_read);
            }

            delete[] buffer;
        }
    } while (bytes_available > 0);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    return response;
}

std::string HttpsClient::discoverNode(const std::string& api_url) {
    Response resp = get(api_url);

    if (!resp.success()) {
        std::cerr << "Discovery failed: " << resp.error << " (status: " << resp.status_code << ")\n";
        return "";
    }

    // Parse JSON response: {"ip":"...","port":...,"apiPort":...}
    std::string body = resp.body;

    // Extract IP (can be IPv6)
    size_t ip_pos = body.find("\"ip\":\"");
    if (ip_pos == std::string::npos) {
        std::cerr << "Discovery: no IP in response\n";
        return "";
    }
    ip_pos += 6;
    size_t ip_end = body.find('"', ip_pos);
    if (ip_end == std::string::npos) return "";
    std::string ip = body.substr(ip_pos, ip_end - ip_pos);

    // Extract apiPort
    size_t port_pos = body.find("\"apiPort\":");
    if (port_pos == std::string::npos) {
        // Fallback to "port" + 1
        port_pos = body.find("\"port\":");
        if (port_pos == std::string::npos) return "";
        port_pos += 7;
        int port = std::stoi(body.substr(port_pos));
        port += 1;  // API port is P2P port + 1

        // Format result (IPv6 needs brackets)
        if (ip.find(':') != std::string::npos) {
            return "[" + ip + "]:" + std::to_string(port);
        }
        return ip + ":" + std::to_string(port);
    }

    port_pos += 10;
    int api_port = std::stoi(body.substr(port_pos));

    // Format result
    if (ip.find(':') != std::string::npos) {
        return "[" + ip + "]:" + std::to_string(api_port);
    }
    return ip + ":" + std::to_string(api_port);
}

} // namespace net

#else
// Linux implementation using libcurl (TODO)
// For now, a simple stub

#include <cstdlib>

namespace net {

HttpsClient::Response HttpsClient::get(const std::string& url) {
    Response response;

    // Use curl command as fallback
    std::string cmd = "curl -s -m 10 \"" + url + "\" 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");

    if (!pipe) {
        response.error = "Failed to execute curl";
        return response;
    }

    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        response.body += buffer;
    }

    int status = pclose(pipe);
    response.status_code = (status == 0) ? 200 : 500;

    return response;
}

HttpsClient::Response HttpsClient::post(const std::string& url, const std::string& body,
                                        const std::string& content_type) {
    Response response;

    std::string cmd = "curl -s -m 10 -X POST -H \"Content-Type: " + content_type +
                      "\" -d '" + body + "' \"" + url + "\" 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");

    if (!pipe) {
        response.error = "Failed to execute curl";
        return response;
    }

    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        response.body += buffer;
    }

    int status = pclose(pipe);
    response.status_code = (status == 0) ? 200 : 500;

    return response;
}

std::string HttpsClient::discoverNode(const std::string& api_url) {
    Response resp = get(api_url);

    if (!resp.success() || resp.body.empty()) {
        return "";
    }

    // Same parsing as Windows
    std::string body = resp.body;

    size_t ip_pos = body.find("\"ip\":\"");
    if (ip_pos == std::string::npos) return "";
    ip_pos += 6;
    size_t ip_end = body.find('"', ip_pos);
    if (ip_end == std::string::npos) return "";
    std::string ip = body.substr(ip_pos, ip_end - ip_pos);

    size_t port_pos = body.find("\"apiPort\":");
    if (port_pos == std::string::npos) {
        port_pos = body.find("\"port\":");
        if (port_pos == std::string::npos) return "";
        port_pos += 7;
        int port = std::stoi(body.substr(port_pos));
        port += 1;

        if (ip.find(':') != std::string::npos) {
            return "[" + ip + "]:" + std::to_string(port);
        }
        return ip + ":" + std::to_string(port);
    }

    port_pos += 10;
    int api_port = std::stoi(body.substr(port_pos));

    if (ip.find(':') != std::string::npos) {
        return "[" + ip + "]:" + std::to_string(api_port);
    }
    return ip + ":" + std::to_string(api_port);
}

} // namespace net

#endif
