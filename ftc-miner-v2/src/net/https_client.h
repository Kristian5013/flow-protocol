#ifndef FTC_MINER_NET_HTTPS_CLIENT_H
#define FTC_MINER_NET_HTTPS_CLIENT_H

#include <string>
#include <optional>

namespace net {

// Simple HTTPS client for auto-discovery
// Uses WinHTTP on Windows
class HttpsClient {
public:
    struct Response {
        int status_code = 0;
        std::string body;
        std::string error;
        bool success() const { return status_code >= 200 && status_code < 300; }
    };

    // Perform HTTPS GET request
    static Response get(const std::string& url);

    // Perform HTTPS POST request
    static Response post(const std::string& url, const std::string& body,
                        const std::string& content_type = "application/json");

    // Parse node info from API response (deprecated - use local node)
    // Returns host:port string or empty on error
    static std::string discoverNode(const std::string& api_url = "http://localhost:17319");
};

} // namespace net

#endif // FTC_MINER_NET_HTTPS_CLIENT_H
