#include "seed_client.h"
#include <cstring>
#include <set>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

namespace seed {

SeedClient::SeedClient(uint16_t default_port)
    : default_port_(default_port)
    , discovered_count_(0)
{
}

void SeedClient::addSeed(const std::string& hostname) {
    seeds_.push_back(hostname);
}

std::vector<std::string> SeedClient::resolveDNS(const std::string& hostname) {
    std::vector<std::string> addresses;

    struct addrinfo hints;
    struct addrinfo* result = nullptr;

    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
    if (status != 0) {
        return addresses;
    }

    for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
        char ip[INET6_ADDRSTRLEN];

        if (rp->ai_family == AF_INET) {
            // IPv4
            struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(rp->ai_addr);
            inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
            addresses.push_back(ip);
        } else if (rp->ai_family == AF_INET6) {
            // IPv6
            struct sockaddr_in6* addr = reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr);
            inet_ntop(AF_INET6, &addr->sin6_addr, ip, sizeof(ip));
            addresses.push_back(ip);
        }
    }

    freeaddrinfo(result);
    return addresses;
}

std::vector<PeerInfo> SeedClient::discoverPeers() {
    std::set<std::string> unique_ips;
    std::vector<PeerInfo> peers;

    for (const auto& seed : seeds_) {
        auto addresses = resolveDNS(seed);

        for (const auto& ip : addresses) {
            // Skip duplicates
            if (unique_ips.count(ip) > 0) {
                continue;
            }
            unique_ips.insert(ip);

            PeerInfo peer;
            peer.ip = ip;
            peer.port = default_port_;
            peers.push_back(peer);
        }
    }

    discovered_count_ = peers.size();

    if (on_peers_discovered_ && !peers.empty()) {
        on_peers_discovered_(peers);
    }

    return peers;
}

} // namespace seed
