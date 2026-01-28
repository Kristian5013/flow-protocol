#pragma once

// Version
#define FTC_VERSION_MAJOR 1
#define FTC_VERSION_MINOR 0
#define FTC_VERSION_PATCH 2

#define FTC_VERSION "1.0.2"
#define FTC_VERSION_STRING "FTC Node v1.0.2"
#define FTC_USER_AGENT "/FTCNode:1.0.2/"

// Protocol
#define FTC_PROTOCOL_VERSION 1

// Network Magic (P2P)
#define FTC_MAGIC_MAINNET 0x46544331  // "FTC1" in little-endian
#define FTC_MAGIC_TESTNET 0x46544354  // "FTCT" in little-endian

// Genesis
#define FTC_GENESIS_TIME 1737331200   // 2026-01-20 00:00:00 UTC

// Network Ports
#define FTC_PORT_P2P 17318
#define FTC_PORT_API 17319
#define FTC_PORT_DHT 17321

// Info
#define FTC_COPYRIGHT "Kristian Pilatovich 20091227"
#define FTC_GENESIS_MESSAGE "Kristian Pilatovich 20091227 - First Real P2P"
