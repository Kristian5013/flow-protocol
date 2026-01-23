#ifndef FTC_VERSION_H
#define FTC_VERSION_H

#define FTC_VERSION_MAJOR 1
#define FTC_VERSION_MINOR 0
#define FTC_VERSION_PATCH 0

#define FTC_VERSION_STRING "1.0.0"
#define FTC_VERSION_NAME "Flow Token Chain"

#define FTC_GENESIS_MESSAGE "Kristian Pilatovich 20091227 - First Real P2P"
#define FTC_GENESIS_TIME 1737331200  // 2026-01-20 00:00:00 UTC

// Network magic bytes
#define FTC_MAGIC_MAINNET 0x46544301  // "FTC\x01"
#define FTC_MAGIC_TESTNET 0x46544354  // "FTCT"

// Protocol version
#define FTC_PROTOCOL_VERSION 1

// Network ports
#define FTC_PORT_DISCOVERY 17317
#define FTC_PORT_P2P       17318
#define FTC_PORT_API       17319
#define FTC_PORT_STRATUM   3333

// Discovery magic
#define FTC_DISCOVERY_MAGIC_V4 0x46544334  // "FTC4"
#define FTC_DISCOVERY_MAGIC_V6 0x46544336  // "FTC6"

#endif // FTC_VERSION_H
