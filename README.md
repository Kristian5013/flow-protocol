# FTC (Flow Token Chain)

<p align="center">
  <img src="ftc-node/assets/ftc-node.svg" alt="FTC Logo" width="200" height="200"/>
</p>

<p align="center">
  <strong>Fully Decentralized Cryptocurrency with Keccak-256 Proof-of-Work & Integrated P2Pool</strong>
</p>

<p align="center">
  <a href="https://github.com/Kristian5013/flow-protocol/releases"><img src="https://img.shields.io/github/v/release/Kristian5013/flow-protocol?style=flat-square" alt="Release"/></a>
  <a href="https://t.me/flow_protocol_main"><img src="https://img.shields.io/badge/Telegram-Join%20Chat-blue?style=flat-square&logo=telegram" alt="Telegram"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License"/></a>
</p>

---

## Overview

FTC (Flow Token Chain) is a decentralized cryptocurrency designed for true peer-to-peer mining without centralized pools. Built from scratch in C++, it combines Bitcoin-proven economics with modern technology:

- **Keccak-256 PoW** - GPU-friendly, ASIC-resistant mining algorithm
- **Integrated P2Pool** - Decentralized mining pool built into every node
- **Bitcoin Economics** - 21M max supply, halving every 210,000 blocks
- **Modern Network** - IPv6-native with DHT peer discovery
- **Full REST API** - Complete node control via HTTP

### Genesis Block

```
Message: "Kristian Pilatovich 20091227 - First Real P2P"
Date: January 20, 2026 00:00:00 UTC
```

---

## Quick Start

### Windows

1. Download `ftc-node-1.0.0-win64-setup.exe` from [Releases](https://github.com/Kristian5013/flow-protocol/releases)
2. Run installer (creates Start Menu shortcuts, configures firewall)
3. Node starts automatically as background process

**Mining:**
```cmd
ftc-miner.exe -a ftc1qYOUR_ADDRESS
```

### Linux

```bash
# Download and install
wget https://github.com/Kristian5013/flow-protocol/releases/download/v1.0.0/ftc-linux-x64.tar.gz
tar -xzf ftc-linux-x64.tar.gz
cd ftc-linux-x64
sudo ./install.sh

# Start node (systemd service)
sudo systemctl start ftc-node

# Start mining
./ftc-miner -a ftc1qYOUR_ADDRESS
```

---

## Components

| Binary | Description |
|--------|-------------|
| `ftc-node` | Full blockchain node with P2Pool (runs as daemon) |
| `ftc-miner` | GPU miner with TUI interface |

---

## Network Ports

| Port | Protocol | Description |
|------|----------|-------------|
| **17318** | TCP | P2P network (blockchain sync, block/tx relay) |
| **17319** | HTTP | REST API (node control, mining, wallet) |
| **17320** | TCP | P2Pool sharechain sync |
| **17321** | UDP | DHT peer discovery |

---

## Consensus Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| **Block Time** | 600 seconds (10 min) | Target time between blocks |
| **Initial Reward** | 50 FTC | Block reward at genesis |
| **Halving Interval** | 210,000 blocks | Reward halves (~4 years) |
| **Max Supply** | 21,000,000 FTC | Total coins ever created |
| **Difficulty Adjustment** | 2016 blocks | Retarget interval (~2 weeks) |
| **Initial Difficulty** | 256 | Genesis block difficulty |
| **Coinbase Maturity** | 100 blocks | Confirmations before spending |
| **PoW Algorithm** | Keccak-256 | SHA-3 family hash function |

### Difficulty Adjustment Algorithm

Bitcoin-style adjustment every 2016 blocks:
- Calculate actual time for last 2016 blocks
- Compare to target time (2016 * 600 = 1,209,600 seconds)
- Adjust difficulty proportionally
- Maximum 4x change per period

---

## Mining

### GPU Mining with TUI

```bash
# Basic mining (auto-connects to localhost node)
ftc-miner -a ftc1qYOUR_ADDRESS

# Connect to remote node
ftc-miner -a ftc1qYOUR_ADDRESS -o http://192.168.1.100:17319

# Benchmark mode (no node required)
ftc-miner --benchmark

# Disable TUI (simple log output)
ftc-miner -a ftc1qYOUR_ADDRESS --no-tui
```

### Mining Options

| Option | Description |
|--------|-------------|
| `-a, --address` | Payout address (required) |
| `-o, --pool` | Node URL (default: http://localhost:17319) |
| `-I, --intensity` | GPU intensity 8-31 (default: auto) |
| `--benchmark` | Benchmark mode |
| `--no-tui` | Disable terminal UI |

### P2Pool Mining

FTC uses integrated P2Pool - no separate pool software needed. All miners connected to any node form a decentralized pool with PPLNS payout scheme.

**Benefits:**
- No pool fees
- No single point of failure
- Instant payouts in coinbase
- Truly decentralized

---

## Wallet Operations

### Generate New Address

```bash
curl http://localhost:17319/wallet/new
```

Response:
```json
{
  "address": "ftc1q...",
  "private_key": "...",
  "public_key": "..."
}
```

### Check Balance

```bash
curl http://localhost:17319/balance/ftc1qYOUR_ADDRESS
```

### Send Transaction

```bash
curl -X POST http://localhost:17319/wallet/send \
  -H "Content-Type: application/json" \
  -d '{
    "private_key": "YOUR_PRIVATE_KEY",
    "to": "ftc1qRECIPIENT_ADDRESS",
    "amount": 100000000,
    "fee": 1000
  }'
```

Note: Amount and fee are in satoshis (1 FTC = 100,000,000 satoshis)

---

## HTTP API Reference

Base URL: `http://localhost:17319`

---

### Status Endpoints

#### `GET /`
Returns API info and available endpoints.

```json
{
  "name": "FTC Node API",
  "version": "1.0.0",
  "endpoints": ["/status", "/block/:id", "/tx/:txid", ...]
}
```

---

#### `GET /status`
Node status with network info.

**Response:**
```json
{
  "node": "FTC Node",
  "version": "1.0.0",
  "network": "mainnet",
  "running": true,
  "uptime": 3600,
  "chain_height": 1234,
  "best_hash": "abc123...",
  "sync_progress": 1.0,
  "mempool_size": 5,
  "mempool_bytes": 1250,
  "peer_count": 8,
  "connections": 8,
  "inbound": 3,
  "outbound": 5,
  "network_hashrate": 1000000000
}
```

---

#### `GET /health`
Health check for monitoring systems.

**Response:**
```json
{
  "status": "healthy",
  "healthy": true,
  "peers": 8,
  "height": 1234
}
```

---

#### `GET /genesis`
Genesis block information.

**Response:**
```json
{
  "message": "Kristian Pilatovich 20091227 - First Real P2P",
  "timestamp": 1737331200,
  "timestamp_utc": "2026-01-20 00:00:00 UTC",
  "hash": "...",
  "version": 1,
  "bits": 469762303,
  "nonce": 0
}
```

---

#### `GET /sync`
Detailed synchronization status.

**Response:**
```json
{
  "state": "complete",
  "current_height": 1234,
  "target_height": 1234,
  "progress": 1.0,
  "blocks_per_second": 0,
  "blocks_in_flight": 0,
  "active_peers": 5,
  "eta_seconds": 0
}
```

---

### Blockchain Endpoints

#### `GET /block/:id`
Get block by height or hash.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `id` | string/number | Block height or block hash |

**Example:**
```bash
curl http://localhost:17319/block/100
curl http://localhost:17319/block/abc123def456...
```

**Response:**
```json
{
  "hash": "abc123...",
  "version": 1,
  "prev_hash": "def456...",
  "merkle_root": "ghi789...",
  "timestamp": 1737331800,
  "bits": 469762303,
  "nonce": 12345678,
  "tx_count": 2,
  "transactions": ["txid1...", "txid2..."]
}
```

---

#### `GET /tx/:txid`
Get transaction by ID.

**Response:**
```json
{
  "txid": "abc123...",
  "version": 1,
  "locktime": 0,
  "confirmations": 6,
  "in_mempool": false,
  "input_count": 1,
  "output_count": 2
}
```

---

#### `POST /tx`
Broadcast raw transaction.

**Request Body:**
```json
{
  "hex": "0100000001..."
}
```

**Success Response:**
```json
{
  "txid": "abc123...",
  "accepted": true
}
```

**Error Codes:**

| Code | Description |
|------|-------------|
| `SCRIPT_ERROR` | Invalid transaction script |
| `DOUBLE_SPEND` | Input already spent |
| `INSUFFICIENT_FEE` | Fee too low |
| `MEMPOOL_FULL` | Mempool at capacity |
| `ALREADY_IN_MEMPOOL` | Transaction already exists |
| `MISSING_INPUTS` | Referenced UTXOs not found |
| `IMMATURE_COINBASE` | Coinbase needs 100 confirmations |
| `NEGATIVE_FEE` | Outputs exceed inputs |
| `TOO_LARGE` | Transaction size exceeds limit |
| `ALREADY_IN_CHAIN` | Already confirmed |

---

### Mempool Endpoints

#### `GET /mempool`
Mempool statistics.

**Response:**
```json
{
  "size": 5,
  "bytes": 1250,
  "total_fees": 5000,
  "min_fee_rate": 1.0
}
```

---

#### `GET /mempool/txids`
List all transaction IDs in mempool.

**Response:**
```json
{
  "count": 5,
  "txids": ["txid1...", "txid2...", ...]
}
```

---

### Address Endpoints

#### `GET /balance/:address`
Get address balance.

**Response:**
```json
{
  "address": "ftc1q...",
  "confirmed": 5000000000,
  "unconfirmed": 100000000,
  "total": 5100000000,
  "utxo_count": 3
}
```

---

#### `GET /utxo/:address`
Get unspent transaction outputs for address.

**Response:**
```json
{
  "address": "ftc1q...",
  "count": 3,
  "utxos": [
    {
      "txid": "abc123...",
      "vout": 0,
      "amount": 5000000000,
      "height": 100,
      "coinbase": true
    }
  ]
}
```

---

#### `GET /address/:addr/history`
Transaction history for address.

**Response:**
```json
{
  "address": "ftc1q...",
  "count": 5,
  "transactions": [
    {
      "txid": "abc123...",
      "type": "receive",
      "amount": 5000000000,
      "height": 100,
      "confirmations": 50,
      "coinbase": true
    }
  ]
}
```

---

### Wallet Endpoints

#### `GET /wallet/new`
Generate new wallet keypair.

**Response:**
```json
{
  "address": "ftc1q...",
  "private_key": "abc123...",
  "public_key": "def456..."
}
```

---

#### `POST /wallet/send`
Build, sign, and broadcast transaction.

**Request Body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `private_key` | string | Yes | Sender's private key (hex) |
| `to` | string | Yes | Recipient address |
| `amount` | number | Yes | Amount in satoshis |
| `fee` | number | No | Fee in satoshis (default: 1000) |

**Example:**
```bash
curl -X POST http://localhost:17319/wallet/send \
  -H "Content-Type: application/json" \
  -d '{
    "private_key": "abc123...",
    "to": "ftc1qrecipient...",
    "amount": 100000000,
    "fee": 1000
  }'
```

**Response:**
```json
{
  "txid": "abc123...",
  "from": "ftc1qsender...",
  "to": "ftc1qrecipient...",
  "amount": 100000000,
  "fee": 1000,
  "change": 4899999000,
  "inputs_used": 1
}
```

---

### Mining Endpoints

#### `GET /mining/info`
Current mining information.

**Response:**
```json
{
  "height": 1235,
  "difficulty_bits": 469762303,
  "block_reward": 5000000000,
  "block_time_target": 600,
  "difficulty_algorithm": "classic-2016",
  "difficulty_adjustment_interval": 2016
}
```

---

#### `GET /mining/template`
Get block template for mining.

**Query Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `address` | string | Yes | Payout address for coinbase |

**Example:**
```bash
curl "http://localhost:17319/mining/template?address=ftc1q..."
```

**Response:**
```json
{
  "version": 1,
  "height": 1235,
  "prev_hash": "abc123...",
  "merkle_root": "def456...",
  "timestamp": 1737332400,
  "bits": 469762303,
  "block_bits": 469762303,
  "share_bits": 486604799,
  "coinbase": "0100000001...",
  "coinbase_value": 5000001000,
  "block_reward": 5000000000,
  "total_fees": 1000,
  "tx_count": 1,
  "transactions": ["0100000001..."],
  "sharechain_tip": "ghi789...",
  "sharechain_height": 500
}
```

**Fields:**
| Field | Description |
|-------|-------------|
| `bits` | Target difficulty for block header |
| `block_bits` | Main chain difficulty |
| `share_bits` | P2Pool share difficulty (easier) |
| `coinbase` | Serialized coinbase transaction (hex) |
| `transactions` | Mempool transactions to include (hex) |

---

#### `POST /mining/submit`
Submit mined block or P2Pool share.

**Request Body:**
```json
{
  "hex": "0100000001..."
}
```

**Response (Block found):**
```json
{
  "hash": "abc123...",
  "accepted": true,
  "is_block": true,
  "share_accepted": true
}
```

**Response (Share only):**
```json
{
  "hash": "abc123...",
  "accepted": true,
  "is_block": false,
  "share_accepted": true
}
```

**Error Codes:**
| Code | Description |
|------|-------------|
| `Invalid header` | Block header malformed |
| `Invalid proof of work` | Hash doesn't meet target |
| `Invalid timestamp` | Timestamp out of range |
| `Invalid merkle root` | Merkle root mismatch |
| `Invalid coinbase` | Coinbase transaction invalid |
| `Orphan block` | Previous block unknown |

---

#### `GET /mining/generate`
CPU mining for testing (regtest only).

**Query Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `blocks` | number | 1 | Blocks to mine (1-100) |
| `address` | string | - | Payout address |

**Response:**
```json
{
  "blocks_mined": 1,
  "hashes": ["abc123..."]
}
```

---

### P2Pool Endpoints

#### `GET /p2pool/status`
P2Pool network statistics.

**Response:**
```json
{
  "enabled": true,
  "running": true,
  "sharechain_height": 500,
  "sharechain_tip": "abc123...",
  "pool_hashrate": 5000000000,
  "active_miners": 10,
  "total_shares": 1000,
  "total_blocks": 5,
  "shares_per_minute": 2.5,
  "peer_count": 8
}
```

---

#### `GET /p2pool/template`
Get P2Pool share template.

**Query Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `address` | string | Yes | Payout address |

**Response:**
```json
{
  "share_version": 1,
  "share_target_bits": 486604799,
  "prev_share": "abc123...",
  "block_prev_hash": "def456...",
  "block_height": 1235,
  "block_bits": 469762303,
  "timestamp": 1737332400,
  "merkle_root": "ghi789...",
  "generation_tx": "0100000001...",
  "main_chain_height": 1234,
  "main_chain_tip": "jkl012..."
}
```

---

#### `POST /p2pool/submit`
Submit share to P2Pool sharechain.

**Request Body:**
```json
{
  "nonce": 12345678,
  "extra_nonce": "abc123"
}
```

**Response:**
```json
{
  "accepted": true,
  "message": "Share submitted to P2Pool"
}
```

---

#### `GET /p2pool/payouts`
Estimated PPLNS payout distribution.

**Response:**
```json
{
  "payouts": [
    {
      "script": "76a914...",
      "amount": 2500000000
    }
  ]
}
```

---

### Peer Endpoints

#### `GET /peers`
Connected peers list.

**Response:**
```json
{
  "count": 8,
  "peers": [
    {
      "id": 1,
      "address": "[2001:db8::1]:17318",
      "version": 70015,
      "user_agent": "/FTC:1.0.0/",
      "height": 1234,
      "inbound": false,
      "reachability": "reachable",
      "ping_ms": 50,
      "bytes_sent": 102400,
      "bytes_recv": 204800
    }
  ]
}
```

**Reachability Values:**
| Value | Description |
|-------|-------------|
| `unknown` | Not yet checked |
| `checking` | Connection test in progress |
| `reachable` | Peer can accept connections |
| `unreachable` | Peer behind NAT/firewall |

---

#### `GET /peers/banned`
Banned peers list.

**Response:**
```json
{
  "count": 2,
  "banned": [
    {
      "address": "[2001:db8::bad]:17318",
      "reason": "misbehaving",
      "ban_time": 1737332400,
      "unban_time": 1737418800
    }
  ]
}
```

---

### Snapshot Endpoints

#### `GET /snapshot`
UTXO snapshot info for fast sync.

**Response:**
```json
{
  "exists": true,
  "file": "./data/snapshot.dat",
  "size": 1048576,
  "height": 1000,
  "block_hash": "abc123...",
  "utxo_count": 500,
  "total_value": 50000000000,
  "current_height": 1234,
  "current_utxos": 600
}
```

---

#### `POST /snapshot`
Create new UTXO snapshot.

**Response:**
```json
{
  "success": true,
  "file": "./data/snapshot.dat",
  "height": 1234,
  "block_hash": "abc123...",
  "utxo_count": 600,
  "size": 1572864,
  "time_ms": 500
}
```

---

#### `GET /snapshot/download`
Download snapshot file (binary).

**Response:** `application/octet-stream`

---

## Data Directories

| OS | Path |
|----|------|
| **Windows** | `%APPDATA%\FTC\` |
| **Linux** | `~/.ftc/` |
| **macOS** | `~/Library/Application Support/FTC/` |

### Directory Structure

```
FTC/
  blocks/           # Block data
  chainstate/       # UTXO database
  peers.dat         # Known peer addresses
  ftc.conf          # Configuration (optional)
  debug.log         # Debug log file
```

---

## Building from Source

### Prerequisites

**Windows:**
- Visual Studio 2022 with C++ workload
- CMake 3.16+

**Linux:**
```bash
sudo apt-get install build-essential cmake libssl-dev ocl-icd-opencl-dev
```

### Build Commands

**Windows:**
```cmd
cd ftc-node
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

**Linux:**
```bash
cd ftc-node
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

---

## Troubleshooting

### Node won't start
- Check if port 17318/17319 are already in use
- Verify firewall allows connections
- Delete corrupted chainstate: `rm -rf ~/.ftc/chainstate`

### No peers found
- Ensure IPv6 is enabled on your network
- Check DHT port 17321 UDP is open
- Add manual peers via config

### Mining not finding shares
- Check node is fully synced: `curl http://localhost:17319/sync`
- Verify P2Pool is running: `curl http://localhost:17319/p2pool/status`
- Confirm GPU is detected: `ftc-miner --benchmark`

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Links

- **GitHub:** https://github.com/Kristian5013/flow-protocol
- **Telegram:** https://t.me/flow_protocol_main

---

<p align="center">
  <strong>FTC - First Real P2P</strong><br/>
  <em>"Kristian Pilatovich 20091227"</em>
</p>
