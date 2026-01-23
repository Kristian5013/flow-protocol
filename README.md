# FTC (Flow Token Chain)

<p align="center">
  <img src="assets/ftc-logo.svg" alt="FTC Logo" width="128" height="128"/>
</p>

<p align="center">
  <strong>A fully decentralized cryptocurrency with Keccak-256 proof-of-work.</strong>
</p>

[![Telegram](https://img.shields.io/badge/Telegram-Join%20Chat-blue?logo=telegram)](https://t.me/flow_protocol_main)

---

**Genesis Block:** `Kristian Pilatovich 20091227 - First Real P2P`

## Network

| Node | Address | Region | Status |
|------|---------|--------|--------|
| Seed Node 1 | `[2406:5900:2:d47::1234]:17318` | Asia | **Online** |
| Seed Node 2 | `[2600:1f18:2a2a:6f10:d463:f827:7b2c:c26b]:17318` | US-East (AWS) | **Online** |

**Connect to the network:**
```bash
# Add to peers.dat:
[2406:5900:2:d47::1234]:17318
[2600:1f18:2a2a:6f10:d463:f827:7b2c:c26b]:17318
```

## Features

- **Keccak-256 PoW** - ASIC-resistant mining algorithm
- **UTXO Model** - Bitcoin-like transaction model
- **Bech32 Addresses** - Modern address format (`ftc1...`)
- **IPv6-Only Network** - Modern internet protocol
- **REST API** - Full node control via HTTP
- **Self-Connection Prevention** - Automatic local IP detection

## Quick Start

### 1. Generate a wallet
```bash
./ftc-keygen
# Or via API:
curl http://[::1]:17319/wallet/new
```

### 2. Start the node
```bash
./ftc-node
```

### 3. Configure peers
Add seed nodes to `peers.dat` in data directory:
```
# peers.dat (IPv6 format)
[2406:5900:2:d47::1234]:17318
[2600:1f18:2a2a:6f10:d463:f827:7b2c:c26b]:17318
```

### 4. Start mining
```bash
./ftc-miner
# Follow the prompts to enter your wallet address
```

### 5. Check balance
```bash
curl http://[::1]:17319/balance/YOUR_ADDRESS
```

---

## Components

| Component | Description |
|-----------|-------------|
| `ftc-node` | Full blockchain node with REST API |
| `ftc-miner` | GPU/CPU miner with TUI |
| `ftc-wallet` | Command-line wallet |
| `ftc-keygen` | Offline key generator |

---

## Network Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 17318 | TCP | P2P network (IPv6) |
| 17319 | HTTP | REST API |

---

## REST API Reference

Base URL: `http://[::1]:17319`

### Node Status

#### GET /status
Returns node status and network info.

**Response:**
```json
{
  "node": "FTC Node",
  "version": "1.0.0",
  "network": "mainnet",
  "running": true,
  "chain": {
    "height": 1234,
    "best_hash": "00000000abc123..."
  },
  "mempool": {
    "size": 5,
    "bytes": 1250,
    "fees": 5000
  },
  "peers": {
    "nodes": 8,
    "connections": 12,
    "inbound": 4,
    "outbound": 8,
    "known_addresses": 25
  }
}
```

#### GET /health
Health check endpoint for monitoring.

**Response:**
```json
{
  "status": "healthy",
  "healthy": true,
  "peers": 8,
  "height": 1234
}
```

#### GET /genesis
Returns genesis block information.

**Response:**
```json
{
  "message": "Kristian Pilatovich 20091227 - First Real P2P",
  "timestamp": 1737331200,
  "timestamp_utc": "2026-01-20 00:00:00 UTC",
  "hash": "77f9f0080a665b359d964b57ef93f4556977c06a46ed4a3b0bbce6d426a65cd2",
  "version": 1,
  "bits": 486604799,
  "nonce": 0
}
```

---

### Blockchain

#### GET /block/:id
Get block by height or hash.

**Parameters:**
- `id` - Block height (number) or block hash (64 hex chars)

**Response:**
```json
{
  "hash": "00000000abc123...",
  "height": 100,
  "version": 1,
  "prev_hash": "00000000def456...",
  "merkle_root": "abcdef123456...",
  "timestamp": 1737331200,
  "bits": 486604799,
  "nonce": 12345678,
  "tx_count": 2,
  "transactions": ["txid1...", "txid2..."]
}
```

#### GET /tx/:txid
Get transaction by ID.

**Parameters:**
- `txid` - Transaction ID (64 hex chars)

#### POST /tx
Broadcast a signed transaction.

**Request Body:**
```json
{
  "hex": "0100000001..."
}
```

---

### Wallet

#### GET /wallet/new
Generate a new wallet.

**Response:**
```json
{
  "address": "ftc1qrshzzcek6xkle2885ynpv942yhrwxupkqehr4ah",
  "private_key": "79f10d754c50777422b56bf87cd3012b629ad34e20da25f4eb5c93e136f97f6d",
  "public_key": "02836c62822fd31f3d57d1817cf7e70ddc833d16e54220957234c9a1babc7bec92"
}
```

#### GET /balance/:address
Get balance for an address.

**Response:**
```json
{
  "address": "ftc1q...",
  "balance": 5000000000,
  "unconfirmed": 0
}
```

#### GET /utxo/:address
Get unspent transaction outputs.

**Response:**
```json
{
  "address": "ftc1q...",
  "utxos": [
    {
      "txid": "abc123...",
      "vout": 0,
      "amount": 5000000000,
      "height": 100,
      "coinbase": true,
      "confirmations": 150
    }
  ]
}
```

#### POST /wallet/send
Send FTC from wallet.

**Request Body:**
```json
{
  "private_key": "your_private_key_hex",
  "to_address": "ftc1q...",
  "amount": 1000000000,
  "fee": 1000
}
```

**Response:**
```json
{
  "txid": "abc123...",
  "accepted": true
}
```

---

### Mining

#### GET /mining/info
Get current mining information.

**Response:**
```json
{
  "height": 1234,
  "difficulty": 1.0,
  "target": "00000000ffff0000...",
  "block_reward": 5000000000
}
```

#### GET /mining/template?address=ftc1q...
Get block template for mining.

#### POST /mining/submit
Submit a mined block.

---

### Peers

#### GET /peers
Get connected peers.

**Response:**
```json
{
  "count": 2,
  "peers": [
    {
      "id": 1,
      "address": "[2001:db8::1]:17318",
      "version": 70015,
      "user_agent": "/FTC:1.0.0/",
      "height": 1234,
      "inbound": false,
      "ping_ms": 50,
      "bytes_sent": 1024,
      "bytes_recv": 2048
    }
  ]
}
```

---

### Mempool

#### GET /mempool
Get mempool contents.

#### GET /mempool/txids
Get list of transaction IDs in mempool.

---

## Consensus Rules

| Parameter | Value |
|-----------|-------|
| Block time | 600 seconds (10 minutes) |
| Block reward | 50 FTC (halving every 210,000 blocks) |
| Max supply | 21,000,000 FTC |
| Difficulty adjustment | Every 2016 blocks |
| Coinbase maturity | 100 confirmations |
| Max block size | 1 MB |

---

## Data Directory

| OS | Path |
|----|------|
| Windows | `%APPDATA%\FTC\` |
| Linux/macOS | `~/.ftc/` |

**Files:**
- `peers.dat` - Known peer addresses
- `blocks/` - Block data
- `chainstate/` - UTXO database

---

## Building from Source

### Windows (MinGW)
```batch
cd ftc-node
cmake -B build -G "MinGW Makefiles"
cmake --build build

cd ../ftc-miner-v2
cmake -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
```

### Linux
```bash
# Install dependencies
sudo apt-get install build-essential cmake

# Build node
cd ftc-node
cmake -B build
cmake --build build

# Build miner
cd ../ftc-miner-v2
cmake -B build
cmake --build build
```

---

## License

MIT License

---

## Genesis Block Verification

```bash
curl -s http://[::1]:17319/genesis
```

```json
{
  "message": "Kristian Pilatovich 20091227 - First Real P2P",
  "hash": "77f9f0080a665b359d964b57ef93f4556977c06a46ed4a3b0bbce6d426a65cd2"
}
```
