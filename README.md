# FTC (Flow Token Chain)

<p align="center">
  <img src="assets/ftc-logo.svg" alt="FTC Logo" width="128" height="128"/>
</p>

<p align="center">
  <strong>A fully decentralized cryptocurrency with Keccak-256 proof-of-work and P2Pool mining.</strong>
</p>

[![Telegram](https://img.shields.io/badge/Telegram-Join%20Chat-blue?logo=telegram)](https://t.me/flow_protocol_main)

---

## Network Status

| Node | Address | API | Status |
|------|---------|-----|--------|
| Main Node | `211.201.177.236:17318` | [API](http://211.201.177.236:17319/status) | **Online** |

**Connect to the network:**
```bash
./ftc-node --addnode=211.201.177.236:17318
```

**Start mining:**
```bash
./ftc-miner -o 211.201.177.236:17319 -u YOUR_WALLET_ADDRESS
```

---

**Genesis Block:** `Kristian Pilatovich 20091227 - First Real P2P`

## Features

- **Keccak-256 PoW** - ASIC-resistant mining algorithm
- **P2Pool** - Decentralized mining pool (no central pool server)
- **UTXO Model** - Bitcoin-like transaction model
- **Bech32 Addresses** - Modern address format (`ftc1...`)
- **Dual-Stack IPv4/IPv6** - Full network support

## Quick Start

### 1. Generate a wallet
```bash
./ftc-keygen
# Save the private key securely!
```

### 2. Start the node
```bash
./ftc-node
```

### 3. Start mining
```bash
./ftc-miner -o 127.0.0.1:17319 -u YOUR_WALLET_ADDRESS --no-interactive
```

### 4. Check balance
```bash
./ftc-wallet balance YOUR_WALLET_ADDRESS
```

---

## Components

| Component | Description |
|-----------|-------------|
| `ftc-node` | Full blockchain node with REST API |
| `ftc-miner` | GPU miner (OpenCL) with TUI |
| `ftc-wallet` | Command-line wallet |
| `ftc-keygen` | Offline key generator |

---

## Network Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 17318 | TCP | P2P network |
| 17319 | HTTP | REST API |
| 17320 | TCP | P2Pool |
| 3333 | TCP | Stratum mining |

---

## REST API Reference

Base URL: `http://127.0.0.1:17319`

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
    "connected": 8,
    "inbound": 3,
    "outbound": 5
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
Returns genesis block information for verification.

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

**Response:**
```json
{
  "txid": "abc123...",
  "version": 1,
  "inputs": [
    {
      "txid": "prev_txid...",
      "vout": 0,
      "script_sig": "...",
      "sequence": 4294967295
    }
  ],
  "outputs": [
    {
      "value": 5000000000,
      "script_pubkey": "0014..."
    }
  ],
  "locktime": 0
}
```

#### POST /tx
Broadcast a signed transaction.

**Request Body:**
```json
{
  "hex": "0100000001..."
}
```

**Response (success):**
```json
{
  "txid": "abc123...",
  "accepted": true
}
```

**Response (error):**
```json
{
  "accepted": false,
  "reason": "Insufficient fee"
}
```

---

### Wallet

#### GET /wallet/balance/:address
Get balance for an address.

**Parameters:**
- `address` - FTC address (ftc1...)

**Response:**
```json
{
  "address": "ftc1q...",
  "balance": 5000000000,
  "balance_ftc": "50.00000000",
  "unconfirmed": 0
}
```

#### GET /wallet/utxos/:address
Get unspent transaction outputs for an address.

**Parameters:**
- `address` - FTC address (ftc1...)

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

#### GET /wallet/history/:address
Get transaction history for an address.

**Parameters:**
- `address` - FTC address (ftc1...)
- `limit` (optional) - Max transactions (default: 100)
- `offset` (optional) - Skip transactions (default: 0)

**Response:**
```json
{
  "address": "ftc1q...",
  "transactions": [
    {
      "txid": "abc123...",
      "height": 100,
      "timestamp": 1737331200,
      "amount": 5000000000,
      "type": "receive"
    }
  ]
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
  "difficulty_bits": 486604799,
  "hashrate": 1500000000,
  "block_reward": 5000000000
}
```

#### GET /mining/template
Get block template for mining.

**Query Parameters:**
- `address` - Payout address (required)

**Response:**
```json
{
  "height": 1235,
  "prev_hash": "00000000abc123...",
  "merkle_root": "def456...",
  "timestamp": 1737331260,
  "bits": 486604799,
  "coinbase": "01000000010000...",
  "transactions": ["tx_hex_1", "tx_hex_2"]
}
```

#### POST /mining/submit
Submit a mined block.

**Request Body:**
```json
{
  "hex": "0100000000000000..."
}
```

**Response:**
```json
{
  "accepted": true,
  "hash": "00000000abc123..."
}
```

---

### P2Pool

#### GET /p2pool/status
Get P2Pool status.

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

#### GET /p2pool/miners
Get list of active miners.

**Response:**
```json
{
  "miners": [
    {
      "address": "ftc1q...",
      "hashrate": 500000000,
      "shares": 100,
      "last_share": 1737331200
    }
  ]
}
```

#### GET /p2pool/payouts
Get pending payouts.

**Response:**
```json
{
  "payouts": [
    {
      "address": "ftc1q...",
      "amount": 250000000,
      "shares": 100
    }
  ]
}
```

---

### Peers

#### GET /peers
Get connected peers.

**Response:**
```json
{
  "peers": [
    {
      "address": "192.168.1.100:17318",
      "version": "1.0.0",
      "height": 1234,
      "latency_ms": 50,
      "connected_since": 1737331200,
      "inbound": false
    }
  ]
}
```

#### POST /peers/add
Add a peer manually.

**Request Body:**
```json
{
  "address": "192.168.1.100:17318"
}
```

---

### Mempool

#### GET /mempool
Get mempool contents.

**Response:**
```json
{
  "size": 5,
  "bytes": 1250,
  "transactions": [
    {
      "txid": "abc123...",
      "size": 250,
      "fee": 1000,
      "time": 1737331200
    }
  ]
}
```

---

## Consensus Rules

| Parameter | Value |
|-----------|-------|
| Block time | 60 seconds |
| Block reward | 50 FTC (halving every 210,000 blocks) |
| Max supply | 21,000,000 FTC |
| Difficulty adjustment | Every 2016 blocks |
| Coinbase maturity | 100 confirmations |
| Max block size | 1 MB |

---

## Building from Source

### Windows
```batch
scripts\build-all.bat
```

### Linux
```bash
# Install dependencies
sudo apt-get install build-essential cmake libssl-dev libleveldb-dev libuv1-dev ocl-icd-opencl-dev

# Build
chmod +x scripts/build-all.sh
./scripts/build-all.sh
```

Binaries will be in the `release/` directory.

---

## License

MIT License

---

## Genesis Block Verification

```bash
curl -s http://127.0.0.1:17319/genesis | jq
```

```json
{
  "message": "Kristian Pilatovich 20091227 - First Real P2P",
  "hash": "77f9f0080a665b359d964b57ef93f4556977c06a46ed4a3b0bbce6d426a65cd2"
}
```
