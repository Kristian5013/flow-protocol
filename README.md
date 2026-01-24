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

## Quick Start

### Option 1: Combined Node + Miner (Recommended)

```bash
# Windows
ftc-full.exe -a ftc1qYOUR_ADDRESS

# Linux
./ftc-full -a ftc1qYOUR_ADDRESS
```

This starts both node and miner together. Node loads peers from `peers.dat`.

### Option 2: Separate Components

```bash
# Start node (auto-discovers peers)
./ftc-node

# Start miner (auto-discovers node)
./ftc-miner -a ftc1qYOUR_ADDRESS
```

## Downloads

Get the latest release from [GitHub Releases](https://github.com/Kristian5013/flow-protocol/releases).

| Platform | Archive |
|----------|---------|
| Windows x64 | `ftc-windows-x64.zip` |
| Linux x64 | `ftc-linux-x64.tar.gz` |

**Contents:**
- `ftc-full` - Combined node + miner (recommended)
- `ftc-node` - Full blockchain node
- `ftc-miner` - GPU miner
- `ftc-wallet` - CLI wallet

---

## Features

- **Keccak-256 PoW** - ASIC-resistant mining algorithm
- **UTXO Model** - Bitcoin-like transaction model
- **Bech32 Addresses** - Modern address format (`ftc1...`)
- **IPv6-Only Network** - Modern internet protocol
- **P2P Network** - Peers via peers.dat + addr exchange
- **REST API** - Full node control via HTTP
- **TUI Miner** - Beautiful terminal interface with GPU stats

---

## Mining

```bash
# Simple mining (auto-discovery)
ftc-miner -a ftc1qYOUR_ADDRESS

# With AI auto-tune
ftc-miner -a ftc1q... --autotune

# Connect to specific node (IPv6)
ftc-miner -o [::1]:17319 -a ftc1q...

# Benchmark mode (no node required)
ftc-miner --benchmark
```

### Miner Options

```
Required:
  -a, --address ADDR   Mining wallet address (ftc1q...)

Optional:
  -o, --pool URL       Node URL (default: http://localhost:17319)
  -I, --intensity N    GPU intensity 8-31 (default: auto)
  --autotune           Enable AI auto-tune
  --no-tui             Disable TUI, use simple output
  --benchmark          Benchmark mode
```

---

## Wallet

### Generate New Wallet

```bash
ftc-wallet new
```

Or via API:
```bash
curl http://[::1]:17319/wallet/new
```

### Check Balance

```bash
ftc-wallet balance ftc1qYOUR_ADDRESS
```

### Send FTC

```bash
ftc-wallet send <private_key> <to_address> <amount>
```

---

## Network

IPv6 only P2P network. Peer discovery via `peers.dat` file + P2P addr exchange.

| Port | Protocol | Description |
|------|----------|-------------|
| 17318 | TCP | P2P network (IPv6 only) |
| 17319 | HTTP | REST API |

### First Run

1. Place `peers.dat` next to `ftc-node` binary
2. Run: `ftc-node`

peers.dat format (one per line):
```
[2001:db8::1]:17318
```

---

## REST API Reference

Base URL: `http://[::1]:17319` (IPv6 localhost)

> **Note:** API uses IPv6 only. Use `[::1]` instead of `127.0.0.1`

### Node Status

```bash
GET /status       # Node status and network info
GET /health       # Health check
GET /genesis      # Genesis block info
```

### Blockchain

```bash
GET /block/:height    # Get block by height
GET /block/:hash      # Get block by hash
GET /tx/:txid         # Get transaction
POST /tx              # Broadcast transaction
```

### Wallet

```bash
GET /wallet/new           # Generate new wallet
GET /balance/:address     # Get balance
GET /utxo/:address        # Get UTXOs
POST /wallet/send         # Send FTC
```

### Mining

```bash
GET /mining/info                    # Mining info
GET /mining/template?address=ftc1q  # Get block template
POST /mining/submit                 # Submit mined block
```

### Peers

```bash
GET /peers        # Connected peers list
```

---

## Consensus Rules

| Parameter | Value |
|-----------|-------|
| Block time | 600 seconds (10 minutes) |
| Block reward | 50 FTC (halving every 210,000 blocks) |
| Max supply | 21,000,000 FTC |
| Difficulty adjustment | Every 2016 blocks |
| Coinbase maturity | 100 confirmations |
| PoW Algorithm | Keccak-256 |

---

## Building from Source

### Windows

```cmd
build-windows.bat
```

Or manually:
```cmd
cd ftc-node
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

### Linux

```bash
chmod +x build-linux.sh
./build-linux.sh
```

Or manually:
```bash
# Install dependencies
sudo apt-get install build-essential cmake ocl-icd-opencl-dev

# Build
cd ftc-node && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

---

## Data Directory

| OS | Path |
|----|------|
| Windows | `%APPDATA%\FTC\` |
| Linux/macOS | `~/.ftc/` |

---

## Genesis Block

```bash
curl http://[::1]:17319/genesis
```

```json
{
  "message": "Kristian Pilatovich 20091227 - First Real P2P",
  "hash": "77f9f0080a665b359d964b57ef93f4556977c06a46ed4a3b0bbce6d426a65cd2",
  "timestamp": 1737331200
}
```

---

## License

MIT License
