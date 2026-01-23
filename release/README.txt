FTC (Flow Token Chain) v1.0.0
==============================

Kristian Pilatovich 20091227 - First Real P2P

A fully decentralized cryptocurrency with Keccak-256 mining.
IPv6-native peer-to-peer network.


INCLUDED FILES
==============

Windows:
  ftc-node.exe    - Full blockchain node
  ftc-keygen.exe  - Offline wallet generator
  ftc-miner.exe   - CPU miner
  ftc-wallet.exe  - Command-line wallet

Linux:
  ftc-node-linux  - Full blockchain node (Ubuntu 22.04+)


NETWORK INFO
============

Mainnet Seed Node: [2406:5900:2:d47::1234]:17318

Ports:
  17318 - P2P (TCP/IPv6)  - Node-to-node communication
  17319 - API (HTTP)      - Wallet/miner interface

Block Time: 600 seconds (10 minutes)
Block Reward: 50 FTC
Max Supply: 21,000,000 FTC
Algorithm: Keccak-256


JOINING THE NETWORK
===================

Your node needs IPv6 connectivity to join the main network.

1. Check IPv6 connectivity:
   ping6 2406:5900:2:d47::1234

   If this fails, you need to enable IPv6 on your network/VPS.

2. Create peers.dat file:

   Windows: %APPDATA%\FTC\peers.dat
   Linux:   ~/.ftc/peers.dat

   Content:
   [2406:5900:2:d47::1234]:17318

3. Start the node:

   Windows: ftc-node.exe --verbose
   Linux:   chmod +x ftc-node-linux && ./ftc-node-linux --verbose

4. Verify connection:
   curl http://localhost:17319/status

   Look for "connections" > 0


LINUX SERVER SETUP (Ubuntu/Debian)
==================================

# 1. Download and set permissions
chmod +x ftc-node-linux

# 2. Create data directory and peers file
mkdir -p ~/.ftc
echo "[2406:5900:2:d47::1234]:17318" > ~/.ftc/peers.dat

# 3. Run node
./ftc-node-linux --verbose

# 4. Run as service (optional)
sudo cp ftc-node-linux /usr/local/bin/ftc-node
sudo nano /etc/systemd/system/ftc-node.service

[Unit]
Description=FTC Node
After=network.target

[Service]
Type=simple
User=ftc
ExecStart=/usr/local/bin/ftc-node
Restart=always

[Install]
WantedBy=multi-user.target

sudo systemctl enable ftc-node
sudo systemctl start ftc-node


CLOUD/VPS IPv6 SETUP
====================

AWS EC2:
  1. Enable IPv6 on VPC (Amazon-provided IPv6 CIDR)
  2. Add IPv6 CIDR to subnet
  3. Add ::/0 route to Internet Gateway
  4. Assign IPv6 address to instance
  5. Allow ports 17318-17319 TCP for ::/0 in Security Group

DigitalOcean:
  IPv6 enabled by default on new droplets

Vultr:
  Enable IPv6 in server settings

Hetzner:
  IPv6 included with all servers


QUICK START (WINDOWS)
=====================

Step 1: Generate a wallet
  ftc-keygen.exe

  Save your private key securely!

Step 2: Configure network
  Create %APPDATA%\FTC\peers.dat with content:
  [2406:5900:2:d47::1234]:17318

Step 3: Start the node
  ftc-node.exe --verbose

Step 4: Start mining
  ftc-miner.exe

  Enter your FTC address when prompted.

Step 5: Check balance
  curl http://127.0.0.1:17319/balance/YOUR_ADDRESS

  Or use: ftc-wallet.exe balance YOUR_ADDRESS


FTC-NODE OPTIONS
================

Usage: ftc-node [options]

Options:
  --verbose         Show progress output
  --debug           Enable debug logging
  --port PORT       P2P port (default: 17318)
  --api-port PORT   API port (default: 17319)
  --datadir DIR     Data directory
  --reindex         Rebuild UTXO set from blocks
  -h, --help        Show help

Examples:
  Start with output:
    ftc-node --verbose

  Custom data directory:
    ftc-node --datadir /data/ftc --verbose


FTC-MINER OPTIONS
=================

Interactive mode - just run:
  ftc-miner.exe

The miner will ask for:
  - Node address (default: localhost:17319)
  - Your FTC address for payouts

For benchmark mode, select option 2 or 3 in the menu.


API ENDPOINTS
=============

Node Status:
  GET /status
  GET /health

Blockchain:
  GET /block/{hash}
  GET /block/height/{height}
  GET /genesis

Transactions:
  GET /tx/{txid}
  POST /tx/broadcast

Wallet:
  GET /balance/{address}
  GET /utxo/{address}
  GET /address/{address}/history

Mining:
  GET /mining/template?address=FTC_ADDRESS
  POST /mining/submit
  GET /mining/info
  GET /mining/generate?blocks=1&address=FTC_ADDRESS

P2Pool:
  GET /p2pool/status

Network:
  GET /peers
  GET /mempool


DATA DIRECTORY
==============

Windows: %APPDATA%\FTC
Linux:   ~/.ftc

Contents:
  blocks/     - Block data
  chainstate/ - UTXO database
  peers.dat   - Known peers (IPv6 format)


SECURITY NOTES
==============

1. NEVER share your private key
2. Generate keys OFFLINE with ftc-keygen
3. Backup your private key securely
4. API only listens on localhost by default


COMMUNITY
=========

Telegram: https://t.me/flow_protocol_main
GitHub: https://github.com/user/flow-protocol-main


LICENSE
=======

MIT License
