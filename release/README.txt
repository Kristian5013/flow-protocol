FTC (Flow Token Chain) v1.0.0
==============================

A fully decentralized cryptocurrency with Keccak-256 mining.


INCLUDED TOOLS
==============

1. ftc-node.exe   - Full blockchain node
2. ftc-keygen.exe - Offline wallet generator
3. ftc-miner.exe  - CPU miner


QUICK START
===========

Step 1: Generate a wallet (offline)
  ftc-keygen.exe

  Save your private key securely!

Step 2: Start the node
  ftc-node.exe

  Or connect to existing node:
  ftc-node.exe --addnode=IP:PORT

Step 3: Start mining
  ftc-miner.exe -a YOUR_FTC_ADDRESS

Step 4: Check balance via API
  curl http://127.0.0.1:17319/balance/YOUR_ADDRESS


FTC-NODE
========

Usage:
  ftc-node.exe [options]

Options:
  --addnode=IP:PORT   Connect to peer (can use multiple times)
  --port PORT         P2P port (default: 17318)
  --api-port PORT     API port (default: 17319)
  --debug             Enable debug logging
  --testnet           Use testnet
  --datadir DIR       Data directory
  -h, --help          Show help

Examples:
  First node (just listens):
    ftc-node.exe

  Connect to existing node:
    ftc-node.exe --addnode=192.168.1.10:17318

  Multiple peers:
    ftc-node.exe --addnode=1.2.3.4:17318 --addnode=5.6.7.8:17318


FTC-KEYGEN
==========

Usage:
  ftc-keygen.exe [options]

Options:
  --testnet           Generate testnet address (tftc1...)
  --from-hex PRIVKEY  Derive address from existing private key
  -h, --help          Show help

Examples:
  Generate new wallet:
    ftc-keygen.exe

  Testnet wallet:
    ftc-keygen.exe --testnet

  Recover from private key:
    ftc-keygen.exe --from-hex 0123456789abcdef...


FTC-MINER
=========

Usage:
  ftc-miner.exe [options]

Options:
  -o, --node HOST:PORT   Node API address (default: 127.0.0.1:17319)
  -a, --address ADDR     Payout address (required)
  -t, --threads N        Mining threads (default: auto)
  --benchmark            Run hashrate benchmark
  -h, --help             Show help

Examples:
  Mine to your address:
    ftc-miner.exe -a ftc1qwfk0r2r9f6352ad9m4nph5mh9xhrf9yukv6pap

  Mine on remote node:
    ftc-miner.exe -o 192.168.1.10:17319 -a ftc1...

  Use 4 threads:
    ftc-miner.exe -a ftc1... -t 4

  Benchmark:
    ftc-miner.exe --benchmark


API ENDPOINTS
=============

Node Status:
  GET /status

Block Info:
  GET /block/{hash}
  GET /block/height/{height}

Transaction:
  GET /tx/{txid}
  POST /tx/broadcast

Wallet:
  GET /balance/{address}
  GET /utxo/{address}

Mining:
  GET /mining/template?address=FTC_ADDRESS
  POST /mining/submit
  GET /mining/info

Network:
  GET /peers
  GET /mempool


GPU MINING (sgminer)
====================

For GPU mining, use sgminer with the Keccak algorithm:

  sgminer -k keccak -o stratum+tcp://127.0.0.1:3333 -u YOUR_FTC_ADDRESS -p x

Or create ftc.conf:
  {
    "pools": [{
      "url": "stratum+tcp://127.0.0.1:3333",
      "user": "ftc1...",
      "pass": "x",
      "algorithm": "keccak"
    }]
  }

Then run: sgminer -c ftc.conf


NETWORK PORTS
=============

17318 - P2P (TCP)       - For node-to-node communication
17319 - API (HTTP)      - For wallet/miner (localhost only)
3333  - Stratum (TCP)   - For GPU miners (sgminer)


DATA DIRECTORY
==============

Windows: %APPDATA%\FTC
Linux:   ~/.ftc


IMPORTANT SECURITY NOTES
========================

1. NEVER share your private key
2. The API only listens on localhost (127.0.0.1)
3. Generate keys OFFLINE with ftc-keygen
4. Backup your private key securely

