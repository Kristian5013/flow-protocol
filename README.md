<p align="center">
  <img src="logo.png" alt="Flow Protocol" width="200" />
</p>

<h1 align="center">Flow Protocol (FTC)</h1>

<p align="center">
  A modern proof-of-work cryptocurrency built from scratch in C++20.
</p>

<p align="center">
  <a href="https://flowcoin.org">flowcoin.org</a> &bull;
  <a href="https://flowprotocol.net">flowprotocol.net</a> &bull;
  <a href="https://t.me/flow_protocol_main">Telegram</a> &bull;
  <a href="https://github.com/Kristian5013/flow-protocol">GitHub</a>
</p>

---

## Overview

Flow Protocol is a Layer-1 blockchain with its own native coin **FTC**. The network uses **Equihash (200,9)** proof-of-work, 10-minute block times, and a fixed supply of **21,000,000 FTC**. All consensus rules (SegWit, BIP34/65/66) are active from genesis.

The entire codebase — core libraries, cryptography, networking, consensus, wallet, miner, and RPC server — is written from the ground up in modern C++20 with zero external dependencies beyond OpenSSL.

## Key Specifications

| Parameter | Value |
|---|---|
| **Algorithm** | Equihash (N=200, K=9) |
| **Block Time** | 600 seconds (10 minutes) |
| **Block Reward** | 50 FTC (halves every 210,000 blocks) |
| **Max Supply** | 21,000,000 FTC |
| **Difficulty Adjustment** | Every 2,016 blocks (~2 weeks) |
| **Max Block Weight** | 4,000,000 WU |
| **Coinbase Maturity** | 100 confirmations |
| **P2P Port** | 9333 |
| **RPC Port** | 9332 |
| **SegWit** | Active from genesis |
| **Address Format** | Base58Check (P2PKH, P2SH) |

## Seed Nodes

| Domain | Location | IP |
|---|---|---|
| seed.flowcoin.org | Seoul, South Korea | 3.35.208.160 |
| seed.flowprotocol.net | Virginia, USA | 44.221.81.40 |

## Building from Source

### Requirements

- C++20 compiler (GCC 13+, Clang 16+, MSVC 2022)
- CMake 3.20+
- OpenSSL 3.0+

### Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y build-essential cmake libssl-dev

git clone https://github.com/Kristian5013/flow-protocol.git
cd flow-protocol
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j$(nproc)
```

### Windows (MSYS2)

```bash
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-openssl

git clone https://github.com/Kristian5013/flow-protocol.git
cd flow-protocol
mkdir build && cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build . -j8
```

### Build Outputs

| Binary | Description |
|---|---|
| `ftcd` | Full node daemon |
| `ftc-miner` | External Equihash miner |
| `ftc-wallet` | Wallet CLI utility |
| `ftc_tests` | Test suite (184 tests, 791 checks) |

## Running a Node

### Quick Start

```bash
./ftcd -datadir=/var/lib/ftc -rpcuser=myuser -rpcpassword=mypass
```

### Configuration File

Create `ftc.conf` in your data directory:

```ini
# Network
listen=1
port=9333
maxoutbound=8
maxinbound=117
dnsseed=1

# RPC
rpcuser=myuser
rpcpassword=mypass
rpcbind=127.0.0.1
rpcport=9332

# Logging
loglevel=info
```

### Command-Line Options

```
-datadir=<path>       Data directory for blockchain, wallet, logs
-listen=<0|1>         Accept incoming P2P connections (default: 1)
-port=<n>             P2P listen port (default: 9333)
-rpcport=<n>          RPC listen port (default: 9332)
-rpcuser=<user>       RPC authentication username
-rpcpassword=<pass>   RPC authentication password
-rpcbind=<addr>       RPC bind address (default: 127.0.0.1)
-norpc                Disable RPC server
-nowallet             Disable wallet functionality
-connect=<addr>       Connect only to specified node
-addnode=<addr>       Add a node to connect to
-maxoutbound=<n>      Max outbound connections (default: 8)
-maxinbound=<n>       Max inbound connections (default: 117)
-dnsseed=<0|1>        Use DNS seeds for peer discovery (default: 1)
-mine                 Enable built-in miner
-minethreads=<n>      Mining threads (default: all CPUs)
-mineaddress=<addr>   Mining reward address
-testnet              Use testnet
-regtest              Use regression test mode
-loglevel=<level>     Log level: debug, info, warn, error
```

### systemd Service

```ini
[Unit]
Description=FTC Node
After=network.target

[Service]
ExecStart=/opt/ftc/ftcd -datadir=/var/lib/ftc -conf=/etc/ftc/ftc.conf
Restart=on-failure
User=ftc

[Install]
WantedBy=multi-user.target
```

## Mining

FTC uses **Equihash (200,9)** — an ASIC-resistant, memory-hard proof-of-work algorithm. The external miner communicates with the node via `getwork`/`submitwork` RPC calls.

### External Miner

```bash
./ftc-miner \
  --rpcuser=myuser \
  --rpcpassword=mypass \
  --rpchost=127.0.0.1 \
  --rpcport=9332 \
  --address=<your_FTC_address> \
  --threads=4
```

### Mining via RPC

```bash
# Generate 1 block (built-in solver)
curl --user myuser:mypass --data-binary \
  '{"jsonrpc":"1.0","id":1,"method":"generate","params":[1,"<address>"]}' \
  http://127.0.0.1:9332/

# External mining flow
# Step 1: Get work
curl --user myuser:mypass --data-binary \
  '{"jsonrpc":"1.0","id":1,"method":"getwork","params":["<address>"]}' \
  http://127.0.0.1:9332/

# Step 2: Submit solved nonce
curl --user myuser:mypass --data-binary \
  '{"jsonrpc":"1.0","id":1,"method":"submitwork","params":[<nonce>]}' \
  http://127.0.0.1:9332/
```

## JSON-RPC API Reference

All RPC calls use standard JSON-RPC 1.0 over HTTP with Basic authentication.

```bash
curl --user <rpcuser>:<rpcpassword> \
  --data-binary '{"jsonrpc":"1.0","id":1,"method":"<method>","params":[...]}' \
  -H 'content-type: text/plain;' \
  http://127.0.0.1:9332/
```

---

### Blockchain

#### `getblockchaininfo`

Returns an object containing various state info regarding blockchain processing.

```
Parameters: none
```

```json
{
  "chain": "main",
  "blocks": 6,
  "headers": 6,
  "bestblockhash": "00064a5c...",
  "difficulty": 0.0000019073,
  "mediantime": 1770459231,
  "chainwork": "000...0e000",
  "pruned": false,
  "initialblockdownload": false,
  "verificationprogress": 1.0
}
```

#### `getblock "blockhash" ( verbosity )`

Returns block data for the given block hash.

```
Parameters:
  1. blockhash  (string, required) The block hash
  2. verbosity  (int, optional, default=1) 0=hex, 1=json, 2=json with full tx details
```

#### `getblockhash height`

Returns hash of block at the given height.

```
Parameters:
  1. height  (int, required) The height index
```

#### `getblockheader "blockhash" ( verbose )`

Returns information about a block header.

```
Parameters:
  1. blockhash  (string, required) The block hash
  2. verbose    (bool, optional, default=true) true=json object, false=hex
```

#### `getblockcount`

Returns the height of the most-work fully-validated chain (tip height).

```
Parameters: none
```

#### `getbestblockhash`

Returns the hash of the best (tip) block in the most-work fully-validated chain.

```
Parameters: none
```

#### `getdifficulty`

Returns the proof-of-work difficulty as a multiple of the minimum difficulty.

```
Parameters: none
```

#### `getchaintips`

Returns information about all known tips in the block tree, including the main chain and any orphan/fork branches.

```
Parameters: none
```

#### `gettxout "txid" n`

Returns details about an unspent transaction output (UTXO).

```
Parameters:
  1. txid  (string, required) The transaction id
  2. n     (int, required) The output index (vout)
```

#### `scantxoutset "action" [scanobjects,...]`

Scans the UTXO set for outputs matching the given addresses.

```
Parameters:
  1. action       (string, required) "start"
  2. scanobjects  (array, required)  [{"address":"addr"}, ...] or ["addr", ...]
```

---

### Mempool

#### `getmempoolinfo`

Returns details on the active state of the transaction memory pool.

```
Parameters: none
```

```json
{
  "loaded": true,
  "size": 5,
  "bytes": 1250,
  "usage": 4096,
  "maxmempool": 300000000,
  "mempoolminfee": 0.00001000
}
```

#### `getrawmempool ( verbose )`

Returns all transaction IDs in the memory pool.

```
Parameters:
  1. verbose  (bool, optional, default=false) true=detailed JSON, false=array of txids
```

#### `getmempoolentry "txid"`

Returns mempool data for the given transaction.

```
Parameters:
  1. txid  (string, required) The transaction id
```

#### `testmempoolaccept ["rawtx",...]`

Tests whether raw transactions would be accepted by the mempool (dry run, does not submit).

```
Parameters:
  1. rawtxs  (array, required) Array of hex-encoded raw transactions
```

---

### Mining

#### `getmininginfo`

Returns a JSON object containing mining-related information.

```
Parameters: none
```

```json
{
  "blocks": 6,
  "difficulty": 0.0000019073,
  "networkhashps": 42.5,
  "pooledtx": 0,
  "chain": "main"
}
```

#### `getnetworkhashps ( nblocks height )`

Returns the estimated network hashes per second.

```
Parameters:
  1. nblocks  (int, optional, default=120) Number of blocks to use for estimate
  2. height   (int, optional, default=-1) Height to estimate at (-1 for tip)
```

#### `getblocktemplate ( "template_request" )`

Returns data needed to construct a block to work on. Used by advanced mining software.

```
Parameters:
  1. template_request  (object, optional) Template request parameters
```

#### `submitblock "hexdata"`

Submits a new block to the network. The block hex must include all transactions.

```
Parameters:
  1. hexdata  (string, required) The hex-encoded block data
```

#### `generate nblocks "address"`

Mines blocks using the built-in Equihash solver. Returns array of mined block hashes.

```
Parameters:
  1. nblocks  (int, required) Number of blocks to mine (1-1000)
  2. address  (string, required) FTC address for coinbase reward
```

#### `getwork "address"`

Returns mining work (header + target) for external miners. The miner solves Equihash locally and submits the nonce via `submitwork`.

```
Parameters:
  1. address  (string, required) FTC address for coinbase reward
```

```json
{
  "header": "0100000042a3...",
  "target": "0007ffff000000...",
  "height": 7
}
```

#### `submitwork nonce`

Submits a solved nonce from an external miner. Call `getwork` first to obtain the work.

```
Parameters:
  1. nonce  (int, required) The solved nonce value
```

---

### Network

#### `getnetworkinfo`

Returns an object containing various state info regarding P2P networking.

```
Parameters: none
```

```json
{
  "version": 70015,
  "subversion": "/FTC:1.0.0/",
  "protocolversion": 70015,
  "connections": 2,
  "connections_in": 1,
  "connections_out": 1,
  "localaddresses": []
}
```

#### `getpeerinfo`

Returns data about each connected network peer.

```
Parameters: none
```

```json
[
  {
    "id": 1,
    "addr": "3.35.208.160:9333",
    "version": 70015,
    "subver": "/FTC:1.0.0/",
    "inbound": true,
    "startingheight": 0,
    "banscore": 0,
    "synced_headers": 6,
    "synced_blocks": 6,
    "pingtime": 0.178
  }
]
```

#### `getconnectioncount`

Returns the number of connections to other nodes.

```
Parameters: none
```

#### `getnettotals`

Returns information about network traffic (bytes sent/received).

```
Parameters: none
```

#### `addnode "node" "command"`

Attempts to add or remove a node from the connection list.

```
Parameters:
  1. node     (string, required) The address (ip:port)
  2. command  (string, required) "add", "remove", or "onetry"
```

#### `disconnectnode ( "address" nodeid )`

Immediately disconnects from the specified peer.

```
Parameters:
  1. address  (string, optional) The IP address/port of the node
  2. nodeid   (int, optional) The peer node id
```

---

### Raw Transactions

#### `getrawtransaction "txid" ( verbose )`

Returns the raw transaction data.

```
Parameters:
  1. txid     (string, required) The transaction id
  2. verbose  (bool, optional, default=false) true=JSON object, false=hex string
```

#### `decoderawtransaction "hexstring"`

Returns a JSON object representing the serialized hex-encoded transaction.

```
Parameters:
  1. hexstring  (string, required) The hex-encoded transaction
```

#### `createrawtransaction [{"txid":"id","vout":n},...] {"address":amount,...} ( locktime )`

Creates an unsigned raw transaction spending the given inputs.

```
Parameters:
  1. inputs    (array, required)  [{"txid":"hex","vout":n}, ...]
  2. outputs   (object, required) {"address": amount, ...}
  3. locktime  (int, optional, default=0) Transaction locktime
```

#### `signrawtransactionwithkey "hexstring" ["privatekey",...]`

Signs inputs for a raw transaction with the provided private keys.

```
Parameters:
  1. hexstring    (string, required) The hex-encoded raw transaction
  2. privatekeys  (array, required)  Private keys in WIF or hex format
```

```json
{
  "hex": "0100000001...",
  "complete": true
}
```

#### `sendrawtransaction "hexstring"`

Submits a signed raw transaction to the network.

```
Parameters:
  1. hexstring  (string, required) The hex-encoded signed transaction
```

Returns the transaction hash (txid).

---

### Wallet

#### `getbalance`

Returns the total available balance in FTC.

```
Parameters: none
```

#### `getnewaddress ( "label" )`

Generates a new FTC address with a fresh private key.

```
Parameters:
  1. label  (string, optional) A label for the address
```

```json
{
  "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
  "wif": "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
  "hex": "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
}
```

#### `sendtoaddress "address" amount ( "comment" )`

Sends FTC to the given address. Returns the transaction ID.

```
Parameters:
  1. address  (string, required) The FTC address to send to
  2. amount   (numeric, required) The amount in FTC
  3. comment  (string, optional) A comment for the transaction
```

#### `listtransactions ( count skip )`

Returns the most recent wallet transactions.

```
Parameters:
  1. count  (int, optional, default=10) Number of transactions to return
  2. skip   (int, optional, default=0) Number of transactions to skip
```

#### `listunspent ( minconf maxconf )`

Returns array of unspent transaction outputs (UTXOs).

```
Parameters:
  1. minconf  (int, optional, default=1) Minimum confirmations
  2. maxconf  (int, optional, default=9999999) Maximum confirmations
```

#### `dumpprivkey "address"`

Reveals the private key for the given address.

```
Parameters:
  1. address  (string, required) The FTC address
```

#### `importprivkey "privkey" ( "label" rescan )`

Imports a private key into the wallet.

```
Parameters:
  1. privkey  (string, required) The private key in WIF format
  2. label    (string, optional) A label for the address
  3. rescan   (bool, optional, default=true) Rescan the blockchain for transactions
```

---

### Fee Estimation

#### `estimatesmartfee conf_target ( "estimate_mode" )`

Estimates the approximate fee per kilobyte for a transaction to confirm within `conf_target` blocks.

```
Parameters:
  1. conf_target    (int, required) Confirmation target in blocks
  2. estimate_mode  (string, optional, default="conservative") "unset", "economical", or "conservative"
```

```json
{
  "feerate": 0.00010000,
  "blocks": 6
}
```

#### `estimaterawfee conf_target ( threshold )`

Returns raw fee estimation data for each tracking horizon.

```
Parameters:
  1. conf_target  (int, required) Confirmation target in blocks
  2. threshold    (numeric, optional) Confidence threshold (0.0 - 1.0)
```

---

### Utility

#### `validateaddress "address"`

Returns information about the given FTC address.

```
Parameters:
  1. address  (string, required) The FTC address to validate
```

```json
{
  "isvalid": true,
  "address": "1EVegNcW9sgaRqgQFyPYVcPEjYq9hikMKo",
  "scriptPubKey": "76a914...",
  "isscript": false,
  "iswitness": false
}
```

#### `createmultisig nrequired ["key",...]`

Creates a multi-signature address with n-of-m keys required.

```
Parameters:
  1. nrequired  (int, required) Number of required signatures
  2. keys       (array, required) Array of public keys or addresses
```

#### `signmessagewithprivkey "privkey" "message"`

Signs a message with a private key.

```
Parameters:
  1. privkey  (string, required) The private key in WIF format
  2. message  (string, required) The message to sign
```

#### `verifymessage "address" "signature" "message"`

Verifies a signed message.

```
Parameters:
  1. address    (string, required) The FTC address that signed the message
  2. signature  (string, required) The base64-encoded signature
  3. message    (string, required) The message that was signed
```

---

### Control

#### `stop`

Request a graceful shutdown of the FTC node.

```
Parameters: none
```

#### `uptime`

Returns the total uptime of the server in seconds.

```
Parameters: none
```

#### `help ( "command" )`

Lists all commands, or gets help for a specific command.

```
Parameters:
  1. command  (string, optional) The command to get help for
```

#### `getmemoryinfo ( "mode" )`

Returns information about memory usage.

```
Parameters:
  1. mode  (string, optional) "stats" or "mallocinfo"
```

#### `logging ( ["include",...] ["exclude",...] )`

Gets and sets the logging configuration.

```
Parameters:
  1. include  (array, optional) Categories to enable
  2. exclude  (array, optional) Categories to disable
```

Available categories: `net`, `mempool`, `validation`, `mining`, `rpc`, `wallet`, `chain`, `script`, `lock`, `p2p`, `bench`, `all`, `none`.

---

## Project Architecture

```
src/
  core/         Core types, serialization, streams, logging, threading
  crypto/       Keccak-256, secp256k1, Schnorr, BIP32/39, AES, ChaCha20, Equihash
  primitives/   Transactions, blocks, scripts, addresses, fees
  consensus/    Consensus rules, PoW validation, block/tx verification
  chain/        Block index, chain state, UTXO set, block storage
  mempool/      Transaction memory pool, fee estimation, RBF
  net/          P2P networking, peer management, block/tx relay
  rpc/          JSON-RPC server with 51 commands
  wallet/       Key management, HD wallet, coin selection, signing
  miner/        Block template construction, Equihash solver
  node/         Node lifecycle, initialization, shutdown
  test/         Test suite (184 tests across 12 test files)
```

## Genesis Block

```
Hash:    0000451ca7b54fd5e3d96f6b07b9ee74d9dd9abebd8b8ae4e9b78f2c740c2bb7
Time:    2026-02-03 00:00:00 UTC
Message: "Pilatovich Kristian 20091227"
Nonce:   4737
```

## License

Distributed under the MIT software license. See [COPYING](COPYING) for more information.

## Links

- Website: [flowcoin.org](https://flowcoin.org)
- Website: [flowprotocol.net](https://flowprotocol.net)
- Telegram: [t.me/flow_protocol_main](https://t.me/flow_protocol_main)
- GitHub: [github.com/Kristian5013/flow-protocol](https://github.com/Kristian5013/flow-protocol)
