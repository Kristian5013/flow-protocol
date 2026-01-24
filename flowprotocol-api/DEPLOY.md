# FlowProtocol Seed API Deployment

## Prerequisites
- Cloudflare account (free tier works)
- Domain flowprotocol.net configured in Cloudflare

## Setup

### 1. Install Wrangler CLI
```bash
npm install -g wrangler
wrangler login
```

### 2. Create KV Namespace
```bash
cd flowprotocol-api
wrangler kv:namespace create NODES
```

Copy the ID from output and update `wrangler.toml`:
```toml
[[kv_namespaces]]
binding = "NODES"
id = "YOUR_ID_HERE"
```

### 3. Deploy
```bash
npm install
wrangler deploy
```

### 4. Configure DNS
Add CNAME record in Cloudflare:
```
api.flowprotocol.net -> workers.dev (proxied)
```

Or use custom domain routing (already in wrangler.toml).

## API Endpoints

### POST /api/register
Register a node with the network.
```json
{
  "port": 17318,
  "version": "1.0.0",
  "height": 12345,
  "network": "mainnet"
}
```

Response:
```json
{
  "success": true,
  "node_id": "node:mainnet:1.2.3.4:17318",
  "ttl": 900,
  "your_ip": "1.2.3.4",
  "country": "US"
}
```

### POST /api/heartbeat
Keep node alive (send every 5 min).
```json
{
  "port": 17318,
  "height": 12350,
  "network": "mainnet"
}
```

### GET /api/nodes?network=mainnet
Get list of active nodes.
```json
{
  "count": 42,
  "network": "mainnet",
  "nodes": [
    {
      "ip": "1.2.3.4",
      "port": 17318,
      "version": "1.0.0",
      "height": 12345,
      "country": "US",
      "age": 120
    }
  ]
}
```

### GET /api/status
API health check.
```json
{
  "status": "ok",
  "version": "1.0.0",
  "nodes": {
    "mainnet": 42,
    "testnet": 5
  },
  "ttl": 900
}
```

## Testing Locally
```bash
wrangler dev
# API available at http://localhost:8787
```

## Cost
- Free tier: 100,000 requests/day
- KV storage: 1GB free
- No server required!
