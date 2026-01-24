/**
 * FlowProtocol Node Discovery API
 * Cloudflare Worker for automatic peer discovery + wallet proxy
 *
 * Node Discovery:
 *   POST /api/register   - Register a node
 *   POST /api/heartbeat  - Keep node alive
 *   GET  /api/nodes      - Get list of active nodes
 *   GET  /api/node       - Get best node for connection
 *   GET  /api/status     - API status
 *
 * Wallet Proxy (no IP needed):
 *   GET  /api/balance/:address  - Get address balance
 *   GET  /api/utxos/:address    - Get UTXOs for address
 *   POST /api/tx/send           - Broadcast transaction
 *   GET  /api/tx/:txid          - Get transaction info
 *   GET  /api/height            - Get current block height
 *
 * Mining:
 *   GET  /api/mining/template   - Get mining template
 *   POST /api/mining/submit     - Submit mined block
 */

interface Env {
  NODES: KVNamespace;
  NODE_TTL: string;
  MAX_NODES: string;
}

interface NodeInfo {
  ip: string;
  port: number;
  apiPort: number;  // HTTP API port (usually port + 1)
  version: string;
  height: number;
  network: string;
  registered: number;
  lastSeen: number;
  country?: string;
}

interface RegisterRequest {
  port: number;
  apiPort?: number;
  version?: string;
  height?: number;
}

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function getClientIP(request: Request): string {
  return request.headers.get('CF-Connecting-IP') ||
         request.headers.get('X-Real-IP') ||
         '0.0.0.0';
}

function getCountry(request: Request): string {
  return request.headers.get('CF-IPCountry') || 'XX';
}

function nodeKey(ip: string, port: number, network: string): string {
  return `node:${network}:${ip}:${port}`;
}

function handleOptions(): Response {
  return new Response(null, { headers: corsHeaders });
}

// Get best node for proxying requests
async function getBestNode(env: Env, network: string = 'mainnet'): Promise<NodeInfo | null> {
  const prefix = `node:${network}:`;
  const list = await env.NODES.list({ prefix, limit: 50 });

  let bestNode: NodeInfo | null = null;
  let bestHeight = 0;

  for (const key of list.keys) {
    const data = await env.NODES.get(key.name);
    if (data) {
      try {
        const node: NodeInfo = JSON.parse(data);
        // Prefer nodes with highest height and most recent heartbeat
        if (node.height > bestHeight ||
            (node.height === bestHeight && (!bestNode || node.lastSeen > bestNode.lastSeen))) {
          bestNode = node;
          bestHeight = node.height;
        }
      } catch (e) {}
    }
  }

  return bestNode;
}

// Proxy request to a node
async function proxyToNode(node: NodeInfo, path: string, method: string = 'GET', body?: string): Promise<Response> {
  const apiPort = node.apiPort || (node.port + 1);  // Default: P2P port + 1
  const url = `http://[${node.ip}]:${apiPort}${path}`;

  try {
    const options: RequestInit = {
      method,
      headers: { 'Content-Type': 'application/json' },
    };
    if (body) options.body = body;

    const response = await fetch(url, options);
    const data = await response.text();

    return new Response(data, {
      status: response.status,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: 'Node unavailable', details: String(e) }), {
      status: 503,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// POST /api/register
async function handleRegister(request: Request, env: Env): Promise<Response> {
  try {
    const body: RegisterRequest = await request.json();

    if (!body.port || body.port < 1 || body.port > 65535) {
      return new Response(JSON.stringify({ error: 'Invalid port' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const ip = getClientIP(request);
    const country = getCountry(request);
    const ttl = parseInt(env.NODE_TTL) || 900;
    const now = Date.now();

    const node: NodeInfo = {
      ip,
      port: body.port,
      apiPort: body.apiPort || (body.port + 1),
      version: body.version || 'unknown',
      height: body.height || 0,
      network: 'mainnet',
      registered: now,
      lastSeen: now,
      country
    };

    const key = nodeKey(ip, body.port, 'mainnet');
    await env.NODES.put(key, JSON.stringify(node), { expirationTtl: ttl });

    return new Response(JSON.stringify({
      success: true,
      node_id: key,
      ttl,
      your_ip: ip,
      country
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });

  } catch (e) {
    return new Response(JSON.stringify({ error: 'Invalid request' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// POST /api/heartbeat
async function handleHeartbeat(request: Request, env: Env): Promise<Response> {
  try {
    const body: RegisterRequest = await request.json();

    if (!body.port) {
      return new Response(JSON.stringify({ error: 'Port required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const ip = getClientIP(request);
    const key = nodeKey(ip, body.port, 'mainnet');
    const ttl = parseInt(env.NODE_TTL) || 900;

    const existing = await env.NODES.get(key);

    if (!existing) {
      return handleRegister(request, env);
    }

    const node: NodeInfo = JSON.parse(existing);
    node.lastSeen = Date.now();
    if (body.height) node.height = body.height;
    if (body.version) node.version = body.version;
    if (body.apiPort) node.apiPort = body.apiPort;

    await env.NODES.put(key, JSON.stringify(node), { expirationTtl: ttl });

    return new Response(JSON.stringify({ success: true, node_id: key }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });

  } catch (e) {
    return new Response(JSON.stringify({ error: 'Invalid request' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// GET /api/nodes
async function handleGetNodes(request: Request, env: Env): Promise<Response> {
  const maxNodes = parseInt(env.MAX_NODES) || 100;
  const list = await env.NODES.list({ prefix: 'node:mainnet:', limit: maxNodes });

  const nodes: NodeInfo[] = [];

  for (const key of list.keys) {
    const data = await env.NODES.get(key.name);
    if (data) {
      try {
        nodes.push(JSON.parse(data));
      } catch (e) {}
    }
  }

  nodes.sort((a, b) => {
    if (b.height !== a.height) return b.height - a.height;
    return b.lastSeen - a.lastSeen;
  });

  return new Response(JSON.stringify({
    count: nodes.length,
    nodes: nodes.map(n => ({
      ip: n.ip,
      port: n.port,
      apiPort: n.apiPort,
      version: n.version,
      height: n.height,
      country: n.country,
      age: Math.floor((Date.now() - n.lastSeen) / 1000)
    }))
  }), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

// GET /api/node - Get single best node for connection
async function handleGetNode(env: Env): Promise<Response> {
  const node = await getBestNode(env);

  if (!node) {
    return new Response(JSON.stringify({ error: 'No nodes available' }), {
      status: 503,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  return new Response(JSON.stringify({
    ip: node.ip,
    port: node.port,
    apiPort: node.apiPort,
    version: node.version,
    height: node.height,
    country: node.country,
    url: `http://[${node.ip}]:${node.apiPort}`
  }), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

// GET /api/status
async function handleStatus(env: Env): Promise<Response> {
  const nodeList = await env.NODES.list({ prefix: 'node:mainnet:', limit: 1000 });

  return new Response(JSON.stringify({
    status: 'ok',
    version: '1.1.0',
    nodes: nodeList.keys.length,
    ttl: parseInt(env.NODE_TTL) || 900,
    endpoints: {
      discovery: ['GET /api/nodes', 'GET /api/node', 'POST /api/register', 'POST /api/heartbeat'],
      wallet: ['GET /api/balance/:addr', 'GET /api/utxos/:addr', 'POST /api/tx/send', 'GET /api/tx/:txid'],
      mining: ['GET /api/mining/template', 'POST /api/mining/submit']
    }
  }), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

// Wallet proxy handlers
async function handleBalance(request: Request, env: Env, address: string): Promise<Response> {
  const node = await getBestNode(env);
  if (!node) {
    return new Response(JSON.stringify({ error: 'No nodes available' }), {
      status: 503,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
  return proxyToNode(node, `/address/${address}`);
}

async function handleUtxos(request: Request, env: Env, address: string): Promise<Response> {
  const node = await getBestNode(env);
  if (!node) {
    return new Response(JSON.stringify({ error: 'No nodes available' }), {
      status: 503,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
  return proxyToNode(node, `/utxo/${address}`);
}

async function handleTxSend(request: Request, env: Env): Promise<Response> {
  const node = await getBestNode(env);
  if (!node) {
    return new Response(JSON.stringify({ error: 'No nodes available' }), {
      status: 503,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
  const body = await request.text();
  return proxyToNode(node, '/tx/send', 'POST', body);
}

async function handleTxInfo(request: Request, env: Env, txid: string): Promise<Response> {
  const node = await getBestNode(env);
  if (!node) {
    return new Response(JSON.stringify({ error: 'No nodes available' }), {
      status: 503,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
  return proxyToNode(node, `/tx/${txid}`);
}

async function handleHeight(request: Request, env: Env): Promise<Response> {
  const node = await getBestNode(env);
  if (!node) {
    return new Response(JSON.stringify({ error: 'No nodes available' }), {
      status: 503,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
  return proxyToNode(node, '/status');
}

// Mining proxy handlers
async function handleMiningTemplate(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const address = url.searchParams.get('address') || '';

  const node = await getBestNode(env);
  if (!node) {
    return new Response(JSON.stringify({ error: 'No nodes available' }), {
      status: 503,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
  return proxyToNode(node, `/mining/template?address=${address}`);
}

async function handleMiningSubmit(request: Request, env: Env): Promise<Response> {
  const node = await getBestNode(env);
  if (!node) {
    return new Response(JSON.stringify({ error: 'No nodes available' }), {
      status: 503,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
  const body = await request.text();
  return proxyToNode(node, '/mining/submit', 'POST', body);
}

// Main router
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return handleOptions();
    }

    // Node discovery endpoints
    if (path === '/api/register' && request.method === 'POST') {
      return handleRegister(request, env);
    }
    if (path === '/api/heartbeat' && request.method === 'POST') {
      return handleHeartbeat(request, env);
    }
    if (path === '/api/nodes' && request.method === 'GET') {
      return handleGetNodes(request, env);
    }
    if (path === '/api/node' && request.method === 'GET') {
      return handleGetNode(env);
    }
    if (path === '/api/status' && request.method === 'GET') {
      return handleStatus(env);
    }

    // Wallet proxy endpoints
    const balanceMatch = path.match(/^\/api\/balance\/(.+)$/);
    if (balanceMatch && request.method === 'GET') {
      return handleBalance(request, env, balanceMatch[1]);
    }

    const utxosMatch = path.match(/^\/api\/utxos\/(.+)$/);
    if (utxosMatch && request.method === 'GET') {
      return handleUtxos(request, env, utxosMatch[1]);
    }

    if (path === '/api/tx/send' && request.method === 'POST') {
      return handleTxSend(request, env);
    }

    const txMatch = path.match(/^\/api\/tx\/([a-fA-F0-9]{64})$/);
    if (txMatch && request.method === 'GET') {
      return handleTxInfo(request, env, txMatch[1]);
    }

    if (path === '/api/height' && request.method === 'GET') {
      return handleHeight(request, env);
    }

    // Mining proxy endpoints
    if (path === '/api/mining/template' && request.method === 'GET') {
      return handleMiningTemplate(request, env);
    }
    if (path === '/api/mining/submit' && request.method === 'POST') {
      return handleMiningSubmit(request, env);
    }

    // 404
    return new Response(JSON.stringify({
      error: 'Not found',
      endpoints: {
        discovery: ['GET /api/nodes', 'GET /api/node', 'POST /api/register', 'POST /api/heartbeat', 'GET /api/status'],
        wallet: ['GET /api/balance/:addr', 'GET /api/utxos/:addr', 'POST /api/tx/send', 'GET /api/tx/:txid', 'GET /api/height'],
        mining: ['GET /api/mining/template?address=ftc1...', 'POST /api/mining/submit']
      }
    }), {
      status: 404,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
};
