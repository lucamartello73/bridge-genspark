/**
 * Bridge Genspark MCP - server.js
 * MCP proxy for Genspark -> n8n via Railway
 * Adapted from bridge-companion for Genspark compatibility
 * Supports: HTTP POST /mcp endpoint + SSE /sse endpoint
 */

const express = require("express");
const crypto = require("crypto");

process.on("uncaughtException", (err) => console.error("UNCAUGHT EXCEPTION:", err));
process.on("unhandledRejection", (err) => console.error("UNHANDLED REJECTION:", err));

const app = express();
const port = process.env.PORT || 3000;
const fetch = global.fetch;

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false }));

// ============================
// ENV
// ============================
const BRIDGE_API_KEY = process.env.BRIDGE_API_KEY;
const N8N_MCP_TOOLS_URL = process.env.N8N_MCP_TOOLS_URL;
const N8N_API_KEY = process.env.N8N_API_KEY || "";
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || "https://bridge-genspark-production.up.railway.app";
const UPSTREAM_TIMEOUT_MS = Number(process.env.UPSTREAM_TIMEOUT_MS || 8000);
const TOOLS_LIST_TTL_MS = Number(process.env.TOOLS_LIST_TTL_MS || 60000);
const SSE_KEEPALIVE_MS = Number(process.env.SSE_KEEPALIVE_MS || 10000);
const SSE_TIMEOUT_MS = Number(process.env.SSE_TIMEOUT_MS || 14400000);

if (!BRIDGE_API_KEY) {
  console.error("BRIDGE_API_KEY not set");
  process.exit(1);
}

// ============================
// OAuth in-memory stores
// ============================
const clients = new Map();
const authCodes = new Map();
const refreshTokens = new Map();
const accessTokens = new Map();

// tools/list cache
let toolsListCache = { ts: 0, payload: null };

// SSE sessions
const sseSessions = new Map();

// ============================
// Helpers
// ============================
const nowMs = () => Date.now();
const base64url = (buf) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const sha256Base64Url = (str) => base64url(crypto.createHash("sha256").update(str).digest());
const genToken = (bytes = 32) => base64url(crypto.randomBytes(bytes));

const extractBearer = (req) => {
  const h = req.headers.authorization || "";
  return h.startsWith("Bearer ") ? h.slice(7) : null;
};

const validateAccessToken = (token) => {
  if (!token) return false;
  if (token === BRIDGE_API_KEY) return true;
  const e = accessTokens.get(token);
  if (!e) return false;
  if (nowMs() > e.expires_at) {
    accessTokens.delete(token);
    return false;
  }
  return true;
};

const n8nHeaders = () => ({
  "Content-Type": "application/json",
  ...(N8N_API_KEY ? { "X-N8N-API-KEY": N8N_API_KEY } : {}),
});

async function fetchWithTimeout(url, opts, timeout = UPSTREAM_TIMEOUT_MS) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), timeout);
  try {
    return await fetch(url, { ...opts, signal: c.signal });
  } finally {
    clearTimeout(t);
  }
}

// ============================
// Schema fix: add items to arrays where missing
// ============================
function inferArrayItems(propName) {
  if (!propName) return { type: "object" };
  const k = String(propName);
  if (k === "position") return { type: "number" };
  if (k === "workflowIds" || k.toLowerCase().endsWith("ids")) return { type: "string" };
  return { type: "object" };
}

function patchSchemaArrays(schema, propName = "") {
  if (!schema || typeof schema !== "object") return schema;
  if (schema.type === "array" && schema.items == null) {
    schema.items = inferArrayItems(propName);
  }
  if (schema.items && typeof schema.items === "object") {
    patchSchemaArrays(schema.items, propName);
  }
  if (schema.properties && typeof schema.properties === "object") {
    for (const [k, v] of Object.entries(schema.properties)) {
      patchSchemaArrays(v, k);
    }
  }
  for (const key of ["anyOf", "oneOf", "allOf"]) {
    if (Array.isArray(schema[key])) {
      for (const s of schema[key]) patchSchemaArrays(s, propName);
    }
  }
  return schema;
}

function patchToolsListPayload(parsed) {
  if (!parsed || typeof parsed !== "object") return parsed;
  const tools = parsed?.result?.tools;
  if (!Array.isArray(tools)) return parsed;
  for (const tool of tools) {
    if (tool && tool.inputSchema && typeof tool.inputSchema === "object") {
      patchSchemaArrays(tool.inputSchema);
    }
  }
  return parsed;
}

// ============================
// MCP request handler (shared)
// ============================
async function handleMcpRequest(body, token) {
  const { jsonrpc, method, params = {}, id = null } = body || {};
  
  if (jsonrpc !== "2.0") {
    return { jsonrpc: "2.0", id, error: { code: -32600, message: "Invalid Request" } };
  }

  const isBootstrap = method === "initialize" || method === "tools/list" || 
                      method === "resources/list" || method === "prompts/list";
  
  if (!isBootstrap && !validateAccessToken(token)) {
    return { jsonrpc: "2.0", id, error: { code: -32001, message: "Unauthorized" } };
  }

  try {
    if (method === "initialize") {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {}, resources: {}, prompts: {} },
          serverInfo: { name: "bridge-genspark-mcp", version: "1.0.0" },
        },
      };
    }

    if (method === "resources/list") return { jsonrpc: "2.0", id, result: { resources: [] } };
    if (method === "prompts/list") return { jsonrpc: "2.0", id, result: { prompts: [] } };

    if (method === "tools/list") {
      const now = nowMs();
      if (toolsListCache.payload && now - toolsListCache.ts < TOOLS_LIST_TTL_MS) {
        return { ...toolsListCache.payload, id };
      }
      const r = await fetchWithTimeout(
        N8N_MCP_TOOLS_URL,
        { method: "POST", headers: n8nHeaders(), body: JSON.stringify({ jsonrpc: "2.0", id, method, params }) }
      );
      const parsedRaw = await r.json();
      const parsed = patchToolsListPayload(parsedRaw);
      if (parsed?.result?.tools) toolsListCache = { ts: now, payload: parsed };
      return parsed;
    }

    if (method === "tools/call") {
      const r = await fetchWithTimeout(
        N8N_MCP_TOOLS_URL,
        { method: "POST", headers: n8nHeaders(), body: JSON.stringify({ jsonrpc: "2.0", id, method, params }) }
      );
      return await r.json();
    }

    return { jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } };
  } catch (e) {
    return { jsonrpc: "2.0", id, error: { code: -32603, message: e.message } };
  }
}

// ============================
// ROOT / HEALTH
// ============================
app.get("/", (_req, res) => res.json({ ok: true, service: "bridge-genspark", message: "Use /mcp or /sse" }));
app.post("/", (_req, res) => res.json({ ok: true, service: "bridge-genspark", message: "Use /mcp or /sse" }));

app.get("/health", (_req, res) => res.json({
  ok: true,
  oauth: true,
  mcp: true,
  sse: true,
  n8n_mcp_tools: !!N8N_MCP_TOOLS_URL,
  tools_cache_ttl_ms: TOOLS_LIST_TTL_MS,
  upstream_timeout_ms: UPSTREAM_TIMEOUT_MS,
  public_base_url: PUBLIC_BASE_URL
}));

// ============================
// OAuth discovery endpoints
// ============================
app.get("/.well-known/oauth-protected-resource", (_req, res) => res.json({
  resource: PUBLIC_BASE_URL,
  authorization_servers: [PUBLIC_BASE_URL],
  scopes_supported: ["mcp:tools"],
  resource_documentation: `${PUBLIC_BASE_URL}/health`,
}));

app.get("/.well-known/oauth-protected-resource/mcp", (_req, res) => res.json({
  resource: `${PUBLIC_BASE_URL}/mcp`,
  authorization_servers: [PUBLIC_BASE_URL],
  scopes_supported: ["mcp:tools"],
}));

app.get("/mcp/.well-known/oauth-protected-resource", (_req, res) => res.redirect(302, "/.well-known/oauth-protected-resource"));
app.get("/.well-known/oauth-authorization-server/mcp", (_req, res) => res.redirect(302, "/.well-known/oauth-authorization-server"));
app.get("/mcp/.well-known/oauth-authorization-server", (_req, res) => res.redirect(302, "/.well-known/oauth-authorization-server"));

app.get("/.well-known/oauth-authorization-server", (_req, res) => res.json({
  issuer: PUBLIC_BASE_URL,
  authorization_endpoint: `${PUBLIC_BASE_URL}/oauth/authorize`,
  token_endpoint: `${PUBLIC_BASE_URL}/oauth/token`,
  registration_endpoint: `${PUBLIC_BASE_URL}/oauth/register`,
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token"],
  token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
  code_challenge_methods_supported: ["S256"],
  scopes_supported: ["mcp:tools"],
}));

app.get("/.well-known/openid-configuration/mcp", (_req, res) => res.redirect(302, "/.well-known/openid-configuration"));
app.get("/mcp/.well-known/openid-configuration", (_req, res) => res.redirect(302, "/.well-known/openid-configuration"));
app.get("/.well-known/openid-configuration", (_req, res) => res.json({
  issuer: PUBLIC_BASE_URL,
  authorization_endpoint: `${PUBLIC_BASE_URL}/oauth/authorize`,
  token_endpoint: `${PUBLIC_BASE_URL}/oauth/token`,
}));

app.get("/oauth/token/.well-known/openid-configuration", (_req, res) => res.redirect(302, "/.well-known/openid-configuration"));
app.get("/oauth/token/.well-known/oauth-authorization-server", (_req, res) => res.redirect(302, "/.well-known/oauth-authorization-server"));

// ============================
// OAuth register
// ============================
app.post("/oauth/register", (req, res) => {
  const client_id = crypto.randomUUID();
  const client_secret = genToken(24);
  const redirect_uris = req.body?.redirect_uris || [];
  clients.set(client_id, { client_secret, redirect_uris, public_client: false });
  return res.status(201).json({
    client_id,
    client_secret,
    token_endpoint_auth_method: "client_secret_post",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    redirect_uris,
  });
});

// ============================
// OAuth authorize (PKCE)
// ============================
app.get("/oauth/authorize", (req, res) => {
  const { response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method } = req.query;
  if (response_type !== "code") return res.status(400).send("unsupported_response_type");
  if (!client_id || !redirect_uri || !code_challenge) return res.status(400).send("invalid_request");
  if (code_challenge_method !== "S256") return res.status(400).send("invalid_code_challenge_method");
  
  let client = clients.get(client_id);
  if (!client) {
    client = { public_client: true, redirect_uris: [redirect_uri] };
    clients.set(client_id, client);
  }
  
  const code = crypto.randomUUID();
  authCodes.set(code, { client_id, redirect_uri, code_challenge, expires_at: nowMs() + 5 * 60 * 1000 });
  
  const u = new URL(redirect_uri);
  u.searchParams.set("code", code);
  if (state) u.searchParams.set("state", state);
  return res.redirect(u.toString());
});

// ============================
// OAuth token
// ============================
app.post("/oauth/token", (req, res) => {
  const body = req.body || {};
  const grant_type = body.grant_type;

  if (grant_type === "authorization_code") {
    const { client_id, code, redirect_uri, code_verifier } = body;
    const entry = authCodes.get(code);
    if (!entry) return res.status(400).json({ error: "invalid_grant" });
    if (entry.client_id !== client_id) return res.status(400).json({ error: "invalid_grant" });
    if (entry.redirect_uri !== redirect_uri) return res.status(400).json({ error: "invalid_grant" });
    if (sha256Base64Url(code_verifier) !== entry.code_challenge) return res.status(400).json({ error: "invalid_grant" });
    
    authCodes.delete(code);
    const access_token = genToken(32);
    const refresh_token = genToken(32);
    accessTokens.set(access_token, { expires_at: nowMs() + 60 * 60 * 1000 });
    refreshTokens.set(refresh_token, { expires_at: nowMs() + 30 * 24 * 60 * 60 * 1000 });
    return res.json({ access_token, token_type: "Bearer", expires_in: 3600, refresh_token });
  }

  if (grant_type === "refresh_token") {
    const rt = body.refresh_token;
    if (!rt) return res.status(400).json({ error: "invalid_request" });
    const rEntry = refreshTokens.get(rt);
    if (!rEntry) return res.status(400).json({ error: "invalid_grant" });
    if (nowMs() > rEntry.expires_at) {
      refreshTokens.delete(rt);
      return res.status(400).json({ error: "invalid_grant" });
    }
    const access_token = genToken(32);
    accessTokens.set(access_token, { expires_at: nowMs() + 60 * 60 * 1000 });
    return res.json({ access_token, token_type: "Bearer", expires_in: 3600 });
  }

  return res.status(400).json({ error: "unsupported_grant_type" });
});

// ============================
// MCP HTTP endpoint (POST /mcp)
// ============================
app.post("/mcp", async (req, res) => {
  const token = extractBearer(req);
  const response = await handleMcpRequest(req.body, token);
  
  if (response.error?.code === -32001) {
    res.setHeader(
      "WWW-Authenticate",
      `Bearer realm="mcp", resource_metadata="${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource"`
    );
  }
  
  return res.json(response);
});

// ============================
// SSE endpoint for Genspark (GET /sse)
// ============================
app.get("/sse", (req, res) => {
  const sessionId = crypto.randomUUID();
  
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.flushHeaders();

  // Send endpoint info
      res.write(`event: endpoint\ndata: ${PUBLIC_BASE_URL}/sse/messages?sessionId=${sessionId}\n\n`);

    // Set connection timeout to 4 hours
  req.setTimeout(SSE_TIMEOUT_MS);
  sseSessions.set(sessionId, { res, createdAt: nowMs() });
  console.log(`[SSE] Session ${sessionId} connected`);

    // SSE keep-alive heartbeat to prevent connection timeout
  const keepAliveInterval = setInterval(() => {
    try {
      res.write(': ping\n\n');
    } catch (e) {
      clearInterval(keepAliveInterval);
    }
  }, SSE_KEEPALIVE_MS);

  req.on("close", () => {
    sseSessions.delete(sessionId);
        clearInterval(keepAliveInterval);
    console.log(`[SSE] Session ${sessionId} disconnected`);
  });
});
// ============================
// SSE messages endpoint (POST /sse/messages)
// ============================
app.post("/sse/messages", async (req, res) => {
  const sessionId = req.query.sessionId;
  const session = sseSessions.get(sessionId);
  
  if (!session) {
    return res.status(400).json({ error: "Invalid session" });
  }

  const token = extractBearer(req) || BRIDGE_API_KEY;
  const response = await handleMcpRequest(req.body, token);
  
  // Send response via SSE
      session.res.write(`event: message\ndata: ${JSON.stringify(response)}\n\n`);
  
  return res.json({ ok: true });
});

// ============================
// START
// ============================
app.listen(port, () => {
  console.log(`Bridge Genspark MCP listening on port ${port}`);
  console.log("MCP ready at /mcp");
  console.log("SSE ready at /sse");
});
