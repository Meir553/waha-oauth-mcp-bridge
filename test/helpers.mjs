import http from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { hashPassword } from '../src/crypto.mjs';
import { loadConfig } from '../src/config.mjs';
import { captureSink, createLogger } from '../src/log.mjs';
import { createCimdResolver } from '../src/oauth/cimd.mjs';
import { startBridge } from '../src/server.mjs';
import { initializeStore } from '../src/store.mjs';

const CLIENT = 'https://chatgpt.com/oauth/client.json';
const REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect';

/**
 * @param {Record<string, unknown>} [overrides]
 */
export function cimdDocument(overrides = {}) {
  return {
    client_id: CLIENT,
    client_name: 'ChatGPT',
    redirect_uris: [REDIRECT],
    response_types: ['code'],
    token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
    token_endpoint_auth_method: 'private_key_jwt',
    ...overrides,
  };
}

function tool(name, extra = {}) {
  return {
    name,
    description: `${name} description`,
    inputSchema: { type: 'object', properties: { text: { type: 'string' } } },
    outputSchema: { type: 'object' },
    annotations: extra.annotations || { title: name },
    _meta: extra.meta || { source: 'waha' },
    ...extra.rest,
  };
}

/**
 * @returns {Promise<object>}
 */
export async function startFakeWaha() {
  const calls = [];
  const control = {
    tools: [tool('get_chats'), tool('send_message', { annotations: {}, meta: {} })],
    sessionId: 'sess-fixed-1',
    callCount: 0,
    open: [],
  };
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    calls.push({ method: req.method, url: req.url, headers: { ...req.headers }, body });
    if (control.handler) {
      await control.handler(req, res, { body, headers: req.headers });
      return;
    }
    let rpc = null;
    try { rpc = body.length ? JSON.parse(body.toString('utf8')) : null; } catch { rpc = null; }
    if (control.status) {
      const headers = { 'content-type': 'text/plain', ...(control.responseHeaders || {}) };
      res.writeHead(control.status, headers);
      res.end(control.body || 'upstream failure');
      return;
    }
    if (req.method === 'GET') {
      res.writeHead(control.getStatus || 200, { 'content-type': control.getStatus === 405 ? 'application/json' : 'text/event-stream', allow: 'GET, POST, DELETE', ...(control.getHeaders || {}) });
      res.end(control.getBody || `id: ${req.headers['last-event-id'] || '0'}\ndata: {"ok":true}\n\n`);
      return;
    }
    if (req.method === 'DELETE') {
      res.writeHead(control.deleteStatus || 200, { 'content-type': 'application/json', allow: 'GET, POST, DELETE' });
      res.end('{}');
      return;
    }
    const method = rpc && rpc.method;
    if (method === 'notifications/initialized') {
      res.writeHead(202);
      res.end();
      return;
    }
    if (method === 'initialize') {
      res.writeHead(200, {
        'content-type': 'application/json',
        'mcp-session-id': control.sessionId,
        'mcp-protocol-version': String(req.headers['mcp-protocol-version'] || '2025-11-25'),
      });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: { protocolVersion: '2025-11-25', capabilities: {}, serverInfo: { name: 'fake-waha', version: '0' } } }));
      return;
    }
    if (method === 'tools/list') {
      const payload = { jsonrpc: '2.0', id: rpc.id, result: { tools: control.tools } };
      if (control.listSse) {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        const raw = control.listSse(payload);
        const pieces = Array.isArray(raw) ? raw : [raw];
        for (const piece of pieces) res.write(piece);
        res.end();
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(payload));
      return;
    }
    if (method === 'tools/call') {
      control.callCount += 1;
      if (control.holdCall) {
        control.open.push(res);
        return;
      }
    }
    const payload = control.callPayload ? control.callPayload(rpc) : {
      jsonrpc: '2.0',
      id: rpc ? rpc.id : null,
      result: { content: [{ type: 'text', text: 'שלום 😀' }], structuredContent: { ok: true, text: 'שלום 😀' }, isError: false },
    };
    const encoded = Buffer.from(JSON.stringify(payload));
    if (control.sseCall) {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      const sse = `id: 7\ndata: ${encoded.toString('utf8')}\n\n`;
      const buf = Buffer.from(sse);
      const size = control.piece || 1;
      for (let i = 0; i < buf.length; i += size) res.write(buf.subarray(i, i + size));
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    const size = control.piece || encoded.length;
    for (let i = 0; i < encoded.length; i += size) res.write(encoded.subarray(i, i + size));
    res.end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  return {
    calls,
    control,
    port,
    url: `http://127.0.0.1:${port}/mcp`,
    close() {
      for (const open of control.open) open.destroy();
      if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

let operatorPromise;
export function testOperator() {
  if (!operatorPromise) operatorPromise = hashPassword('correct-horse-battery-staple');
  return operatorPromise;
}

/**
 * @param {number} [start]
 */
export function createClock(start = 1_700_000_000_000) {
  let now = start;
  return {
    now() { return now; },
    advance(ms) { now += ms; },
    set(ms) { now = ms; },
  };
}

/**
 * @param {{ port: number, hostHeader: string }} options
 */
export function createClient(options) {
  const cookies = new Map();
  return {
    cookies,
    request(spec) {
      const headers = { host: options.hostHeader, ...(spec.headers || {}) };
      if (!headers.cookie && cookies.size) {
        headers.cookie = [...cookies].map(([key, value]) => `${key}=${value}`).join('; ');
      }
      let body = spec.body;
      if (spec.form) {
        body = new URLSearchParams(spec.form).toString();
        headers['content-type'] = headers['content-type'] || 'application/x-www-form-urlencoded';
        headers['content-length'] = String(Buffer.byteLength(body));
      } else if (body && !headers['content-length']) {
        headers['content-length'] = String(Buffer.isBuffer(body) ? body.length : Buffer.byteLength(body));
      }
      return new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: options.port,
          path: spec.path,
          method: spec.method || 'GET',
          headers,
        }, (res) => {
          const chunks = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('end', () => {
            const setCookie = res.headers['set-cookie'] || [];
            for (const item of (Array.isArray(setCookie) ? setCookie : [setCookie])) remember(cookies, item);
            const buffer = Buffer.concat(chunks);
            resolve({
              status: res.statusCode,
              headers: res.headers,
              body: buffer,
              text: buffer.toString('utf8'),
              json() { return JSON.parse(buffer.toString('utf8')); },
            });
          });
        });
        req.on('error', reject);
        if (body) req.end(body);
        else req.end();
      });
    },
  };
}

function remember(cookies, header) {
  if (!header) return;
  const pair = header.split(';', 1)[0];
  const idx = pair.indexOf('=');
  if (idx < 1) return;
  const name = pair.slice(0, idx).trim();
  const value = pair.slice(idx + 1).trim();
  if (/Max-Age=0/i.test(header)) cookies.delete(name);
  else cookies.set(name, value);
}

/**
 * @param {string} html
 * @param {string} name
 */
export function hidden(html, name) {
  const match = new RegExp(`name="${name}" value="([^"]*)"`).exec(html);
  if (!match) throw new Error(`missing hidden field ${name}`);
  return match[1];
}

/**
 * @param {object} [options]
 */
export async function createHarness(options = {}) {
  const clock = options.clock || createClock();
  const dir = await mkdtemp(path.join(tmpdir(), 'waha-bridge-'));
  const operator = await testOperator();
  await initializeStore({
    dataDir: dir,
    clock,
    operator: { username: 'admin', ...operator },
  });
  const waha = await startFakeWaha();
  const capture = captureSink();
  const env = {
    NODE_ENV: 'test',
    ENABLE_LOCAL_TEST_HTTP: 'true',
    PUBLIC_ORIGIN: 'https://mcp.test.local',
    MCP_PATH: '/mcp',
    LISTEN_HOST: '127.0.0.1',
    LISTEN_PORT: '0',
    UPSTREAM_MCP_URL: waha.url,
    UPSTREAM_API_KEY: 'test-upstream-key-value',
    UPSTREAM_API_KEY_HEADER: 'X-Api-Key',
    DATA_DIR: dir,
    LOG_LEVEL: 'info',
    ...(options.env || {}),
  };
  const config = await loadConfig(env, { lookup: options.lookup, extraUpstreams: options.extraUpstreams });
  if (options.limits) Object.assign(config.limits, options.limits);
  if (options.ttl) Object.assign(config.ttl, options.ttl);
  const logger = createLogger({
    level: 'info',
    secrets: [...config.upstreams.map((item) => item.apiKey), 'WHATSAPP-PRIVATE-PHRASE-9f3a'],
    sink: capture.sink,
    clock,
  });
  const { openStore } = await import('../src/store.mjs');
  const store = await openStore({ dataDir: dir, clock, logger, hooks: options.hooks });
  const documents = options.documents || { [CLIENT]: cimdDocument(options.cimd) };
  const cimd = createCimdResolver({
    clock,
    ttlMs: options.cimdTtlMs || config.limits.cimdCacheMs,
    timeoutMs: options.cimdTimeoutMs || 1000,
    maxBytes: options.cimdMaxBytes || 65536,
    fetchImpl: options.fetchImpl || (async (url, fetchOptions) => {
      if (fetchOptions && fetchOptions.redirect !== 'manual') {
        throw new Error('redirect policy was not manual');
      }
      const doc = documents[url];
      if (!doc) return { status: 404, headers: { 'content-type': 'application/json' }, body: Buffer.from('{}') };
      if (doc === 'hang') return new Promise(() => {});
      if (doc === 'redirect') return { status: 302, headers: { 'content-type': 'application/json', location: 'https://evil.example' }, body: Buffer.alloc(0) };
      if (doc === 'huge') return { status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.alloc(70 * 1024, 0x61) };
      const body = Buffer.from(typeof doc === 'string' ? doc : JSON.stringify(doc));
      return { status: 200, headers: { 'content-type': 'application/json' }, body };
    }),
  });
  const bridge = await startBridge({ config, store, logger, clock, cimd, lookup: options.lookup });
  const client = createClient({ port: bridge.port, hostHeader: 'mcp.test.local' });
  return {
    dir, waha, clock, config, store, bridge, client, capture, password: 'correct-horse-battery-staple',
    async close() {
      await bridge.close();
      await waha.close();
      await rm(dir, { recursive: true, force: true });
    },
  };
}

export const FIXTURE = { CLIENT, REDIRECT };

/**
 * @param {object} harness
 * @param {Record<string, string>} [extra]
 */
export async function authorize(harness, extra = {}) {
  const client = extra.client || harness.client;
  const { createHash, randomBytes } = await import('node:crypto');
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: extra.client_id || CLIENT,
    redirect_uri: extra.redirect_uri || REDIRECT,
    code_challenge: extra.code_challenge || challenge,
    code_challenge_method: extra.code_challenge_method || 'S256',
    resource: extra.resource || harness.config.resource,
    scope: extra.scope || 'mcp:access',
    ...(extra.state === undefined ? { state: extra.stateValue || 'state-1' } : extra.state ? { state: extra.state } : {}),
  });
  if (extra.omit) {
    for (const key of extra.omit) params.delete(key);
  }
  if (extra.rawQuery) {
    return harness.client.request({ path: `/oauth/authorize?${extra.rawQuery}` });
  }
  return {
    verifier,
    challenge,
    response: await client.request({ path: `/oauth/authorize?${params.toString()}` }),
  };
}

/**
 * @param {object} harness
 * @param {{ scope?: string, state?: string }} [options]
 */
export async function approvedGrant(harness, options = {}) {
  const client = options.client || harness.client;
  const started = await authorize(harness, options);
  if (started.response.status !== 303) {
    throw new Error(`authorize failed ${started.response.status} ${started.response.text}`);
  }
  const loginPage = await client.request({ path: '/login' });
  const posted = await client.request({
    method: 'POST',
    path: '/login',
    form: {
      username: 'admin',
      password: harness.password,
      csrf: hidden(loginPage.text, 'csrf'),
      request_id: hidden(loginPage.text, 'request_id'),
    },
  });
  if (posted.status !== 303) throw new Error(`login failed ${posted.status} ${posted.text}`);
  const consent = await client.request({ path: '/oauth/consent' });
  const approved = await client.request({
    method: 'POST',
    path: '/oauth/consent',
    form: {
      csrf: hidden(consent.text, 'csrf'),
      request_id: hidden(consent.text, 'request_id'),
      decision: 'approve',
    },
  });
  if (approved.status !== 303) throw new Error(`consent failed ${approved.status} ${approved.text}`);
  const location = new URL(approved.headers.location);
  const token = await client.request({
    method: 'POST',
    path: '/oauth/token',
    form: {
      grant_type: 'authorization_code',
      code: location.searchParams.get('code'),
      redirect_uri: REDIRECT,
      client_id: CLIENT,
      code_verifier: started.verifier,
      resource: options.resource || harness.config.resource,
    },
  });
  return { location, token: token.json(), tokenResponse: token, verifier: started.verifier, consent: consent.text };
}

