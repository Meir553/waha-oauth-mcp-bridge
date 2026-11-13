import http from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { hashPassword, nodeMajor } from '../src/crypto.mjs';
import { loadConfig } from '../src/config.mjs';
import { createLogger } from '../src/log.mjs';
import { createCimdResolver } from '../src/oauth/cimd.mjs';
import { startBridge } from '../src/server.mjs';
import { initializeStore, openStore } from '../src/store.mjs';

const CLIENT = 'https://chatgpt.com/oauth/client.json';
const REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect';
const KEY = `doctor-local-${randomBytes(8).toString('hex')}`;

/**
 * Offline simulation. It does not contact ChatGPT, WhatsApp, or a deployed host.
 */
export async function runLocalDoctor(options = {}) {
  const out = options.stdout || process.stdout;
  const lines = [];
  const dir = await mkdtemp(path.join(tmpdir(), 'waha-doctor-'));
  const clock = { now: () => Date.now() };
  let bridge;
  let waha;
  try {
    out.write(`doctor:local node ${process.version}\n`);
    if (nodeMajor(process.version) < 18) {
      throw new Error(`Node.js 18 or newer is required (found ${process.version})`);
    }
    const password = `doctor-${randomBytes(18).toString('base64url')}`;
    const operator = await hashPassword(password);
    await initializeStore({ dataDir: dir, clock, operator: { username: 'admin', ...operator } });
    waha = await fakeWaha();
    const capture = [];
    const config = await loadConfig({
      NODE_ENV: 'test',
      ENABLE_LOCAL_TEST_HTTP: 'true',
      PUBLIC_ORIGIN: 'https://mcp.test.local',
      MCP_PATH: '/mcp',
      LISTEN_HOST: '127.0.0.1',
      LISTEN_PORT: '0',
      UPSTREAM_MCP_URL: waha.url,
      UPSTREAM_API_KEY: KEY,
      DATA_DIR: dir,
      LOG_LEVEL: 'info',
    });
    const logger = createLogger({
      level: 'info',
      secrets: [KEY, password],
      clock,
      sink: { write(line) { capture.push(line); } },
    });
    const store = await openStore({ dataDir: dir, clock, logger });
    const cimd = createCimdResolver({
      clock,
      ttlMs: config.limits.cimdCacheMs,
      timeoutMs: 1000,
      maxBytes: 65536,
      fetchImpl: async (_url, fetchOptions) => {
        if (!fetchOptions || fetchOptions.redirect !== 'manual') throw new Error('redirect policy');
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: Buffer.from(JSON.stringify({
            client_id: CLIENT,
            client_name: 'ChatGPT',
            redirect_uris: [REDIRECT],
            response_types: ['code'],
            token_endpoint_auth_methods_supported: ['none'],
          })),
        };
      },
    });
    bridge = await startBridge({ config, store, logger, clock, cimd });
    const client = createClient(bridge.port);
    const resource = await client.request({ path: '/.well-known/oauth-protected-resource' });
    if (resource.status !== 200 || resource.json().resource !== 'https://mcp.test.local/mcp') {
      throw new Error('protected resource metadata failed');
    }
    lines.push('protected-resource pass');
    const metadata = await client.request({ path: '/.well-known/oauth-authorization-server' });
    const methods = metadata.json().token_endpoint_auth_methods_supported;
    if (metadata.status !== 200 || !Array.isArray(methods) || methods.length !== 1 || methods[0] !== 'none') {
      throw new Error('authorization server metadata failed');
    }
    lines.push('authorization-server pass');
    const denied = await client.request({
      method: 'POST',
      path: '/mcp',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    });
    if (denied.status !== 401 || !String(denied.headers['www-authenticate'] || '').includes('resource_metadata=')) {
      throw new Error('unauthenticated MCP challenge failed');
    }
    if (waha.calls !== 0) throw new Error('unauthenticated MCP called upstream');
    lines.push('unauthenticated-mcp pass');
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: CLIENT,
      redirect_uri: REDIRECT,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      resource: config.resource,
      scope: 'mcp:access',
      state: 'doctor-state',
    });
    const authorize = await client.request({ path: `/oauth/authorize?${query}` });
    if (authorize.status !== 303) throw new Error('authorize simulation failed');
    const login = await client.request({ path: '/login' });
    const posted = await client.request({
      method: 'POST',
      path: '/login',
      form: {
        username: 'admin',
        password,
        csrf: hidden(login.text, 'csrf'),
        request_id: hidden(login.text, 'request_id'),
      },
    });
    if (posted.status !== 303) throw new Error('login simulation failed');
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
    if (approved.status !== 303) throw new Error('consent simulation failed');
    const location = new URL(approved.headers.location);
    const tokenResponse = await client.request({
      method: 'POST',
      path: '/oauth/token',
      form: {
        grant_type: 'authorization_code',
        code: location.searchParams.get('code'),
        redirect_uri: REDIRECT,
        client_id: CLIENT,
        code_verifier: verifier,
        resource: config.resource,
      },
    });
    const token = tokenResponse.json();
    if (tokenResponse.status !== 200 || !token.access_token) throw new Error('token simulation failed');
    lines.push('authorization pass');
    const listed = await client.request({
      method: 'POST',
      path: '/mcp',
      headers: {
        authorization: `Bearer ${token.access_token}`,
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
    });
    const tools = listed.json().result.tools;
    if (listed.status !== 200 || !tools.some((tool) => tool.securitySchemes?.some((scheme) => scheme.type === 'oauth2'))) {
      throw new Error('proxy simulation failed');
    }
    lines.push('proxy pass');
    const printed = `${lines.join('\n')}\n${capture.join('')}`;
    if (printed.includes(KEY) || printed.includes(password) || printed.includes(token.access_token)) {
      throw new Error('doctor output contained a secret');
    }
    for (const line of lines) out.write(`doctor:local ${line}\n`);
    out.write('doctor:local pass\n');
    out.write('doctor:local live ChatGPT, live WAHA, and public TLS were not contacted.\n');
    return { ok: true };
  } finally {
    if (bridge) await bridge.close();
    if (waha) await waha.close();
    await rm(dir, { recursive: true, force: true });
  }
}

function fakeWaha() {
  let calls = 0;
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    calls += 1;
    const body = Buffer.concat(chunks);
    let rpc = null;
    try { rpc = JSON.parse(body.toString('utf8')); } catch { rpc = null; }
    if (rpc && rpc.method === 'tools/list') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: rpc.id,
        result: { tools: [{ name: 'get_chats', description: 'list', inputSchema: { type: 'object' }, annotations: {} }] },
      }));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: rpc ? rpc.id : null, result: {} }));
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        url: `http://127.0.0.1:${port}/mcp`,
        get calls() { return calls; },
        close() {
          if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
          return new Promise((done) => server.close(() => done()));
        },
      });
    });
  });
}

function createClient(port) {
  const cookies = new Map();
  return {
    request(spec) {
      const headers = { host: 'mcp.test.local', ...(spec.headers || {}) };
      if (cookies.size) headers.cookie = [...cookies].map(([name, value]) => `${name}=${value}`).join('; ');
      let body = spec.body;
      if (spec.form) {
        body = new URLSearchParams(spec.form).toString();
        headers['content-type'] = 'application/x-www-form-urlencoded';
      }
      if (body) headers['content-length'] = String(Buffer.byteLength(body));
      return new Promise((resolve, reject) => {
        const req = http.request({ hostname: '127.0.0.1', port, path: spec.path, method: spec.method || 'GET', headers }, (res) => {
          const chunks = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('end', () => {
            const setCookie = res.headers['set-cookie'] || [];
            for (const item of (Array.isArray(setCookie) ? setCookie : [setCookie])) {
              const pair = String(item).split(';', 1)[0];
              const idx = pair.indexOf('=');
              if (idx > 0) cookies.set(pair.slice(0, idx), pair.slice(idx + 1));
            }
            const buffer = Buffer.concat(chunks);
            resolve({
              status: res.statusCode,
              headers: res.headers,
              text: buffer.toString('utf8'),
              json() { return JSON.parse(buffer.toString('utf8')); },
            });
          });
        });
        req.on('error', reject);
        req.end(body || undefined);
      });
    },
  };
}

function hidden(html, name) {
  const match = new RegExp(`name="${name}" value="([^"]*)"`).exec(html);
  if (!match || !match[1]) throw new Error('doctor form was incomplete');
  return match[1];
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runLocalDoctor().catch((err) => {
    process.stderr.write(`doctor:local fail ${err.message}\n`);
    process.exit(1);
  });
}
