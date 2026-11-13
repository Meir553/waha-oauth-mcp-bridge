import http from 'node:http';
import https from 'node:https';
import { pathToFileURL } from 'node:url';

const READ_ONLY = new Set(['initialize', 'tools/list']);

/**
 * @param {string} method
 */
export function assertReadOnlyMethod(method) {
  if (!READ_ONLY.has(method)) {
    throw new Error('doctor:remote refuses methods other than initialize and tools/list');
  }
}

/**
 * @param {{ origin?: string, upstreamUrl?: string, apiKey?: string, stdout?: { write: Function }, stderr?: { write: Function }, method?: string }} [options]
 */
export async function runRemoteDoctor(options = {}) {
  const out = options.stdout || process.stdout;
  const err = options.stderr || process.stderr;
  if (options.method) assertReadOnlyMethod(options.method);
  const origin = options.origin ?? process.env.DOCTOR_ORIGIN ?? '';
  if (!origin) {
    out.write('doctor:remote: live checks were not performed. Set DOCTOR_ORIGIN to the public HTTPS origin when a deployed bridge is available.\n');
    return { performed: false };
  }
  let url;
  try {
    url = new URL(origin);
  } catch {
    throw new Error('DOCTOR_ORIGIN is invalid');
  }
  if (url.protocol !== 'https:' || url.username || url.password || (url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) {
    throw new Error('DOCTOR_ORIGIN must be an https origin');
  }
  const prm = await request(new URL('/.well-known/oauth-protected-resource', url));
  if (prm.status !== 200) throw new Error(`protected resource metadata returned ${prm.status}`);
  const metadata = JSON.parse(prm.text);
  if (!Array.isArray(metadata.authorization_servers) || metadata.authorization_servers.length !== 1) {
    throw new Error('protected resource metadata has no single authorization server');
  }
  const as = await request(new URL('/.well-known/oauth-authorization-server', url));
  if (as.status !== 200) throw new Error(`authorization server metadata returned ${as.status}`);
  const server = JSON.parse(as.text);
  if (!Array.isArray(server.token_endpoint_auth_methods_supported) || server.token_endpoint_auth_methods_supported.includes('private_key_jwt') || !server.token_endpoint_auth_methods_supported.includes('none')) {
    throw new Error('authorization server does not advertise public client authentication only');
  }
  const denied = await request(new URL('/mcp', url), {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
  });
  if (denied.status !== 401) throw new Error(`unauthenticated MCP returned ${denied.status}`);
  const challenge = String(denied.headers['www-authenticate'] || '');
  if (!challenge.includes('resource_metadata=') || !challenge.includes('scope="mcp:access"')) {
    throw new Error('401 challenge does not advertise protected resource metadata');
  }
  const upstream = options.upstreamUrl ?? process.env.DOCTOR_UPSTREAM_URL ?? '';
  const apiKey = options.apiKey ?? process.env.DOCTOR_UPSTREAM_API_KEY ?? '';
  if (upstream && apiKey) {
    await upstreamCall(upstream, apiKey, 'initialize');
    await upstreamCall(upstream, apiKey, 'tools/list');
    out.write('doctor:remote: upstream initialize and tools/list completed. No write tool was called.\n');
  } else if (upstream || apiKey) {
    err.write('doctor:remote: upstream check skipped. Set both DOCTOR_UPSTREAM_URL and DOCTOR_UPSTREAM_API_KEY in the environment. The key is never read from argv.\n');
  }
  out.write('doctor:remote: discovery checks finished. This does not prove a ChatGPT account or a live WhatsApp session.\n');
  return { performed: true };
}

/**
 * @param {URL} url
 * @param {{ method?: string, headers?: Record<string, string>, body?: string }} [spec]
 */
function request(url, spec = {}) {
  return exchange(url, spec, false);
}

/**
 * @param {string} upstream
 * @param {string} apiKey
 * @param {string} method
 */
async function upstreamCall(upstream, apiKey, method) {
  assertReadOnlyMethod(method);
  const url = new URL(upstream);
  if (url.pathname !== '/mcp' || url.username || url.password || url.search || url.hash) {
    throw new Error('DOCTOR_UPSTREAM_URL must be an exact /mcp URL');
  }
  const body = JSON.stringify({
    jsonrpc: '2.0',
    id: method === 'initialize' ? 1 : 2,
    method,
    params: method === 'initialize' ? { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'waha-mcp-bridge-doctor', version: '1.0.0' } } : {},
  });
  const response = await exchange(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'x-api-key': apiKey,
    },
    body,
  }, true);
  if (response.status !== 200) throw new Error(`upstream ${method} returned ${response.status}`);
}

/**
 * @param {URL} url
 * @param {{ method?: string, headers?: Record<string, string>, body?: string }} spec
 * @param {boolean} sendKeyHeader
 */
function exchange(url, spec, sendKeyHeader) {
  const lib = url.protocol === 'https:' ? https : http;
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('unsupported URL');
  const headers = { ...(spec.headers || {}) };
  if (!sendKeyHeader) delete headers['x-api-key'];
  if (spec.body) headers['content-length'] = String(Buffer.byteLength(spec.body));
  return new Promise((resolve, reject) => {
    const req = lib.request({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || undefined,
      path: `${url.pathname}${url.search}`,
      method: spec.method || 'GET',
      headers,
      servername: url.protocol === 'https:' ? url.hostname : undefined,
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        resolve({ status: res.statusCode || 0, headers: res.headers, text: body.toString('utf8') });
      });
    });
    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error('doctor request timed out'));
    });
    req.on('error', reject);
    if (spec.body) req.end(spec.body);
    else req.end();
  });
}

async function main() {
  for (const arg of process.argv.slice(2)) {
    if (arg.startsWith('--method=')) assertReadOnlyMethod(arg.slice('--method='.length));
  }
  await runRemoteDoctor();
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    process.stderr.write(`${err.message}\n`);
    process.exit(1);
  });
}
