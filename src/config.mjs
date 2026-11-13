import { lstat, readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import path from 'node:path';
import { lookup as dnsLookup } from 'node:dns/promises';
import { X509Certificate } from 'node:crypto';
import { createSecureContext } from 'node:tls';
import { assertNodeVersion } from './crypto.mjs';
import { assertApiKey, assertUpstreamId, cleanDisplayName, readUpstreamDefinitions, registerUpstreams } from './upstreams.mjs';

const HEADER_DENY = new Set([
  'authorization', 'cookie', 'host', 'content-type', 'content-length',
  'connection', 'transfer-encoding', 'mcp-session-id', 'mcp-protocol-version',
]);

/**
 * @param {string} ip
 * @returns {boolean}
 */
export function isPrivateIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  let value = ip.trim().toLowerCase();
  if (value.startsWith('::ffff:')) value = value.slice(7);
  if (value === '::1') return true;
  if (value.includes(':')) {
    const head = value.split('::')[0];
    return head.startsWith('fc') || head.startsWith('fd');
  }
  const parts = value.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  if (parts[0] === 127) return true;
  if (parts[0] === 10) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  return false;
}

/**
 * @param {string} value
 * @returns {{ href: string, origin: string, hostname: string, port: number }}
 */
export function parsePublicOrigin(value) {
  if (typeof value !== 'string' || value.length > 256 || /[\s\u0000-\u001F]/.test(value)) {
    throw new Error('PUBLIC_ORIGIN is invalid');
  }
  if (value.endsWith('/')) throw new Error('PUBLIC_ORIGIN must not have a trailing slash');
  let url;
  try { url = new URL(value); } catch { throw new Error('PUBLIC_ORIGIN is invalid'); }
  if (url.protocol !== 'https:') throw new Error('PUBLIC_ORIGIN must use https');
  if (url.username || url.password) throw new Error('PUBLIC_ORIGIN must not contain userinfo');
  if (url.pathname !== '/' || url.search || url.hash) throw new Error('PUBLIC_ORIGIN must not include a path, query, or fragment');
  if (!url.hostname || url.hostname === 'localhost' || isIP(url.hostname)) {
    throw new Error('PUBLIC_ORIGIN must be a DNS name');
  }
  if (url.hostname.includes('*') || url.hostname.endsWith('.')) throw new Error('PUBLIC_ORIGIN hostname is invalid');
  const port = url.port ? Number(url.port) : 443;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PUBLIC_ORIGIN port is invalid');
  return {
    href: url.port ? `https://${url.hostname}:${port}` : `https://${url.hostname}`,
    origin: url.port ? `https://${url.hostname}:${port}` : `https://${url.hostname}`,
    hostname: url.hostname.toLowerCase(),
    port,
  };
}

/**
 * @param {string} value
 * @param {{ allowPublic: boolean, lookup?: Function }} options
 */
export async function parseUpstreamUrl(value, options) {
  if (typeof value !== 'string' || value.length > 512 || /[\s\u0000-\u001F]/.test(value)) {
    throw new Error('UPSTREAM_MCP_URL is invalid');
  }
  let url;
  try { url = new URL(value); } catch { throw new Error('UPSTREAM_MCP_URL is invalid'); }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('UPSTREAM_MCP_URL scheme is invalid');
  if (url.username || url.password) throw new Error('UPSTREAM_MCP_URL must not contain userinfo');
  if (url.search || url.hash) throw new Error('UPSTREAM_MCP_URL must not contain a query or fragment');
  if (url.pathname !== '/mcp') throw new Error('UPSTREAM_MCP_URL path must be /mcp');
  const port = url.port
    ? Number(url.port)
    : (url.protocol === 'https:' ? 443 : 80);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('UPSTREAM_MCP_URL port is invalid');
  const pinned = await pinUpstreamAddress(url.hostname, options);
  return {
    href: url.href,
    protocol: url.protocol,
    hostname: url.hostname,
    port,
    pinnedAddress: pinned.address,
    pinnedFamily: pinned.family,
  };
}

/**
 * @param {string} hostname
 * @param {{ allowPublic: boolean, lookup?: Function }} options
 */
export async function pinUpstreamAddress(hostname, options) {
  const allowPublic = options.allowPublic === true;
  const lookup = options.lookup || dnsLookup;
  if (isIP(hostname)) {
    if (!allowPublic && !isPrivateIp(hostname)) throw new Error('UPSTREAM_MCP_URL address is not private');
    return { address: hostname, family: isIP(hostname) };
  }
  let records;
  try {
    records = await lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new Error('UPSTREAM_MCP_URL hostname could not be resolved');
  }
  if (!Array.isArray(records) || records.length === 0) {
    throw new Error('UPSTREAM_MCP_URL hostname could not be resolved');
  }
  for (const record of records) {
    if (!allowPublic && !isPrivateIp(record.address)) {
      throw new Error('UPSTREAM_MCP_URL address is not private');
    }
  }
  return { address: records[0].address, family: records[0].family || isIP(records[0].address) };
}

/**
 * @param {{ certPem: string, keyPem: string, hostname: string, now?: Date }} input
 */
export function assertCertificatePair(input) {
  const now = input.now || new Date();
  let cert;
  try {
    cert = new X509Certificate(input.certPem);
  } catch {
    throw new Error('TLS certificate is unreadable');
  }
  const from = new Date(cert.validFrom);
  const to = new Date(cert.validTo);
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime()) || now < from || now > to) {
    throw new Error('TLS certificate is expired or not yet valid');
  }
  if (typeof cert.checkHost !== 'function' || !cert.checkHost(input.hostname)) {
    throw new Error('TLS certificate hostname does not match PUBLIC_ORIGIN');
  }
  try {
    createSecureContext({ cert: input.certPem, key: input.keyPem, minVersion: 'TLSv1.2' });
  } catch {
    throw new Error('TLS certificate and private key do not match or are unusable');
  }
}

/**
 * @param {import('node:fs').Stats} stat
 * @param {string} label
 * @returns {{ warning?: string }}
 */
export function assertPrivatePermissions(stat, label) {
  if (process.platform === 'win32') {
    return { warning: `${label}: on Windows, restrict the file ACL to the operator account. chmod is not a security boundary here.` };
  }
  const mode = stat.mode & 0o777;
  if ((mode & 0o077) !== 0) throw new Error(`${label} permissions are too open`);
  return {};
}

/**
 * @param {string | undefined} value
 * @param {boolean} fallback
 */
function parseBool(value, fallback) {
  if (value === undefined || value === '') return fallback;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error('boolean configuration must be true or false');
}

/**
 * @param {string | undefined} value
 * @param {number} fallback
 * @param {number} min
 * @param {number} max
 * @param {string} name
 */
function parseIntRange(value, fallback, min, max, name) {
  if (value === undefined || value === '') return fallback;
  if (!/^[0-9]+$/.test(value)) throw new Error(`${name} must be an integer`);
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) throw new Error(`${name} is outside the allowed range`);
  return number;
}

/**
 * @param {NodeJS.ProcessEnv} env
 * @param {string} dataDir
 */
async function loadApiKey(env, dataDir) {
  const fromEnv = env.UPSTREAM_API_KEY;
  const secretPath = path.join(dataDir, 'upstream-secret.json');
  let fromFile;
  try {
    const st = await lstat(secretPath);
    if (st.isSymbolicLink()) throw new Error('upstream secret path is a symlink');
    if (!st.isFile()) throw new Error('upstream secret path is not a file');
    assertPrivatePermissions(st, 'upstream secret');
    const parsed = JSON.parse(await readFile(secretPath, 'utf8'));
    if (!parsed || typeof parsed.apiKey !== 'string') throw new Error('upstream secret file is invalid');
    fromFile = parsed.apiKey;
  } catch (err) {
    if (err && err.code === 'ENOENT') fromFile = undefined;
    else if (fromEnv && err && err.code === 'ENOENT') fromFile = undefined;
    else if (err && err.code === 'ENOENT') fromFile = undefined;
    else throw err;
  }
  if (fromEnv !== undefined && fromFile !== undefined && fromEnv !== fromFile) {
    throw new Error('UPSTREAM_API_KEY does not match the secret file');
  }
  const key = fromEnv !== undefined ? fromEnv : fromFile;
  if (typeof key !== 'string' || key.length < 8 || key.length > 512 || /[\u0000-\u001F\u007F]/.test(key)) {
    throw new Error('upstream API key is missing or invalid');
  }
  return key;
}

/**
 * @param {NodeJS.ProcessEnv} env
 * @param {{ testMode?: boolean, runtimeVersion?: string, lookup?: Function, now?: Date }} [options]
 */
export async function loadConfig(env, options = {}) {
  const testMode = options.testMode === true;
  const nodeEnv = env.NODE_ENV || 'production';
  const version = testMode ? (options.runtimeVersion || process.version) : process.version;
  assertNodeVersion(version);

  const origin = parsePublicOrigin(env.PUBLIC_ORIGIN);
  if ((env.MCP_PATH || '/mcp') !== '/mcp') throw new Error('MCP_PATH must be /mcp');
  const listenHost = env.LISTEN_HOST || '';
  if (!listenHost || /[\s\u0000-\u001F]/.test(listenHost)) throw new Error('LISTEN_HOST is invalid');
  const listenPort = parseIntRange(env.LISTEN_PORT, 443, 0, 65535, 'LISTEN_PORT');
  if (listenPort === 0 && nodeEnv === 'production') throw new Error('LISTEN_PORT must be 1..65535 in production');
  if (listenPort !== 0 && (listenPort < 1 || listenPort > 65535)) throw new Error('LISTEN_PORT is invalid');

  const testHttp = parseBool(env.ENABLE_LOCAL_TEST_HTTP, false);
  if (testHttp && nodeEnv === 'production') {
    throw new Error('HTTP test mode is refused in production');
  }
  if (testHttp && listenHost !== '127.0.0.1' && listenHost !== '::1') {
    throw new Error('HTTP test mode requires a loopback listener');
  }

  const allowPublic = parseBool(env.ALLOW_PUBLIC_UPSTREAM, false);
  const upstream = await parseUpstreamUrl(env.UPSTREAM_MCP_URL, { allowPublic, lookup: options.lookup });
  const headerName = env.UPSTREAM_API_KEY_HEADER || 'X-Api-Key';
  if (!/^[A-Za-z0-9-]{1,64}$/.test(headerName) || HEADER_DENY.has(headerName.toLowerCase())) {
    throw new Error('UPSTREAM_API_KEY_HEADER is invalid');
  }

  const dataDir = path.resolve(env.DATA_DIR || '');
  if (!env.DATA_DIR || dataDir === path.parse(dataDir).root) throw new Error('DATA_DIR is invalid');
  const apiKey = await loadApiKey(env, dataDir);

  const logLevel = env.LOG_LEVEL || 'info';
  if (!['debug', 'info', 'warn', 'error'].includes(logLevel)) throw new Error('LOG_LEVEL is invalid');

  const displayName = cleanDisplayName(env.UPSTREAM_DISPLAY_NAME || 'connected WhatsApp session');
  const definitions = [
    ...(await readUpstreamDefinitions(path.join(dataDir, 'upstreams.json'))),
    ...(options.extraUpstreams || []),
  ];
  const extras = [];
  const seenUrl = new Set([upstream.href]);
  const seenId = new Set();
  for (const definition of definitions) {
    assertUpstreamId(definition.id);
    if (seenId.has(definition.id)) throw new Error('upstream id is invalid');
    let parsed;
    try {
      parsed = await parseUpstreamUrl(definition.url, { allowPublic, lookup: options.lookup });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'upstream URL is invalid';
      throw new Error(message.replaceAll('UPSTREAM_MCP_URL', `upstream ${definition.id}`));
    }
    if (seenUrl.has(parsed.href)) throw new Error('upstream URL is already configured');
    seenId.add(definition.id);
    seenUrl.add(parsed.href);
    extras.push({
      id: definition.id,
      ...parsed,
      displayName: cleanDisplayName(definition.displayName),
      apiKey: assertApiKey(definition.apiKey),
      headerName,
      allowPublic,
    });
  }
  const registry = registerUpstreams(origin.origin, [
    { id: 'default', ...upstream, displayName, apiKey, headerName, allowPublic },
    ...extras,
  ]);

  const originAllowlist = parseOriginAllowlist(env.ORIGIN_ALLOWLIST, origin.origin);
  const limits = {
    maxRequestBytes: parseIntRange(env.MAX_REQUEST_BYTES, 1024 * 1024, 1024, 8 * 1024 * 1024, 'MAX_REQUEST_BYTES'),
    maxTokenBodyBytes: 16 * 1024,
    maxFormBodyBytes: 8 * 1024,
    maxStreams: parseIntRange(env.MAX_STREAMS, 8, 1, 64, 'MAX_STREAMS'),
    streamIdleMs: parseIntRange(env.STREAM_IDLE_MS, 120000, 1000, 30 * 60 * 1000, 'STREAM_IDLE_MS'),
    streamLifetimeMs: parseIntRange(env.STREAM_LIFETIME_MS, 30 * 60 * 1000, 5000, 60 * 60 * 1000, 'STREAM_LIFETIME_MS'),
    connectTimeoutMs: parseIntRange(env.CONNECT_TIMEOUT_MS, 5000, 200, 10000, 'CONNECT_TIMEOUT_MS'),
    headerTimeoutMs: parseIntRange(env.HEADER_TIMEOUT_MS, 10000, 200, 60000, 'HEADER_TIMEOUT_MS'),
    bodyTimeoutMs: parseIntRange(env.BODY_TIMEOUT_MS, 30000, 200, 120000, 'BODY_TIMEOUT_MS'),
    loginMaxFailures: parseIntRange(env.LOGIN_MAX_FAILURES, 5, 3, 20, 'LOGIN_MAX_FAILURES'),
    loginWindowMs: parseIntRange(env.LOGIN_WINDOW_SEC, 900, 60, 3600, 'LOGIN_WINDOW_SEC') * 1000,
    loginLockMs: parseIntRange(env.LOGIN_LOCK_SEC, 900, 60, 3600, 'LOGIN_LOCK_SEC') * 1000,
    tokenMaxPerWindow: parseIntRange(env.TOKEN_MAX_PER_WINDOW, 60, 5, 300, 'TOKEN_MAX_PER_WINDOW'),
    tokenWindowMs: parseIntRange(env.TOKEN_WINDOW_SEC, 60, 10, 600, 'TOKEN_WINDOW_SEC') * 1000,
    cimdCacheMs: parseIntRange(env.CIMD_CACHE_SEC, 300, 5, 3600, 'CIMD_CACHE_SEC') * 1000,
    cimdTimeoutMs: 5000,
    cimdMaxBytes: 64 * 1024,
    toolsListMaxBytes: 4 * 1024 * 1024,
    sseEventMaxBytes: 4 * 1024 * 1024,
    shutdownMs: 5000,
  };
  const ttl = {
    codeMs: parseIntRange(env.CODE_TTL_SEC, 120, 30, 600, 'CODE_TTL_SEC') * 1000,
    accessMs: parseIntRange(env.ACCESS_TTL_SEC, 900, 60, 3600, 'ACCESS_TTL_SEC') * 1000,
    refreshMs: parseIntRange(env.REFRESH_TTL_SEC, 30 * 24 * 3600, 3600, 90 * 24 * 3600, 'REFRESH_TTL_SEC') * 1000,
    sessionIdleMs: parseIntRange(env.SESSION_IDLE_SEC, 900, 60, 3600, 'SESSION_IDLE_SEC') * 1000,
    sessionAbsoluteMs: parseIntRange(env.SESSION_ABSOLUTE_SEC, 8 * 3600, 300, 86400, 'SESSION_ABSOLUTE_SEC') * 1000,
    authRequestMs: parseIntRange(env.AUTH_REQUEST_TTL_SEC, 600, 60, 1800, 'AUTH_REQUEST_TTL_SEC') * 1000,
  };

  const certFile = (env.TLS_CERT_FILE || '').trim();
  const keyFile = (env.TLS_KEY_FILE || '').trim();
  if (Boolean(certFile) !== Boolean(keyFile)) {
    throw new Error('TLS certificate and private key must both be set, or both left empty');
  }
  let tls = null;
  if (!testHttp && !certFile && listenHost !== '127.0.0.1' && listenHost !== '::1') {
    throw new Error('Without TLS files, LISTEN_HOST must be 127.0.0.1 or ::1. Terminate HTTPS at the reverse proxy, or set TLS_CERT_FILE and TLS_KEY_FILE.');
  }
  if (!testHttp && certFile) {
    const certPath = path.resolve(certFile);
    const keyPath = path.resolve(keyFile);
    let certStat;
    let keyStat;
    try {
      certStat = await lstat(certPath);
      keyStat = await lstat(keyPath);
    } catch {
      throw new Error('TLS certificate or private key is unreadable');
    }
    if (certStat.isSymbolicLink() || keyStat.isSymbolicLink()) throw new Error('TLS certificate or private key path is a symlink');
    if (!certStat.isFile() || !keyStat.isFile()) throw new Error('TLS certificate or private key is unreadable');
    assertPrivatePermissions(keyStat, 'TLS private key');
    const certPem = await readFile(certPath, 'utf8');
    const keyPem = await readFile(keyPath, 'utf8');
    assertCertificatePair({ certPem, keyPem, hostname: origin.hostname, now: options.now });
    tls = { certPath, keyPath, certPem, keyPem };
  }

  return {
    nodeEnv,
    testMode,
    testHttp,
    publicOrigin: origin.origin,
    issuer: origin.origin,
    resource: registry.byId.get('default').resource,
    mcpPath: '/mcp',
    publicHost: origin.hostname,
    publicPort: origin.port,
    listenHost,
    listenPort,
    tls,
    hsts: !testHttp && origin.origin.startsWith('https://'),
    upstream: registry.byId.get('default'),
    upstreams: registry.list,
    upstreamById: registry.byId,
    upstreamByPath: registry.byPath,
    upstreamByResource: registry.byResource,
    upstreamByMetadata: registry.byMetadata,
    dataDir,
    logLevel,
    upstreamDisplayName: displayName,
    originAllowlist,
    limits,
    ttl,
  };
}

/**
 * @param {string | undefined} raw
 * @param {string} publicOrigin
 * @returns {string[]}
 */
export function parseOriginAllowlist(raw, publicOrigin) {
  const values = (raw && raw.trim()) ? raw.split(',') : [publicOrigin, 'https://chatgpt.com'];
  const out = [];
  for (const item of values) {
    const value = item.trim();
    if (!value || value === '*' || value.includes('*')) throw new Error('ORIGIN_ALLOWLIST must not contain wildcards');
    let url;
    try { url = new URL(value); } catch { throw new Error('ORIGIN_ALLOWLIST entry is invalid'); }
    if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.pathname !== '/' || url.search || url.hash) {
      throw new Error('ORIGIN_ALLOWLIST entries must be origins');
    }
    const origin = url.origin;
    if (!out.includes(origin)) out.push(origin);
  }
  if (!out.includes(publicOrigin)) out.unshift(publicOrigin);
  return out;
}

/**
 * @returns {{ now: () => number }}
 */
export function systemClock() {
  return { now: () => Date.now() };
}

/**
 * @param {string} hostHeader
 * @param {{ publicHost: string, publicPort: number }} config
 * @returns {boolean}
 */
export function hostAllowed(hostHeader, config) {
  if (!hostHeader || Array.isArray(hostHeader)) return false;
  if (typeof hostHeader !== 'string' || hostHeader.length > 255) return false;
  if (/[\r\n\0\s]/.test(hostHeader)) return false;
  const lower = hostHeader.toLowerCase();
  const name = config.publicHost.toLowerCase();
  if (lower === `${name}:${config.publicPort}`) return true;
  if (lower === name && (config.publicPort === 443 || config.publicPort === 80)) return true;
  return false;
}

/**
 * @param {string | string[] | undefined} originHeader
 * @param {{ originAllowlist: string[] }} config
 * @returns {boolean}
 */
export function originAllowed(originHeader, config) {
  if (originHeader === undefined) return true;
  if (Array.isArray(originHeader)) return false;
  if (typeof originHeader !== 'string' || originHeader.length > 256) return false;
  if (/[\r\n\0\s*]/.test(originHeader)) return false;
  return config.originAllowlist.includes(originHeader);
}
