import http from 'node:http';
import https from 'node:https';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { sha256Hex } from '../crypto.mjs';
import { isPrivateIp, originAllowed, pinUpstreamAddress } from '../config.mjs';
import { headerCount, httpError, sendJson } from '../http.mjs';
import { wwwAuthenticate } from '../oauth/metadata.mjs';
import { authenticateBearer } from '../oauth/bearer.mjs';
import { enrichToolsListPayload, transformSseToolsList } from './tool-metadata.mjs';

const REQUEST_HEADERS = ['accept', 'content-type', 'mcp-session-id', 'mcp-protocol-version', 'last-event-id'];
const RESPONSE_HEADERS = ['content-type', 'mcp-session-id', 'mcp-protocol-version', 'retry-after', 'allow'];

/**
 * @param {object} ctx
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 */
export async function handleMcp(ctx, req, res) {
  if (headerCount(req, 'authorization') > 1 || headerCount(req, 'origin') > 1) {
    throw httpError(400, 'invalid_request', 'duplicate header');
  }
  const auth = await authenticateBearer(ctx, req.headers.authorization);
  if (!auth.ok) return sendChallenge(ctx, res, auth);
  if (!originAllowed(req.headers.origin, ctx.config)) {
    return sendJson(res, 403, { error: 'forbidden' }, { hsts: ctx.config.hsts, requestId: ctx.requestId });
  }
  for (const name of ['mcp-session-id', 'mcp-protocol-version', 'content-type', 'accept', 'last-event-id']) {
    if (headerCount(req, name) > 1) throw httpError(400, 'invalid_request', 'duplicate header');
  }
  const expectsStream = req.method === 'GET';
  if (expectsStream && ctx.streams.active >= ctx.config.limits.maxStreams) {
    return sendJson(res, 429, { error: 'too_many_streams' }, {
      hsts: ctx.config.hsts,
      requestId: ctx.requestId,
      headers: { 'Retry-After': '1' },
    });
  }
  if (req.headers.accept && !acceptAllowed(req)) throw httpError(406, 'not_acceptable', 'accept is not supported');

  let body = Buffer.alloc(0);
  if (req.method === 'POST') {
    body = ctx.body;
    if (!body.length) throw httpError(400, 'invalid_request', 'request body is required');
    const type = String(req.headers['content-type'] || '');
    if (!type.toLowerCase().startsWith('application/json')) throw httpError(415, 'unsupported_media_type', 'json body required');
  } else if (Number(req.headers['content-length'] || 0) > 0) {
    throw httpError(400, 'invalid_request', 'unexpected body');
  }

  let rpc = null;
  if (req.method === 'POST') {
    try {
      rpc = JSON.parse(body.toString('utf8'));
    } catch {
      throw httpError(400, 'invalid_request', 'invalid json');
    }
    if (!rpc || typeof rpc !== 'object') throw httpError(400, 'invalid_request', 'invalid json');
  }
  const toolsList = Boolean(rpc && !Array.isArray(rpc) && rpc.method === 'tools/list' && rpc.id !== undefined && rpc.id !== null);
  const initialize = Boolean(rpc && !Array.isArray(rpc) && rpc.method === 'initialize');
  const sessionHeader = req.headers['mcp-session-id'];
  if (sessionHeader !== undefined) {
    if (typeof sessionHeader !== 'string' || !/^[A-Za-z0-9._~:+/=-]{1,256}$/.test(sessionHeader)) {
      throw httpError(400, 'invalid_request', 'invalid session');
    }
    const allowed = await ctx.store.enqueue(async () => {
      const record = ctx.store.read().mcpSessions[mcpSessionKey(currentUpstream(ctx).id, sessionHeader)];
      if (!record || (record.expiresAt && record.expiresAt <= ctx.clock.now())) return 'missing';
      if (record.upstreamId && record.upstreamId !== currentUpstream(ctx).id) return 'cross';
      if (record.grantId !== auth.grant.grantId) return 'cross';
      return 'ok';
    });
    if (allowed === 'missing') return sendJson(res, 404, { error: 'session_not_found' }, { hsts: ctx.config.hsts, requestId: ctx.requestId });
    if (allowed === 'cross') return sendJson(res, 403, { error: 'forbidden' }, { hsts: ctx.config.hsts, requestId: ctx.requestId });
  }

  if (expectsStream) {
    ctx.streams.active += 1;
    res.on('close', () => { ctx.streams.active = Math.max(0, ctx.streams.active - 1); });
  }

  const upstream = currentUpstream(ctx);
  const pinned = await pinUpstreamAddress(upstream.hostname, {
    allowPublic: upstream.allowPublic,
    lookup: ctx.lookup,
  });
  if (!upstream.allowPublic && !isPrivateIp(pinned.address)) {
    return sendJson(res, 502, { error: 'bad_gateway', requestId: ctx.requestId }, { hsts: ctx.config.hsts, requestId: ctx.requestId });
  }
  const headers = buildUpstreamHeaders(req, body, upstream);
  const lib = upstream.protocol === 'https:' ? https : http;
  const upstreamReq = lib.request({
    protocol: upstream.protocol,
    hostname: pinned.address,
    port: upstream.port,
    method: req.method,
    path: '/mcp',
    family: Number(pinned.family) || undefined,
    setHost: false,
    servername: upstream.protocol === 'https:' ? upstream.hostname : undefined,
    headers,
  });
  ctx.inflight.add(upstreamReq);
  upstreamReq.on('close', () => ctx.inflight.delete(upstreamReq));
  let clientGone = false;
  res.on('close', () => {
    if (!res.writableEnded) {
      clientGone = true;
      upstreamReq.destroy();
      ctx.logger.warn({ event: 'write_completion_uncertain', route: '/mcp', requestId: ctx.requestId });
    }
  });
  const outcome = await waitForUpstream(upstreamReq, body, ctx);
  if (!outcome.response) {
    const status = outcome.timeout ? 504 : 502;
    return sendJson(res, status, { error: status === 504 ? 'gateway_timeout' : 'bad_gateway', requestId: ctx.requestId }, {
      hsts: ctx.config.hsts,
      requestId: ctx.requestId,
    });
  }
  const up = outcome.response;
  ctx.upstreamStatus = up.statusCode || 0;
  const remote = outcome.remoteAddress;
  if (remote && !upstream.allowPublic && !isPrivateIp(remote)) {
    up.resume();
    upstreamReq.destroy();
    return sendJson(res, 502, { error: 'bad_gateway', requestId: ctx.requestId }, { hsts: ctx.config.hsts, requestId: ctx.requestId });
  }
  if (up.statusCode >= 300 && up.statusCode < 400) {
    up.resume();
    return sendJson(res, 502, { error: 'bad_gateway', requestId: ctx.requestId }, { hsts: ctx.config.hsts, requestId: ctx.requestId });
  }
  if (up.statusCode === 401 || up.statusCode === 403) {
    up.resume();
    return sendJson(res, 502, { error: 'bad_gateway', requestId: ctx.requestId }, { hsts: ctx.config.hsts, requestId: ctx.requestId });
  }
  const encoding = String(up.headers['content-encoding'] || 'identity').toLowerCase();
  if (encoding !== 'identity') {
    up.resume();
    return sendJson(res, 502, { error: 'bad_gateway', requestId: ctx.requestId }, { hsts: ctx.config.hsts, requestId: ctx.requestId });
  }
  const upstreamSession = typeof up.headers['mcp-session-id'] === 'string' ? up.headers['mcp-session-id'] : '';
  if (initialize && upstreamSession && /^[A-Za-z0-9._~:+/=-]{1,256}$/.test(upstreamSession)) {
    await rememberSession(ctx, upstreamSession, auth.grant.grantId);
  }
  if (sessionHeader && (up.statusCode === 404 || (req.method === 'DELETE' && up.statusCode >= 200 && up.statusCode < 300))) {
    await forgetSession(ctx, sessionHeader);
  }
  const responseHeaders = safeResponseHeaders(up.headers, ctx);
  if (toolsList && (mediaType(up.headers['content-type']) === 'application/json' || mediaType(up.headers['content-type']) === 'text/event-stream')) {
    const buffered = await readLimited(up, ctx.config.limits.toolsListMaxBytes);
    let output;
    try {
      if (mediaType(up.headers['content-type']) === 'text/event-stream') {
        output = transformSseToolsList(buffered, rpc.id, ctx.config.limits.sseEventMaxBytes);
      } else {
        const parsed = JSON.parse(buffered.toString('utf8'));
        if (isPlainToolsResult(parsed, rpc.id)) output = Buffer.from(JSON.stringify(enrichToolsListPayload(parsed)));
        else output = buffered;
      }
    } catch {
      return sendJson(res, 502, { error: 'bad_gateway', requestId: ctx.requestId }, { hsts: ctx.config.hsts, requestId: ctx.requestId });
    }
    responseHeaders['content-length'] = String(output.length);
    if (!res.headersSent) res.writeHead(up.statusCode || 502, responseHeaders);
    res.end(output);
    return;
  }
  if (!res.headersSent) res.writeHead(up.statusCode || 502, responseHeaders);
  if ((up.statusCode || 0) === 204 || (up.statusCode || 0) === 205) {
    up.resume();
    res.end();
    return;
  }
  const expected = up.headers['content-length'] !== undefined ? Number(up.headers['content-length']) : NaN;
  let seen = 0;
  const counter = new Transform({
    transform(chunk, _enc, callback) {
      seen += chunk.length;
      callback(null, chunk);
    },
    flush(callback) {
      if (Number.isFinite(expected) && seen !== expected) callback(Object.assign(new Error('truncated'), { code: 'TRUNCATED' }));
      else callback();
    },
  });
  try {
    await pipeline(up, counter, res);
  } catch {
    if (!res.writableEnded && !clientGone) res.destroy();
  }
}

/**
 * @param {object} ctx
 * @param {import('node:http').ServerResponse} res
 * @param {{ reason: string }} auth
 */
function sendChallenge(ctx, res, auth) {
  if (auth.reason === 'scope') {
    return sendJson(res, 403, { error: 'insufficient_scope' }, {
      hsts: ctx.config.hsts,
      requestId: ctx.requestId,
      headers: { 'WWW-Authenticate': wwwAuthenticate(ctx.config, { error: 'insufficient_scope', metadataUrl: currentUpstream(ctx).metadataUrl }) },
    });
  }
  const error = auth.reason === 'missing' ? undefined : 'invalid_token';
  return sendJson(res, 401, { error: 'unauthorized' }, {
    hsts: ctx.config.hsts,
    requestId: ctx.requestId,
      headers: { 'WWW-Authenticate': wwwAuthenticate(ctx.config, { error, metadataUrl: currentUpstream(ctx).metadataUrl }) },
  });
}

/**
 * @param {import('node:http').IncomingMessage} req
 */
function acceptAllowed(req) {
  const accept = String(req.headers.accept || '').toLowerCase();
  if (accept.includes('*/*')) return true;
  if (req.method === 'GET' || req.method === 'DELETE') return accept.includes('text/event-stream') || accept.includes('application/json');
  return accept.includes('application/json') || accept.includes('text/event-stream');
}

/**
 * @param {import('node:http').IncomingMessage} req
 * @param {Buffer} body
 * @param {object} upstream
 */
function buildUpstreamHeaders(req, body, upstream) {
  const defaultPort = upstream.protocol === 'https:' ? 443 : 80;
  const host = upstream.port === defaultPort ? upstream.hostname : `${upstream.hostname}:${upstream.port}`;
  const headers = {
    Host: host,
    'Accept-Encoding': 'identity',
    'User-Agent': 'waha-mcp-bridge',
    [upstream.headerName]: upstream.apiKey,
  };
  for (const name of REQUEST_HEADERS) {
    const value = req.headers[name];
    if (typeof value !== 'string' || value.length === 0) continue;
    if (/[\r\n]/.test(value)) throw httpError(400, 'invalid_request', 'invalid header');
    headers[name] = value;
  }
  if (req.method === 'POST') headers['content-length'] = String(body.length);
  return headers;
}

/**
 * @param {import('node:http').ClientRequest} upstreamReq
 * @param {Buffer} body
 * @param {object} ctx
 */
function waitForUpstream(upstreamReq, body, ctx) {
  return new Promise((resolve) => {
    let settled = false;
    let remoteAddress = '';
    const timer = setTimeout(() => {
      upstreamReq.destroy();
      finish({ timeout: true });
    }, ctx.config.limits.headerTimeoutMs);
    function finish(result) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    }
    upstreamReq.on('socket', (socket) => {
      const note = () => { remoteAddress = socket.remoteAddress || ''; };
      if (socket.connecting) socket.once('connect', note);
      else note();
    });
    upstreamReq.on('response', (response) => finish({ response, remoteAddress }));
    upstreamReq.on('error', () => finish({ timeout: false }));
    upstreamReq.on('timeout', () => {
      upstreamReq.destroy();
      finish({ timeout: true });
    });
    if (body.length) upstreamReq.end(body);
    else upstreamReq.end();
  });
}

/**
 * @param {import('node:stream').Readable} stream
 * @param {number} max
 * @returns {Promise<Buffer>}
 */
function readLimited(stream, max) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    stream.on('data', (chunk) => {
      size += chunk.length;
      if (size > max) {
        stream.destroy();
        reject(Object.assign(new Error('oversized'), { code: 'bad_upstream' }));
        return;
      }
      chunks.push(chunk);
    });
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', () => reject(Object.assign(new Error('upstream read failed'), { code: 'bad_upstream' })));
  });
}

/**
 * @param {object} ctx
 * @param {string} sessionId
 * @param {string} grantId
 */
async function rememberSession(ctx, sessionId, grantId) {
  const now = ctx.clock.now();
  const upstream = currentUpstream(ctx);
  const key = mcpSessionKey(upstream.id, sessionId);
  await ctx.store.transaction(async (draft) => {
    const keys = Object.keys(draft.mcpSessions);
    if (keys.length >= 200 && !draft.mcpSessions[key]) {
      delete draft.mcpSessions[keys[0]];
    }
    draft.mcpSessions[key] = { grantId, upstreamId: upstream.id, createdAt: now, expiresAt: now + 24 * 60 * 60 * 1000 };
  });
}

/**
 * @param {object} ctx
 * @param {string} sessionId
 */
async function forgetSession(ctx, sessionId) {
  const key = mcpSessionKey(currentUpstream(ctx).id, sessionId);
  await ctx.store.transaction(async (draft) => {
    delete draft.mcpSessions[key];
  });
}

/**
 * @param {object} ctx
 */
function currentUpstream(ctx) {
  return ctx.upstream || ctx.config.upstream;
}

/**
 * Sessions are stored per WAHA so the same upstream session id cannot cross connections.
 * @param {string} upstreamId
 * @param {string} sessionId
 */
function mcpSessionKey(upstreamId, sessionId) {
  return sha256Hex(`${upstreamId}\n${sessionId}`);
}

/**
 * @param {import('node:http').IncomingHttpHeaders} headers
 * @param {object} ctx
 */
function safeResponseHeaders(headers, ctx) {
  const out = {
    'cache-control': 'no-store',
    pragma: 'no-cache',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'x-request-id': ctx.requestId,
  };
  for (const name of RESPONSE_HEADERS) {
    const value = headers[name];
    if (typeof value !== 'string' || /[\r\n]/.test(value)) continue;
    out[name] = value;
  }
  if (ctx.config.hsts) out['strict-transport-security'] = 'max-age=63072000; includeSubDomains';
  return out;
}

/**
 * @param {string | string[] | undefined} value
 */
function mediaType(value) {
  if (Array.isArray(value) || typeof value !== 'string') return '';
  return value.split(';', 1)[0].trim().toLowerCase();
}

/**
 * @param {object} parsed
 * @param {string | number} requestId
 */
function isPlainToolsResult(parsed, requestId) {
  return Boolean(parsed) && parsed.id === requestId && parsed.result && Array.isArray(parsed.result.tools) && !parsed.error && !parsed.method;
}
