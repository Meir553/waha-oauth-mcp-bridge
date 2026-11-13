import http from 'node:http';
import https from 'node:https';
import { randomBytes } from 'node:crypto';
import { lookup as dnsLookup } from 'node:dns/promises';
import { hostAllowed } from './config.mjs';
import { HttpError, headerCount, normalizePath, readBody, securityHeaders, sendHtml, sendJson } from './http.mjs';
import { authorizationServerMetadata, protectedResourceMetadata } from './oauth/metadata.mjs';
import { handleAuthorize, handleConsentGet, handleConsentPost, handleLoginGet, handleLoginPost, handleLogout } from './oauth/authorization.mjs';
import { OAuthError, handleToken } from './oauth/token.mjs';
import { handleMcp } from './mcp/proxy.mjs';
import { createWindowLimiter } from './rate-limit.mjs';
import { renderLocalErrorPage } from './web/login.mjs';

const BROWSER = new Set(['/login', '/oauth/authorize', '/oauth/consent', '/logout']);

/**
 * @param {{ config: object, store: object, logger: object, clock: { now: () => number }, cimd: object, lookup?: Function, css: Buffer }} deps
 */
export function createHandler(deps) {
  const tokenLimiter = createWindowLimiter({
    clock: deps.clock,
    max: deps.config.limits.tokenMaxPerWindow,
    windowMs: deps.config.limits.tokenWindowMs,
  });
  const streams = { active: 0 };
  const inflight = new Set();
  async function onRequest(req, res) {
    const started = deps.clock.now();
    const requestId = randomBytes(8).toString('hex');
    const pathname = safePath(req.url || '/');
    const ctx = {
      config: deps.config,
      store: deps.store,
      logger: deps.logger,
      clock: deps.clock,
      cimd: deps.cimd,
      lookup: deps.lookup || dnsLookup,
      tokenLimiter,
      streams,
      inflight,
      requestId,
      upstreamStatus: undefined,
      body: Buffer.alloc(0),
      css: deps.css,
    };
    try {
      if (!req.url || req.url.length > 8192 || req.url.includes('\\') || req.url.includes('\0')) {
        throw new HttpError(400, 'invalid_request', 'invalid target');
      }
      if (headerCount(req, 'host') !== 1 || !hostAllowed(req.headers.host, deps.config)) {
        throw new HttpError(400, 'invalid_request', 'invalid host');
      }
      if ((req.rawHeaders || []).join('').length > 16 * 1024) throw new HttpError(431, 'headers_too_large', 'headers too large');
      const route = matchRoute(pathname, deps.config);
      if (!route) return sendJson(res, 404, { error: 'not_found' }, { hsts: deps.config.hsts, requestId });
      ctx.upstream = route.upstream;
      const handler = route.handlers[req.method || ''];
      if (!handler) {
        return sendJson(res, 405, { error: 'method_not_allowed' }, {
          hsts: deps.config.hsts,
          requestId,
          headers: { Allow: Object.keys(route.handlers).join(', ') },
        });
      }
      if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
        const limit = pathname === '/oauth/token'
          ? deps.config.limits.maxTokenBodyBytes
          : route.mcp
            ? deps.config.limits.maxRequestBytes
            : deps.config.limits.maxFormBodyBytes;
        ctx.body = await readBody(req, { limit, timeoutMs: deps.config.limits.bodyTimeoutMs });
      }
      await handler(ctx, req, res);
      if (!res.headersSent && !res.writableEnded) {
        sendJson(res, 500, { error: 'internal_error', requestId }, { hsts: deps.config.hsts, requestId });
      }
    } catch (err) {
      if (res.headersSent || res.writableEnded) {
        res.destroy();
        return;
      }
      if (err instanceof OAuthError) {
        sendJson(res, err.status, { error: err.oauthError }, { hsts: deps.config.hsts, requestId });
        return;
      }
      if (err instanceof HttpError) {
        if (BROWSER.has(pathname)) {
          sendHtml(res, err.status, renderLocalErrorPage(), { hsts: deps.config.hsts, requestId });
          return;
        }
        const headers = { ...(err.headers || {}) };
        sendJson(res, err.status, { error: err.code }, { hsts: deps.config.hsts, requestId, headers });
        return;
      }
      deps.logger.error({ event: 'internal', requestId, route: pathname, errorCategory: 'internal' });
      sendJson(res, 500, { error: 'internal_error', requestId }, { hsts: deps.config.hsts, requestId });
    } finally {
      deps.logger.info({
        event: 'request',
        requestId,
        route: pathname,
        method: req.method,
        status: res.statusCode || 0,
        latencyMs: Math.max(0, deps.clock.now() - started),
        upstreamStatus: ctx.upstreamStatus,
      });
    }
  }
  onRequest.inflight = inflight;
  return onRequest;
}

/**
 * @param {string} pathname
 * @param {{ upstreamByPath: Map<string, object>, upstreamByMetadata: Map<string, object> }} config
 */
function matchRoute(pathname, config) {
  const fixed = {
    '/.well-known/oauth-protected-resource': { GET: sendResource },
    '/.well-known/oauth-protected-resource/mcp': { GET: sendResource },
    '/.well-known/oauth-authorization-server': { GET: sendAuthorizationServer },
    '/oauth/authorize': { GET: handleAuthorize },
    '/login': { GET: handleLoginGet, POST: handleLoginPost },
    '/oauth/consent': { GET: handleConsentGet, POST: handleConsentPost },
    '/oauth/token': { POST: handleToken },
    '/logout': { POST: handleLogout },
    '/mcp': { GET: handleMcp, POST: handleMcp, DELETE: handleMcp },
    '/health/live': { GET: sendHealth },
    '/styles.css': { GET: sendCss },
  };
  if (fixed[pathname]) {
    const describesDefault = pathname === '/mcp'
      || pathname === '/.well-known/oauth-protected-resource'
      || pathname === '/.well-known/oauth-protected-resource/mcp';
    return {
      handlers: fixed[pathname],
      upstream: describesDefault ? config.upstreamByPath.get('/mcp') : null,
      mcp: pathname === '/mcp',
    };
  }
  const mcp = config.upstreamByPath.get(pathname);
  if (mcp && mcp.id !== 'default') {
    return { handlers: { GET: handleMcp, POST: handleMcp, DELETE: handleMcp }, upstream: mcp, mcp: true };
  }
  const metadata = config.upstreamByMetadata.get(pathname);
  if (metadata && metadata.id !== 'default') {
    return { handlers: { GET: sendResource }, upstream: metadata, mcp: false };
  }
  return null;
}

/**
 * @param {object} ctx
 * @param {import('node:http').IncomingMessage} _req
 * @param {import('node:http').ServerResponse} res
 */
function sendResource(ctx, _req, res) {
  const upstream = ctx.upstream || ctx.config.upstream;
  sendJson(res, 200, protectedResourceMetadata({ resource: upstream.resource, issuer: ctx.config.issuer }), {
    hsts: ctx.config.hsts,
    requestId: ctx.requestId,
  });
}

/**
 * @param {object} ctx
 * @param {import('node:http').IncomingMessage} _req
 * @param {import('node:http').ServerResponse} res
 */
function sendAuthorizationServer(ctx, _req, res) {
  sendJson(res, 200, authorizationServerMetadata(ctx.config), { hsts: ctx.config.hsts, requestId: ctx.requestId });
}

/**
 * @param {object} ctx
 * @param {import('node:http').IncomingMessage} _req
 * @param {import('node:http').ServerResponse} res
 */
function sendHealth(ctx, _req, res) {
  sendJson(res, 200, { status: 'live' }, { hsts: ctx.config.hsts, requestId: ctx.requestId });
}

/**
 * @param {object} ctx
 * @param {import('node:http').IncomingMessage} _req
 * @param {import('node:http').ServerResponse} res
 * @param {Buffer} css
 */
function sendCss(ctx, _req, res) {
  const headers = {
    ...securityHeaders({ html: false, hsts: ctx.config.hsts, noStore: true }),
    'Content-Type': 'text/css; charset=utf-8',
    'Content-Length': String(ctx.css.length),
    'X-Request-Id': ctx.requestId,
  };
  res.writeHead(200, headers);
  res.end(ctx.css);
}

/**
 * @param {string} url
 */
function safePath(url) {
  const pathOnly = url.split('?')[1] === undefined ? url : url.slice(0, url.indexOf('?'));
  if (pathOnly.includes('..')) return '/rejected';
  return normalizePath(pathOnly);
}

/**
 * @param {{ config: object, store: object, logger: object, clock: { now: () => number }, cimd: object, lookup?: Function }} deps
 */
export async function startBridge(deps) {
  const { readFile } = await import('node:fs/promises');
  const css = deps.css || await readFile(new URL('./web/styles.css', import.meta.url));
  const handler = createHandler({ ...deps, css });
  const server = deps.config.testHttp
    ? http.createServer(handler)
    : https.createServer({
      key: deps.config.tls.keyPem,
      cert: deps.config.tls.certPem,
      minVersion: 'TLSv1.2',
    }, handler);
  server.requestTimeout = 0;
  server.headersTimeout = Math.max(deps.config.limits.headerTimeoutMs, 60_000);
  server.timeout = 0;
  server.maxHeadersCount = 64;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(deps.config.listenPort, deps.config.listenHost, () => resolve());
  });
  const address = server.address();
  return {
    server,
    port: typeof address === 'object' && address ? address.port : deps.config.listenPort,
    inflight: handler.inflight,
    async close() {
      for (const request of handler.inflight) request.destroy();
      if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
      await new Promise((resolve) => server.close(() => resolve()));
      await deps.store.close();
    },
  };
}
