import path from 'node:path';
import { assertPasswordPolicy, hashPassword, randomToken, sha256Hex, timingSafeEqualString, verifyPassword } from '../crypto.mjs';
import { originAllowed, parseUpstreamUrl } from '../config.mjs';
import { COOKIE, clearCookie, httpError, parseForm, readCookies, sendHtml, sendJson, sendRedirect, setCookie } from '../http.mjs';
import { beginLoginAttempt, hashIp, recordLoginFailure } from '../rate-limit.mjs';
import { revokeEverything, revokeUpstream } from '../oauth/token.mjs';
import {
  assertApiKey,
  assertUpstreamId,
  cleanDisplayName,
  installRegistry,
  readUpstreamDefinitions,
  registerUpstreams,
  writeUpstreamDefinitions,
} from '../upstreams.mjs';
import { renderAdminApp, renderAdminLogin } from '../web/admin-page.mjs';

/**
 * Operator control panel. Sessions stay in memory. The persistent store keeps approvals and the password.
 * @param {{ activity: { attach: Function }, script: Buffer }} deps
 */
export function createAdmin(deps) {
  const sessions = new Map();
  const challenges = new Map();

  function issueLogin(now) {
    const csrf = randomToken(32);
    for (const [key, exp] of challenges) {
      if (exp <= now) challenges.delete(key);
    }
    if (challenges.size >= 30) {
      const first = challenges.keys().next().value;
      if (first) challenges.delete(first);
    }
    challenges.set(sha256Hex(csrf), now + 10 * 60 * 1000);
    return csrf;
  }

  function openSession(username, now, ttl) {
    const token = randomToken(32);
    const csrf = randomToken(32);
    sessions.set(sha256Hex(token), {
      username,
      csrf,
      csrfHash: sha256Hex(csrf),
      createdAt: now,
      expiresAt: Math.min(now + ttl.sessionAbsoluteMs, now + ttl.sessionIdleMs),
      absoluteExpiresAt: now + ttl.sessionAbsoluteMs,
    });
    if (sessions.size > 8) {
      const oldest = [...sessions.entries()].sort((a, b) => a[1].createdAt - b[1].createdAt)[0];
      if (oldest) sessions.delete(oldest[0]);
    }
    return { token, csrf };
  }

  function touch(token, now, ttl) {
    if (!token) return null;
    const key = sha256Hex(token);
    const session = sessions.get(key);
    if (!session) return null;
    if (session.expiresAt <= now || session.absoluteExpiresAt <= now) {
      sessions.delete(key);
      return null;
    }
    session.expiresAt = Math.min(session.absoluteExpiresAt, now + ttl.sessionIdleMs);
    return session;
  }

  async function handleGet(ctx, req, res) {
    const session = touch(cookieValue(req, COOKIE.admin), ctx.clock.now(), ctx.config.ttl);
    if (!session) {
      const csrf = issueLogin(ctx.clock.now());
      setCookie(res, COOKIE.adminLogin, csrf, { maxAge: 600 });
      return sendHtml(res, 200, renderAdminLogin({ csrf, error: '' }), { hsts: ctx.config.hsts, requestId: ctx.requestId });
    }
    return sendHtml(res, 200, renderAdminApp({ csrf: session.csrf, username: session.username }), {
      hsts: ctx.config.hsts,
      requestId: ctx.requestId,
      script: true,
    });
  }

  async function handleLogin(ctx, req, res) {
    const form = parseForm(ctx.body, { maxPairs: 8, maxKey: 32, maxValue: 256 });
    const cookies = safeCookies(req);
    const csrf = form.get('csrf') || '';
    const username = form.get('username') || '';
    const password = form.get('password') || '';
    const ipHash = hashIp(req.socket?.remoteAddress || '', ctx.store.read().loginPepper || 'pepper');
    const known = csrf && csrf === (cookies.get(COOKIE.adminLogin) || '') && challenges.get(sha256Hex(csrf)) > ctx.clock.now();
    const result = await ctx.store.transaction(async (draft) => {
      const now = ctx.clock.now();
      const attempt = beginLoginAttempt(draft, throttle(ctx, ipHash, now));
      if (attempt.locked) return { locked: true, retryAfterSec: attempt.retryAfterSec };
      const userOk = timingSafeEqualString(username, draft.operator.username);
      const passOk = await verifyPassword(password, draft.operator);
      if (!known || !userOk || !passOk) {
        const failure = recordLoginFailure(draft, throttle(ctx, ipHash, now));
        return { failed: true, locked: failure.locked, retryAfterSec: failure.retryAfterSec };
      }
      return { ok: true, username: draft.operator.username };
    });
    if (!result.ok) {
      const fresh = issueLogin(ctx.clock.now());
      setCookie(res, COOKIE.adminLogin, fresh, { maxAge: 600 });
      const page = renderAdminLogin({ csrf: fresh, error: 'Sign-in failed.' });
      if (result.locked) {
        return sendHtml(res, 429, page, {
          hsts: ctx.config.hsts,
          requestId: ctx.requestId,
          headers: { 'Retry-After': String(result.retryAfterSec || 60) },
        });
      }
      return sendHtml(res, 401, page, { hsts: ctx.config.hsts, requestId: ctx.requestId });
    }
    const opened = openSession(result.username, ctx.clock.now(), ctx.config.ttl);
    setCookie(res, COOKIE.admin, opened.token, { maxAge: Math.floor(ctx.config.ttl.sessionAbsoluteMs / 1000) });
    clearCookie(res, COOKIE.adminLogin);
    return sendRedirect(res, '/admin', { hsts: ctx.config.hsts, requestId: ctx.requestId });
  }

  async function handleLogout(ctx, req, res) {
    const auth = await requireSession(ctx, req, true);
    if (!auth.session) return sendJson(res, auth.status, { error: auth.error }, jsonOpts(ctx, auth.headers));
    sessions.delete(sha256Hex(cookieValue(req, COOKIE.admin)));
    clearCookie(res, COOKIE.admin);
    return sendJson(res, 200, { ok: true }, jsonOpts(ctx));
  }

  async function handleState(ctx, req, res) {
    const auth = await requireSession(ctx, req, false);
    if (!auth.session) return sendJson(res, auth.status, { error: auth.error }, jsonOpts(ctx, auth.headers));
    return sendJson(res, 200, snapshot(ctx), jsonOpts(ctx));
  }

  async function handleEvents(ctx, req, res) {
    const auth = await requireSession(ctx, req, false);
    if (!auth.session) return sendJson(res, auth.status, { error: auth.error }, jsonOpts(ctx, auth.headers));
    const headers = {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Accel-Buffering': 'no',
      'X-Request-Id': ctx.requestId,
    };
    res.writeHead(200, headers);
    const last = Number(req.headers['last-event-id']);
    deps.activity.attach(res, Number.isInteger(last) && last > 0 ? last : 0);
  }

  async function handleAdd(ctx, req, res) {
    const auth = await requireSession(ctx, req, true);
    if (!auth.session) return sendJson(res, auth.status, { error: auth.error }, jsonOpts(ctx, auth.headers));
    try {
      const body = readJson(ctx, req);
      const id = assertUpstreamId(String(body.id || ''));
      const displayName = cleanDisplayName(body.displayName);
      const apiKey = assertApiKey(body.apiKey);
      const file = upstreamFile(ctx);
      const existing = await readUpstreamDefinitions(file);
      if (existing.some((item) => item.id === id)) throw new Error('That short name is already in use.');
      const next = [...existing, { id, url: String(body.url || ''), displayName, apiKey }];
      const prepared = await prepare(ctx, next);
      await writeUpstreamDefinitions(ctx.config.dataDir, next);
      installRegistry(ctx.config, prepared.registry);
      if (ctx.logger && typeof ctx.logger.addSecret === 'function') ctx.logger.addSecret(apiKey);
      return sendJson(res, 200, { ok: true, state: snapshot(ctx) }, jsonOpts(ctx));
    } catch (err) {
      return sendJson(res, 400, { error: explain(err) }, jsonOpts(ctx));
    }
  }

  async function handleRemove(ctx, req, res) {
    const auth = await requireSession(ctx, req, true);
    if (!auth.session) return sendJson(res, auth.status, { error: auth.error }, jsonOpts(ctx, auth.headers));
    try {
      const body = readJson(ctx, req);
      const id = assertUpstreamId(String(body.id || ''));
      const existing = await readUpstreamDefinitions(upstreamFile(ctx));
      if (!existing.some((item) => item.id === id)) throw new Error('That WhatsApp is not in the list.');
      const next = existing.filter((item) => item.id !== id);
      const prepared = await prepare(ctx, next);
      await ctx.store.transaction(async (draft) => { revokeUpstream(draft, id, ctx.clock.now()); });
      await writeUpstreamDefinitions(ctx.config.dataDir, next);
      installRegistry(ctx.config, prepared.registry);
      return sendJson(res, 200, { ok: true, state: snapshot(ctx) }, jsonOpts(ctx));
    } catch (err) {
      return sendJson(res, 400, { error: explain(err) }, jsonOpts(ctx));
    }
  }

  async function handleRevoke(ctx, req, res) {
    const auth = await requireSession(ctx, req, true);
    if (!auth.session) return sendJson(res, auth.status, { error: auth.error }, jsonOpts(ctx, auth.headers));
    try {
      const body = readJson(ctx, req);
      const grantId = String(body.grantId || '');
      if (!/^[a-f0-9]{8,64}$/.test(grantId)) throw new Error('That approval was not found.');
      await ctx.store.transaction(async (draft) => {
        const grant = draft.grants[grantId];
        if (!grant) throw new Error('That approval was not found.');
        grant.revokedAt = ctx.clock.now();
        for (const [key, token] of Object.entries(draft.accessTokens)) {
          if (token.grantId === grantId) delete draft.accessTokens[key];
        }
        for (const [key, family] of Object.entries(draft.refreshFamilies)) {
          if (family.grantId === grantId) family.revokedAt = ctx.clock.now();
        }
      });
      return sendJson(res, 200, { ok: true, state: snapshot(ctx) }, jsonOpts(ctx));
    } catch (err) {
      return sendJson(res, 400, { error: explain(err) }, jsonOpts(ctx));
    }
  }

  async function handleRevokeAll(ctx, req, res) {
    const auth = await requireSession(ctx, req, true);
    if (!auth.session) return sendJson(res, auth.status, { error: auth.error }, jsonOpts(ctx, auth.headers));
    readJson(ctx, req);
    await ctx.store.transaction(async (draft) => { revokeEverything(draft, ctx.clock.now()); });
    return sendJson(res, 200, { ok: true, state: snapshot(ctx) }, jsonOpts(ctx));
  }

  async function handlePassword(ctx, req, res) {
    const auth = await requireSession(ctx, req, true);
    if (!auth.session) return sendJson(res, auth.status, { error: auth.error }, jsonOpts(ctx, auth.headers));
    const body = readJson(ctx, req);
    const current = String(body.current || '');
    const next = String(body.next || '');
    const confirm = String(body.confirm || '');
    if (next !== confirm) return sendJson(res, 400, { error: 'The new passwords do not match.' }, jsonOpts(ctx));
    try { assertPasswordPolicy(next); } catch {
      return sendJson(res, 400, { error: 'The new password needs to be at least 16 characters.' }, jsonOpts(ctx));
    }
    const ipHash = hashIp(req.socket?.remoteAddress || '', ctx.store.read().loginPepper || 'pepper');
    const check = await ctx.store.transaction(async (draft) => {
      const now = ctx.clock.now();
      const attempt = beginLoginAttempt(draft, throttle(ctx, ipHash, now));
      if (attempt.locked) return { locked: true, retryAfterSec: attempt.retryAfterSec };
      if (!await verifyPassword(current, draft.operator)) {
        const failure = recordLoginFailure(draft, throttle(ctx, ipHash, now));
        return { failed: true, locked: failure.locked, retryAfterSec: failure.retryAfterSec };
      }
      return { ok: true };
    });
    if (!check.ok) {
      const status = check.locked ? 429 : 401;
      const headers = check.locked ? { 'Retry-After': String(check.retryAfterSec || 60) } : undefined;
      return sendJson(res, status, { error: 'That password was not accepted.' }, jsonOpts(ctx, headers));
    }
    const hashed = await hashPassword(next);
    await ctx.store.transaction(async (draft) => {
      const now = ctx.clock.now();
      revokeEverything(draft, now);
      draft.operator.passwordSalt = hashed.passwordSalt;
      draft.operator.passwordVerifier = hashed.passwordVerifier;
      draft.operator.scryptParams = hashed.scryptParams;
      draft.operator.passwordChangedAt = now;
    });
    sessions.clear();
    clearCookie(res, COOKIE.admin);
    return sendJson(res, 200, { ok: true, signedOut: true }, jsonOpts(ctx));
  }

  async function requireSession(ctx, req, needsCsrf) {
    const session = touch(cookieValue(req, COOKIE.admin), ctx.clock.now(), ctx.config.ttl);
    if (!session) return { session: null, status: 401, error: 'Sign in again.' };
    if (needsCsrf) {
      const header = req.headers['x-csrf-token'];
      const presented = typeof header === 'string' ? header : '';
      if (!presented || !timingSafeEqualString(sha256Hex(presented), session.csrfHash)) {
        return { session: null, status: 403, error: 'The page needs to be reloaded.' };
      }
      if (!originAllowed(req.headers.origin, ctx.config)) {
        return { session: null, status: 403, error: 'The page needs to be reloaded.' };
      }
    }
    return { session, status: 200, error: '' };
  }

  return {
    close() {
      sessions.clear();
      challenges.clear();
    },
    routes: {
      '/admin': { GET: handleGet },
      '/admin/login': { POST: handleLogin },
      '/admin/logout': { POST: handleLogout },
      '/admin/events': { GET: handleEvents },
      '/admin/api/state': { GET: handleState },
      '/admin/api/upstream': { POST: handleAdd },
      '/admin/api/upstream/remove': { POST: handleRemove },
      '/admin/api/revoke': { POST: handleRevoke },
      '/admin/api/revoke-all': { POST: handleRevokeAll },
      '/admin/api/password': { POST: handlePassword },
      '/admin.js': { GET: (_ctx, _req, res) => sendScript(res, deps.script) },
    },
  };
}

/**
 * @param {object} ctx
 * @param {Array<{ id: string, url: string, displayName: string, apiKey: string }>} definitions
 */
async function prepare(ctx, definitions) {
  const current = ctx.config.upstreamById.get('default');
  const allowPublic = current.allowPublic === true;
  const seen = new Set([current.href]);
  const extras = [];
  for (const definition of definitions) {
    assertUpstreamId(definition.id);
    let parsed;
    try {
      parsed = await parseUpstreamUrl(definition.url, { allowPublic, lookup: ctx.lookup });
    } catch (err) {
      throw new Error(explain(err));
    }
    if (seen.has(parsed.href)) throw new Error('That WhatsApp address is already connected.');
    seen.add(parsed.href);
    extras.push({
      id: definition.id,
      ...parsed,
      displayName: cleanDisplayName(definition.displayName),
      apiKey: assertApiKey(definition.apiKey),
      headerName: current.headerName,
      allowPublic,
    });
  }
  const registry = registerUpstreams(ctx.config.publicOrigin, [plainUpstream(current), ...extras]);
  return { registry, extras };
}

/**
 * @param {object} entry
 */
function plainUpstream(entry) {
  return {
    id: entry.id,
    href: entry.href,
    protocol: entry.protocol,
    hostname: entry.hostname,
    port: entry.port,
    pinnedAddress: entry.pinnedAddress,
    pinnedFamily: entry.pinnedFamily,
    displayName: entry.displayName,
    apiKey: entry.apiKey,
    headerName: entry.headerName,
    allowPublic: entry.allowPublic,
  };
}

/**
 * @param {object} ctx
 */
function snapshot(ctx) {
  const state = ctx.store.read();
  const names = new Map(ctx.config.upstreams.map((item) => [item.id, item.displayName]));
  const grants = Object.values(state.grants).map((grant) => ({
    grantId: grant.grantId,
    client: grant.clientDisplay || 'ChatGPT',
    upstreamId: grant.upstreamId || '',
    upstreamName: names.get(grant.upstreamId) || grant.upstreamId || '',
    createdAt: grant.createdAt,
    revoked: Boolean(grant.revokedAt),
  }));
  grants.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  return {
    operator: state.operator.username,
    upstreams: ctx.config.upstreams.map((item) => ({
      id: item.id,
      name: item.displayName,
      path: item.path,
      url: item.resource,
    })),
    grants,
  };
}

/**
 * @param {object} ctx
 */
function upstreamFile(ctx) {
  return path.join(ctx.config.dataDir, 'upstreams.json');
}

/**
 * @param {object} ctx
 * @param {string} ipHash
 * @param {number} now
 */
function throttle(ctx, ipHash, now) {
  return {
    ipHash,
    now,
    maxFailures: ctx.config.limits.loginMaxFailures,
    windowMs: ctx.config.limits.loginWindowMs,
    lockMs: ctx.config.limits.loginLockMs,
  };
}

/**
 * @param {unknown} err
 */
function explain(err) {
  const message = err instanceof Error ? err.message : '';
  const known = [
    ['upstream id is invalid', 'Use a short name of lowercase letters, numbers, and hyphens. It cannot be the word default.'],
    ['already configured', 'That WhatsApp address is already connected.'],
    ['already connected', 'That WhatsApp address is already connected.'],
    ['display name', 'Enter a name for the approval page.'],
    ['API key', 'Enter the MCP App key from that WAHA.'],
    ['too many upstreams', 'This bridge already has as many WhatsApps as it can.'],
    ['not private', 'That address has to be on your own network.'],
    ['path must be /mcp', 'The WAHA address has to end in /mcp.'],
    ['userinfo', 'The WAHA address cannot contain a username or password.'],
    ['not found', 'That approval was not found.'],
    ['not in the list', 'That WhatsApp is not in the list.'],
    ['already in use', 'That short name is already in use.'],
    ['do not match', 'The new passwords do not match.'],
    ['at least 16', 'The new password needs to be at least 16 characters.'],
  ];
  for (const [needle, text] of known) {
    if (message.includes(needle)) return text;
  }
  if (/^(That |Use |Enter |The )/.test(message)) return message.slice(0, 200);
  return 'That change was rejected.';
}

/**
 * @param {object} ctx
 * @param {import('node:http').IncomingMessage} req
 */
function readJson(ctx, req) {
  const type = String(req.headers['content-type'] || '');
  if (!type.toLowerCase().startsWith('application/json')) throw httpError(415, 'unsupported_media_type', 'json body required');
  let value;
  try {
    value = JSON.parse(ctx.body.toString('utf8') || '{}');
  } catch {
    throw httpError(400, 'invalid_request', 'invalid json');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw httpError(400, 'invalid_request', 'invalid json');
  return value;
}

/**
 * @param {import('node:http').ServerResponse} res
 * @param {Buffer} script
 */
function sendScript(res, script) {
  if (res.headersSent || res.writableEnded) return;
  res.writeHead(200, {
    'Content-Type': 'text/javascript; charset=utf-8',
    'Content-Length': String(script.length),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(script);
}

/**
 * @param {import('node:http').IncomingMessage} req
 * @param {string} name
 */
function cookieValue(req, name) {
  return safeCookies(req).get(name) || '';
}

/**
 * @param {import('node:http').IncomingMessage} req
 */
function safeCookies(req) {
  try {
    return readCookies(req.headers.cookie);
  } catch {
    return new Map();
  }
}

/**
 * @param {object} ctx
 * @param {Record<string, string>} [headers]
 */
function jsonOpts(ctx, headers) {
  return { hsts: ctx.config.hsts, requestId: ctx.requestId, headers };
}
