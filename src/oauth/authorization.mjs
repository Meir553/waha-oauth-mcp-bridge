import { randomBytes } from 'node:crypto';
import { isValidPkceChallenge, randomToken, sha256Hex, timingSafeEqualString, verifyPassword } from '../crypto.mjs';
import { COOKIE, clearCookie, parseForm, parseQuery, readCookies, sendHtml, sendRedirect, setCookie } from '../http.mjs';
import { beginLoginAttempt, hashIp, recordLoginFailure } from '../rate-limit.mjs';
import { classifyClientId, isRedirectStructurallyAllowed } from './cimd.mjs';
import { parseScope } from './metadata.mjs';
import { connectorLabel } from '../upstreams.mjs';
import { layout, renderConsentForm, renderLocalErrorPage, renderLoginForm } from '../web/login.mjs';

const issuedConsents = new Map();

const CRITICAL = new Set([
  'response_type', 'client_id', 'redirect_uri', 'code_challenge', 'code_challenge_method',
  'resource', 'scope', 'state',
]);

/**
 * @param {object} ctx
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 */
export async function handleAuthorize(ctx, req, res) {
  let query;
  try {
    const url = new URL(req.url || '/', ctx.config.publicOrigin);
    query = parseQuery(url.search);
  } catch {
    return localError(ctx, res, 400);
  }
  const params = query.params;
  const clientId = params.get('client_id');
  const redirectUri = params.get('redirect_uri');
  const state = params.has('state') ? params.get('state') : null;
  const client = typeof clientId === 'string' ? classifyClientId(clientId) : { ok: false };
  const structurallyOk = client.ok
    && typeof redirectUri === 'string'
    && isRedirectStructurallyAllowed(redirectUri, client)
    && !query.duplicates.has('client_id')
    && !query.duplicates.has('redirect_uri')
    && isSafeEcho(redirectUri)
    && isSafeEcho(clientId);
  let doc = null;
  if (structurallyOk) {
    try {
      doc = await ctx.cimd.resolve(clientId);
      if (!doc.redirectUris.includes(redirectUri)) doc = null;
    } catch {
      doc = null;
    }
  }
  const canRedirect = Boolean(doc) && isSafeState(state);
  if (!canRedirect) return localError(ctx, res, 400);
  const problem = authorizeProblem(params, query.duplicates, ctx.config.upstreamByResource);
  if (problem) return oauthRedirect(ctx, res, redirectUri, { error: problem, state });

  const requestId = randomToken(32);
  const csrf = randomToken(32);
  const now = ctx.clock.now();
  const cookies = safeCookies(req);
  const sessionId = cookies.get(COOKIE.session) || '';
  const bound = await ctx.store.transaction(async (draft) => {
    const selected = ctx.config.upstreamByResource.get(params.get('resource'));
    if (!selected) return { missing: true };
    if (Object.keys(draft.pendingAuthorizations).length >= 100) {
      return { overflow: true };
    }
    const session = liveSession(draft, sessionId, now, ctx.config.ttl);
    if (session) session.csrfHash = sha256Hex(csrf);
    draft.pendingAuthorizations[sha256Hex(requestId)] = {
      clientId,
      redirectUri,
      resource: selected.resource,
      upstreamId: selected.id,
      pkceChallenge: params.get('code_challenge'),
      requestedScopes: parseScope(params.get('scope')).scopes,
      state,
      expiresAt: now + ctx.config.ttl.authRequestMs,
      sessionBinding: session ? sha256Hex(sessionId) : null,
      csrfHash: sha256Hex(csrf),
      createdAt: now,
      clientDisplay: doc.clientName,
    };
    return { session: Boolean(session) };
  });
  if (bound.missing) return localError(ctx, res, 400);
  if (bound.overflow) return localError(ctx, res, 503);
  setCookie(res, COOKIE.pending, requestId);
  setCookie(res, COOKIE.csrf, csrf);
  return sendRedirect(res, bound.session ? '/oauth/consent' : '/login', { hsts: ctx.config.hsts, requestId: ctx.requestId });
}

/**
 * @param {object} ctx
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 */
export async function handleLoginGet(ctx, req, res) {
  const pending = await currentPending(ctx, req);
  if (!pending.ok) return localError(ctx, res, 400);
  return sendHtml(res, 200, renderLoginForm({ csrf: pending.csrf, requestId: pending.requestId, error: '' }), { hsts: ctx.config.hsts, requestId: ctx.requestId });
}

/**
 * @param {object} ctx
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 */
export async function handleLoginPost(ctx, req, res) {
  const form = parseForm(ctx.body, { maxPairs: 8, maxKey: 32, maxValue: 256 });
  const cookies = safeCookies(req);
  const requestId = form.get('request_id') || '';
  const csrf = form.get('csrf') || '';
  const username = form.get('username') || '';
  const password = form.get('password') || '';
  const ipHash = hashIp(req.socket?.remoteAddress || '', ctx.store.read().loginPepper || 'pepper');
  if (requestId !== (cookies.get(COOKIE.pending) || '') || csrf !== (cookies.get(COOKIE.csrf) || '')) {
    const locked = await noteFailure(ctx, ipHash);
    return loginFailed(ctx, res, cookies.get(COOKIE.csrf) || '', cookies.get(COOKIE.pending) || '', locked);
  }
  const result = await ctx.store.transaction(async (draft) => {
    const now = ctx.clock.now();
    const attempt = beginLoginAttempt(draft, throttleOptions(ctx, ipHash, now));
    if (attempt.locked) return { locked: true, retryAfterSec: attempt.retryAfterSec };
    const pending = draft.pendingAuthorizations[sha256Hex(requestId)];
    const csrfOk = Boolean(pending) && timingSafeEqualString(sha256Hex(csrf), pending.csrfHash || '');
    const fresh = Boolean(pending) && pending.expiresAt > now;
    const userOk = timingSafeEqualString(username, draft.operator.username);
    const passOk = await verifyPassword(password, draft.operator);
    if (!csrfOk || !fresh || !userOk || !passOk) {
      const failure = recordLoginFailure(draft, throttleOptions(ctx, ipHash, now));
      return { failed: true, locked: failure.locked, retryAfterSec: failure.retryAfterSec };
    }
    if (cookies.get(COOKIE.session)) delete draft.browserSessions[sha256Hex(cookies.get(COOKIE.session))];
    const newSession = randomToken(32);
    const newCsrf = randomToken(32);
    const absolute = now + ctx.config.ttl.sessionAbsoluteMs;
    draft.browserSessions[sha256Hex(newSession)] = {
      createdAt: now,
      lastSeenAt: now,
      absoluteExpiresAt: absolute,
      expiresAt: Math.min(absolute, now + ctx.config.ttl.sessionIdleMs),
      csrfHash: sha256Hex(newCsrf),
      userId: 'operator',
    };
    pending.sessionBinding = sha256Hex(newSession);
    pending.csrfHash = sha256Hex(newCsrf);
    return { session: newSession, csrf: newCsrf };
  });
  if (result.locked || result.failed) return loginFailed(ctx, res, csrf, requestId, result);
  setCookie(res, COOKIE.session, result.session);
  setCookie(res, COOKIE.csrf, result.csrf);
  return sendRedirect(res, '/oauth/consent', { hsts: ctx.config.hsts, requestId: ctx.requestId });
}

/**
 * @param {object} ctx
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 */
export async function handleConsentGet(ctx, req, res) {
  const view = await consentContext(ctx, req);
  if (!view.ok) return localError(ctx, res, view.status || 400);
  const upstream = upstreamFor(ctx, view.pending);
  if (!upstream) return localError(ctx, res, 400);
  return sendHtml(res, 200, renderConsentForm({
    csrf: view.csrf,
    requestId: view.requestId,
    clientName: view.pending.clientDisplay,
    clientId: view.pending.clientId,
    scopes: view.pending.requestedScopes,
    upstreamName: upstream.displayName,
    upstreamPath: upstream.path,
  }), { hsts: ctx.config.hsts, requestId: ctx.requestId });
}

/**
 * @param {object} ctx
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 */
export async function handleConsentPost(ctx, req, res) {
  const form = parseForm(ctx.body, { maxPairs: 8, maxKey: 32, maxValue: 256 });
  const decision = form.get('decision');
  const label = connectorLabel(form.get('label'));
  const view = await consentContext(ctx, req, form.get('csrf') || '', form.get('request_id') || '');
  if (!view.ok) {
    const again = view.sessionId ? recallConsent(ctx, view.sessionId, view.requestId) : null;
    if (again) return sendRedirect(res, again, { hsts: ctx.config.hsts, requestId: ctx.requestId });
    return localError(ctx, res, view.status || 403);
  }
  if (decision !== 'approve' && decision !== 'deny') return localError(ctx, res, 400);
  const outcome = await ctx.store.transaction(async (draft) => {
    const now = ctx.clock.now();
    const pending = draft.pendingAuthorizations[sha256Hex(view.requestId)];
    const selected = ctx.config.upstreamByResource.get(pending ? pending.resource : '');
    const session = liveSession(draft, view.sessionId, now, ctx.config.ttl);
    if (!pending || !selected || selected.id !== pending.upstreamId || !session || pending.sessionBinding !== sha256Hex(view.sessionId) || pending.expiresAt <= now) {
      return { error: 'stale' };
    }
    if (!timingSafeEqualString(sha256Hex(view.csrf), pending.csrfHash)) return { error: 'csrf' };
    delete draft.pendingAuthorizations[sha256Hex(view.requestId)];
    if (decision === 'deny') {
      const redirect = redirectTarget(pending.redirectUri, { error: 'access_denied', state: pending.state, iss: ctx.config.issuer });
      rememberConsent(view.requestId, view.sessionId, redirect, '', now + ctx.config.ttl.codeMs);
      return { redirect };
    }
    const grantId = randomBytes(16).toString('hex');
    draft.grants[grantId] = {
      grantId,
      clientId: pending.clientId,
      userId: 'operator',
      resource: selected.resource,
      upstreamId: selected.id,
      scopes: pending.requestedScopes.slice(),
      createdAt: now,
      revokedAt: null,
      expiresAt: null,
      clientDisplay: pending.clientDisplay,
      label,
    };
    const code = randomToken(32);
    draft.authorizationCodes[sha256Hex(code)] = {
      clientId: pending.clientId,
      redirectUri: pending.redirectUri,
      resource: pending.resource,
      pkceChallenge: pending.pkceChallenge,
      scope: pending.requestedScopes.slice(),
      userId: 'operator',
      grantId,
      expiresAt: now + ctx.config.ttl.codeMs,
      usedAt: null,
    };
    const redirect = redirectTarget(pending.redirectUri, { code, state: pending.state, iss: ctx.config.issuer });
    rememberConsent(view.requestId, view.sessionId, redirect, sha256Hex(code), now + ctx.config.ttl.codeMs);
    return { redirect };
  });
  if (!outcome.redirect) return localError(ctx, res, 403);
  clearCookie(res, COOKIE.pending);
  return sendRedirect(res, outcome.redirect, { hsts: ctx.config.hsts, requestId: ctx.requestId });
}

/**
 * @param {object} ctx
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 */
export async function handleLogout(ctx, req, res) {
  const form = parseForm(ctx.body, { maxPairs: 4, maxKey: 32, maxValue: 256 });
  const cookies = safeCookies(req);
  const sessionId = cookies.get(COOKIE.session) || '';
  const csrf = form.get('csrf') || '';
  const ok = await ctx.store.transaction(async (draft) => {
    const session = draft.browserSessions[sha256Hex(sessionId)];
    if (!session || !timingSafeEqualString(sha256Hex(csrf), session.csrfHash || '')) return false;
    if ((cookies.get(COOKIE.csrf) || '') !== csrf) return false;
    delete draft.browserSessions[sha256Hex(sessionId)];
    return true;
  });
  if (!ok) return localError(ctx, res, 403);
  clearCookie(res, COOKIE.session);
  clearCookie(res, COOKIE.csrf);
  clearCookie(res, COOKIE.pending);
  return sendHtml(res, 200, layout({
    title: 'Signed out',
    body: '<h1>Signed out</h1><p>You are signed out.</p>',
  }), { hsts: ctx.config.hsts, requestId: ctx.requestId });
}

/**
 * @param {Map<string, string>} params
 * @param {Set<string>} duplicates
 * @param {Map<string, object> | undefined} resources
 */
function upstreamFor(ctx, pending) {
  if (!pending) return null;
  const upstream = ctx.config.upstreamByResource.get(pending.resource);
  if (!upstream || upstream.id !== pending.upstreamId) return null;
  return upstream;
}

function authorizeProblem(params, duplicates, resources) {
  for (const name of duplicates) {
    if (CRITICAL.has(name)) return 'invalid_request';
  }
  if (params.get('response_mode') && params.get('response_mode') !== 'query') return 'invalid_request';
  const responseType = params.get('response_type');
  if (!responseType) return 'invalid_request';
  if (responseType !== 'code') return 'unsupported_response_type';
  if (params.get('code_challenge_method') !== 'S256') return 'invalid_request';
  if (!isValidPkceChallenge(params.get('code_challenge') || '')) return 'invalid_request';
  if (!params.get('resource')) return 'invalid_request';
  if (!resources || !resources.has(params.get('resource'))) return 'invalid_target';
  if (!parseScope(params.get('scope') || '').ok) return 'invalid_scope';
  return null;
}

/**
 * @param {object} draft
 * @param {string} sessionId
 * @param {number} now
 * @param {{ sessionIdleMs: number }} ttl
 */
function peekSession(state, sessionId, now) {
  if (!sessionId) return null;
  const record = state.browserSessions[sha256Hex(sessionId)];
  if (!record || record.expiresAt <= now || record.absoluteExpiresAt <= now) return null;
  return record;
}

function liveSession(draft, sessionId, now, ttl) {
  if (!sessionId) return null;
  const record = draft.browserSessions[sha256Hex(sessionId)];
  if (!record) return null;
  if (record.expiresAt <= now || record.absoluteExpiresAt <= now) {
    delete draft.browserSessions[sha256Hex(sessionId)];
    return null;
  }
  record.lastSeenAt = now;
  record.expiresAt = Math.min(record.absoluteExpiresAt, now + ttl.sessionIdleMs);
  return record;
}

/**
 * @param {object} ctx
 * @param {import('node:http').IncomingMessage} req
 */
async function currentPending(ctx, req) {
  const cookies = safeCookies(req);
  const requestId = cookies.get(COOKIE.pending) || '';
  const csrf = cookies.get(COOKIE.csrf) || '';
  if (!requestId || !csrf) return { ok: false };
  const pending = ctx.store.read().pendingAuthorizations[sha256Hex(requestId)];
  if (!pending || pending.expiresAt <= ctx.clock.now()) return { ok: false };
  if (!timingSafeEqualString(sha256Hex(csrf), pending.csrfHash || '')) return { ok: false };
  return { ok: true, requestId, csrf, pending };
}

/**
 * The browser may block the first return trip to ChatGPT. A second click from the
 * same login must send the same unused code, not a dead-end error.
 * @param {string} requestId
 * @param {string} sessionId
 * @param {string} redirect
 * @param {string} codeHash
 * @param {number} expiresAt
 */
function rememberConsent(requestId, sessionId, redirect, codeHash, expiresAt) {
  const key = sha256Hex(`${sessionId}\n${requestId}`);
  issuedConsents.set(key, { redirect, codeHash, expiresAt });
  if (issuedConsents.size > 100) {
    const now = Date.now();
    for (const [id, row] of issuedConsents) {
      if (row.expiresAt <= now) issuedConsents.delete(id);
    }
  }
}

/**
 * @param {object} ctx
 * @param {string} sessionId
 * @param {string} requestId
 */
function recallConsent(ctx, sessionId, requestId) {
  const row = issuedConsents.get(sha256Hex(`${sessionId}\n${requestId}`));
  if (!row || row.expiresAt <= ctx.clock.now()) return null;
  if (row.codeHash) {
    const code = ctx.store.read().authorizationCodes[row.codeHash];
    if (!code || code.usedAt) return null;
  }
  return row.redirect;
}

/**
 * @param {object} ctx
 * @param {import('node:http').IncomingMessage} req
 * @param {string} [csrf]
 * @param {string} [requestId]
 */
async function consentContext(ctx, req, csrf, requestId) {
  const cookies = safeCookies(req);
  const sessionId = cookies.get(COOKIE.session) || '';
  const cookieCsrf = cookies.get(COOKIE.csrf) || '';
  const pendingId = requestId || cookies.get(COOKIE.pending) || '';
  const presented = csrf || cookieCsrf;
  if (!sessionId || !pendingId || !presented || presented !== cookieCsrf) return { ok: false, status: 403 };
  const snapshot = await ctx.store.enqueue(async () => {
    const state = ctx.store.read();
    const now = ctx.clock.now();
    return {
      session: peekSession(state, sessionId, now),
      pending: state.pendingAuthorizations[sha256Hex(pendingId)],
    };
  });
  if (!snapshot.session) return { ok: false, status: 403 };
  if (!timingSafeEqualString(sha256Hex(presented), snapshot.session.csrfHash || '')) return { ok: false, status: 403 };
  if (!snapshot.pending) return { ok: false, status: 403, sessionId, requestId: pendingId, csrf: presented };
  if (snapshot.pending.sessionBinding !== sha256Hex(sessionId)) return { ok: false, status: 403 };
  if (!timingSafeEqualString(sha256Hex(presented), snapshot.pending.csrfHash || '')) return { ok: false, status: 403 };
  return { ok: true, sessionId, csrf: presented, requestId: pendingId, pending: snapshot.pending };
}

/**
 * @param {object} ctx
 * @param {string} ipHash
 */
async function noteFailure(ctx, ipHash) {
  return ctx.store.transaction(async (draft) => recordLoginFailure(draft, throttleOptions(ctx, ipHash, ctx.clock.now())));
}

/**
 * @param {object} ctx
 * @param {string} ipHash
 * @param {number} now
 */
function throttleOptions(ctx, ipHash, now) {
  return {
    ipHash,
    now,
    maxFailures: ctx.config.limits.loginMaxFailures,
    windowMs: ctx.config.limits.loginWindowMs,
    lockMs: ctx.config.limits.loginLockMs,
  };
}

/**
 * @param {object} ctx
 * @param {import('node:http').ServerResponse} res
 * @param {string} csrf
 * @param {{ locked?: boolean, retryAfterSec?: number }} result
 */
function loginFailed(ctx, res, csrf, requestId, result) {
  const page = renderLoginForm({ csrf, requestId, error: 'Sign-in failed.' });
  if (result.locked) {
    return sendHtml(res, 429, page, {
      hsts: ctx.config.hsts,
      requestId: ctx.requestId,
      headers: { 'Retry-After': String(result.retryAfterSec || 60) },
    });
  }
  return sendHtml(res, 401, page, { hsts: ctx.config.hsts, requestId: ctx.requestId });
}

/**
 * @param {object} ctx
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 */
function localError(ctx, res, status) {
  return sendHtml(res, status, renderLocalErrorPage(), { hsts: ctx.config.hsts, requestId: ctx.requestId });
}

/**
 * @param {object} ctx
 * @param {import('node:http').ServerResponse} res
 * @param {string} redirectUri
 * @param {{ error: string, state: string | null }} fields
 */
function oauthRedirect(ctx, res, redirectUri, fields) {
  return sendRedirect(res, redirectTarget(redirectUri, { error: fields.error, state: fields.state, iss: ctx.config.issuer }), {
    hsts: ctx.config.hsts,
    requestId: ctx.requestId,
  });
}

/**
 * @param {string} redirectUri
 * @param {{ code?: string, error?: string, state: string | null, iss: string }} fields
 */
export function redirectTarget(redirectUri, fields) {
  const url = new URL(redirectUri);
  if (fields.code) url.searchParams.set('code', fields.code);
  if (fields.error) url.searchParams.set('error', fields.error);
  if (fields.state !== null && fields.state !== undefined) url.searchParams.set('state', fields.state);
  url.searchParams.set('iss', fields.iss);
  url.hash = '';
  return url.toString();
}

/**
 * @param {string | null} state
 */
function isSafeState(state) {
  if (state === null) return true;
  return typeof state === 'string' && state.length <= 512 && isSafeEcho(state);
}

/**
 * @param {string} value
 */
function isSafeEcho(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 512 && !/[\u0000-\u001F\u007F]/.test(value);
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
