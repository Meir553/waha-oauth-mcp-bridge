import { randomBytes } from 'node:crypto';
import { pkceMatches, randomToken, sha256Hex } from '../crypto.mjs';
import { contentTypeIs, parseForm, sendJson } from '../http.mjs';
import { parseScope } from './metadata.mjs';
import { classifyClientId } from './cimd.mjs';

export class OAuthError extends Error {
  /**
   * @param {string} error
   * @param {number} [status]
   */
  constructor(error, status = 400) {
    super(error);
    this.name = 'OAuthError';
    this.oauthError = error;
    this.status = status;
  }
}

/**
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {string} error
 * @param {{ hsts?: boolean, requestId?: string, headers?: Record<string, string> }} ctxLike
 */
export function sendTokenError(res, status, error, ctxLike) {
  sendJson(res, status, { error }, {
    hsts: ctxLike.hsts,
    requestId: ctxLike.requestId,
    headers: ctxLike.headers,
    noStore: true,
  });
}

/**
 * Crash window: the refresh token is marked used and the replacement is durable
 * before the HTTP response is written. If the process dies in between, the old
 * token stays invalid. A later replay of that old token revokes the family,
 * including the replacement the client never received. The operator must approve
 * a new grant. The old token is never resurrected.
 * @param {object} ctx
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 */
export async function handleToken(ctx, req, res) {
  const responseCtx = { hsts: ctx.config.hsts, requestId: ctx.requestId };
  if (headerCountSafe(req, 'content-type') > 1) {
    return sendTokenError(res, 400, 'invalid_request', responseCtx);
  }
  if (!contentTypeIs(req.headers['content-type'], ['application/x-www-form-urlencoded'])) {
    return sendTokenError(res, 415, 'invalid_request', responseCtx);
  }
  const limit = ctx.tokenLimiter.hit(req.socket?.remoteAddress || 'unknown');
  if (limit.limited) {
    return sendTokenError(res, 429, 'temporarily_unavailable', {
      ...responseCtx,
      headers: { 'Retry-After': String(limit.retryAfterSec) },
    });
  }
  const form = parseForm(ctx.body, { maxPairs: 16, maxKey: 64, maxValue: 2048 });
  const grantType = form.get('grant_type');
  if (grantType === 'authorization_code') return exchangeCode(ctx, res, form, responseCtx);
  if (grantType === 'refresh_token') return exchangeRefresh(ctx, res, form, responseCtx);
  if (!grantType) return sendTokenError(res, 400, 'invalid_request', responseCtx);
  return sendTokenError(res, 400, 'unsupported_grant_type', responseCtx);
}

/**
 * @param {object} ctx
 * @param {import('node:http').ServerResponse} res
 * @param {Map<string, string>} form
 * @param {object} responseCtx
 */
async function exchangeCode(ctx, res, form, responseCtx) {
  const code = form.get('code');
  const clientId = form.get('client_id');
  const redirectUri = form.get('redirect_uri');
  const verifier = form.get('code_verifier');
  const resource = form.get('resource');
  if (!code || !clientId || !redirectUri || !verifier || !resource) {
    return sendTokenError(res, 400, 'invalid_request', responseCtx);
  }
  if (!classifyClientId(clientId).ok) return sendTokenError(res, 401, 'invalid_client', responseCtx);
  if (!ctx.config.upstreamByResource || !ctx.config.upstreamByResource.has(resource)) {
    return sendTokenError(res, 400, 'invalid_target', responseCtx);
  }
  try {
    const issued = await ctx.store.transaction(async (draft) => {
      const record = draft.authorizationCodes[sha256Hex(code)];
      const now = ctx.clock.now();
      if (!record || record.usedAt || record.expiresAt <= now) throw new OAuthError('invalid_grant');
      if (record.clientId !== clientId || record.redirectUri !== redirectUri || record.resource !== resource) {
        throw new OAuthError('invalid_grant');
      }
      const grant = draft.grants[record.grantId];
      if (!grant || grant.revokedAt) throw new OAuthError('invalid_grant');
      if (!pkceMatches(verifier, record.pkceChallenge)) throw new OAuthError('invalid_grant');
      record.usedAt = now;
      const familyId = randomBytes(16).toString('hex');
      const familyExpires = now + ctx.config.ttl.refreshMs;
      draft.refreshFamilies[familyId] = {
        grantId: grant.grantId,
        revokedAt: null,
        createdAt: now,
        expiresAt: familyExpires,
      };
      return mintTokens(draft, ctx, grant, record.scope, familyId, familyExpires, now);
    });
    return sendTokenSuccess(res, issued, responseCtx);
  } catch (err) {
    if (err instanceof OAuthError) return sendTokenError(res, err.status, err.oauthError, responseCtx);
    throw err;
  }
}

/**
 * @param {object} ctx
 * @param {import('node:http').ServerResponse} res
 * @param {Map<string, string>} form
 * @param {object} responseCtx
 */
async function exchangeRefresh(ctx, res, form, responseCtx) {
  const token = form.get('refresh_token');
  const clientId = form.get('client_id');
  const resource = form.get('resource');
  if (!token || !clientId || !resource) return sendTokenError(res, 400, 'invalid_request', responseCtx);
  if (!classifyClientId(clientId).ok) return sendTokenError(res, 401, 'invalid_client', responseCtx);
  if (!ctx.config.upstreamByResource || !ctx.config.upstreamByResource.has(resource)) {
    return sendTokenError(res, 400, 'invalid_target', responseCtx);
  }
  const scopeParam = form.get('scope');
  let narrowed = null;
  if (scopeParam !== undefined) {
    const parsed = parseScope(scopeParam);
    if (!parsed.ok) return sendTokenError(res, 400, 'invalid_scope', responseCtx);
    narrowed = parsed.scopes;
  }
  try {
    const issued = await ctx.store.transaction(async (draft) => {
      const now = ctx.clock.now();
      const record = draft.refreshTokens[sha256Hex(token)];
      if (!record) throw new OAuthError('invalid_grant');
      const family = draft.refreshFamilies[record.familyId];
      if (!family) throw new OAuthError('invalid_grant');
      if (family.revokedAt || record.usedAt) {
        revokeFamily(draft, record.familyId, now);
        return { revoked: true };
      }
      if (record.expiresAt <= now) throw new OAuthError('invalid_grant');
      if (record.clientId !== clientId || record.resource !== resource) throw new OAuthError('invalid_grant');
      const grant = draft.grants[record.grantId];
      if (!grant || grant.revokedAt || grant.clientId !== clientId) throw new OAuthError('invalid_grant');
      const scopes = narrowed || record.scopes;
      if (scopes.some((scope) => !record.scopes.includes(scope))) throw new OAuthError('invalid_scope');
      record.usedAt = now;
      return mintTokens(draft, ctx, grant, scopes, record.familyId, family.expiresAt, now);
    });
    if (issued && issued.revoked) return sendTokenError(res, 400, 'invalid_grant', responseCtx);
    return sendTokenSuccess(res, issued, responseCtx);
  } catch (err) {
    if (err instanceof OAuthError) return sendTokenError(res, err.status, err.oauthError, responseCtx);
    throw err;
  }
}

/**
 * @param {object} draft
 * @param {string} familyId
 * @param {number} now
 */
export function revokeFamily(draft, familyId, now) {
  const family = draft.refreshFamilies[familyId];
  if (family && !family.revokedAt) family.revokedAt = now;
  for (const [key, token] of Object.entries(draft.accessTokens)) {
    if (token.familyId === familyId) delete draft.accessTokens[key];
  }
  for (const [key, token] of Object.entries(draft.refreshTokens)) {
    if (token.familyId === familyId && !token.usedAt) delete draft.refreshTokens[key];
  }
}

/**
 * @param {object} draft
 * @param {number} now
 */
export function revokeEverything(draft, now) {
  draft.browserSessions = {};
  draft.pendingAuthorizations = {};
  draft.authorizationCodes = {};
  draft.accessTokens = {};
  draft.refreshTokens = {};
  for (const family of Object.values(draft.refreshFamilies)) family.revokedAt = family.revokedAt || now;
  draft.mcpSessions = {};
  for (const grant of Object.values(draft.grants)) grant.revokedAt = grant.revokedAt || now;
}

/**
 * Revoke every grant bound to one configured WAHA and drop its live tokens.
 * @param {object} draft
 * @param {string} upstreamId
 * @param {number} now
 */
export function revokeUpstream(draft, upstreamId, now) {
  const grantIds = new Set();
  for (const grant of Object.values(draft.grants)) {
    if (grant.upstreamId !== upstreamId) continue;
    grant.revokedAt = grant.revokedAt || now;
    grantIds.add(grant.grantId);
  }
  for (const [key, token] of Object.entries(draft.accessTokens)) {
    if (grantIds.has(token.grantId)) delete draft.accessTokens[key];
  }
  for (const [key, token] of Object.entries(draft.refreshTokens)) {
    if (grantIds.has(token.grantId)) delete draft.refreshTokens[key];
  }
  for (const family of Object.values(draft.refreshFamilies)) {
    if (grantIds.has(family.grantId)) family.revokedAt = family.revokedAt || now;
  }
  for (const [key, session] of Object.entries(draft.mcpSessions)) {
    if (grantIds.has(session.grantId) || session.upstreamId === upstreamId) delete draft.mcpSessions[key];
  }
}

/**
 * @param {object} draft
 * @param {object} ctx
 * @param {object} grant
 * @param {string[]} scopes
 * @param {string} familyId
 * @param {number} familyExpires
 * @param {number} now
 */
function mintTokens(draft, ctx, grant, scopes, familyId, familyExpires, now) {
  const access = randomToken(32);
  const refresh = randomToken(48);
  const accessExpires = Math.min(now + ctx.config.ttl.accessMs, familyExpires);
  draft.accessTokens[sha256Hex(access)] = {
    grantId: grant.grantId,
    familyId,
    clientId: grant.clientId,
    userId: grant.userId,
    audience: grant.resource,
    issuer: ctx.config.issuer,
    scopes: scopes.slice(),
    expiresAt: accessExpires,
    createdAt: now,
  };
  draft.refreshTokens[sha256Hex(refresh)] = {
    familyId,
    grantId: grant.grantId,
    clientId: grant.clientId,
    resource: grant.resource,
    scopes: scopes.slice(),
    expiresAt: familyExpires,
    createdAt: now,
    usedAt: null,
  };
  return {
    access_token: access,
    token_type: 'Bearer',
    expires_in: Math.max(1, Math.ceil((accessExpires - now) / 1000)),
    refresh_token: refresh,
    scope: scopes.join(' '),
  };
}

/**
 * @param {import('node:http').ServerResponse} res
 * @param {object} issued
 * @param {object} responseCtx
 */
function sendTokenSuccess(res, issued, responseCtx) {
  sendJson(res, 200, issued, { hsts: responseCtx.hsts, requestId: responseCtx.requestId, noStore: true });
}

/**
 * @param {import('node:http').IncomingMessage} req
 * @param {string} name
 */
function headerCountSafe(req, name) {
  const want = name.toLowerCase();
  let count = 0;
  for (let i = 0; i < (req.rawHeaders || []).length; i += 2) {
    if (String(req.rawHeaders[i]).toLowerCase() === want) count += 1;
  }
  return count;
}
