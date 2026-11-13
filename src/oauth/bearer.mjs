import { sha256Hex } from '../crypto.mjs';

/**
 * @param {string | string[] | undefined} header
 * @returns {{ ok: true, token: string } | { ok: false, reason: 'missing' | 'malformed' }}
 */
export function parseBearer(header) {
  if (header === undefined) return { ok: false, reason: 'missing' };
  if (Array.isArray(header) || typeof header !== 'string') return { ok: false, reason: 'malformed' };
  if (!header.startsWith('Bearer ') || header.slice(0, 7) !== 'Bearer ') return { ok: false, reason: 'malformed' };
  const token = header.slice('Bearer '.length);
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(token)) return { ok: false, reason: 'malformed' };
  return { ok: true, token };
}

/**
 * @param {{ store: { enqueue: Function, read: Function }, clock: { now: () => number }, config: { issuer: string, resource: string } }} ctx
 * @param {string | string[] | undefined} header
 */
export async function authenticateBearer(ctx, header) {
  const parsed = parseBearer(header);
  if (!parsed.ok) return parsed;
  const hash = sha256Hex(parsed.token);
  return ctx.store.enqueue(async () => {
    const state = ctx.store.read();
    const record = state.accessTokens[hash];
    if (!record) return { ok: false, reason: 'invalid' };
    const now = ctx.clock.now();
    if (record.expiresAt <= now) return { ok: false, reason: 'expired' };
    const upstream = ctx.upstream || ctx.config.upstream;
    const resource = upstream && upstream.resource ? upstream.resource : ctx.config.resource;
    const upstreamId = upstream && upstream.id ? upstream.id : 'default';
    if (record.issuer !== ctx.config.issuer || record.audience !== resource) {
      return { ok: false, reason: 'audience' };
    }
    const grant = state.grants[record.grantId];
    if (!grant || grant.revokedAt || grant.clientId !== record.clientId || grant.resource !== resource) {
      return { ok: false, reason: 'revoked' };
    }
    if (grant.upstreamId && grant.upstreamId !== upstreamId) return { ok: false, reason: 'revoked' };
    if (record.familyId) {
      const family = state.refreshFamilies[record.familyId];
      if (!family || family.revokedAt) return { ok: false, reason: 'revoked' };
    }
    if (!Array.isArray(record.scopes) || !record.scopes.includes('mcp:access')) {
      return { ok: false, reason: 'scope' };
    }
    return { ok: true, tokenHash: hash, record, grant };
  });
}
