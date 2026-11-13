import https from 'node:https';

const PRIMARY_CLIENT = 'https://chatgpt.com/oauth/client.json';
const CALLBACK_CLIENT = /^\/oauth\/([A-Za-z0-9_-]{1,128})\/client\.json$/;
const STABLE_REDIRECT = '/connector_platform_oauth_redirect';
const CALLBACK_REDIRECT = /^\/connector\/oauth\/([A-Za-z0-9_-]{1,128})$/;

/**
 * @param {string} value
 * @returns {{ hostname: string, pathname: string } | null}
 */
export function canonicalHttps(value) {
  if (typeof value !== 'string' || value.length < 12 || value.length > 512) return null;
  if (/[\u0000-\u0020\u007F\\]/.test(value)) return null;
  let url;
  try { url = new URL(value); } catch { return null; }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash) return null;
  if (url.hostname !== 'chatgpt.com') return null;
  const canonical = `https://chatgpt.com${url.pathname}`;
  if (canonical !== value) return null;
  return { hostname: url.hostname, pathname: url.pathname };
}

/**
 * @param {string} clientId
 * @returns {{ ok: true, kind: 'primary' | 'callback', callbackId: string | null } | { ok: false }}
 */
export function classifyClientId(clientId) {
  const parsed = canonicalHttps(clientId);
  if (!parsed) return { ok: false };
  if (clientId === PRIMARY_CLIENT && parsed.pathname === '/oauth/client.json') {
    return { ok: true, kind: 'primary', callbackId: null };
  }
  const match = CALLBACK_CLIENT.exec(parsed.pathname);
  if (!match) return { ok: false };
  return { ok: true, kind: 'callback', callbackId: match[1] };
}

/**
 * Structural allowlist. Membership in the fetched CIMD document is a separate check.
 * @param {string} redirectUri
 * @param {{ ok: boolean, kind?: string, callbackId?: string | null }} client
 */
export function isRedirectStructurallyAllowed(redirectUri, client) {
  if (!client || !client.ok) return false;
  const parsed = canonicalHttps(redirectUri);
  if (!parsed) return false;
  if (parsed.pathname === STABLE_REDIRECT) return true;
  const match = CALLBACK_REDIRECT.exec(parsed.pathname);
  if (!match) return false;
  return client.kind === 'callback' && client.callbackId === match[1];
}

/**
 * @param {object} doc
 * @param {string} clientId
 */
export function validateCimdDocument(doc, clientId) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw Object.assign(new Error('client metadata is invalid'), { code: 'cimd_invalid' });
  }
  if (doc.client_id !== clientId) {
    throw Object.assign(new Error('client metadata identity does not match'), { code: 'cimd_invalid' });
  }
  const redirects = doc.redirect_uris;
  if (!Array.isArray(redirects) || redirects.length === 0 || redirects.length > 20) {
    throw Object.assign(new Error('client metadata redirects are invalid'), { code: 'cimd_invalid' });
  }
  const redirectUris = [];
  for (const entry of redirects) {
    if (typeof entry !== 'string' || redirectUris.includes(entry)) {
      throw Object.assign(new Error('client metadata redirects are invalid'), { code: 'cimd_invalid' });
    }
    if (!canonicalHttps(entry)) {
      throw Object.assign(new Error('client metadata redirects are invalid'), { code: 'cimd_invalid' });
    }
    redirectUris.push(entry);
  }
  const responseTypes = doc.response_types || doc.response_types_supported;
  if (!Array.isArray(responseTypes) || !responseTypes.includes('code')) {
    throw Object.assign(new Error('client metadata does not support code'), { code: 'cimd_invalid' });
  }
  if (!documentSupportsNone(doc)) {
    throw Object.assign(new Error('client metadata does not support public client authentication'), { code: 'cimd_invalid' });
  }
  let clientName = 'ChatGPT';
  if (doc.client_name !== undefined) {
    if (typeof doc.client_name !== 'string') {
      throw Object.assign(new Error('client metadata name is invalid'), { code: 'cimd_invalid' });
    }
    clientName = doc.client_name.replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, 80) || 'ChatGPT';
  }
  return {
    clientId,
    clientName,
    redirectUris,
    client: classifyClientId(clientId),
  };
}

/**
 * @param {object} doc
 * @returns {boolean}
 */
export function documentSupportsNone(doc) {
  const plural = doc.token_endpoint_auth_methods_supported;
  if (Array.isArray(plural)) return plural.includes('none');
  return doc.token_endpoint_auth_method === 'none';
}

/**
 * @param {string} url
 * @param {{ timeoutMs: number, maxBytes: number }} options
 */
export function defaultCimdFetch(url, options) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(url); } catch { reject(new Error('cimd-url')); return; }
    if (parsed.protocol !== 'https:' || parsed.username || parsed.search || parsed.hash) {
      reject(new Error('cimd-url'));
      return;
    }
    const req = https.request({
      protocol: 'https:',
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname,
      method: 'GET',
      timeout: options.timeoutMs,
      rejectUnauthorized: true,
      headers: { accept: 'application/json' },
    }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400) {
        res.resume();
        reject(new Error('cimd-redirect'));
        return;
      }
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > options.maxBytes) {
          req.destroy();
          reject(new Error('cimd-size'));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        resolve({
          status: res.statusCode || 0,
          headers: { 'content-type': String(res.headers['content-type'] || '') },
          body: Buffer.concat(chunks),
        });
      });
    });
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('cimd-timeout'));
    });
    req.on('error', () => reject(new Error('cimd-fetch')));
    req.end();
  });
}

/**
 * @param {{ fetchImpl?: Function, clock: { now: () => number }, ttlMs: number, timeoutMs: number, maxBytes: number }} options
 */
export function createCimdResolver(options) {
  const cache = new Map();
  const fetchImpl = options.fetchImpl || defaultCimdFetch;
  return {
    /**
     * @param {string} clientId
     */
    async resolve(clientId) {
      const client = classifyClientId(clientId);
      if (!client.ok) throw Object.assign(new Error('client id is not allowlisted'), { code: 'invalid_client' });
      const now = options.clock.now();
      const hit = cache.get(clientId);
      if (hit && hit.expiresAt > now) return hit.doc;
      let response;
      let timer;
      try {
        response = await Promise.race([
          fetchImpl(clientId, {
            timeoutMs: options.timeoutMs,
            maxBytes: options.maxBytes,
            redirect: 'manual',
          }),
          new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error('cimd-timeout')), options.timeoutMs);
          }),
        ]);
      } catch {
        clearTimeout(timer);
        cache.delete(clientId);
        throw Object.assign(new Error('client metadata is unavailable'), { code: 'cimd_unavailable' });
      }
      clearTimeout(timer);
      if (!response || response.status !== 200 || !response.body || response.body.length > options.maxBytes) {
        cache.delete(clientId);
        throw Object.assign(new Error('client metadata is unavailable'), { code: 'cimd_unavailable' });
      }
      const type = String(response.headers?.['content-type'] || response.contentType || '');
      if (!type.includes('application/json')) {
        cache.delete(clientId);
        throw Object.assign(new Error('client metadata is unavailable'), { code: 'cimd_unavailable' });
      }
      let json;
      try {
        json = JSON.parse(Buffer.from(response.body).toString('utf8'));
      } catch {
        cache.delete(clientId);
        throw Object.assign(new Error('client metadata is corrupt'), { code: 'cimd_unavailable' });
      }
      const doc = validateCimdDocument(json, clientId);
      cache.set(clientId, { doc, expiresAt: now + options.ttlMs });
      while (cache.size > 16) cache.delete(cache.keys().next().value);
      return doc;
    },
  };
}
