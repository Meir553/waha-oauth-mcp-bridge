export const COOKIE = Object.freeze({
  session: '__Host-session',
  pending: '__Host-pending',
  csrf: '__Host-csrf',
  admin: '__Host-admin',
  adminLogin: '__Host-admin-login',
});

export class HttpError extends Error {
  /**
   * @param {number} status
   * @param {string} code
   * @param {string} message
   * @param {Record<string, string>} [headers]
   */
  constructor(status, code, message, headers) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
    this.headers = headers || {};
  }
}

/**
 * @param {number} status
 * @param {string} code
 * @param {string} message
 * @param {Record<string, string>} [headers]
 */
export function httpError(status, code, message, headers) {
  return new HttpError(status, code, message, headers);
}

/**
 * @param {string} value
 * @returns {string}
 */
export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[ch]));
}

/**
 * @param {{ html?: boolean, script?: boolean, noStore?: boolean, hsts?: boolean }} options
 * @returns {Record<string, string>}
 */
export function securityHeaders(options = {}) {
  let policy = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";
  if (options.html && options.script) {
    policy = "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
  } else if (options.html) {
    policy = "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
  }
  const headers = {
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': policy,
  };
  if (options.noStore !== false) {
    headers['Cache-Control'] = 'no-store';
    headers.Pragma = 'no-cache';
  }
  if (options.hsts) {
    headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains';
  }
  return headers;
}

/**
 * @param {import('node:http').ServerResponse} res
 * @param {string} name
 * @param {string} value
 */
export function appendHeader(res, name, value) {
  const current = res.getHeader(name);
  if (current === undefined) res.setHeader(name, value);
  else if (Array.isArray(current)) res.setHeader(name, [...current, value]);
  else res.setHeader(name, [current, value]);
}

/**
 * @param {import('node:http').ServerResponse} res
 * @param {string} name
 * @param {string} value
 * @param {{ maxAge?: number }} [options]
 */
export function setCookie(res, name, value, options = {}) {
  if (!name.startsWith('__Host-')) throw new Error('browser cookies must use the __Host- prefix');
  if (/[\r\n;]/.test(name) || /[\r\n;]/.test(value)) throw new Error('invalid cookie');
  let cookie = `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax`;
  if (options.maxAge !== undefined) cookie += `; Max-Age=${options.maxAge}`;
  appendHeader(res, 'Set-Cookie', cookie);
}

/**
 * @param {import('node:http').ServerResponse} res
 * @param {string} name
 */
export function clearCookie(res, name) {
  setCookie(res, name, '', { maxAge: 0 });
}

/**
 * @param {string | string[] | undefined} header
 * @returns {Map<string, string>}
 */
export function readCookies(header) {
  if (Array.isArray(header)) throw httpError(400, 'invalid_request', 'duplicate cookie header');
  const out = new Map();
  if (!header) return out;
  if (/[\r\n]/.test(header)) throw httpError(400, 'invalid_request', 'invalid cookie');
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (out.has(key)) throw httpError(400, 'invalid_request', 'duplicate cookie');
    out.set(key, value);
  }
  return out;
}

/**
 * @param {string} component
 * @returns {string}
 */
function decodeFormComponent(component) {
  if (/%(?![0-9A-Fa-f]{2})/.test(component)) {
    throw httpError(400, 'invalid_request', 'invalid form');
  }
  try {
    return decodeURIComponent(component.replace(/\+/g, ' '));
  } catch {
    throw httpError(400, 'invalid_request', 'invalid form');
  }
}

/**
 * @param {Buffer} buffer
 * @param {{ maxPairs?: number, maxKey?: number, maxValue?: number }} [limits]
 * @returns {Map<string, string>}
 */
export function parseForm(buffer, limits = {}) {
  const maxPairs = limits.maxPairs ?? 32;
  const maxKey = limits.maxKey ?? 64;
  const maxValue = limits.maxValue ?? 4096;
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch {
    throw httpError(400, 'invalid_request', 'invalid form');
  }
  if (text.length === 0 || text.includes('\0')) throw httpError(400, 'invalid_request', 'invalid form');
  const parts = text.split('&');
  if (parts.length > maxPairs) throw httpError(400, 'invalid_request', 'invalid form');
  const params = new Map();
  for (const part of parts) {
    if (!part) throw httpError(400, 'invalid_request', 'invalid form');
    const eq = part.indexOf('=');
    if (eq <= 0) throw httpError(400, 'invalid_request', 'invalid form');
    const key = decodeFormComponent(part.slice(0, eq));
    const value = decodeFormComponent(part.slice(eq + 1));
    if (key.length === 0 || key.length > maxKey || value.length > maxValue) {
      throw httpError(413, 'invalid_request', 'invalid form');
    }
    if (/[\u0000-\u001F\u007F]/.test(key) || /[\u0000-\u001F\u007F]/.test(value)) {
      throw httpError(400, 'invalid_request', 'invalid form');
    }
    if (params.has(key)) throw httpError(400, 'invalid_request', 'duplicate field');
    params.set(key, value);
  }
  return params;
}

/**
 * @param {string} search
 * @returns {{ params: Map<string, string>, duplicates: Set<string> }}
 */
export function parseQuery(search) {
  const q = search.startsWith('?') ? search.slice(1) : search;
  const params = new Map();
  const duplicates = new Set();
  if (!q) return { params, duplicates };
  if (q.length > 8192) throw httpError(414, 'invalid_request', 'query too large');
  const parts = q.split('&');
  if (parts.length > 32) throw httpError(400, 'invalid_request', 'invalid query');
  for (const part of parts) {
    if (!part) throw httpError(400, 'invalid_request', 'invalid query');
    const eq = part.indexOf('=');
    const rawKey = eq === -1 ? part : part.slice(0, eq);
    const rawVal = eq === -1 ? '' : part.slice(eq + 1);
    const key = decodeFormComponent(rawKey);
    const value = decodeFormComponent(rawVal);
    if (key.length === 0 || key.length > 64 || value.length > 2048) {
      throw httpError(400, 'invalid_request', 'invalid query');
    }
    if (params.has(key)) duplicates.add(key);
    else params.set(key, value);
  }
  return { params, duplicates };
}

/**
 * @param {import('node:http').IncomingMessage} req
 * @param {{ limit: number, timeoutMs: number }} options
 * @returns {Promise<Buffer>}
 */
export function readBody(req, options) {
  const limit = options.limit;
  const timeoutMs = options.timeoutMs;
  const declared = req.headers['content-length'];
  if (Array.isArray(declared)) {
    return Promise.reject(httpError(400, 'invalid_request', 'duplicate content-length'));
  }
  if (declared !== undefined) {
    if (!/^\d+$/.test(declared)) return Promise.reject(httpError(400, 'invalid_request', 'invalid content-length'));
    if (Number(declared) > limit) return Promise.reject(httpError(413, 'payload_too_large', 'request body too large'));
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    const timer = setTimeout(() => {
      fail(httpError(408, 'timeout', 'request timeout'));
      req.destroy();
    }, timeoutMs);
    function finish(buf) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(buf);
    }
    function fail(err) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    }
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        fail(httpError(413, 'payload_too_large', 'request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => finish(Buffer.concat(chunks)));
    req.on('error', () => fail(httpError(400, 'invalid_request', 'request aborted')));
    req.on('aborted', () => fail(httpError(400, 'invalid_request', 'request aborted')));
  });
}

/**
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {unknown} body
 * @param {{ headers?: Record<string, string>, html?: boolean, hsts?: boolean, noStore?: boolean, requestId?: string }} [options]
 */
export function sendJson(res, status, body, options = {}) {
  if (res.headersSent || res.writableEnded) return;
  const payload = Buffer.from(JSON.stringify(body));
  const headers = {
    ...securityHeaders({ html: false, hsts: options.hsts, noStore: options.noStore }),
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': String(payload.length),
    ...(options.requestId ? { 'X-Request-Id': options.requestId } : {}),
    ...(options.headers || {}),
  };
  res.writeHead(status, headers);
  res.end(payload);
}

/**
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {string} html
 * @param {{ hsts?: boolean, requestId?: string, headers?: Record<string, string>, script?: boolean }} [options]
 */
export function sendHtml(res, status, html, options = {}) {
  if (res.headersSent || res.writableEnded) return;
  const payload = Buffer.from(html);
  const headers = {
    ...securityHeaders({ html: true, script: options.script, hsts: options.hsts, noStore: true }),
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': String(payload.length),
    ...(options.requestId ? { 'X-Request-Id': options.requestId } : {}),
    ...(options.headers || {}),
  };
  res.writeHead(status, headers);
  res.end(payload);
}

/**
 * @param {import('node:http').ServerResponse} res
 * @param {string} location
 * @param {{ hsts?: boolean, requestId?: string }} [options]
 */
export function sendRedirect(res, location, options = {}) {
  if (res.headersSent || res.writableEnded) return;
  const headers = {
    ...securityHeaders({ html: false, hsts: options.hsts, noStore: true }),
    Location: location,
    'Content-Length': '0',
    ...(options.requestId ? { 'X-Request-Id': options.requestId } : {}),
  };
  res.writeHead(303, headers);
  res.end();
}

/**
 * @param {string} contentType
 * @param {string[]} allowed
 * @returns {boolean}
 */
export function contentTypeIs(contentType, allowed) {
  if (Array.isArray(contentType) || typeof contentType !== 'string') return false;
  const base = contentType.split(';', 1)[0].trim().toLowerCase();
  return allowed.includes(base);
}

/**
 * Count occurrences of a header in the raw header list.
 * @param {import('node:http').IncomingMessage} req
 * @param {string} name
 * @returns {number}
 */
export function headerCount(req, name) {
  const want = name.toLowerCase();
  let count = 0;
  const raw = req.rawHeaders || [];
  for (let i = 0; i < raw.length; i += 2) {
    if (String(raw[i]).toLowerCase() === want) count += 1;
  }
  return count;
}

/**
 * @param {string} pathname
 * @returns {string}
 */
export function normalizePath(pathname) {
  try {
    const url = new URL(pathname, 'http://bridge.local');
    return url.pathname;
  } catch {
    return '/';
  }
}
