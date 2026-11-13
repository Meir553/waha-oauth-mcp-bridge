import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import http from 'node:http';
import { test } from 'node:test';
import { assertNodeVersion } from '../src/crypto.mjs';
import { loadConfig } from '../src/config.mjs';
import { classifyClientId, documentSupportsNone, isRedirectStructurallyAllowed } from '../src/oauth/cimd.mjs';
import { recordLoginFailure } from '../src/rate-limit.mjs';
import { emptyState } from '../src/store.mjs';
import { approvedGrant, authorize, cimdDocument, createClient, createClock, createHarness, FIXTURE, hidden } from './helpers.mjs';

const CLIENT = FIXTURE.CLIENT;
const REDIRECT = FIXTURE.REDIRECT;

test('B-01 node preflight accepts 18 and newer', () => {
  for (const version of ['v18.0.0', 'v20.18.0', 'v22.16.0', 'v26.0.0']) {
    assert.doesNotThrow(() => assertNodeVersion(version));
  }
  assert.throws(() => assertNodeVersion('v16.20.2'), /Node\.js 18/);
  assert.throws(() => assertNodeVersion('v17.9.1'), /Node\.js 18/);
  if (Number(process.versions.node.split('.')[0]) >= 18) {
    assert.doesNotThrow(() => assertNodeVersion(process.version));
  }
});

test('M-01 M-02 M-03 M-06 M-07 discovery metadata', async () => {
  const h = await createHarness();
  try {
    const root = await h.client.request({ path: '/.well-known/oauth-protected-resource', headers: { 'x-forwarded-host': 'evil.example' } });
    assert.equal(root.status, 200);
    assert.equal(root.json().resource, 'https://mcp.test.local/mcp');
    assert.deepEqual(root.json().authorization_servers, ['https://mcp.test.local']);
    assert.deepEqual(root.json().scopes_supported, ['mcp:access']);
    assert.equal(root.text.includes('test-upstream-key-value'), false);
    assert.equal(root.headers['access-control-allow-origin'], undefined);
    const pathMeta = await h.client.request({ path: '/.well-known/oauth-protected-resource/mcp' });
    assert.deepEqual(pathMeta.json(), root.json());
    const as = await h.client.request({ path: '/.well-known/oauth-authorization-server' });
    const body = as.json();
    assert.equal(body.issuer, 'https://mcp.test.local');
    assert.deepEqual(body.code_challenge_methods_supported, ['S256']);
    assert.deepEqual(body.grant_types_supported, ['authorization_code', 'refresh_token']);
    assert.deepEqual(body.token_endpoint_auth_methods_supported, ['none']);
    assert.equal(body.client_id_metadata_document_supported, true);
    assert.equal(body.authorization_response_iss_parameter_supported, true);
    assert.ok(body.scopes_supported.includes('offline_access'));
    assert.equal(body.registration_endpoint, undefined);
    assert.equal(body['cache-control'] || as.headers['cache-control'], 'no-store');
    const spoofed = await h.client.request({ path: '/.well-known/oauth-protected-resource', headers: { host: 'evil.example' } });
    assert.equal(spoofed.status, 400);
  } finally {
    await h.close();
  }
});

test('M-04 M-05 unauthenticated MCP and unknown paths', async () => {
  const h = await createHarness();
  try {
    for (const method of ['POST', 'GET', 'DELETE']) {
      const response = await h.client.request({ method, path: '/mcp', body: method === 'POST' ? '{}' : undefined, headers: method === 'POST' ? { 'content-type': 'application/json' } : {} });
      assert.equal(response.status, 401);
      assert.match(response.headers['www-authenticate'], /resource_metadata="https:\/\/mcp\.test\.local\/\.well-known\/oauth-protected-resource"/);
      assert.match(response.headers['www-authenticate'], /scope="mcp:access"/);
    }
    assert.equal(h.waha.calls.length, 0);
    for (const path of ['/.env', '/data/state.json', '/data/upstream-secret.json', '/src/main.mjs', '/nope']) {
      const response = await h.client.request({ path });
      assert.equal(response.status, 404);
    }
    const wrong = await h.client.request({ method: 'PUT', path: '/mcp' });
    assert.equal(wrong.status, 405);
    assert.match(wrong.headers.allow, /POST/);
  } finally {
    await h.close();
  }
});

test('C-01 through C-07 client validation', async () => {
  assert.equal(classifyClientId('https://chatgpt.com.evil/oauth/client.json').ok, false);
  assert.equal(classifyClientId('https://evil.example/oauth/client.json').ok, false);
  assert.equal(isRedirectStructurallyAllowed('https://evil.example/capture', classifyClientId(CLIENT)), false);
  assert.equal(isRedirectStructurallyAllowed('https://chatgpt.com.evil/connector_platform_oauth_redirect', classifyClientId(CLIENT)), false);
  assert.equal(documentSupportsNone(cimdDocument()), true);
  assert.equal(documentSupportsNone({ token_endpoint_auth_method: 'none' }), true);
  assert.equal(documentSupportsNone({ token_endpoint_auth_methods_supported: ['private_key_jwt'], token_endpoint_auth_method: 'private_key_jwt' }), false);

  const seen = [];
  const h = await createHarness({
    fetchImpl: async (url, options) => {
      seen.push(options);
      return { status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify(cimdDocument())) };
    },
  });
  try {
    const ok = await authorize(h);
    assert.equal(ok.response.status, 303);
    assert.equal(seen[0].redirect, 'manual');
    const hostile = await authorize(h, { redirect_uri: 'https://evil.example/capture' });
    assert.equal(hostile.response.status, 400);
    assert.equal(hostile.response.headers.location, undefined);
    const plain = await authorize(h, { code_challenge_method: 'plain' });
    assert.equal(plain.response.status, 303);
    assert.match(plain.response.headers.location, /error=invalid_request/);
    assert.match(plain.response.headers.location, /iss=https%3A%2F%2Fmcp\.test\.local/);
    const dup = await h.client.request({ path: `/oauth/authorize?response_type=code&response_type=code&client_id=${encodeURIComponent(CLIENT)}&redirect_uri=${encodeURIComponent(REDIRECT)}` });
    assert.equal(dup.status, 303);
    assert.match(dup.headers.location, /^https:\/\/chatgpt\.com\/connector_platform_oauth_redirect\?/);
    assert.match(dup.headers.location, /error=invalid_request/);
    assert.match(dup.headers.location, /iss=https%3A%2F%2Fmcp\.test\.local/);
  } finally {
    await h.close();
  }

  const mismatch = await createHarness({ cimd: { client_id: 'https://chatgpt.com/oauth/other/client.json' } });
  try {
    const response = await authorize(mismatch);
    assert.equal(response.response.status, 400);
    assert.equal(response.response.headers.location, undefined);
  } finally {
    await mismatch.close();
  }

  const noNone = await createHarness({
    cimd: { token_endpoint_auth_methods_supported: ['private_key_jwt'], token_endpoint_auth_method: 'private_key_jwt' },
  });
  try {
    const response = await authorize(noNone);
    assert.equal(response.response.status, 400);
  } finally {
    await noNone.close();
  }
});

test('C-07 C-08 C-09 C-10 metadata failure, escaping, iss, and flow isolation', async () => {
  const gate = { fail: false, calls: 0 };
  const h = await createHarness({
    cimdTtlMs: 1000,
    fetchImpl: async () => {
      gate.calls += 1;
      if (gate.fail) throw new Error('unavailable');
      return { status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify(cimdDocument({ client_name: '<script>alert(1)</script>' }))) };
    },
  });
  try {
    const first = await authorize(h, { state: 'keep me' });
    assert.equal(first.response.status, 303);
    gate.fail = true;
    h.clock.advance(1001);
    const stale = await authorize(h, { state: 'other' });
    assert.equal(stale.response.status, 400);
    assert.equal(stale.response.headers.location, undefined);
    gate.fail = false;
    const login = await h.client.request({ path: '/login' });
    await h.client.request({
      method: 'POST',
      path: '/login',
      form: { username: 'admin', password: h.password, csrf: hidden(login.text, 'csrf'), request_id: hidden(login.text, 'request_id') },
    });
    const consent = await h.client.request({ path: '/oauth/consent' });
    assert.equal(consent.text.includes('<script'), false);
    assert.match(consent.text, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    const approved = await h.client.request({
      method: 'POST',
      path: '/oauth/consent',
      form: { csrf: hidden(consent.text, 'csrf'), request_id: hidden(consent.text, 'request_id'), decision: 'approve' },
    });
    assert.match(consent.headers['content-security-policy'], /form-action 'self' https:\/\/chatgpt\.com/);
    const location = new URL(approved.headers.location);
    const again = await h.client.request({
      method: 'POST',
      path: '/oauth/consent',
      form: { csrf: hidden(consent.text, 'csrf'), request_id: hidden(consent.text, 'request_id'), decision: 'approve' },
    });
    assert.equal(again.status, 303);
    assert.equal(again.headers.location, approved.headers.location);
    assert.equal(location.searchParams.get('iss'), 'https://mcp.test.local');
    assert.equal(location.searchParams.get('state'), 'keep me');
    assert.equal(location.hash, '');
    assert.equal(h.capture.lines().join('').includes('keep me'), false);
  } finally {
    await h.close();
  }

  const a = await createHarness();
  const b = createClient({ port: a.bridge.port, hostHeader: 'mcp.test.local' });
  try {
    const flowA = await authorize(a, { state: 'A' });
    const flowB = await authorize(a, { client: b, state: 'B' });
    assert.equal(flowA.response.status, 303);
    assert.equal(flowB.response.status, 303);
    const login = await a.client.request({ path: '/login' });
    await a.client.request({ method: 'POST', path: '/login', form: { username: 'admin', password: a.password, csrf: hidden(login.text, 'csrf'), request_id: hidden(login.text, 'request_id') } });
    const consentA = await a.client.request({ path: '/oauth/consent' });
    const pageB = await b.request({ path: '/login' });
    const crossed = await a.client.request({ method: 'POST', path: '/oauth/consent', form: { csrf: hidden(consentA.text, 'csrf'), request_id: hidden(pageB.text, 'request_id'), decision: 'approve' } });
    assert.notEqual(crossed.status, 303);
    assert.equal(String(crossed.headers.location || '').includes('code='), false);
  } finally {
    await a.close();
  }
});

test('L-03 through L-10 login consent session and headers', async () => {
  const h = await createHarness();
  try {
    await authorize(h);
    const page = await h.client.request({ path: '/login?username=<script>' });
    assert.equal(page.text.includes('<script'), false);
    assert.match(page.headers['cache-control'], /no-store/);
    assert.equal(page.headers['referrer-policy'], 'no-referrer');
    assert.match(page.headers['content-security-policy'], /default-src 'none'/);
    const bad = await h.client.request({ method: 'POST', path: '/login', form: { username: 'admin', password: 'wrong-password-value', csrf: hidden(page.text, 'csrf'), request_id: hidden(page.text, 'request_id') } });
    assert.equal(bad.status, 401);
    assert.match(bad.text, /Sign-in failed/);
    assert.equal(bad.headers['set-cookie']?.includes?.('__Host-session=') || JSON.stringify(bad.headers['set-cookie'] || '').includes('__Host-session='), false);
    h.client.cookies.set('__Host-session', 'attacker-fixed-value-abcdefghijklmnopqrstuvwxyz');
    const again = await h.client.request({ path: '/login' });
    const ok = await h.client.request({ method: 'POST', path: '/login', form: { username: 'no-such-user', password: h.password, csrf: hidden(again.text, 'csrf'), request_id: hidden(again.text, 'request_id') } });
    assert.equal(ok.status, 401);
    const goodPage = await h.client.request({ path: '/login' });
    const good = await h.client.request({ method: 'POST', path: '/login', form: { username: 'admin', password: h.password, csrf: hidden(goodPage.text, 'csrf'), request_id: hidden(goodPage.text, 'request_id') } });
    assert.equal(good.status, 303);
    const session = JSON.stringify(good.headers['set-cookie']);
    assert.match(session, /__Host-session=/);
    assert.match(session, /HttpOnly/);
    assert.match(session, /Secure/);
    assert.match(session, /SameSite=Lax/);
    assert.match(session, /Path=\//);
    assert.equal(session.includes('Domain='), false);
    assert.equal(session.includes('attacker-fixed-value'), false);
    const consent = await h.client.request({ path: '/oauth/consent' });
    const denied = await createHarness();
    await denied.close();
    const logout = await h.client.request({ method: 'POST', path: '/logout', form: { csrf: hidden(consent.text, 'csrf') } });
    assert.equal(logout.status, 200);
    const after = await h.client.request({ path: '/oauth/consent' });
    assert.notEqual(after.status, 200);
    const missing = await h.client.request({ method: 'POST', path: '/login', headers: { cookie: '' }, form: { username: 'admin', password: h.password, csrf: 'nope', request_id: 'nope' } });
    assert.ok(missing.status === 401 || missing.status === 403 || missing.status === 400);
    const huge = Buffer.from(`username=${'a'.repeat(9000)}`);
    const oversized = await h.client.request({ method: 'POST', path: '/login', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: huge });
    assert.ok(oversized.status === 400 || oversized.status === 413);
    assert.equal(oversized.text.includes('Error:'), false);
  } finally {
    await h.close();
  }
});

test('L-06 L-08 expiry and login lockout', async () => {
  const clock = createClock();
  const h = await createHarness({ clock, limits: { loginMaxFailures: 5, loginWindowMs: 60_000, loginLockMs: 60_000 } });
  try {
    await authorize(h);
    const page = await h.client.request({ path: '/login' });
    const fields = { csrf: hidden(page.text, 'csrf'), request_id: hidden(page.text, 'request_id') };
    const statuses = [];
    for (let i = 0; i < 5; i += 1) {
      const response = await h.client.request({ method: 'POST', path: '/login', form: { username: `user-${i}`, password: `wrong-password-${i}-xxxx`, ...fields } });
      statuses.push(response.status);
      if (response.status !== 429) {
        fields.csrf = hidden(response.text, 'csrf');
        fields.request_id = hidden(response.text, 'request_id');
      }
    }
    assert.equal(statuses.at(-1), 429);
    assert.equal(statuses.slice(0, 4).every((status) => status === 401), true);
    const locked = await h.client.request({ method: 'POST', path: '/login', form: { username: 'admin', password: h.password, ...fields } });
    assert.equal(locked.status, 429);
    const draft = emptyState({ username: 'admin', passwordSalt: 'x', passwordVerifier: 'y', scryptParams: {} }, 0);
    for (let i = 0; i < 5; i += 1) {
      recordLoginFailure(draft, { ipHash: `ip-${i}`, now: 1_000, maxFailures: 5, windowMs: 60_000, lockMs: 60_000 });
    }
    assert.ok(draft.loginThrottle.global.lockedUntil > 1_000);

    const clock2 = createClock();
    const h2 = await createHarness({ clock: clock2, ttl: { sessionIdleMs: 1000, sessionAbsoluteMs: 5000 } });
    try {
      const grant = await approvedGrant(h2);
      clock2.advance(1001);
      const still = await h2.client.request({ method: 'POST', path: '/mcp', headers: { authorization: `Bearer ${grant.token.access_token}`, 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }) });
      assert.equal(still.status, 200);
      const page2 = await h2.client.request({ path: '/oauth/consent' });
      assert.notEqual(page2.status, 200);
      clock2.advance(h2.config.ttl.accessMs);
      const expired = await h2.client.request({ method: 'POST', path: '/mcp', headers: { authorization: `Bearer ${grant.token.access_token}`, 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'initialize', params: {} }) });
      assert.equal(expired.status, 401);
    } finally {
      await h2.close();
    }
  } finally {
    await h.close();
  }
});

test('T-01 through T-14 token lifecycle', async () => {
  const clock = createClock();
  const h = await createHarness({ clock });
  try {
    const grant = await approvedGrant(h, { scope: 'mcp:access' });
    assert.equal(grant.token.token_type, 'Bearer');
    assert.ok(grant.token.expires_in > 0);
    assert.ok(grant.token.refresh_token.length >= 64);
    assert.equal(grant.token.scope, 'mcp:access');
    assert.match(grant.tokenResponse.headers['cache-control'], /no-store/);
    const state = await readFile(`${h.dir}/state.json`, 'utf8');
    assert.equal(state.includes(grant.token.access_token), false);
    assert.equal(state.includes(grant.token.refresh_token), false);
    assert.equal(h.capture.lines().join('').includes(grant.token.access_token), false);
    const replay = await h.client.request({ method: 'POST', path: '/oauth/token', form: { grant_type: 'authorization_code', code: grant.location.searchParams.get('code'), redirect_uri: REDIRECT, client_id: CLIENT, code_verifier: grant.verifier, resource: h.config.resource } });
    assert.equal(replay.status, 400);
    assert.equal(replay.json().error, 'invalid_grant');
    const bad = await h.client.request({ method: 'POST', path: '/oauth/token', form: { grant_type: 'authorization_code', code: 'not-a-real-code', redirect_uri: REDIRECT, client_id: CLIENT, code_verifier: 'a'.repeat(43), resource: h.config.resource } });
    assert.equal(bad.json().error, 'invalid_grant');
    const mcp = await h.client.request({ method: 'POST', path: '/mcp', headers: { authorization: `Bearer ${grant.token.access_token}`, 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }) });
    assert.equal(mcp.status, 200);
    const missing = await h.client.request({ method: 'GET', path: '/mcp' });
    assert.equal(missing.status, 401);
    const refreshed = await h.client.request({ method: 'POST', path: '/oauth/token', form: { grant_type: 'refresh_token', refresh_token: grant.token.refresh_token, client_id: CLIENT, resource: h.config.resource } });
    assert.equal(refreshed.status, 200);
    const reuse = await h.client.request({ method: 'POST', path: '/oauth/token', form: { grant_type: 'refresh_token', refresh_token: grant.token.refresh_token, client_id: CLIENT, resource: h.config.resource } });
    assert.equal(reuse.status, 400);
    const after = await h.client.request({ method: 'GET', path: '/mcp', headers: { authorization: `Bearer ${refreshed.json().access_token}` } });
    assert.equal(after.status, 401);
    const wrongResource = await h.client.request({ method: 'POST', path: '/oauth/token', form: { grant_type: 'password' } });
    assert.equal(wrongResource.json().error, 'unsupported_grant_type');
    const query = await h.client.request({ path: `/mcp?access_token=${grant.token.access_token}` });
    assert.equal(query.status, 401);
    clock.advance(h.config.ttl.accessMs + 1);
    const expiredToken = await h.client.request({ method: 'GET', path: '/mcp', headers: { authorization: `Bearer ${grant.token.access_token}` } });
    assert.equal(expiredToken.status, 401);
  } finally {
    await h.close();
  }
});
