import assert from 'node:assert/strict';
import { test } from 'node:test';
import { sha256Hex, verifyPassword } from '../src/crypto.mjs';
import { runAdmin } from '../scripts/admin.mjs';
import { openStore } from '../src/store.mjs';
import { approvedGrant, authorize, createClock, createHarness, FIXTURE, hidden } from './helpers.mjs';

const CLIENT = FIXTURE.CLIENT;
const REDIRECT = FIXTURE.REDIRECT;

test('L-07 T-03 T-12 consent deny, expired code, and offline_access', async () => {
  const clock = createClock();
  const h = await createHarness({ clock });
  try {
    const started = await authorize(h, { state: 'deny-me' });
    const login = await h.client.request({ path: '/login' });
    const posted = await h.client.request({
      method: 'POST',
      path: '/login',
      form: { username: 'admin', password: h.password, csrf: hidden(login.text, 'csrf'), request_id: hidden(login.text, 'request_id') },
    });
    assert.equal(posted.status, 303);
    const consent = await h.client.request({ path: '/oauth/consent' });
    const denied = await h.client.request({
      method: 'POST',
      path: '/oauth/consent',
      form: { csrf: hidden(consent.text, 'csrf'), request_id: hidden(consent.text, 'request_id'), decision: 'deny' },
    });
    assert.equal(denied.status, 303);
    const deniedUrl = new URL(denied.headers.location);
    assert.equal(deniedUrl.searchParams.get('error'), 'access_denied');
    assert.equal(deniedUrl.searchParams.get('code'), null);
    assert.equal(deniedUrl.searchParams.get('state'), 'deny-me');
    assert.equal(deniedUrl.searchParams.get('iss'), 'https://mcp.test.local');

    const again = await authorize(h, { state: 'once' });
    const consentAgain = await h.client.request({ path: '/oauth/consent' });
    const approved = await h.client.request({
      method: 'POST',
      path: '/oauth/consent',
      form: { csrf: hidden(consentAgain.text, 'csrf'), request_id: hidden(consentAgain.text, 'request_id'), decision: 'approve' },
    });
    const code = new URL(approved.headers.location).searchParams.get('code');
    clock.advance(h.config.ttl.codeMs + 1);
    const expired = await h.client.request({
      method: 'POST',
      path: '/oauth/token',
      form: {
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT,
        client_id: CLIENT,
        code_verifier: again.verifier,
        resource: h.config.resource,
      },
    });
    assert.equal(expired.status, 400);
    assert.equal(expired.json().error, 'invalid_grant');
  } finally {
    await h.close();
  }
});

test('T-05 T-07 T-11 T-12 insufficient scope, resource, and concurrent refresh', async () => {
  const h = await createHarness();
  try {
    const grant = await approvedGrant(h, { scope: 'mcp:access offline_access' });
    assert.equal(grant.token.scope, 'mcp:access offline_access');
    const wrongResource = await h.client.request({
      method: 'POST',
      path: '/oauth/token',
      form: {
        grant_type: 'refresh_token',
        refresh_token: grant.token.refresh_token,
        client_id: CLIENT,
        resource: 'https://mcp.test.local',
      },
    });
    assert.equal(wrongResource.status, 400);
    assert.equal(wrongResource.json().error, 'invalid_target');
    const token = 'a'.repeat(43);
    await h.store.transaction(async (draft) => {
      const existing = Object.values(draft.grants)[0];
      draft.accessTokens[sha256Hex(token)] = {
        grantId: existing.grantId,
        familyId: '',
        clientId: existing.clientId,
        userId: 'operator',
        audience: h.config.resource,
        issuer: h.config.issuer,
        scopes: ['mcp:access'].filter(() => false),
        expiresAt: h.clock.now() + 60_000,
        createdAt: h.clock.now(),
      };
      draft.accessTokens[sha256Hex(token)].scopes = [];
    });
    const narrow = await h.client.request({
      method: 'POST',
      path: '/mcp',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} }),
    });
    assert.equal(narrow.status, 403);
    assert.equal(narrow.json().error, 'insufficient_scope');
    assert.equal(h.waha.calls.length, 0);

    const form = {
      grant_type: 'refresh_token',
      refresh_token: grant.token.refresh_token,
      client_id: CLIENT,
      resource: h.config.resource,
    };
    const [first, second] = await Promise.all([
      h.client.request({ method: 'POST', path: '/oauth/token', form }),
      h.client.request({ method: 'POST', path: '/oauth/token', form }),
    ]);
    const statuses = [first.status, second.status].sort();
    assert.deepEqual(statuses, [200, 400]);
    const winner = first.status === 200 ? first : second;
    const reused = await h.client.request({
      method: 'GET',
      path: '/mcp',
      headers: { authorization: `Bearer ${winner.json().access_token}`, accept: 'application/json' },
    });
    assert.equal(reused.status, 401);
  } finally {
    await h.close();
  }
});

test('P-10 P-16 P-18 delete 405, stream limit, and bad upstream stay healthy', async () => {
  const h = await createHarness({ limits: { maxStreams: 1, headerTimeoutMs: 400 } });
  try {
    const grant = await approvedGrant(h);
    const headers = { authorization: `Bearer ${grant.token.access_token}`, 'content-type': 'application/json', accept: 'application/json' };
    const init = await h.client.request({
      method: 'POST',
      path: '/mcp',
      headers,
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    });
    assert.equal(init.headers['mcp-session-id'], 'sess-fixed-1');
    h.waha.control.deleteStatus = 405;
    const kept = await h.client.request({
      method: 'DELETE',
      path: '/mcp',
      headers: { authorization: headers.authorization, accept: 'application/json', 'mcp-session-id': 'sess-fixed-1' },
    });
    assert.equal(kept.status, 405);
    const still = await h.client.request({
      method: 'POST',
      path: '/mcp',
      headers: { ...headers, 'mcp-session-id': 'sess-fixed-1' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: {} }),
    });
    assert.equal(still.status, 200);

    h.waha.control.handler = (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' });
      res.end('not-gzip');
    };
    const encoded = await h.client.request({
      method: 'POST',
      path: '/mcp',
      headers,
      body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: {} }),
    });
    assert.equal(encoded.status, 502);
    h.waha.control.handler = (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('not-json');
    };
    const malformed = await h.client.request({
      method: 'POST',
      path: '/mcp',
      headers,
      body: JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'tools/list', params: {} }),
    });
    assert.equal(malformed.status, 502);
    h.waha.control.handler = (req) => {
      req.socket.destroy();
    };
    const dropped = await h.client.request({
      method: 'POST',
      path: '/mcp',
      headers,
      body: JSON.stringify({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: {} }),
    });
    assert.equal(dropped.status, 502);

    h.waha.control.handler = (req, res) => new Promise((resolve) => {
      req.on('close', () => { res.destroy(); resolve(); });
    });
    const pending = h.client.request({
      method: 'GET',
      path: '/mcp',
      headers: { authorization: headers.authorization, accept: 'text/event-stream' },
    });
    await new Promise((resolve) => setTimeout(resolve, 80));
    const extra = await h.client.request({
      method: 'GET',
      path: '/mcp',
      headers: { authorization: headers.authorization, accept: 'text/event-stream' },
    });
    assert.equal(extra.status, 429);
    assert.equal((await pending).status, 504);
    const live = await h.client.request({ path: '/health/live' });
    assert.equal(live.status, 200);
  } finally {
    await h.close();
  }
});

test('D-09 reset-password revokes grants and replaces the verifier', async () => {
  const clock = createClock();
  const h = await createHarness({ clock });
  const dir = h.dir;
  try {
    await approvedGrant(h);
    await h.bridge.close();
    await runAdmin({
      dataDir: dir,
      command: 'reset-password',
      password: h.password,
      newPassword: 'replacement-passphrase',
      clock,
    });
    const store = await openStore({ dataDir: dir, clock, logger: { warn() {}, info() {} } });
    try {
      const state = store.read();
      assert.ok(Object.values(state.grants).every((grant) => grant.revokedAt));
      assert.equal(Object.keys(state.accessTokens).length, 0);
      assert.equal(await verifyPassword(h.password, state.operator), false);
      assert.equal(await verifyPassword('replacement-passphrase', state.operator), true);
    } finally {
      await store.close();
    }
  } finally {
    await h.waha.close();
    await h.close().catch(() => {});
  }
});
