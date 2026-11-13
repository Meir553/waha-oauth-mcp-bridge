import assert from 'node:assert/strict';
import http from 'node:http';
import { test } from 'node:test';
import { createActivityLog } from '../src/activity.mjs';
import { approvedGrant, createHarness, hidden, startFakeWaha } from './helpers.mjs';

test('activity log keeps the tool name and drops message text', () => {
  const log = createActivityLog({ clock: { now: () => 1700000000000 } });
  const event = log.record({
    upstreamId: 'sales',
    grantId: 'ab'.repeat(16),
    method: 'tools/call',
    tool: 'send_message',
    label: 'Book keeping',
    status: 200,
    arguments: { text: 'WHATSAPP-PRIVATE-PHRASE-9f3a' },
    apiKey: 'test-upstream-key-value',
  });
  assert.equal(event.tool, 'send_message');
  assert.equal(event.label, 'Book keeping');
  assert.equal(event.arguments, undefined);
  assert.equal(JSON.stringify(event).includes('WHATSAPP-PRIVATE-PHRASE-9f3a'), false);
  assert.equal(JSON.stringify(event).includes('test-upstream-key-value'), false);
  assert.equal(log.record({ label: 'A\u0000B', status: 200 }).label, 'AB');
  log.close();
});

test('admin panel manages WhatsApps and streams assistant actions without a page reload', async () => {
  const h = await createHarness();
  const extra = await startFakeWaha();
  try {
    const login = await h.client.request({ path: '/admin' });
    assert.equal(login.status, 200);
    assert.equal(login.text.includes('test-upstream-key-value'), false);
    assert.match(login.headers['content-security-policy'], /style-src 'self'/);
    assert.equal(/script-src/.test(login.headers['content-security-policy']), false);
    const bad = await h.client.request({
      method: 'POST',
      path: '/admin/login',
      form: { username: 'admin', password: 'wrong-password-value', csrf: hidden(login.text, 'csrf') },
    });
    assert.equal(bad.status, 401);
    const good = await h.client.request({
      method: 'POST',
      path: '/admin/login',
      form: { username: 'admin', password: h.password, csrf: hidden(bad.text, 'csrf') },
    });
    assert.equal(good.status, 303);
    const page = await h.client.request({ path: '/admin' });
    assert.equal(page.status, 200);
    assert.match(page.text, /id="activity-title">Activity/);
    assert.match(page.text, /src="\/admin\.js"/);
    assert.match(page.headers['content-security-policy'], /script-src 'self'/);
    assert.match(page.headers['content-security-policy'], /connect-src 'self'/);
    const script = await h.client.request({ path: '/admin.js' });
    assert.equal(script.status, 200);
    assert.match(script.text, /EventSource/);
    assert.equal(script.text.includes('innerHTML'), false);
    const csrf = meta(page.text, 'csrf');
    const denied = await requestWithoutCookie(h.bridge.port, '/admin/api/state');
    assert.equal(denied.status, 401);
    const state = await h.client.request({ path: '/admin/api/state' });
    assert.equal(state.status, 200);
    assert.equal(JSON.stringify(state.json()).includes('apiKey'), false);
    assert.equal(state.text.includes('test-upstream-key-value'), false);
    const missing = await h.client.request({
      method: 'POST',
      path: '/admin/api/upstream',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: 'sales', displayName: 'Sales', url: extra.url, apiKey: 'sales-panel-key-value' }),
    });
    assert.equal(missing.status, 403);
    const added = await h.client.request({
      method: 'POST',
      path: '/admin/api/upstream',
      headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
      body: JSON.stringify({ id: 'sales', displayName: 'Sales', url: extra.url, apiKey: 'sales-panel-key-value' }),
    });
    assert.equal(added.status, 200, added.text);
    assert.equal(added.text.includes('sales-panel-key-value'), false);
    assert.ok(added.json().state.upstreams.some((item) => item.id === 'sales' && item.url.endsWith('/mcp/sales')));
    const metadata = await h.client.request({ path: '/.well-known/oauth-protected-resource/mcp/sales' });
    assert.equal(metadata.status, 200);
    assert.equal(metadata.json().resource, 'https://mcp.test.local/mcp/sales');

    const grant = await approvedGrant(h);
    const token = grant.token.access_token;
    const call = await h.client.request({
      method: 'POST',
      path: '/mcp',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'hebrew',
        method: 'tools/call',
        params: { name: 'send_message', arguments: { text: 'שלום WHATSAPP-PRIVATE-PHRASE-9f3a' } },
      }),
    });
    assert.equal(call.status, 200);
    const stream = await readStream(h.bridge.port, cookieHeader(h.client.cookies), 'send_message');
    assert.equal(stream.status, 200);
    assert.match(stream.text, /"tool":"send_message"/);
    assert.equal(stream.text.includes('WHATSAPP-PRIVATE-PHRASE-9f3a'), false);
    assert.equal(stream.text.includes('test-upstream-key-value'), false);
    assert.equal(stream.text.includes('sales-panel-key-value'), false);
    assert.equal(h.capture.lines().join('').includes('WHATSAPP-PRIVATE-PHRASE-9f3a'), false);

    const listed = await h.client.request({ path: '/admin/api/state' });
    const liveGrant = listed.json().grants.find((item) => !item.revoked);
    assert.ok(liveGrant);
    const renamed = await h.client.request({
      method: 'POST',
      path: '/admin/api/rename',
      headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
      body: JSON.stringify({ grantId: liveGrant.grantId, label: 'Bookkeeping' }),
    });
    assert.equal(renamed.status, 200, renamed.text);
    assert.equal(renamed.json().state.grants.find((item) => item.grantId === liveGrant.grantId).client, 'Bookkeeping');
    assert.equal(renamed.text.includes('test-upstream-key-value'), false);
    const blank = await h.client.request({
      method: 'POST',
      path: '/admin/api/rename',
      headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
      body: JSON.stringify({ grantId: liveGrant.grantId, label: '   ' }),
    });
    assert.equal(blank.status, 400);
    const revoked = await h.client.request({
      method: 'POST',
      path: '/admin/api/revoke',
      headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
      body: JSON.stringify({ grantId: liveGrant.grantId }),
    });
    assert.equal(revoked.status, 200, revoked.text);
    assert.equal(revoked.json().state.grants.find((item) => item.grantId === liveGrant.grantId).revoked, true);
    const removed = await h.client.request({
      method: 'POST',
      path: '/admin/api/upstream/remove',
      headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
      body: JSON.stringify({ id: 'sales' }),
    });
    assert.equal(removed.status, 200, removed.text);
    assert.equal(removed.json().state.upstreams.some((item) => item.id === 'sales'), false);
    const gone = await h.client.request({ path: '/.well-known/oauth-protected-resource/mcp/sales' });
    assert.equal(gone.status, 404);
    const changed = await h.client.request({
      method: 'POST',
      path: '/admin/api/password',
      headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
      body: JSON.stringify({
        current: h.password,
        next: 'correct-horse-battery-next',
        confirm: 'correct-horse-battery-next',
      }),
    });
    assert.equal(changed.status, 200, changed.text);
    assert.equal(changed.json().signedOut, true);
    const lockedOut = await h.client.request({ path: '/admin/api/state' });
    assert.equal(lockedOut.status, 401);
  } finally {
    await extra.close();
    await h.close();
  }
});

function meta(html, name) {
  const match = new RegExp(`<meta name="${name}" content="([^"]+)">`).exec(html);
  assert.ok(match, `missing ${name}`);
  return match[1];
}

function cookieHeader(cookies) {
  return [...cookies].map(([key, value]) => `${key}=${value}`).join('; ');
}

function requestWithoutCookie(port, path) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1', port, path, method: 'GET', headers: { host: 'mcp.test.local' },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.end();
  });
}

function readStream(port, cookie, needle) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path: '/admin/events',
      method: 'GET',
      headers: { host: 'mcp.test.local', cookie, accept: 'text/event-stream' },
    }, (res) => {
      let buf = '';
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        req.destroy();
        reject(new Error(`activity stream timed out: ${buf}`));
      }, 5000);
      res.on('data', (chunk) => {
        buf += chunk.toString('utf8');
        if (!buf.includes(needle) || settled) return;
        settled = true;
        clearTimeout(timer);
        req.destroy();
        resolve({ status: res.statusCode, text: buf });
      });
    });
    req.on('error', (err) => {
      if (!settled && err.code !== 'ECONNRESET') reject(err);
    });
    req.end();
  });
}
