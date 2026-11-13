import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { loadConfig } from '../src/config.mjs';
import { initializeStore, openStore } from '../src/store.mjs';
import { runAdmin } from '../scripts/admin.mjs';
import { approvedGrant, createClient, createClock, createHarness, FIXTURE, startFakeWaha, testOperator } from './helpers.mjs';

const SALES_RESOURCE = 'https://mcp.test.local/mcp/sales';

test('each ChatGPT grant can reach only the WAHA it was approved for', async () => {
  const sales = await startFakeWaha();
  sales.control.tools = [{ name: 'sales_only', description: 'sales', inputSchema: { type: 'object' } }];
  let harness;
  try {
    harness = await createHarness({
      extraUpstreams: [{
        id: 'sales',
        url: sales.url,
        displayName: 'Sales WhatsApp',
        apiKey: 'sales-upstream-key-value',
      }],
    });
    const main = await approvedGrant(harness);
    const other = createClient({ port: harness.bridge.port, hostHeader: 'mcp.test.local' });
    const salesGrant = await approvedGrant(harness, { client: other, resource: SALES_RESOURCE });
    assert.equal(main.tokenResponse.status, 200);
    assert.equal(salesGrant.tokenResponse.status, 200);
    assert.match(main.consent, /connected WhatsApp session/);
    assert.equal(main.consent.includes('/mcp/sales'), false);
    assert.match(salesGrant.consent, /Sales WhatsApp/);
    assert.equal(salesGrant.consent.includes('connected WhatsApp session'), false);
    const grants = Object.values(harness.store.read().grants);
    assert.ok(grants.some((grant) => grant.upstreamId === 'default' && grant.resource === harness.config.resource));
    assert.ok(grants.some((grant) => grant.upstreamId === 'sales' && grant.resource === SALES_RESOURCE));

    const metadata = await harness.client.request({ path: '/.well-known/oauth-protected-resource/mcp/sales' });
    assert.equal(metadata.json().resource, SALES_RESOURCE);
    const anonymous = await harness.client.request({
      method: 'POST',
      path: '/mcp/sales',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: '{}',
    });
    assert.equal(anonymous.status, 401);
    assert.match(anonymous.headers['www-authenticate'], /resource_metadata="https:\/\/mcp\.test\.local\/\.well-known\/oauth-protected-resource\/mcp\/sales"/);
    assert.equal(sales.calls.length, 0);

    const salesInit = await call(other, salesGrant.token.access_token, '/mcp/sales', 'initialize');
    assert.equal(salesInit.status, 200);
    const crossed = await call(harness.client, main.token.access_token, '/mcp', 'tools/list', { 'mcp-session-id': 'sess-fixed-1' });
    assert.equal(crossed.status, 404);
    assert.equal(harness.waha.calls.length, 0);

    const mainList = await call(harness.client, main.token.access_token, '/mcp', 'tools/list');
    assert.equal(mainList.status, 200);
    assert.ok(mainList.json().result.tools.some((tool) => tool.name === 'search_tools'));
    assert.equal(mainList.json().result.tools.some((tool) => tool.name === 'get_chats'), false);
    assert.equal(harness.waha.calls.at(-1).headers['x-api-key'], 'test-upstream-key-value');

    const beforeSales = sales.calls.length;
    const mainOnSales = await call(harness.client, main.token.access_token, '/mcp/sales', 'tools/list');
    assert.equal(mainOnSales.status, 401);
    assert.equal(sales.calls.length, beforeSales);

    const beforeMain = harness.waha.calls.length;
    const salesOnMain = await call(other, salesGrant.token.access_token, '/mcp', 'tools/list');
    assert.equal(salesOnMain.status, 401);
    assert.equal(harness.waha.calls.length, beforeMain);

    const salesList = await call(other, salesGrant.token.access_token, '/mcp/sales', 'tools/list', { 'mcp-session-id': 'sess-fixed-1' });
    assert.equal(salesList.status, 200);
    assert.ok(salesList.json().result.tools.some((tool) => tool.name === 'search_tools'));
    assert.equal(salesList.json().result.tools.some((tool) => tool.name === 'sales_only'), false);
    assert.equal(sales.calls.at(-1).headers['x-api-key'], 'sales-upstream-key-value');
    assert.equal(sales.calls.at(-1).headers.authorization, undefined);

    const unknown = await call(other, salesGrant.token.access_token, '/mcp/not-a-waha', 'tools/list');
    assert.equal(unknown.status, 404);
    const wrongRefresh = await other.request({
      method: 'POST',
      path: '/oauth/token',
      form: {
        grant_type: 'refresh_token',
        refresh_token: salesGrant.token.refresh_token,
        client_id: FIXTURE.CLIENT,
        resource: harness.config.resource,
      },
    });
    assert.equal(wrongRefresh.status, 400);
    assert.equal(wrongRefresh.json().error, 'invalid_grant');
    const refreshed = await other.request({
      method: 'POST',
      path: '/oauth/token',
      form: {
        grant_type: 'refresh_token',
        refresh_token: salesGrant.token.refresh_token,
        client_id: FIXTURE.CLIENT,
        resource: SALES_RESOURCE,
      },
    });
    assert.equal(refreshed.status, 200);
    assert.equal(harness.capture.lines().join('').includes('sales-upstream-key-value'), false);
    assert.equal(harness.capture.lines().join('').includes('test-upstream-key-value'), false);
  } finally {
    if (harness) await harness.close();
    await sales.close();
  }
});

test('admin assigns an upstream without printing its key and removal revokes only that WAHA', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'waha-upstreams-'));
  const clock = createClock();
  const lines = [];
  const stdout = { write(chunk) { lines.push(String(chunk)); } };
  const upstream = {
    id: 'sales',
    url: 'http://127.0.0.1:3010/mcp',
    displayName: 'Sales WhatsApp',
    apiKey: 'sales-admin-key-value',
  };
  try {
    await initializeStore({ dataDir: dir, clock, operator: { username: 'admin', ...(await testOperator()) } });
    await assert.rejects(() => runAdmin({
      dataDir: dir, command: 'add-upstream', password: 'wrong-password-value', stdout, upstream,
    }), /authentication failed/);
    await assert.rejects(() => readFile(path.join(dir, 'upstreams.json'), 'utf8'), /ENOENT/);
    await runAdmin({ dataDir: dir, command: 'add-upstream', password: 'correct-horse-battery-staple', stdout, upstream });
    const saved = JSON.parse(await readFile(path.join(dir, 'upstreams.json'), 'utf8'));
    assert.equal(saved.sales.apiKey, 'sales-admin-key-value');
    assert.equal(lines.join('').includes('sales-admin-key-value'), false);
    const store = await openStore({ dataDir: dir, clock, logger: { warn() {}, info() {} } });
    await store.transaction(async (draft) => {
      draft.grants.keep = grant('keep', 'default', 'https://mcp.test.local/mcp', clock.now());
      draft.grants.sales = grant('sales', 'sales', SALES_RESOURCE, clock.now());
      draft.accessTokens.salesToken = {
        grantId: 'sales', familyId: 'fam', clientId: FIXTURE.CLIENT, userId: 'operator',
        audience: SALES_RESOURCE, issuer: 'https://mcp.test.local', scopes: ['mcp:access'],
        expiresAt: clock.now() + 1000, createdAt: clock.now(),
      };
    });
    await store.close();
    lines.length = 0;
    await runAdmin({ dataDir: dir, command: 'status', stdout });
    const status = lines.join('');
    assert.match(status, /"id":"sales"/);
    assert.match(status, /"upstreamId":"sales"/);
    assert.equal(status.includes('sales-admin-key-value'), false);
    await runAdmin({
      dataDir: dir, command: 'remove-upstream', password: 'correct-horse-battery-staple', upstreamId: 'sales', stdout, clock,
    });
    const reopened = await openStore({ dataDir: dir, clock, logger: { warn() {}, info() {} } });
    assert.ok(reopened.read().grants.sales.revokedAt);
    assert.equal(reopened.read().grants.keep.revokedAt, null);
    assert.equal(reopened.read().accessTokens.salesToken, undefined);
    await reopened.close();
    const after = JSON.parse(await readFile(path.join(dir, 'upstreams.json'), 'utf8'));
    assert.equal(after.sales, undefined);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('upstream configuration fails closed on a symlink, a bad id, or a repeated URL', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'waha-upstream-file-'));
  const env = {
    NODE_ENV: 'test',
    ENABLE_LOCAL_TEST_HTTP: 'true',
    PUBLIC_ORIGIN: 'https://mcp.test.local',
    LISTEN_HOST: '127.0.0.1',
    LISTEN_PORT: '0',
    UPSTREAM_MCP_URL: 'http://127.0.0.1:9/mcp',
    UPSTREAM_API_KEY: 'test-upstream-key-value',
    DATA_DIR: dir,
  };
  try {
    await writeFile(path.join(dir, 'upstreams.json'), '{');
    await assert.rejects(() => loadConfig(env), /upstreams file is invalid/);
    await rm(path.join(dir, 'upstreams.json'));
    await writeFile(path.join(dir, 'real.json'), '{}');
    await symlink(path.join(dir, 'real.json'), path.join(dir, 'upstreams.json'), 'file');
    await assert.rejects(() => loadConfig(env), /symlink/);
    await rm(path.join(dir, 'upstreams.json'));
    await assert.rejects(() => loadConfig(env, {
      extraUpstreams: [{ id: 'sales', url: env.UPSTREAM_MCP_URL, displayName: 'Sales', apiKey: 'sales-upstream-key-value' }],
    }), /already configured/);
    await assert.rejects(() => loadConfig(env, {
      extraUpstreams: [{ id: '../sales', url: 'http://127.0.0.1:10/mcp', displayName: 'Sales', apiKey: 'sales-upstream-key-value' }],
    }), /upstream id is invalid/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

function call(client, token, requestPath, method, extraHeaders = {}) {
  return client.request({
    method: 'POST',
    path: requestPath,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': '2025-11-25',
      ...extraHeaders,
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: {} }),
  });
}

function grant(grantId, upstreamId, resource, now) {
  return {
    grantId,
    upstreamId,
    clientId: FIXTURE.CLIENT,
    userId: 'operator',
    resource,
    scopes: ['mcp:access'],
    createdAt: now,
    revokedAt: null,
    expiresAt: null,
    clientDisplay: 'ChatGPT',
  };
}
