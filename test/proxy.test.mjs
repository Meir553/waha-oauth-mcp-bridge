import assert from 'node:assert/strict';
import http from 'node:http';
import { test } from 'node:test';
import { enrichTool } from '../src/mcp/tool-metadata.mjs';
import { approvedGrant, createClient, createHarness } from './helpers.mjs';

test('P-01 through P-05 and P-20 proxy and tool metadata', async () => {
  const h = await createHarness();
  try {
    const grant = await approvedGrant(h);
    const token = grant.token.access_token;
    const init = await h.client.request({
      method: 'POST',
      path: '/mcp',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-11-25',
        'x-api-key': 'spoofed-key',
        cookie: 'a=b',
        'x-forwarded-for': '1.2.3.4',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    });
    assert.equal(init.status, 200);
    assert.equal(init.headers['mcp-session-id'], 'sess-fixed-1');
    assert.equal(init.headers['mcp-protocol-version'], '2025-11-25');
    const seen = h.waha.calls.at(-1);
    assert.equal(seen.url, '/mcp');
    assert.equal(seen.method, 'POST');
    assert.equal(seen.headers['x-api-key'], 'test-upstream-key-value');
    assert.equal(seen.headers.authorization, undefined);
    assert.equal(seen.headers.cookie, undefined);
    assert.equal(seen.headers['x-forwarded-for'], undefined);
    assert.equal(seen.headers['accept-encoding'], 'identity');
    const note = await h.client.request({
      method: 'POST',
      path: '/mcp',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json', 'mcp-session-id': 'sess-fixed-1' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
    });
    assert.equal(note.status, 202);
    assert.equal(note.text, '');
    const list = await h.client.request({
      method: 'POST',
      path: '/mcp',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json', 'mcp-session-id': 'sess-fixed-1' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
    });
    const tools = list.json().result.tools;
    assert.deepEqual(tools.map((item) => item.name), ['get_chats', 'send_message']);
    assert.equal(tools[1].annotations.readOnlyHint, undefined);
    assert.ok(tools[0]._meta.securitySchemes.some((scheme) => scheme.type === 'oauth2' && scheme.scopes.includes('mcp:access')));
    assert.equal(tools[0]._meta.source, 'waha');
    h.waha.control.tools.push({ name: 'brand_new_tool', description: 'new', inputSchema: { type: 'object' } });
    const again = await h.client.request({
      method: 'POST',
      path: '/mcp',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json', 'mcp-session-id': 'sess-fixed-1' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} }),
    });
    assert.ok(again.json().result.tools.some((item) => item.name === 'brand_new_tool'));
    const call = await h.client.request({
      method: 'POST',
      path: '/mcp',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json', 'mcp-session-id': 'sess-fixed-1' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 'hebrew', method: 'tools/call', params: { name: 'send_message', arguments: { text: 'שלום 😀 WHATSAPP-PRIVATE-PHRASE-9f3a' } } }),
    });
    assert.equal(call.status, 200);
    assert.equal(call.json().result.content[0].text, 'שלום 😀');
    assert.equal(h.capture.lines().join('').includes('WHATSAPP-PRIVATE-PHRASE-9f3a'), false);
    assert.equal(h.capture.lines().join('').includes('test-upstream-key-value'), false);
    const bare = enrichTool({ name: 'plain', inputSchema: { type: 'object' }, annotations: {} });
    assert.equal(bare.annotations.readOnlyHint, undefined);
    assert.equal(bare.securitySchemes.some((scheme) => scheme.type === 'noauth'), false);
  } finally {
    await h.close();
  }
});

test('P-06 streaming does not buffer a large non-tool response', async () => {
  const h = await createHarness();
  try {
    const grant = await approvedGrant(h);
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    h.waha.control.handler = async (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.write(Buffer.alloc(64 * 1024, 7));
      await gate;
      res.end(Buffer.alloc(10 * 1024 * 1024, 8));
    };
    const body = JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'tools/call', params: {} });
    const received = await new Promise((resolve, reject) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port: h.bridge.port,
        path: '/mcp',
        method: 'POST',
        headers: {
          host: 'mcp.test.local',
          authorization: `Bearer ${grant.token.access_token}`,
          'content-type': 'application/json',
          accept: 'application/json',
          'content-length': String(Buffer.byteLength(body)),
        },
      }, (res) => {
        const chunks = [];
        res.once('data', () => release());
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => resolve(Buffer.concat(chunks)));
      });
      req.on('error', reject);
      req.end(body);
    });
    assert.equal(received.length, 64 * 1024 + 10 * 1024 * 1024);
    assert.equal(received[0], 7);
    assert.equal(received.at(-1), 8);
  } finally {
    await h.close();
  }
});

test('P-07 P-08 SSE passthrough and tools/list transform', async () => {
  const h = await createHarness();
  try {
    const grant = await approvedGrant(h);
    h.waha.control.sseCall = true;
    h.waha.control.piece = 2;
    const headers = { authorization: `Bearer ${grant.token.access_token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
    const call = await h.client.request({ method: 'POST', path: '/mcp', headers, body: JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: {} }) });
    assert.match(call.text, /שלום/);
    assert.match(call.headers['content-type'], /text\/event-stream/);
    h.waha.control.sseCall = false;
    const payloadText = '{"jsonrpc":"2.0","id":5,"result":{"tools":[{"name":"get_chats","description":"d","inputSchema":{"type":"object"},"annotations":{}}]}}';
    h.waha.control.listSse = () => [
      Buffer.from(`id: evt-1\r\nevent: message\r\nretry: 5000\r\ndata: ${payloadText}\r\n\r\n`),
      Buffer.from(': ping\r\n\r\n'),
      Buffer.from('id: evt-2\r\nevent: ping\r\ndata: keep\r\n\r\n'),
    ];
    const list = await h.client.request({ method: 'POST', path: '/mcp', headers, body: JSON.stringify({ jsonrpc: '2.0', id: 5, method: 'tools/list', params: {} }) });
    assert.match(list.text, /id: evt-1/);
    assert.match(list.text, /retry: 5000/);
    assert.match(list.text, /securitySchemes/);
    assert.match(list.text, /id: evt-2/);
    assert.match(list.text, /data: keep/);
    assert.equal(list.text.includes('readOnlyHint'), false);
  } finally {
    await h.close();
  }
});

test('P-09 through P-18 session, origin, limits, and upstream failures', async () => {
  const h = await createHarness({ limits: { maxStreams: 1, headerTimeoutMs: 300, maxRequestBytes: 128 } });
  try {
    const grant = await approvedGrant(h);
    const headers = { authorization: `Bearer ${grant.token.access_token}`, accept: 'text/event-stream' };
    const sse = await h.client.request({ method: 'GET', path: '/mcp', headers: { ...headers, 'last-event-id': 'abc-9' } });
    assert.match(sse.headers['content-type'], /text\/event-stream/);
    assert.match(sse.text, /abc-9/);
    assert.equal(h.waha.calls.at(-1).headers['last-event-id'], 'abc-9');
    h.waha.control.getStatus = 405;
    const missingGet = await h.client.request({ method: 'GET', path: '/mcp', headers });
    assert.equal(missingGet.status, 405);
    h.waha.control.getStatus = 0;
    const init = await h.client.request({
      method: 'POST', path: '/mcp',
      headers: { authorization: `Bearer ${grant.token.access_token}`, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    });
    assert.equal(init.headers['mcp-session-id'], 'sess-fixed-1');
    const refreshed = await h.client.request({ method: 'POST', path: '/oauth/token', form: { grant_type: 'refresh_token', refresh_token: grant.token.refresh_token, client_id: 'https://chatgpt.com/oauth/client.json', resource: h.config.resource } });
    const next = refreshed.json().access_token;
    const allowed = await h.client.request({
      method: 'POST', path: '/mcp',
      headers: { authorization: `Bearer ${next}`, 'content-type': 'application/json', accept: 'application/json', 'mcp-session-id': 'sess-fixed-1' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 8, method: 'tools/call', params: {} }),
    });
    assert.equal(allowed.status, 200);
    const otherClient = createClient({ port: h.bridge.port, hostHeader: 'mcp.test.local' });
    const second = await approvedGrant(h, { client: otherClient });
    const callsBefore = h.waha.calls.length;
    const blocked = await otherClient.request({
      method: 'POST', path: '/mcp',
      headers: { authorization: `Bearer ${second.token.access_token}`, 'content-type': 'application/json', accept: 'application/json', 'mcp-session-id': 'sess-fixed-1' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 8, method: 'tools/call', params: {} }),
    });
    assert.equal(blocked.status, 403);
    assert.equal(h.waha.calls.length, callsBefore);
    const removed = await h.client.request({ method: 'DELETE', path: '/mcp', headers: { authorization: `Bearer ${next}`, 'mcp-session-id': 'sess-fixed-1' } });
    assert.equal(removed.status, 200);
    const gone = await h.client.request({
      method: 'POST', path: '/mcp',
      headers: { authorization: `Bearer ${next}`, 'content-type': 'application/json', accept: 'application/json', 'mcp-session-id': 'sess-fixed-1' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 8, method: 'tools/call', params: {} }),
    });
    assert.equal(gone.status, 404);
    h.waha.control.status = 401;
    h.waha.control.body = `key=test-upstream-key-value host=${h.waha.url}`;
    const mapped = await h.client.request({
      method: 'POST', path: '/mcp',
      headers: { authorization: `Bearer ${next}`, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    });
    assert.equal(mapped.status, 502);
    assert.equal(mapped.text.includes('test-upstream-key-value'), false);
    assert.equal(mapped.text.includes(h.waha.url), false);
    h.waha.control.status = 302;
    h.waha.control.responseHeaders = { location: 'http://evil.example/steal' };
    const redirect = await h.client.request({
      method: 'POST', path: '/mcp',
      headers: { authorization: `Bearer ${next}`, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    });
    assert.equal(redirect.status, 502);
    assert.equal(redirect.text.includes('evil.example'), false);
    h.waha.control.status = 0;
    const origin = await h.client.request({
      method: 'POST', path: '/mcp',
      headers: { authorization: `Bearer ${next}`, 'content-type': 'application/json', accept: 'application/json', origin: 'https://evil.example' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} }),
    });
    assert.equal(origin.status, 403);
    const before = h.waha.calls.length;
    const stateless = await h.client.request({
      method: 'POST', path: '/mcp',
      headers: { authorization: `Bearer ${next}`, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} }),
    });
    assert.equal(stateless.status, 200);
    assert.ok(h.waha.calls.length > before);
    const large = await h.client.request({
      method: 'POST', path: '/mcp',
      headers: { authorization: `Bearer ${next}`, 'content-type': 'application/json', accept: 'application/json' },
      body: Buffer.alloc(200, 0x61),
    });
    assert.equal(large.status, 413);
    h.waha.control.handler = (req, res) => new Promise((resolve) => {
      req.on('close', () => { res.destroy(); resolve(); });
    });
    const hung = await h.client.request({
      method: 'POST', path: '/mcp',
      headers: { authorization: `Bearer ${next}`, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} }),
    });
    assert.equal(hung.status, 504);
    const live = await h.client.request({ path: '/health/live' });
    assert.equal(live.status, 200);
    assert.deepEqual(live.json(), { status: 'live' });
  } finally {
    await h.close();
  }
});

test('P-17 client disconnect does not retry a tool call', async () => {
  const h = await createHarness();
  try {
    const grant = await approvedGrant(h);
    h.waha.control.holdCall = true;
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { arguments: { text: 'WHATSAPP-PRIVATE-PHRASE-9f3a' } } });
    await new Promise((resolve, reject) => {
      const req = http.request({
        hostname: '127.0.0.1', port: h.bridge.port, path: '/mcp', method: 'POST',
        headers: {
          host: 'mcp.test.local',
          authorization: `Bearer ${grant.token.access_token}`,
          'content-type': 'application/json',
          accept: 'application/json',
          'content-length': String(Buffer.byteLength(body)),
        },
      }, () => {});
      req.on('error', () => resolve());
      req.end(body);
      const wait = setInterval(() => {
        if (h.waha.control.callCount >= 1) {
          clearInterval(wait);
          req.destroy();
          resolve();
        }
      }, 20);
      setTimeout(() => { clearInterval(wait); req.destroy(); resolve(); }, 2000);
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(h.waha.control.callCount, 1);
    assert.match(h.capture.lines().join(''), /write_completion_uncertain/);
    assert.equal(h.capture.lines().join('').includes('WHATSAPP-PRIVATE-PHRASE-9f3a'), false);
  } finally {
    await h.close();
  }
});
