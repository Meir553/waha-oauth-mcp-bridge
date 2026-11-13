import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { loadEnvFile } from '../src/env-file.mjs';
import { hashPassword } from '../src/crypto.mjs';
import { isPrivateIp, loadConfig } from '../src/config.mjs';
import { runAdmin } from '../scripts/admin.mjs';
import { assertReadOnlyMethod } from '../scripts/doctor-remote.mjs';
import { askHidden, runInit } from '../scripts/init.mjs';
import { atomicWriteJson, initializeStore, openStore } from '../src/store.mjs';
import { createClock, testOperator } from './helpers.mjs';

test('init keeps a hidden answer out of the terminal echo', async () => {
  const chunks = [];
  const rl = {
    output: { write(text) { chunks.push(String(text)); } },
    _writeToOutput(text) { this.output.write(text); },
    question(prompt) {
      this.output.write(prompt);
      this._writeToOutput('secret-value');
      this._writeToOutput('\n');
      return Promise.resolve(' secret-value ');
    },
  };
  const value = await askHidden(rl, 'Password: ');
  assert.equal(value, 'secret-value');
  const shown = chunks.join('');
  assert.match(shown, /Password: /);
  assert.equal(shown.includes('secret-value'), false);
  assert.match(shown, /\n/);
});

test('L-01 L-02 init stores scrypt and refuses overwrite', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'waha-init-'));
  const logs = [];
  try {
    await assert.rejects(() => runInit({
      directory: dir,
      stdout: { write(chunk) { logs.push(String(chunk)); } },
      answers: {
        username: 'admin', password: 'short', confirm: 'short', publicOrigin: 'https://mcp.example.com',
        upstreamUrl: 'http://127.0.0.1:9/mcp', apiKey: 'scoped-key-value', certPath: 'cert.pem', keyPath: 'key.pem',
      },
    }), /password/);
    await assert.rejects(() => runInit({
      directory: dir,
      stdout: { write() {} },
      answers: {
        username: 'admin', password: 'correct-horse-battery', confirm: 'correct-horse-battery-other',
        publicOrigin: 'https://mcp.example.com', upstreamUrl: 'http://127.0.0.1:9/mcp', apiKey: 'scoped-key-value',
        certPath: 'cert.pem', keyPath: 'key.pem',
      },
    }), /match/);
    await runInit({
      directory: dir,
      stdout: { write(chunk) { logs.push(String(chunk)); } },
      answers: {
        username: 'admin', password: 'correct-horse-battery', confirm: 'correct-horse-battery',
        publicOrigin: 'https://mcp.example.com', upstreamUrl: 'http://127.0.0.1:9/mcp', apiKey: 'scoped-key-value',
        certPath: 'cert.pem', keyPath: 'key.pem',
      },
    });
    const state = JSON.parse(await readFile(path.join(dir, 'data', 'state.json'), 'utf8'));
    assert.equal(state.operator.scryptParams.N, 32768);
    assert.equal(JSON.stringify(state).includes('correct-horse-battery'), false);
    assert.equal(logs.join('').includes('correct-horse-battery'), false);
    assert.equal(logs.join('').includes('scoped-key-value'), false);
    const secret = JSON.parse(await readFile(path.join(dir, 'data', 'upstream-secret.json'), 'utf8'));
    assert.equal(secret.apiKey, 'scoped-key-value');
    await assert.rejects(() => runInit({
      directory: dir,
      stdout: { write() {} },
      answers: {
        username: 'admin', password: 'correct-horse-battery', confirm: 'correct-horse-battery',
        publicOrigin: 'https://mcp.example.com', upstreamUrl: 'http://127.0.0.1:9/mcp', apiKey: 'scoped-key-value',
        certPath: 'cert.pem', keyPath: 'key.pem',
      },
    }), /overwrite|exists/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('D-01 D-02 D-03 config fails closed', async () => {
  assert.equal(isPrivateIp('8.8.8.8'), false);
  assert.equal(isPrivateIp('10.1.2.3'), true);
  assert.equal(isPrivateIp('::ffff:127.0.0.1'), true);
  const base = {
    PUBLIC_ORIGIN: 'https://mcp.example.com',
    LISTEN_HOST: '127.0.0.1',
    LISTEN_PORT: '8443',
    UPSTREAM_MCP_URL: 'http://127.0.0.1:9/mcp',
    UPSTREAM_API_KEY: 'scoped-key-value',
    DATA_DIR: await mkdtemp(path.join(tmpdir(), 'waha-cfg-')),
    NODE_ENV: 'production',
  };
  await assert.rejects(() => loadConfig(base, { testMode: true, runtimeVersion: 'v16.20.2' }), /Node\.js 18/);
  await assert.rejects(() => loadConfig(base), /TLS/);
  await assert.rejects(() => loadConfig({ ...base, ENABLE_LOCAL_TEST_HTTP: 'true' }, { testMode: true, runtimeVersion: 'v18.0.0' }), /HTTP test mode/);
  await assert.rejects(() => loadConfig({ ...base, NODE_ENV: 'test', ENABLE_LOCAL_TEST_HTTP: 'true', UPSTREAM_MCP_URL: 'http://user:pass@127.0.0.1:9/mcp' }, { testMode: true, runtimeVersion: 'v18.0.0' }), /userinfo/);
  await assert.rejects(() => loadConfig({ ...base, NODE_ENV: 'test', ENABLE_LOCAL_TEST_HTTP: 'true', UPSTREAM_MCP_URL: 'http://8.8.8.8/mcp' }, { testMode: true, runtimeVersion: 'v18.0.0' }), /not private/);
  await assert.rejects(() => loadConfig({ ...base, TLS_CERT_FILE: '', TLS_KEY_FILE: '' }, { testMode: true, runtimeVersion: 'v18.0.0' }), /TLS/);
  await rm(base.DATA_DIR, { recursive: true, force: true });
});

test('env file fills missing keys and refuses a symlink', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'waha-env-'));
  try {
    const file = path.join(dir, '.env');
    await writeFile(file, 'PUBLIC_ORIGIN=https://from-file.example\nexport LOG_LEVEL="debug"\n# comment\nALREADY=file\n');
    const env = { ALREADY: 'process' };
    assert.equal(await loadEnvFile(file, env), true);
    assert.equal(env.PUBLIC_ORIGIN, 'https://from-file.example');
    assert.equal(env.LOG_LEVEL, 'debug');
    assert.equal(env.ALREADY, 'process');
    assert.equal(await loadEnvFile(path.join(dir, 'missing.env'), env), false);
    const real = path.join(dir, 'real.env');
    await writeFile(real, 'SECRET=value\n');
    await symlink(real, path.join(dir, 'link.env'), 'file');
    await assert.rejects(() => loadEnvFile(path.join(dir, 'link.env'), {}), /symlink/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('T-08 T-09 D-04 store durability, crash, and lock', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'waha-store-'));
  const clock = createClock();
  const operator = await testOperator();
  try {
    await initializeStore({ dataDir: dir, clock, operator: { username: 'admin', ...operator } });
    const store = await openStore({ dataDir: dir, clock, logger: { warn() {}, info() {} } });
    await store.transaction(async (draft) => {
      draft.grants.g1 = { grantId: 'g1', clientId: 'https://chatgpt.com/oauth/client.json', userId: 'operator', resource: 'https://mcp.test.local/mcp', scopes: ['mcp:access'], createdAt: clock.now(), revokedAt: null, expiresAt: null, clientDisplay: 'ChatGPT' };
    });
    await store.close();
    const reopened = await openStore({ dataDir: dir, clock, logger: { warn() {}, info() {} } });
    assert.equal(reopened.read().grants.g1.grantId, 'g1');
    await reopened.close();
    let armed = false;
    const crashing = await openStore({
      dataDir: dir,
      clock,
      logger: { warn() {}, info() {} },
      hooks: { beforeRename() { if (armed) throw new Error('crash'); } },
    });
    const before = await readFile(path.join(dir, 'state.json'), 'utf8');
    armed = true;
    await assert.rejects(() => crashing.transaction(async (draft) => {
      draft.grants.g2 = { ...draft.grants.g1, grantId: 'g2' };
    }));
    const after = await readFile(path.join(dir, 'state.json'), 'utf8');
    assert.equal(after, before);
    assert.equal(JSON.parse(after).grants.g2, undefined);
    await assert.rejects(() => openStore({ dataDir: dir, clock, logger: { warn() {}, info() {} } }), /lock/);
    await crashing.close();
    const valid = JSON.parse(before);
    valid.schemaVersion = 2;
    await writeFile(path.join(dir, 'state.json'), JSON.stringify(valid));
    const { recoverStaleLock } = await import('../src/store.mjs');
    await recoverStaleLock(dir);
    await assert.rejects(() => openStore({ dataDir: dir, clock, logger: { warn() {}, info() {} } }), /schema|unreadable/);
    const still = JSON.parse(await readFile(path.join(dir, 'state.json'), 'utf8'));
    assert.equal(still.schemaVersion, 2);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('D-08 admin revoke survives a new store', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'waha-admin-'));
  const clock = createClock();
  const operator = await hashPassword('correct-horse-battery-staple');
  try {
    await initializeStore({ dataDir: dir, clock, operator: { username: 'admin', ...operator } });
    const store = await openStore({ dataDir: dir, clock, logger: { warn() {}, info() {} } });
    await store.transaction(async (draft) => {
      draft.grants.g1 = { grantId: 'g1', clientId: 'https://chatgpt.com/oauth/client.json', userId: 'operator', resource: 'https://mcp.test.local/mcp', scopes: ['mcp:access'], createdAt: clock.now(), revokedAt: null, expiresAt: null, clientDisplay: 'ChatGPT' };
      draft.accessTokens.abc = { grantId: 'g1', familyId: 'f', clientId: 'https://chatgpt.com/oauth/client.json', userId: 'operator', audience: 'https://mcp.test.local/mcp', issuer: 'https://mcp.test.local', scopes: ['mcp:access'], expiresAt: clock.now() + 1000, createdAt: clock.now() };
    });
    await store.close();
    await runAdmin({ dataDir: dir, command: 'revoke-all', password: 'correct-horse-battery-staple', clock });
    const reopened = await openStore({ dataDir: dir, clock, logger: { warn() {}, info() {} } });
    assert.ok(reopened.read().grants.g1.revokedAt);
    assert.equal(reopened.read().accessTokens.abc, undefined);
    await reopened.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('D-05 refuses a symlinked state file', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'waha-link-'));
  const clock = createClock();
  const operator = await testOperator();
  try {
    await initializeStore({ dataDir: dir, clock, operator: { username: 'admin', ...operator } });
    const state = path.join(dir, 'state.json');
    const moved = path.join(dir, 'state-real.json');
    await rename(state, moved);
    await symlink(moved, state, 'file');
    await assert.rejects(
      () => openStore({ dataDir: dir, clock, logger: { warn() {}, info() {} } }),
      /symlink/,
    );
    assert.equal(JSON.parse(await readFile(moved, 'utf8')).schemaVersion, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('D-06 shutdown closes the listener and releases the lock', async () => {
  const childPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'support', 'lifecycle-child.mjs');
  const operator = await testOperator();
  const clock = createClock();
  async function boot(dir) {
    await initializeStore({ dataDir: dir, clock, operator: { username: 'admin', ...operator } });
    const child = spawn(process.execPath, [childPath], {
      env: {
        NODE_ENV: 'test',
        ENABLE_LOCAL_TEST_HTTP: 'true',
        PUBLIC_ORIGIN: 'https://mcp.test.local',
        LISTEN_HOST: '127.0.0.1',
        LISTEN_PORT: '0',
        UPSTREAM_MCP_URL: 'http://127.0.0.1:9/mcp',
        UPSTREAM_API_KEY: 'lifecycle-test-key',
        DATA_DIR: dir,
        LOG_LEVEL: 'error',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8'); });
    const exit = new Promise((resolve) => child.once('exit', resolve));
    const port = await new Promise((resolve, reject) => {
      let buffer = '';
      const timer = setTimeout(() => reject(new Error(`child did not become ready ${stderr}`)), 15000);
      child.stdout.on('data', (chunk) => {
        buffer += chunk.toString('utf8');
        const match = /ready (\d+)/.exec(buffer);
        if (!match) return;
        clearTimeout(timer);
        resolve(Number(match[1]));
      });
      exit.then((code) => {
        clearTimeout(timer);
        reject(new Error(`child exited ${code} before ready ${stderr}`));
      });
    });
    return { child, port, exit, stderr: () => stderr };
  }
  const dir = await mkdtemp(path.join(tmpdir(), 'waha-life-'));
  let child;
  try {
    const started = await boot(dir);
    child = started.child;
    assert.equal(await health(started.port), 200);
    // Node.js on Windows terminates SIGTERM without entering the JavaScript handler.
    // The handler and this stdin path call the same shutdown function.
    if (process.platform === 'win32') {
      child.stdin.write('stop\n');
      child.stdin.end();
    } else {
      process.kill(child.pid, 'SIGTERM');
    }
    const code = await Promise.race([
      started.exit,
      new Promise((_, reject) => setTimeout(() => reject(new Error(`shutdown timed out ${started.stderr()}`)), 10000)),
    ]);
    assert.equal(code, 0);
    await assert.rejects(() => health(started.port));
    await assert.rejects(() => readFile(path.join(dir, 'bridge.lock'), 'utf8'), { code: 'ENOENT' });
  } finally {
    if (child && child.exitCode === null) child.kill('SIGKILL');
    await rm(dir, { recursive: true, force: true });
  }
  if (process.platform === 'win32') {
    const abruptDir = await mkdtemp(path.join(tmpdir(), 'waha-life-kill-'));
    let abrupt;
    try {
      const started = await boot(abruptDir);
      abrupt = started.child;
      process.kill(abrupt.pid, 'SIGTERM');
      const code = await Promise.race([
        started.exit,
        new Promise((_, reject) => setTimeout(() => reject(new Error('SIGTERM did not end the process')), 10000)),
      ]);
      assert.notEqual(code, 0);
      await assert.rejects(() => health(started.port));
      const { recoverStaleLock } = await import('../src/store.mjs');
      const recovered = await recoverStaleLock(abruptDir);
      assert.equal(recovered.recovered, true);
    } finally {
      if (abrupt && abrupt.exitCode === null) abrupt.kill('SIGKILL');
      await rm(abruptDir, { recursive: true, force: true });
    }
  }
});

function health(port) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path: '/health/live', method: 'GET', headers: { host: 'mcp.test.local' } }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject);
    req.end();
  });
}

test('D-07 doctor remote refuses write methods without a network call', () => {
  assert.doesNotThrow(() => assertReadOnlyMethod('initialize'));
  assert.doesNotThrow(() => assertReadOnlyMethod('tools/list'));
  assert.throws(() => assertReadOnlyMethod('tools/call'), /refuses/);
  assert.throws(() => assertReadOnlyMethod('resources/delete'), /refuses/);
});

test('atomic write replaces a snapshot', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'waha-atomic-'));
  try {
    const file = path.join(dir, 'state.json');
    await atomicWriteJson(file, { hello: 1 });
    await atomicWriteJson(file, { hello: 2 });
    assert.equal(JSON.parse(await readFile(file, 'utf8')).hello, 2);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
