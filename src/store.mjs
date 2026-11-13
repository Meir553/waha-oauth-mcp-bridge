import { closeSync, constants, fsyncSync, openSync, promises as fs } from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';

const STATE_NAME = 'state.json';
const LOCK_NAME = 'bridge.lock';

/**
 * @param {object} operator
 * @param {number} now
 */
export function emptyState(operator, now) {
  return {
    schemaVersion: 1,
    operator: {
      username: operator.username,
      passwordSalt: operator.passwordSalt,
      passwordVerifier: operator.passwordVerifier,
      scryptParams: operator.scryptParams,
      createdAt: now,
      passwordChangedAt: now,
    },
    browserSessions: {},
    pendingAuthorizations: {},
    authorizationCodes: {},
    grants: {},
    accessTokens: {},
    refreshTokens: {},
    refreshFamilies: {},
    mcpSessions: {},
    loginThrottle: { global: { failures: 0, windowStart: now, lockedUntil: 0 }, ips: {} },
    loginPepper: randomBytes(16).toString('base64url'),
    updatedAt: now,
  };
}

/**
 * @param {object} state
 */
export function assertValidState(state) {
  if (!state || state.schemaVersion !== 1) throw new Error('state schema is missing or unsupported');
  const op = state.operator;
  if (!op || typeof op.username !== 'string' || typeof op.passwordSalt !== 'string' || typeof op.passwordVerifier !== 'string') {
    throw new Error('state operator record is invalid');
  }
  for (const key of [
    'browserSessions', 'pendingAuthorizations', 'authorizationCodes', 'grants',
    'accessTokens', 'refreshTokens', 'refreshFamilies', 'mcpSessions',
  ]) {
    if (!state[key] || typeof state[key] !== 'object' || Array.isArray(state[key])) {
      throw new Error(`state field ${key} is invalid`);
    }
  }
  if (!state.loginThrottle || typeof state.loginThrottle !== 'object' || typeof state.loginPepper !== 'string') {
    throw new Error('state login throttle is invalid');
  }
}

/**
 * @param {object} state
 * @param {number} now
 */
export function pruneState(state, now) {
  for (const [key, value] of Object.entries(state.browserSessions)) {
    if (value.expiresAt <= now || value.absoluteExpiresAt <= now) delete state.browserSessions[key];
  }
  for (const [key, value] of Object.entries(state.pendingAuthorizations)) {
    if (value.expiresAt <= now) delete state.pendingAuthorizations[key];
  }
  for (const [key, value] of Object.entries(state.authorizationCodes)) {
    if (value.expiresAt <= now) delete state.authorizationCodes[key];
  }
  for (const [key, value] of Object.entries(state.accessTokens)) {
    if (value.expiresAt <= now) delete state.accessTokens[key];
  }
  for (const [key, family] of Object.entries(state.refreshFamilies)) {
    if (family.expiresAt <= now) {
      delete state.refreshFamilies[key];
      for (const [tokenKey, token] of Object.entries(state.refreshTokens)) {
        if (token.familyId === key) delete state.refreshTokens[tokenKey];
      }
      for (const [tokenKey, token] of Object.entries(state.accessTokens)) {
        if (token.familyId === key) delete state.accessTokens[tokenKey];
      }
    }
  }
  for (const [key, value] of Object.entries(state.mcpSessions)) {
    if (value.expiresAt && value.expiresAt <= now) delete state.mcpSessions[key];
  }
  const ips = state.loginThrottle.ips || {};
  for (const [key, value] of Object.entries(ips)) {
    if ((value.lockedUntil || 0) <= now && (value.windowStart || 0) + 60 * 60 * 1000 <= now) delete ips[key];
  }
}

/**
 * @param {number} pid
 * @returns {boolean}
 */
export function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM';
  }
}

/**
 * @param {string} dataDir
 * @param {{ logger?: { warn: Function } }} [options]
 */
export async function recoverStaleLock(dataDir, options = {}) {
  const lockPath = path.join(dataDir, LOCK_NAME);
  let raw;
  try {
    raw = await fs.readFile(lockPath, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return { recovered: false, reason: 'absent' };
    throw err;
  }
  let info;
  try { info = JSON.parse(raw); } catch { info = {}; }
  if (pidAlive(info.pid)) {
    throw new Error(`lock is held by live process ${info.pid}; refusing to remove it`);
  }
  await fs.unlink(lockPath);
  options.logger?.warn({ event: 'lock_recovered', pid: info.pid || null });
  return { recovered: true };
}

async function openNoFollow(file, flags) {
  const nofollow = constants.O_NOFOLLOW || 0;
  try {
    return await fs.open(file, flags | nofollow, 0o600);
  } catch (err) {
    if (nofollow && (err.code === 'EINVAL' || err.code === 'ENOTSUP' || err.code === 'EOPNOTSUPP')) {
      return fs.open(file, flags, 0o600);
    }
    throw err;
  }
}

async function assertRealPath(file, { allowMissing = false, directory = false } = {}) {
  let st;
  try {
    st = await fs.lstat(file);
  } catch (err) {
    if (allowMissing && err.code === 'ENOENT') return null;
    throw err;
  }
  if (st.isSymbolicLink()) throw new Error(`refusing symlink at ${path.basename(file)}`);
  if (directory && !st.isDirectory()) throw new Error(`${path.basename(file)} is not a directory`);
  if (!directory && !st.isFile()) throw new Error(`${path.basename(file)} is not a file`);
  return st;
}

/**
 * @param {string} dir
 */
async function fsyncDirectory(dir) {
  if (process.platform === 'win32') return false;
  let fd;
  try {
    fd = openSync(dir, 'r');
    fsyncSync(fd);
    return true;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * @param {string} file
 * @param {object} state
 * @param {{ beforeRename?: Function }} [hooks]
 */
export async function atomicWriteJson(file, state, hooks = {}) {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `state.tmp-${randomBytes(8).toString('hex')}`);
  const payload = Buffer.from(`${JSON.stringify(state, null, 2)}\n`);
  const handle = await openNoFollow(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL);
  try {
    await handle.writeFile(payload);
    await handle.sync();
  } catch (err) {
    await handle.close().catch(() => {});
    await fs.unlink(tmp).catch(() => {});
    throw err;
  }
  await handle.close();
  if (hooks.beforeRename) await hooks.beforeRename(tmp);
  try {
    await fs.rename(tmp, file);
  } catch (err) {
    if (process.platform === 'win32' && (err.code === 'EPERM' || err.code === 'EEXIST')) {
      const backup = `${file}.replacing`;
      await fs.rename(file, backup);
      try {
        await fs.rename(tmp, file);
        await fs.unlink(backup).catch(() => {});
      } catch (inner) {
        await fs.rename(backup, file).catch(() => {});
        throw inner;
      }
    } else {
      await fs.unlink(tmp).catch(() => {});
      throw err;
    }
  }
  await fsyncDirectory(dir);
}

/**
 * @param {{ dataDir: string, clock: { now: () => number }, logger?: { warn: Function, info: Function }, hooks?: { beforeRename?: Function } }} options
 */
export async function openStore(options) {
  const dataDir = options.dataDir;
  const clock = options.clock;
  const logger = options.logger || { warn() {}, info() {} };
  const hooks = options.hooks || {};
  await assertRealPath(dataDir, { directory: true });
  const statePath = path.join(dataDir, STATE_NAME);
  const lockPath = path.join(dataDir, LOCK_NAME);
  await assertRealPath(statePath);
  let stateStat = await fs.lstat(statePath);
  if (stateStat.isSymbolicLink()) throw new Error('refusing symlink at state.json');

  let lockHandle;
  try {
    lockHandle = await openNoFollow(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL);
  } catch (err) {
    if (err.code === 'EEXIST') {
      throw new Error(
        'another bridge process holds the state lock. If that process is dead, run `npm run admin -- recover-lock` and start again. The lock is not deleted automatically.',
      );
    }
    throw err;
  }
  const lockBody = JSON.stringify({ pid: process.pid, startedAt: Date.now(), nonce: randomBytes(8).toString('hex') });
  await lockHandle.writeFile(lockBody);
  await lockHandle.sync();

  const names = await fs.readdir(dataDir);
  for (const name of names) {
    if (name.startsWith('state.tmp-')) {
      logger.warn({ event: 'orphan_temp_ignored', file: 'state.tmp' });
    }
  }

  let parsed;
  try {
    const raw = await fs.readFile(statePath, 'utf8');
    parsed = JSON.parse(raw);
    assertValidState(parsed);
  } catch (err) {
    await lockHandle.close().catch(() => {});
    await fs.unlink(lockPath).catch(() => {});
    throw new Error(`refusing to start from unreadable state (${err.message})`);
  }

  let chain = Promise.resolve();
  const store = {
    path: statePath,
    dataDir,
    read() {
      return parsed;
    },
    enqueue(work) {
      const run = chain.then(work);
      chain = run.then(() => undefined, () => undefined);
      return run;
    },
    transaction(mutator) {
      return store.enqueue(async () => {
        const draft = structuredClone(parsed);
        pruneState(draft, clock.now());
        const result = await mutator(draft);
        assertValidState(draft);
        draft.updatedAt = clock.now();
        await atomicWriteJson(statePath, draft, hooks);
        parsed = draft;
        return result;
      });
    },
    async close() {
      await chain.catch(() => {});
      await lockHandle.close().catch(() => {});
      const current = await fs.readFile(lockPath, 'utf8').catch(() => '');
      if (current === lockBody) await fs.unlink(lockPath).catch(() => {});
    },
  };
  await store.transaction(async () => {});
  return store;
}

/**
 * @param {{ dataDir: string, operator: object, clock: { now: () => number } }} options
 */
export async function initializeStore(options) {
  await fs.mkdir(options.dataDir, { recursive: true, mode: 0o700 });
  const dirStat = await fs.lstat(options.dataDir);
  if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) throw new Error('DATA_DIR is not a real directory');
  const statePath = path.join(options.dataDir, STATE_NAME);
  const existing = await fs.lstat(statePath).catch((err) => {
    if (err.code === 'ENOENT') return null;
    throw err;
  });
  if (existing) throw new Error('store already exists; refusing to overwrite');
  const state = emptyState(options.operator, options.clock.now());
  assertValidState(state);
  const payload = Buffer.from(`${JSON.stringify(state, null, 2)}\n`);
  let handle;
  try {
    handle = await openNoFollow(statePath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL);
    await handle.writeFile(payload);
    await handle.sync();
  } catch (err) {
    if (err.code === 'EEXIST') throw new Error('store already exists; refusing to overwrite');
    throw err;
  } finally {
    await handle?.close().catch(() => {});
  }
  await fsyncDirectory(options.dataDir);
  return state;
}
