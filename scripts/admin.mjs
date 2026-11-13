import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { hashPassword, verifyPassword } from '../src/crypto.mjs';
import { loadEnvFile } from '../src/env-file.mjs';
import { parseUpstreamUrl, systemClock } from '../src/config.mjs';
import { openStore, recoverStaleLock } from '../src/store.mjs';
import { revokeEverything, revokeUpstream } from '../src/oauth/token.mjs';
import {
  assertApiKey,
  assertUpstreamId,
  cleanDisplayName,
  readUpstreamDefinitions,
  writeUpstreamDefinitions,
} from '../src/upstreams.mjs';

/**
 * @param {{ dataDir: string, command: string, password?: string, grantId?: string, newPassword?: string, clock?: { now: () => number } }} options
 */
export async function runAdmin(options) {
  const dataDir = path.resolve(options.dataDir);
  const clock = options.clock || systemClock();
  const stdout = options.stdout || process.stdout;
  if (options.command === 'recover-lock') {
    const result = await recoverStaleLock(dataDir);
    stdout.write(`${result.recovered ? 'lock removed' : 'no lock'}\n`);
    return result;
  }
  if (options.command === 'status') {
    const state = JSON.parse(await readFile(path.join(dataDir, 'state.json'), 'utf8'));
    const definitions = await readUpstreamDefinitions(path.join(dataDir, 'upstreams.json'));
    const grants = Object.values(state.grants).map((grant) => ({
      grantId: grant.grantId,
      client: grant.label || grant.clientDisplay || 'client',
      upstreamId: grant.upstreamId || null,
      createdAt: grant.createdAt,
      revoked: Boolean(grant.revokedAt),
      scopes: grant.scopes,
    }));
    const upstreams = [
      { id: 'default', source: 'environment' },
      ...definitions.map((item) => ({ id: item.id, displayName: item.displayName, source: 'file' })),
    ];
    stdout.write(`${JSON.stringify({ operator: state.operator.username, upstreams, grants, sessions: Object.keys(state.browserSessions).length })}\n`);
    return { grants, upstreams };
  }
  if (options.command === 'add-upstream') {
    await assertOperator(dataDir, options.password);
    const added = await addUpstream(dataDir, options.upstream || {});
    stdout.write(`added upstream ${added.id}. Restart the bridge before ChatGPT uses ${added.path}. The API key was not printed.\n`);
    return added;
  }
  const store = await openStore({ dataDir, clock, logger: { warn() {}, info() {} } });
  try {
    const operator = store.read().operator;
    const ok = await verifyPassword(options.password || '', operator);
    if (!ok) throw new Error('authentication failed');
    if (options.command === 'revoke-all') {
      await store.transaction(async (draft) => { revokeEverything(draft, clock.now()); });
      process.stdout.write('revoked all grants\n');
      return { revoked: true };
    }
    if (options.command === 'revoke-grant') {
      await store.transaction(async (draft) => {
        const grant = draft.grants[options.grantId];
        if (!grant) throw new Error('grant not found');
        grant.revokedAt = clock.now();
        for (const [key, token] of Object.entries(draft.accessTokens)) {
          if (token.grantId === options.grantId) delete draft.accessTokens[key];
        }
        for (const [key, family] of Object.entries(draft.refreshFamilies)) {
          if (family.grantId === options.grantId) family.revokedAt = clock.now();
        }
      });
      process.stdout.write('revoked grant\n');
      return { revoked: true };
    }
    if (options.command === 'reset-password') {
      const hashed = await hashPassword(options.newPassword || '');
      await store.transaction(async (draft) => {
        revokeEverything(draft, clock.now());
        draft.operator.passwordSalt = hashed.passwordSalt;
        draft.operator.passwordVerifier = hashed.passwordVerifier;
        draft.operator.scryptParams = hashed.scryptParams;
        draft.operator.passwordChangedAt = clock.now();
      });
      process.stdout.write('password updated and grants revoked\n');
      return { reset: true };
    }
    if (options.command === 'remove-upstream') {
      const id = assertUpstreamId(options.upstreamId || options.grantId);
      const existing = await readUpstreamDefinitions(path.join(dataDir, 'upstreams.json'));
      if (!existing.some((item) => item.id === id)) throw new Error('upstream id is not configured');
      await store.transaction(async (draft) => { revokeUpstream(draft, id, clock.now()); });
      await writeUpstreamDefinitions(dataDir, existing.filter((item) => item.id !== id));
      stdout.write(`removed upstream ${id} and revoked its grants. Restart the bridge.\n`);
      return { removed: id };
    }
    throw new Error('unknown admin command');
  } finally {
    await store.close();
  }
}

async function addUpstream(dataDir, input) {
  const id = assertUpstreamId(input.id);
  const displayName = cleanDisplayName(input.displayName);
  const apiKey = assertApiKey(input.apiKey);
  const allowPublic = process.env.ALLOW_PUBLIC_UPSTREAM === 'true';
  const parsed = await parseUpstreamUrl(input.url, { allowPublic });
  if (process.env.UPSTREAM_MCP_URL) {
    const current = await parseUpstreamUrl(process.env.UPSTREAM_MCP_URL, { allowPublic });
    if (current.href === parsed.href) throw new Error('upstream URL is already configured');
  }
  const existing = await readUpstreamDefinitions(path.join(dataDir, 'upstreams.json'));
  if (existing.some((item) => item.id === id)) throw new Error('upstream id is already configured');
  for (const item of existing) {
    const other = await parseUpstreamUrl(item.url, { allowPublic });
    if (other.href === parsed.href) throw new Error('upstream URL is already configured');
  }
  await writeUpstreamDefinitions(dataDir, [...existing, { id, url: parsed.href, displayName, apiKey }]);
  return { id, path: `/mcp/${id}` };
}

async function assertOperator(dataDir, password) {
  let state;
  try {
    state = JSON.parse(await readFile(path.join(dataDir, 'state.json'), 'utf8'));
  } catch {
    throw new Error('authentication failed');
  }
  const ok = await verifyPassword(password || '', state.operator);
  if (!ok) throw new Error('authentication failed');
}

async function main() {
  await loadEnvFile(path.join(process.cwd(), '.env'));
  const [command, arg] = process.argv.slice(2);
  const dataDir = process.env.DATA_DIR || path.join(process.cwd(), 'data');
  if (!command) {
    process.stderr.write('usage: npm run admin -- status|revoke-all|revoke-grant|reset-password|recover-lock|add-upstream|remove-upstream\n');
    process.exit(1);
  }
  let password;
  let newPassword;
  let upstream;
  if (command === 'revoke-all' || command === 'revoke-grant' || command === 'reset-password' || command === 'remove-upstream') {
    password = await readSecret('Current password: ');
  }
  if (command === 'add-upstream') {
    if (!process.stdin.isTTY) throw new Error('add-upstream must be run from a terminal');
    const url = await readLine('Upstream MCP URL: ');
    const displayName = await readLine('Display name: ');
    const apiKey = await readSecret('API key: ');
    password = await readSecret('Current password: ');
    upstream = { id: arg, url, displayName, apiKey };
  }
  if (command === 'reset-password') {
    newPassword = await readSecret('New password: ');
    const confirm = await readSecret('New password again: ');
    if (newPassword !== confirm) throw new Error('passwords do not match');
  }
  await runAdmin({ dataDir, command, password, newPassword, grantId: arg, upstreamId: arg, upstream });
}

function readLine(prompt) {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    const { stdin } = process;
    stdin.setEncoding('utf8');
    let data = '';
    const onData = (chunk) => {
      data += chunk;
      const end = data.search(/\r?\n/);
      if (end === -1) return;
      stdin.off('data', onData);
      resolve(data.slice(0, end).trim());
    };
    stdin.on('data', onData);
  });
}

function readSecret(prompt) {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    const { stdin } = process;
    if (!stdin.isTTY) {
      stdin.setEncoding('utf8');
      let data = '';
      stdin.on('data', (chunk) => { data += chunk; });
      stdin.on('end', () => resolve(data.trim().split(/\r?\n/)[0] || ''));
      return;
    }
    stdin.setRawMode(true);
    let value = '';
    const onData = (buf) => {
      const text = buf.toString('utf8');
      if (text === '\r' || text === '\n') {
        stdin.setRawMode(false);
        stdin.off('data', onData);
        process.stdout.write('\n');
        resolve(value);
      } else if (text === '\u007f' || text === '\b') value = value.slice(0, -1);
      else if (text >= ' ') value += text;
    };
    stdin.on('data', onData);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    process.stderr.write(`${err.message}\n`);
    process.exit(1);
  });
}
