import { chmod, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { pathToFileURL } from 'node:url';
import { assertPasswordPolicy, hashPassword } from '../src/crypto.mjs';
import { parsePublicOrigin, parseUpstreamUrl, systemClock } from '../src/config.mjs';
import { initializeStore } from '../src/store.mjs';

/**
 * @param {{ answers: Record<string, string>, directory: string, stdout?: { write: Function } }} options
 */
export async function runInit(options) {
  const out = options.stdout || stdout;
  const answers = options.answers;
  const username = answers.username || 'admin';
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(username)) throw new Error('username is invalid');
  if (answers.password !== answers.confirm) throw new Error('passwords do not match');
  assertPasswordPolicy(answers.password);
  parsePublicOrigin(answers.publicOrigin);
  await parseUpstreamUrl(answers.upstreamUrl, { allowPublic: false });
  const header = answers.header || 'X-Api-Key';
  if (!/^[A-Za-z0-9-]{1,64}$/.test(header)) throw new Error('header name is invalid');
  if (typeof answers.apiKey !== 'string' || answers.apiKey.length < 8) throw new Error('API key is invalid');
  if (Boolean(answers.certPath) !== Boolean(answers.keyPath)) {
    throw new Error('TLS certificate and private key must both be set, or both left empty');
  }
  if (answers.listenPort) {
    const port = Number(answers.listenPort);
    if (!Number.isInteger(port) || String(port) !== String(answers.listenPort) || port < 1 || port > 65535) {
      throw new Error('listen port is invalid');
    }
  }
  const dataDir = path.resolve(options.directory, answers.dataDir || 'data');
  const hashed = await hashPassword(answers.password);
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  await initializeStore({
    dataDir,
    clock: systemClock(),
    operator: { username, ...hashed },
  });
  const secretPath = path.join(dataDir, 'upstream-secret.json');
  await writeFile(secretPath, `${JSON.stringify({ apiKey: answers.apiKey })}\n`, { mode: 0o600 });
  await chmod(secretPath, 0o600).catch(() => {});
  await chmod(dataDir, 0o700).catch(() => {});
  const envPath = path.join(options.directory, '.env');
  const env = [
    'NODE_ENV=production',
    `PUBLIC_ORIGIN=${answers.publicOrigin}`,
    'MCP_PATH=/mcp',
    `LISTEN_HOST=${answers.certPath ? (answers.listenHost || '0.0.0.0') : '127.0.0.1'}`,
    `LISTEN_PORT=${answers.listenPort || (answers.certPath ? '443' : '8787')}`,
    ...(answers.certPath ? [`TLS_CERT_FILE=${answers.certPath}`, `TLS_KEY_FILE=${answers.keyPath}`] : []),
    `UPSTREAM_MCP_URL=${answers.upstreamUrl}`,
    `UPSTREAM_API_KEY_HEADER=${header}`,
    'ALLOW_PUBLIC_UPSTREAM=false',
    `DATA_DIR=${dataDir}`,
    'LOG_LEVEL=info',
    'ENABLE_LOCAL_TEST_HTTP=false',
    '# The upstream API key is stored in DATA_DIR/upstream-secret.json and is not written here.',
    '',
  ].join('\n');
  await writeFile(envPath, env, { mode: 0o600, flag: 'wx' });
  await chmod(envPath, 0o600).catch(() => {});
  if (process.platform === 'win32') {
    out.write('Windows does not apply POSIX modes. Restrict the ACLs for .env, data, and the TLS key to the operator account.\n');
  }
  const next = answers.certPath
    ? 'Next: npm start.'
    : `Next: point the reverse proxy at 127.0.0.1:${answers.listenPort || '8787'}, then npm start.`;
  out.write(`Initialized ${username} at ${answers.publicOrigin}. Upstream ${answers.upstreamUrl}. ${next}\n`);
}

async function ask(rl, prompt) {
  return (await rl.question(prompt)).trim();
}

/**
 * Read a secret on the same readline interface. Closing that interface and
 * then reading raw stdin lets Node exit on a TTY, so the next line falls
 * through to the shell. Muting echo keeps the process attached.
 * @param {{ question: Function, _writeToOutput?: Function, output?: { write: Function } }} rl
 * @param {string} prompt
 */
export async function askHidden(rl, prompt) {
  const output = rl.output || stdout;
  const previous = rl._writeToOutput;
  rl._writeToOutput = (text) => {
    if (typeof text === 'string' && /[\r\n]/.test(text)) output.write('\n');
  };
  try {
    return (await rl.question(prompt)).trim();
  } finally {
    rl._writeToOutput = previous;
  }
}

async function main() {
  const rl = readline.createInterface({ input: stdin, output: stdout, terminal: Boolean(stdin.isTTY) });
  let username;
  let password;
  let confirm;
  let upstreamUrl;
  let header;
  let apiKey;
  let publicOrigin;
  let listenPort;
  let certPath;
  let keyPath;
  try {
    username = (await ask(rl, 'Username [admin]: ')) || 'admin';
    password = await askHidden(rl, 'Password (16+ characters, not echoed): ');
    confirm = await askHidden(rl, 'Password again: ');
    upstreamUrl = await ask(rl, 'Upstream MCP URL: ');
    header = (await ask(rl, 'Upstream header [X-Api-Key]: ')) || 'X-Api-Key';
    apiKey = await askHidden(rl, 'Scoped MCP App key: ');
    publicOrigin = await ask(rl, 'Public origin: ');
    listenPort = (await ask(rl, 'Local listen port [8787]: ')) || '8787';
    certPath = await ask(rl, 'TLS certificate file (empty when Caddy terminates HTTPS): ');
    keyPath = certPath ? await ask(rl, 'TLS private key file: ') : '';
  } finally {
    rl.close();
  }
  await runInit({
    directory: process.cwd(),
    answers: { username, password, confirm, upstreamUrl, header, apiKey, publicOrigin, listenPort, certPath, keyPath },
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    process.stderr.write(`${err.message}\n`);
    process.exit(1);
  });
}
