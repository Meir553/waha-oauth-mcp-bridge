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
    `LISTEN_HOST=${answers.listenHost || '0.0.0.0'}`,
    `LISTEN_PORT=${answers.listenPort || '443'}`,
    `TLS_CERT_FILE=${answers.certPath}`,
    `TLS_KEY_FILE=${answers.keyPath}`,
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
  out.write(`Initialized ${username} at ${answers.publicOrigin}. Upstream ${answers.upstreamUrl}. Next: install the TLS files, then npm start.\n`);
}

async function ask(rl, prompt) {
  return (await rl.question(prompt)).trim();
}

async function askSecret(prompt) {
  if (!stdin.isTTY) {
    const rl = readline.createInterface({ input: stdin, output: stdout });
    const value = (await rl.question(prompt)).trim();
    rl.close();
    return value;
  }
  stdout.write(prompt);
  stdin.setRawMode(true);
  return new Promise((resolve) => {
    let value = '';
    const onData = (buf) => {
      const text = buf.toString('utf8');
      if (text === '\u0003') process.exit(1);
      if (text === '\r' || text === '\n') {
        stdin.setRawMode(false);
        stdin.off('data', onData);
        stdout.write('\n');
        resolve(value);
        return;
      }
      if (text === '\u007f' || text === '\b') {
        value = value.slice(0, -1);
        return;
      }
      if (text >= ' ' ) value += text;
    };
    stdin.on('data', onData);
  });
}

async function main() {
  const rl = readline.createInterface({ input: stdin, output: stdout });
  const username = (await ask(rl, 'Username [admin]: ')) || 'admin';
  rl.close();
  const password = await askSecret('Password (16+ characters, not echoed when possible): ');
  const confirm = await askSecret('Password again: ');
  const rl2 = readline.createInterface({ input: stdin, output: stdout });
  const upstreamUrl = await ask(rl2, 'Upstream MCP URL: ');
  const header = (await ask(rl2, 'Upstream header [X-Api-Key]: ')) || 'X-Api-Key';
  rl2.close();
  const apiKey = await askSecret('Scoped MCP App key: ');
  const rl3 = readline.createInterface({ input: stdin, output: stdout });
  const publicOrigin = await ask(rl3, 'Public origin: ');
  const certPath = await ask(rl3, 'TLS certificate file: ');
  const keyPath = await ask(rl3, 'TLS private key file: ');
  rl3.close();
  await runInit({
    directory: process.cwd(),
    answers: { username, password, confirm, upstreamUrl, header, apiKey, publicOrigin, certPath, keyPath },
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    process.stderr.write(`${err.message}\n`);
    process.exit(1);
  });
}
