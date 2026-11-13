import { chmod, lstat, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { pathToFileURL } from 'node:url';
import { assertPasswordPolicy, hashPassword } from '../src/crypto.mjs';
import { parsePublicOrigin, parseUpstreamUrl, systemClock } from '../src/config.mjs';
import { loadEnvFile } from '../src/env-file.mjs';
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
  const allowPublic = answers.allowPublic === true || answers.allowPublic === 'true';
  await parseUpstreamUrl(answers.upstreamUrl, { allowPublic });
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
  if (options.writeEnv !== false) {
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
    `ALLOW_PUBLIC_UPSTREAM=${allowPublic ? 'true' : 'false'}`,
    `DATA_DIR=${dataDir}`,
    'LOG_LEVEL=info',
    'ENABLE_LOCAL_TEST_HTTP=false',
    '# The upstream API key is stored in DATA_DIR/upstream-secret.json and is not written here.',
    '',
  ].join('\n');
  await writeFile(envPath, env, { mode: 0o600, flag: 'wx' });
  await chmod(envPath, 0o600).catch(() => {});
  }
  if (options.writeEnv !== false && process.platform === 'win32') {
    out.write('Windows does not apply POSIX modes. Restrict the ACLs for .env, data, and the TLS key to the operator account.\n');
  }
  if (options.writeEnv === false) {
    out.write(`Saved the admin login for ${username} and the WhatsApp key. The .env file was left as you wrote it.\n`);
    out.write(`Next: npm start, then open ${answers.publicOrigin}/admin\n`);
  } else {
    const next = answers.certPath
      ? 'Next: npm start.'
      : `Next: point the reverse proxy at 127.0.0.1:${answers.listenPort || '8787'}, then npm start.`;
    out.write(`Initialized ${username} at ${answers.publicOrigin}. Upstream ${answers.upstreamUrl}. ${next}\n`);
  }
}

/**
 * Plain-language check of the settings the operator edits in .env.
 * Returns an empty string when those settings are usable.
 * @param {NodeJS.ProcessEnv} env
 * @returns {Promise<string>}
 */
export async function describeEnvProblem(env) {
  const missing = ['PUBLIC_ORIGIN', 'UPSTREAM_MCP_URL', 'LISTEN_HOST', 'LISTEN_PORT'].filter((key) => !String(env[key] || '').trim());
  if (missing.length) {
    return [
      `These lines are missing or empty in .env: ${missing.join(', ')}.`,
      '',
      'Example:',
      '  PUBLIC_ORIGIN=https://mcp.example.com',
      '  LISTEN_HOST=127.0.0.1',
      '  LISTEN_PORT=8787',
      '  UPSTREAM_MCP_URL=http://127.0.0.1:3000/mcp',
      '',
      'PUBLIC_ORIGIN is the https address Caddy serves, with no path and no slash at the end.',
      'LISTEN_PORT is the free local port for this app. LISTEN_HOST stays 127.0.0.1 when Caddy is in front.',
      'UPSTREAM_MCP_URL is the first WAHA. On the same machine it usually ends in :3000/mcp.',
      '',
    ].join('\n');
  }
  try {
    parsePublicOrigin(env.PUBLIC_ORIGIN);
  } catch (err) {
    return [
      'PUBLIC_ORIGIN in .env needs to be fixed.',
      originHint(err instanceof Error ? err.message : ''),
      `It is currently: ${env.PUBLIC_ORIGIN}`,
      'Example: PUBLIC_ORIGIN=https://mcp.example.com',
      '',
    ].join('\n');
  }
  try {
    await parseUpstreamUrl(env.UPSTREAM_MCP_URL, { allowPublic: env.ALLOW_PUBLIC_UPSTREAM === 'true' });
  } catch (err) {
    return [
      'UPSTREAM_MCP_URL in .env needs to be fixed.',
      upstreamHint(err instanceof Error ? err.message : ''),
      `It is currently: ${env.UPSTREAM_MCP_URL}`,
      'Example: UPSTREAM_MCP_URL=http://127.0.0.1:3000/mcp',
      'If that WAHA really has a public address, set ALLOW_PUBLIC_UPSTREAM=true in .env.',
      '',
    ].join('\n');
  }
  const portText = String(env.LISTEN_PORT).trim();
  const port = Number(portText);
  if (!Number.isInteger(port) || String(port) !== portText || port < 1 || port > 65535) {
    return `LISTEN_PORT in .env needs to be a number from 1 to 65535, such as 8787.\nIt is currently: ${env.LISTEN_PORT}\n`;
  }
  const cert = String(env.TLS_CERT_FILE || '').trim();
  const key = String(env.TLS_KEY_FILE || '').trim();
  if (Boolean(cert) !== Boolean(key)) {
    return 'Set both TLS_CERT_FILE and TLS_KEY_FILE in .env, or leave both blank when Caddy has the certificate.\n';
  }
  return '';
}

/**
 * @param {string} message
 */
function originHint(message) {
  if (message.includes('trailing slash')) return 'Remove the slash at the end.';
  if (message.includes('https')) return 'It has to start with https://.';
  if (message.includes('path')) return 'Do not add a path. Use only the site name, such as https://mcp.example.com.';
  return 'Use the https address of this app, with no path and no slash at the end.';
}

/**
 * @param {string} message
 */
function upstreamHint(message) {
  if (message.includes('path')) return 'The address has to end in /mcp.';
  if (message.includes('not private')) return 'The address has to be on this machine or your private network, such as 127.0.0.1.';
  if (message.includes('userinfo')) return 'Do not put a username or password in the address.';
  return 'Use a private WAHA address that ends in /mcp.';
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
  const previousWriteToOutput = rl._writeToOutput;
  const previousWrite = output.write.bind(output);
  const showNewline = (text) => {
    const value = Buffer.isBuffer(text) ? text.toString('utf8') : String(text ?? '');
    if (/[\r\n]/.test(value)) previousWrite('\n');
  };
  rl._writeToOutput = showNewline;
  output.write = (chunk, encoding, callback) => {
    const value = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk ?? '');
    if (value === prompt || value.endsWith(prompt)) return previousWrite(chunk, encoding, callback);
    if (/[\r\n]/.test(value)) return previousWrite('\n', encoding, callback);
    if (typeof callback === 'function') callback();
    return true;
  };
  try {
    return (await rl.question(prompt)).trim();
  } finally {
    output.write = previousWrite;
    rl._writeToOutput = previousWriteToOutput;
  }
}

async function main() {
  const directory = process.cwd();
  const envPath = path.join(directory, '.env');
  const fileEnv = {};
  let found = false;
  try {
    found = await loadEnvFile(envPath, fileEnv);
  } catch (err) {
    const message = err instanceof Error ? err.message : '';
    if (message.includes('symlink')) {
      stdout.write('The .env file is a shortcut. Replace it with a normal file you can edit, then run this again.\n');
      process.exit(1);
    }
    throw err;
  }
  if (!found) {
    stdout.write([
      'There is no .env file in this folder yet.',
      '',
      'Copy the example, edit the lines below, then run this again.',
      'Linux:  cp .env.example .env',
      'Windows: copy .env.example .env',
      '',
      'Fill in:',
      '  PUBLIC_ORIGIN=https://the-name-caddy-serves',
      '  LISTEN_HOST=127.0.0.1',
      '  LISTEN_PORT=8787',
      '  UPSTREAM_MCP_URL=http://127.0.0.1:3000/mcp',
      '',
      'PUBLIC_ORIGIN is the https address in the browser. No path, and no slash at the end.',
      'LISTEN_PORT is any free port on this machine. Caddy forwards to 127.0.0.1 and that port.',
      'UPSTREAM_MCP_URL is the first WAHA. On this same machine it is usually http://127.0.0.1:3000/mcp.',
      'Leave TLS_CERT_FILE and TLS_KEY_FILE blank when Caddy has the certificate.',
      '',
      'Do not put the WAHA key in .env. This script asks for it after the file is ready.',
      '',
    ].join('\n'));
    process.exit(1);
  }
  const problem = await describeEnvProblem(fileEnv);
  if (problem) {
    stdout.write(`${problem}Edit .env and run this again. Nothing was saved.\n`);
    process.exit(1);
  }
  const dataDir = path.resolve(directory, fileEnv.DATA_DIR || 'data');
  try {
    await lstat(path.join(dataDir, 'state.json'));
    stdout.write([
      'An admin login is already saved in data/state.json.',
      'Nothing was changed, including .env.',
      'To start over, stop the app, delete the data folder, and run this again.',
      '',
    ].join('\n'));
    process.exit(1);
  } catch (err) {
    if (!err || err.code !== 'ENOENT') throw err;
  }

  const rl = readline.createInterface({ input: stdin, output: stdout, terminal: Boolean(stdin.isTTY) });
  let username;
  let password;
  let apiKey;
  try {
    stdout.write([
      'The addresses and the port come from .env. This script will not ask for them.',
      `Public address: ${fileEnv.PUBLIC_ORIGIN}`,
      `Local port: ${fileEnv.LISTEN_PORT}`,
      `First WAHA: ${fileEnv.UPSTREAM_MCP_URL}`,
      '',
      'Four questions follow. The password and the key are hidden while you type.',
      '',
    ].join('\n'));
    stdout.write([
      'Step 1 of 4. Admin username.',
      'This is the name you type on the admin page. It is not a WhatsApp number and not a ChatGPT login.',
      'Press Enter to use admin.',
      '',
    ].join('\n'));
    for (;;) {
      username = (await ask(rl, 'Username [admin]: ')) || 'admin';
      if (/^[A-Za-z0-9._-]{1,64}$/.test(username)) break;
      stdout.write('\nUse letters, numbers, dots, dashes, or underscores, up to 64 characters.\n\n');
    }
    stdout.write([
      '',
      'Step 2 of 4. Admin password.',
      'This password unlocks the admin page. It is not the WAHA key and not your ChatGPT password.',
      'Use at least 16 characters. What you type stays hidden.',
      '',
    ].join('\n'));
    for (;;) {
      password = await askHidden(rl, 'Password: ');
      stdout.write('\nStep 3 of 4. Type that same admin password again.\n\n');
      const confirm = await askHidden(rl, 'Password again: ');
      if (password !== confirm) {
        stdout.write('\nThose two passwords did not match. Please type the admin password again, both times.\n\n');
        continue;
      }
      try {
        assertPasswordPolicy(password);
        break;
      } catch {
        stdout.write('\nThat password is too short. It needs at least 16 characters. Please type a longer one.\n\n');
      }
    }
    stdout.write([
      '',
      'Step 4 of 4. WAHA MCP App key.',
      `This is the key for the WAHA at ${fileEnv.UPSTREAM_MCP_URL}.`,
      'In WAHA, open that session, open Apps, create an MCP App, and paste that app key here.',
      'Do not paste the master WAHA API key. The key stays hidden, and it is not written into .env.',
      '',
    ].join('\n'));
    for (;;) {
      apiKey = await askHidden(rl, 'MCP App key: ');
      if (apiKey.length >= 8 && apiKey.length <= 512 && !/[\u0000-\u001F\u007F]/.test(apiKey)) break;
      stdout.write('\nThat does not look like an MCP App key. Paste the key from the WAHA app, as one line.\n\n');
    }
  } finally {
    rl.close();
  }
  await runInit({
    directory,
    writeEnv: false,
    answers: {
      username,
      password,
      confirm: password,
      publicOrigin: fileEnv.PUBLIC_ORIGIN,
      upstreamUrl: fileEnv.UPSTREAM_MCP_URL,
      header: fileEnv.UPSTREAM_API_KEY_HEADER,
      apiKey,
      allowPublic: fileEnv.ALLOW_PUBLIC_UPSTREAM === 'true' ? 'true' : 'false',
      listenHost: fileEnv.LISTEN_HOST,
      listenPort: fileEnv.LISTEN_PORT,
      certPath: fileEnv.TLS_CERT_FILE || '',
      keyPath: fileEnv.TLS_KEY_FILE || '',
      dataDir: fileEnv.DATA_DIR || 'data',
    },
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    process.stderr.write(`${err.message}\n`);
    process.exit(1);
  });
}
