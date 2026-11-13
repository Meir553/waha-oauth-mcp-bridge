import { spawn } from 'node:child_process';
import { cp, mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { nodeMajor } from '../src/crypto.mjs';
import { scanSource } from './security-check.mjs';

const ROOT = process.cwd();
const INCLUDE = ['package.json', 'README.md', '.env.example', 'src', 'scripts', 'systemd'];
const SECRET_MARKERS = ['BEGIN ' + 'PRIVATE KEY', 'BEGIN ' + 'RSA PRIVATE KEY'];

/**
 * @param {string} destination
 */
export async function packageDist(destination) {
  await rm(destination, { recursive: true, force: true });
  await mkdir(destination, { recursive: true });
  for (const item of INCLUDE) {
    const source = path.join(ROOT, item);
    const target = path.join(destination, item);
    const info = await stat(source).catch(() => null);
    if (!info) continue;
    if (info.isDirectory()) await cp(source, target, { recursive: true });
    else await cp(source, target);
  }
  const offenders = await findForbidden(destination);
  if (offenders.length) {
    throw new Error(`dist contains forbidden files: ${offenders.join(', ')}`);
  }
  const text = await readTree(destination);
  for (const marker of SECRET_MARKERS) {
    if (text.includes(marker)) {
      throw new Error('dist contains secret material');
    }
  }
  const assignedKey = new RegExp('UPSTREAM_' + 'API_KEY=(?!$|\\s*#).+');
  if (assignedKey.test(text)) {
    throw new Error('dist contains an upstream API key assignment');
  }
}

/**
 * @param {string} dir
 * @returns {Promise<string[]>}
 */
async function findForbidden(dir) {
  const found = [];
  async function walk(current) {
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === 'test' || entry.name === 'data') found.push(full);
        else await walk(full);
      } else if (/\.(pem|key|p12|pfx|env)$/i.test(entry.name) && entry.name !== '.env.example') {
        found.push(full);
      }
    }
  }
  await walk(dir);
  return found;
}

/**
 * @param {string} dir
 * @returns {Promise<string>}
 */
async function readTree(dir) {
  let text = '';
  async function walk(current) {
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (/\.(mjs|md|json|css|example|service)$/i.test(entry.name)) text += await readFile(full, 'utf8');
    }
  }
  await walk(dir);
  return text;
}

/**
 * @param {string[]} args
 * @returns {Promise<number>}
 */
function run(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, { cwd: ROOT, stdio: 'inherit' });
    child.on('exit', (code) => resolve(code ?? 1));
    child.on('error', reject);
  });
}

/**
 * @param {string} dir
 * @returns {Promise<string[]>}
 */
async function mjsFiles(dir) {
  const files = [];
  async function walk(current) {
    const entries = await readdir(current, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === 'data') continue;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (entry.name.endsWith('.mjs')) files.push(full);
    }
  }
  await walk(dir);
  return files;
}

async function main() {
  const version = process.version;
  process.stdout.write(`node ${version}\n`);
  if (nodeMajor(version) < 18) {
    process.stderr.write(`Node.js 18 or newer is required (found ${version}).\n`);
    process.exit(1);
  }
  for (const file of await mjsFiles(ROOT)) {
    const code = await run(['--check', file]);
    if (code !== 0) process.exit(code);
  }
  const findings = await scanSource(ROOT);
  if (findings.length) {
    for (const finding of findings) process.stderr.write(`${finding.file}:${finding.line} ${finding.name}\n`);
    process.exit(1);
  }
  const testCode = await run(['--test', 'test/oauth.test.mjs', 'test/proxy.test.mjs', 'test/gates.test.mjs', 'test/coverage.test.mjs', 'test/upstreams.test.mjs']);
  if (testCode !== 0) process.exit(testCode);
  await packageDist(path.join(ROOT, 'dist'));
  await writeFile(path.join(ROOT, 'dist', 'RUN.txt'), [
    'WAHA MCP OAuth Bridge',
    'Run with Node.js 18 or newer: npm start',
    'Edit .env, then: node scripts/init.mjs',
    'This package contains no third-party JavaScript and no secrets.',
    '',
  ].join('\n'));
  process.stdout.write('build: dist ready\n');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    process.stderr.write(`${err.stack || err.message}\n`);
    process.exit(1);
  });
}
