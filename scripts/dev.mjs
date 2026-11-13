import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadEnvFile } from '../src/env-file.mjs';

async function main() {
  await loadEnvFile(path.join(process.cwd(), '.env'));
  if (process.env.NODE_ENV === 'production') {
    process.stderr.write('dev: NODE_ENV=production from the environment is changed to development for this process only.\n');
  }
  process.env.NODE_ENV = 'development';
  process.env.ENABLE_LOCAL_TEST_HTTP = 'true';
  process.env.LISTEN_HOST = '127.0.0.1';
  if (!process.env.LISTEN_PORT || process.env.LISTEN_PORT === '443' || process.env.LISTEN_PORT === '0') {
    process.env.LISTEN_PORT = '8787';
  }
  process.stderr.write(`dev: plain HTTP on 127.0.0.1:${process.env.LISTEN_PORT}. This listener is not the production TLS server.\n`);
  await import('../src/main.mjs');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    process.stderr.write(`${err.message}\n`);
    process.exit(1);
  });
}
