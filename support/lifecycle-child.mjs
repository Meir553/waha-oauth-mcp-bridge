import { createLogger } from '../src/log.mjs';
import { loadConfig } from '../src/config.mjs';
import { createCimdResolver } from '../src/oauth/cimd.mjs';
import { startBridge } from '../src/server.mjs';
import { openStore } from '../src/store.mjs';

const clock = { now: () => Date.now() };
const config = await loadConfig(process.env);
const logger = createLogger({
  level: 'error',
  secrets: [config.upstream.apiKey],
  clock,
  sink: { write() {} },
});
const store = await openStore({ dataDir: config.dataDir, clock, logger });
const cimd = createCimdResolver({
  clock,
  ttlMs: config.limits.cimdCacheMs,
  timeoutMs: 1000,
  maxBytes: 65536,
  fetchImpl: async () => ({ status: 404, headers: { 'content-type': 'application/json' }, body: Buffer.from('{}') }),
});
const bridge = await startBridge({ config, store, logger, clock, cimd });
let stopping = false;

async function stop() {
  if (stopping) return;
  stopping = true;
  try {
    await bridge.close();
  } catch {
    process.exit(1);
  }
  process.exit(0);
}

process.on('SIGTERM', () => { stop(); });
process.on('SIGINT', () => { stop(); });
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  if (String(chunk).includes('stop')) stop();
});
process.stdout.write(`ready ${bridge.port}\n`);
