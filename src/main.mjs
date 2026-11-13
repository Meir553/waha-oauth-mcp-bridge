import path from 'node:path';
import { createLogger } from './log.mjs';
import { loadConfig, systemClock } from './config.mjs';
import { loadEnvFile } from './env-file.mjs';
import { openStore } from './store.mjs';
import { createCimdResolver } from './oauth/cimd.mjs';
import { startBridge } from './server.mjs';

const clock = systemClock();
let bridge;
let store;
let shuttingDown = false;

async function main() {
  await loadEnvFile(path.join(process.cwd(), '.env'));
  const config = await loadConfig(process.env);
  const logger = createLogger({ level: config.logLevel, secrets: config.upstreams.map((item) => item.apiKey), clock });
  store = await openStore({ dataDir: config.dataDir, clock, logger });
  const cimd = createCimdResolver({
    clock,
    ttlMs: config.limits.cimdCacheMs,
    timeoutMs: config.limits.cimdTimeoutMs,
    maxBytes: config.limits.cimdMaxBytes,
  });
  bridge = await startBridge({ config, store, logger, clock, cimd });
  logger.info({ event: 'ready', route: config.mcpPath, status: 0 });
  process.on('SIGINT', () => { shutdown(logger, 0); });
  process.on('SIGTERM', () => { shutdown(logger, 0); });
}

async function shutdown(logger, code) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info({ event: 'shutdown' });
  try {
    if (bridge) await bridge.close();
    else if (store) await store.close();
  } catch {
    logger.error({ event: 'shutdown_error', errorCategory: 'shutdown' });
    process.exit(1);
  }
  process.exit(code);
}

main().catch((err) => {
  const message = err && err.message ? err.message : 'startup failed';
  process.stderr.write(`${JSON.stringify({ event: 'startup_failed', errorCategory: 'startup', message })}\n`);
  process.exit(1);
});
