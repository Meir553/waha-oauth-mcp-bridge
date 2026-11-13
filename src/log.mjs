const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

/**
 * Structured JSON logger. Every line is passed through secret redaction.
 * Bodies, tokens, and header dumps are not accepted as fields by convention.
 * @param {{ level?: string, secrets?: string[], sink?: { write: (s: string) => void }, clock?: { now: () => number } }} options
 */
export function createLogger(options = {}) {
  const level = LEVELS[options.level] ? options.level : 'info';
  const secrets = Array.isArray(options.secrets) ? options.secrets.filter((s) => typeof s === 'string' && s.length >= 6) : [];
  const sink = options.sink || process.stdout;
  const clock = options.clock || { now: () => Date.now() };

  function emit(levelName, fields) {
    if (LEVELS[levelName] < LEVELS[level]) return;
    const payload = {
      ts: new Date(clock.now()).toISOString(),
      level: levelName,
    };
    if (fields && typeof fields === 'object') {
      for (const [key, value] of Object.entries(fields)) {
        if (value === undefined) continue;
        payload[key] = value;
      }
    }
    let line;
    try {
      line = JSON.stringify(payload);
    } catch {
      line = JSON.stringify({ ts: payload.ts, level: levelName, event: 'log_serialize_error' });
    }
    for (const secret of secrets) {
      line = line.split(secret).join('[redacted]');
    }
    sink.write(`${line}\n`);
  }

  return {
    debug(fields) { emit('debug', fields); },
    info(fields) { emit('info', fields); },
    warn(fields) { emit('warn', fields); },
    error(fields) { emit('error', fields); },
    addSecret(secret) {
      if (typeof secret === 'string' && secret.length >= 6 && !secrets.includes(secret)) secrets.push(secret);
    },
  };
}

/**
 * @param {{ write: (s: string) => void }} [base]
 * @returns {{ sink: { write: (s: string) => void }, lines: () => string[] }}
 */
export function captureSink() {
  const lines = [];
  return {
    lines: () => lines.slice(),
    sink: {
      write(chunk) {
        lines.push(String(chunk));
      },
    },
  };
}
