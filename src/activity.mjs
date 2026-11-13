/**
 * In-memory activity feed for the admin panel.
 * Events are small and safe to show: which WhatsApp, which approval, which tool, and the result.
 * Message text, tool arguments, tokens, and API keys are not fields this log accepts.
 * @param {{ limit?: number, clock?: { now: () => number } }} [options]
 */
export function createActivityLog(options = {}) {
  const limit = options.limit || 400;
  const clock = options.clock || { now: () => Date.now() };
  /** @type {object[]} */
  const events = [];
  let nextId = 1;
  /** @type {Set<{ res: import('node:http').ServerResponse }>} */
  const clients = new Set();
  let heartbeat = null;

  function record(fields) {
    const event = sanitize(fields, nextId, clock.now());
    nextId += 1;
    events.push(event);
    while (events.length > limit) events.shift();
    const chunk = encode(event);
    for (const client of clients) writeClient(client, chunk);
    return event;
  }

  /**
   * @param {import('node:http').ServerResponse} res
   * @param {number} lastId
   */
  function attach(res, lastId) {
    const client = { res };
    clients.add(client);
    res.write(': connected\n\n');
    for (const event of events) {
      if (event.id > lastId) res.write(encode(event));
    }
    res.on('close', () => clients.delete(client));
  }

  function startHeartbeat(ms = 15000) {
    if (heartbeat) return;
    heartbeat = setInterval(() => {
      for (const client of clients) writeClient(client, ': ping\n\n');
    }, ms);
    if (typeof heartbeat.unref === 'function') heartbeat.unref();
  }

  function close() {
    if (heartbeat) clearInterval(heartbeat);
    heartbeat = null;
    for (const client of clients) {
      if (!client.res.writableEnded) client.res.end();
    }
    clients.clear();
  }

  return { record, attach, close, startHeartbeat };
}

/**
 * @param {object} fields
 * @param {number} id
 * @param {number} now
 */
function sanitize(fields, id, now) {
  const source = fields && typeof fields === 'object' ? fields : {};
  return {
    id,
    ts: new Date(now).toISOString(),
    upstreamId: token(source.upstreamId, 32),
    grantId: hexId(source.grantId),
    method: token(source.method, 64),
    tool: token(source.tool, 80),
    status: Number.isInteger(source.status) && source.status >= 0 && source.status <= 599 ? source.status : 0,
  };
}

/**
 * @param {unknown} value
 * @param {number} max
 */
function token(value, max) {
  if (typeof value !== 'string') return '';
  const clean = value.replace(/[^A-Za-z0-9._:/-]/g, '').slice(0, max);
  return clean;
}

/**
 * @param {unknown} value
 */
function hexId(value) {
  return typeof value === 'string' && /^[a-f0-9]{8,64}$/.test(value) ? value : '';
}

/**
 * @param {object} event
 */
function encode(event) {
  return `id: ${event.id}\ndata: ${JSON.stringify(event)}\n\n`;
}

/**
 * @param {{ res: import('node:http').ServerResponse }} client
 * @param {string} chunk
 */
function writeClient(client, chunk) {
  if (client.res.writableEnded || client.res.destroyed) return;
  client.res.write(chunk);
}
