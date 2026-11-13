const OAUTH_SCHEME = { type: 'oauth2', scopes: ['mcp:access'] };

/**
 * @param {object} payload
 * @returns {object}
 */
export function enrichToolsListPayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw Object.assign(new Error('malformed tools list'), { code: 'bad_upstream' });
  }
  if (payload.error || payload.method || !payload.result || !Array.isArray(payload.result.tools)) {
    return payload;
  }
  return {
    ...payload,
    result: {
      ...payload.result,
      tools: payload.result.tools.map(enrichTool),
    },
  };
}

/**
 * @param {object} tool
 */
export function enrichTool(tool) {
  if (!tool || typeof tool !== 'object' || Array.isArray(tool)) return tool;
  const copy = { ...tool };
  const meta = tool._meta && typeof tool._meta === 'object' && !Array.isArray(tool._meta) ? { ...tool._meta } : {};
  const collected = [];
  for (const scheme of [...asSchemes(meta.securitySchemes), ...asSchemes(tool.securitySchemes)]) {
    if (!scheme || scheme.type === 'noauth') continue;
    collected.push(cloneScheme(scheme));
  }
  if (!collected.some((scheme) => scheme.type === 'oauth2' && Array.isArray(scheme.scopes) && scheme.scopes.includes('mcp:access'))) {
    collected.push({ type: OAUTH_SCHEME.type, scopes: OAUTH_SCHEME.scopes.slice() });
  }
  meta.securitySchemes = collected.map(cloneScheme);
  copy._meta = meta;
  copy.securitySchemes = collected.map(cloneScheme);
  if (tool.annotations && typeof tool.annotations === 'object' && !Array.isArray(tool.annotations)) {
    copy.annotations = { ...tool.annotations };
  }
  return copy;
}

/**
 * @param {Buffer} buffer
 * @param {string | number} requestId
 * @param {number} maxEventBytes
 * @returns {Buffer}
 */
export function transformSseToolsList(buffer, requestId, maxEventBytes) {
  const events = parseSseEvents(buffer, maxEventBytes);
  const pieces = [];
  for (const event of events) {
    let replaced = false;
    if (event.data) {
      try {
        const json = JSON.parse(event.data);
        if (isToolsListResult(json, requestId)) {
          const enriched = enrichToolsListPayload(json);
          pieces.push(Buffer.from(serializeSseEvent({ ...event, data: JSON.stringify(enriched) })));
          replaced = true;
        }
      } catch (err) {
        if (err && err.code === 'bad_upstream') throw err;
        if (event.data.trim().startsWith('{')) {
          throw Object.assign(new Error('malformed tools list'), { code: 'bad_upstream' });
        }
      }
    }
    if (!replaced) pieces.push(event.raw);
  }
  return Buffer.concat(pieces);
}

/**
 * @param {object} json
 * @param {string | number} requestId
 */
function isToolsListResult(json, requestId) {
  return Boolean(json)
    && typeof json === 'object'
    && !Array.isArray(json)
    && json.id === requestId
    && !json.method
    && !json.error
    && json.result
    && Array.isArray(json.result.tools);
}

/**
 * @param {Buffer} buffer
 * @param {number} maxEventBytes
 */
export function parseSseEvents(buffer, maxEventBytes) {
  const events = [];
  let lineStart = 0;
  let eventStart = 0;
  let sawLine = false;
  let current = blankEvent();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  for (let i = 0; i < buffer.length; i += 1) {
    const byte = buffer[i];
    if (byte !== 0x0a && byte !== 0x0d) continue;
    let next = i + 1;
    if (byte === 0x0d && buffer[i + 1] === 0x0a) next = i + 2;
    const line = buffer.subarray(lineStart, i);
    if (line.length === 0) {
      if (sawLine) {
        const raw = buffer.subarray(eventStart, next);
        if (raw.length > maxEventBytes) throw Object.assign(new Error('oversized sse event'), { code: 'bad_upstream' });
        events.push({ ...current, data: current.dataLines.join('\n'), raw });
      }
      current = blankEvent();
      sawLine = false;
      eventStart = next;
    } else {
      if (next - eventStart > maxEventBytes) throw Object.assign(new Error('oversized sse event'), { code: 'bad_upstream' });
      sawLine = true;
      applySseLine(current, decoder.decode(line));
    }
    lineStart = next;
    i = next - 1;
  }
  if (lineStart < buffer.length || sawLine) {
    throw Object.assign(new Error('truncated sse'), { code: 'bad_upstream' });
  }
  return events;
}

/**
 * @param {{ id?: string, event?: string, retry?: string, data?: string }} event
 */
export function serializeSseEvent(event) {
  let out = '';
  if (event.id !== undefined) out += `id: ${event.id}\n`;
  if (event.event !== undefined) out += `event: ${event.event}\n`;
  if (event.retry !== undefined) out += `retry: ${event.retry}\n`;
  const data = event.data ?? '';
  for (const line of String(data).split('\n')) out += `data: ${line}\n`;
  out += '\n';
  return out;
}

function blankEvent() {
  return { dataLines: [], id: undefined, event: undefined, retry: undefined };
}

/**
 * @param {{ dataLines: string[], id?: string, event?: string, retry?: string }} current
 * @param {string} text
 */
function applySseLine(current, text) {
  if (text.startsWith(':')) return;
  const idx = text.indexOf(':');
  const field = idx === -1 ? text : text.slice(0, idx);
  let value = idx === -1 ? '' : text.slice(idx + 1);
  if (value.startsWith(' ')) value = value.slice(1);
  if (field === 'data') current.dataLines.push(value);
  else if (field === 'id' && !value.includes('\0')) current.id = value;
  else if (field === 'event') current.event = value;
  else if (field === 'retry' && /^\d+$/.test(value)) current.retry = value;
}

/**
 * @param {unknown} value
 * @returns {object[]}
 */
function asSchemes(value) {
  return Array.isArray(value) ? value : [];
}

/**
 * @param {object} scheme
 */
function cloneScheme(scheme) {
  const copy = { type: scheme.type };
  if (Array.isArray(scheme.scopes)) copy.scopes = scheme.scopes.map((scope) => String(scope));
  return copy;
}
