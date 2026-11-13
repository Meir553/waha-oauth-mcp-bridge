import { enrichTool, parseSseEvents } from './tool-metadata.mjs';

/** Everyday actions. Anything else stays hidden until ChatGPT searches for it. */
const FEATURED = ['chats-overview', 'chats-get-messages', 'send-text'];
const SEARCH_TOOL = 'search_tools';
const CALL_TOOL = 'call_tool';
const MATCH_LIMIT = 8;

const SEARCH = {
  name: SEARCH_TOOL,
  title: 'Search WhatsApp tools',
  description: 'Search for other WhatsApp tools. Use this when the action you need is not already listed. Try words such as image, voice, group, contact, or session. Then use call_tool with the exact name and the arguments from inputSchema.',
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'What you want to do' },
    },
    required: ['query'],
  },
};

const CALL = {
  name: CALL_TOOL,
  title: 'Use a WhatsApp tool',
  description: 'Run a WhatsApp tool that search_tools found. name is the exact tool name. arguments is an object matching that tool\'s inputSchema.',
  inputSchema: {
    type: 'object',
    properties: {
      name: { type: 'string', description: 'Exact tool name from search_tools' },
      arguments: { type: 'object', description: 'Arguments for that tool' },
    },
    required: ['name'],
  },
};

/**
 * @param {object[]} tools
 */
export function publicToolList(tools) {
  const byName = new Map(tools.filter(isTool).map((tool) => [tool.name, tool]));
  const featured = FEATURED.filter((name) => byName.has(name)).map((name) => enrichTool(byName.get(name)));
  return [...featured, enrichTool(SEARCH), enrichTool(CALL)];
}

/**
 * @param {object[]} tools
 * @param {string} query
 */
export function searchToolCatalog(tools, query) {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  const matches = tools.filter(isTool).filter((tool) => {
    const haystack = `${tool.name} ${tool.title || ''} ${tool.description || ''}`.toLowerCase();
    return words.every((word) => haystack.includes(word));
  }).slice(0, MATCH_LIMIT);
  return matches.map((tool) => ({
    name: tool.name,
    title: typeof tool.title === 'string' ? tool.title.slice(0, 120) : '',
    description: typeof tool.description === 'string' ? tool.description.slice(0, 500) : '',
    inputSchema: tool.inputSchema && typeof tool.inputSchema === 'object' ? tool.inputSchema : { type: 'object' },
  }));
}

/**
 * @param {unknown} value
 * @returns {string | null}
 */
export function cleanSearchQuery(value) {
  if (typeof value !== 'string') return null;
  const query = value.replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, 80);
  return query || null;
}

/**
 * @param {object | null | undefined} params
 * @returns {{ name: string, arguments: object } | { error: string }}
 */
export function readCallTool(params) {
  const args = params && typeof params === 'object' ? params.arguments : null;
  const name = args && typeof args.name === 'string' ? args.name : '';
  if (!/^[A-Za-z0-9._:-]{1,80}$/.test(name) || name === SEARCH_TOOL || name === CALL_TOOL) {
    return { error: 'Use the exact tool name from search_tools.' };
  }
  if (args.arguments === undefined) return { name, arguments: {} };
  if (!args.arguments || typeof args.arguments !== 'object' || Array.isArray(args.arguments)) {
    return { error: 'arguments must be an object.' };
  }
  return { name, arguments: args.arguments };
}

/**
 * @param {string} query
 * @param {object[]} matches
 */
export function formatSearchResult(query, matches) {
  if (!matches.length) {
    return `Nothing matched "${query}". Try a different word, such as image, group, contact, or session.`;
  }
  return `Use call_tool with the exact name and the arguments that inputSchema describes.\n${JSON.stringify(matches)}`;
}

/**
 * @param {Buffer} buffer
 * @param {string} contentType
 * @param {string | number} requestId
 * @param {number} maxEventBytes
 * @returns {object[] | null}
 */
export function toolsFromResponse(buffer, contentType, requestId, maxEventBytes) {
  if (contentType === 'text/event-stream') {
    const events = parseSseEvents(buffer, maxEventBytes);
    for (const event of events) {
      if (!event.data) continue;
      try {
        const tools = toolsFromRpc(JSON.parse(event.data), requestId);
        if (tools) return tools;
      } catch {
        /* a comment or a non-list event */
      }
    }
    return null;
  }
  return toolsFromRpc(JSON.parse(buffer.toString('utf8')), requestId);
}

/**
 * @param {object} rpc
 */
export function isSearchCall(rpc) {
  return Boolean(rpc) && !Array.isArray(rpc) && rpc.method === 'tools/call' && rpc.params && rpc.params.name === SEARCH_TOOL;
}

/**
 * @param {object} rpc
 */
export function isCallTool(rpc) {
  return Boolean(rpc) && !Array.isArray(rpc) && rpc.method === 'tools/call' && rpc.params && rpc.params.name === CALL_TOOL;
}

/**
 * @param {object} json
 * @param {string | number} requestId
 */
function toolsFromRpc(json, requestId) {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return null;
  if (json.id !== requestId || json.error || json.method) return null;
  if (!json.result || !Array.isArray(json.result.tools)) return null;
  return json.result.tools.filter(isTool);
}

/**
 * @param {object} tool
 */
function isTool(tool) {
  return Boolean(tool) && typeof tool === 'object' && !Array.isArray(tool) && typeof tool.name === 'string' && tool.name !== SEARCH_TOOL && tool.name !== CALL_TOOL;
}
