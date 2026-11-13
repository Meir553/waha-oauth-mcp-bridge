import { lstat, readFile } from 'node:fs/promises';
import path from 'node:path';
import { atomicWriteJson } from './store.mjs';

const ID_RE = /^[a-z][a-z0-9-]{0,31}$/;
const FILE_NAME = 'upstreams.json';

/**
 * @param {string} id
 */
export function assertUpstreamId(id) {
  if (typeof id !== 'string' || !ID_RE.test(id) || id === 'default') {
    throw new Error('upstream id is invalid');
  }
  return id;
}

/**
 * @param {unknown} value
 */
export function cleanDisplayName(value) {
  const name = String(value ?? '').replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, 80);
  if (!name) throw new Error('upstream display name is invalid');
  return name;
}

/**
 * @param {unknown} key
 */
export function assertApiKey(key) {
  if (typeof key !== 'string' || key.length < 8 || key.length > 512 || /[\u0000-\u001F\u007F]/.test(key)) {
    throw new Error('upstream API key is missing or invalid');
  }
  return key;
}

/**
 * Additional WAHA endpoints live in DATA_DIR/upstreams.json.
 * A missing file means there are no extras. The default upstream stays in the environment.
 * @param {string} file
 * @returns {Promise<Array<{ id: string, url: string, displayName: string, apiKey: string }>>}
 */
export async function readUpstreamDefinitions(file) {
  let stat;
  try {
    stat = await lstat(file);
  } catch (err) {
    if (err && err.code === 'ENOENT') return [];
    throw new Error('upstreams file is unreadable');
  }
  if (stat.isSymbolicLink()) throw new Error('upstreams file is a symlink');
  if (!stat.isFile()) throw new Error('upstreams file is unreadable');
  let parsed;
  try {
    parsed = JSON.parse(await readFile(file, 'utf8'));
  } catch {
    throw new Error('upstreams file is invalid');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('upstreams file is invalid');
  const definitions = [];
  const seen = new Set();
  for (const [id, value] of Object.entries(parsed)) {
    assertUpstreamId(id);
    if (seen.has(id)) throw new Error('upstream id is invalid');
    seen.add(id);
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('upstream entry is invalid');
    const unknown = Object.keys(value).filter((key) => !['url', 'displayName', 'apiKey'].includes(key));
    if (unknown.length) throw new Error('upstream entry is invalid');
    if (typeof value.url !== 'string' || typeof value.displayName !== 'string' || typeof value.apiKey !== 'string') {
      throw new Error('upstream entry is invalid');
    }
    definitions.push({
      id,
      url: value.url,
      displayName: value.displayName,
      apiKey: value.apiKey,
    });
  }
  if (definitions.length > 31) throw new Error('too many upstreams');
  return definitions;
}

/**
 * @param {string} dataDir
 * @param {Array<{ id: string, url: string, displayName: string, apiKey: string }>} definitions
 */
export async function writeUpstreamDefinitions(dataDir, definitions) {
  const body = {};
  for (const definition of definitions) {
    const id = assertUpstreamId(definition.id);
    body[id] = {
      url: definition.url,
      displayName: cleanDisplayName(definition.displayName),
      apiKey: assertApiKey(definition.apiKey),
    };
  }
  await atomicWriteJson(path.join(dataDir, FILE_NAME), body);
}

/**
 * The default WAHA is served at /mcp. Every other WAHA is served at /mcp/{id}.
 * A token's resource must match that exact URL.
 * @param {string} origin
 * @param {object[]} entries
 */
export function registerUpstreams(origin, entries) {
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > 32) throw new Error('too many upstreams');
  const byId = new Map();
  const byPath = new Map();
  const byResource = new Map();
  const byMetadata = new Map();
  for (const entry of entries) {
    if (!entry || typeof entry.id !== 'string') throw new Error('upstream id is invalid');
    if (entry.id !== 'default') assertUpstreamId(entry.id);
    const routePath = entry.id === 'default' ? '/mcp' : `/mcp/${entry.id}`;
    const resource = `${origin}${routePath}`;
    const metadataPath = entry.id === 'default'
      ? '/.well-known/oauth-protected-resource'
      : `/.well-known/oauth-protected-resource/mcp/${entry.id}`;
    if (byId.has(entry.id) || byResource.has(resource)) throw new Error('upstream id is invalid');
    const record = {
      ...entry,
      path: routePath,
      resource,
      metadataPath,
      metadataUrl: `${origin}${metadataPath}`,
    };
    byId.set(entry.id, record);
    byPath.set(routePath, record);
    byResource.set(resource, record);
    byMetadata.set(metadataPath, record);
    if (entry.id === 'default') byMetadata.set('/.well-known/oauth-protected-resource/mcp', record);
  }
  if (!byId.has('default')) throw new Error('upstream id is invalid');
  return { byId, byPath, byResource, byMetadata, list: [...byId.values()] };
}

/**
 * Swap the live maps the request router reads. Call this after the upstream file is saved.
 * @param {object} config
 * @param {{ byId: Map<string, object>, byPath: Map<string, object>, byResource: Map<string, object>, byMetadata: Map<string, object>, list: object[] }} registry
 */
export function installRegistry(config, registry) {
  config.upstreamById = registry.byId;
  config.upstreamByPath = registry.byPath;
  config.upstreamByResource = registry.byResource;
  config.upstreamByMetadata = registry.byMetadata;
  config.upstreams = registry.list;
  config.upstream = registry.byId.get('default');
  config.resource = registry.byId.get('default').resource;
}
