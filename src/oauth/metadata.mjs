/**
 * @param {{ resource: string, issuer: string }} config
 */
export function protectedResourceMetadata(config) {
  return {
    resource: config.resource,
    authorization_servers: [config.issuer],
    scopes_supported: ['mcp:access'],
  };
}

/**
 * @param {{ issuer: string, publicOrigin: string }} config
 */
export function authorizationServerMetadata(config) {
  return {
    issuer: config.issuer,
    authorization_endpoint: `${config.publicOrigin}/oauth/authorize`,
    token_endpoint: `${config.publicOrigin}/oauth/token`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
    scopes_supported: ['mcp:access', 'offline_access'],
  };
}

/**
 * @param {{ publicOrigin: string }} config
 * @param {{ error?: string }} [options]
 */
export function wwwAuthenticate(config, options = {}) {
  const metadata = options.metadataUrl || `${config.publicOrigin}/.well-known/oauth-protected-resource`;
  const parts = [];
  if (options.error) parts.push(`error="${options.error}"`);
  parts.push(`resource_metadata="${metadata}"`);
  parts.push('scope="mcp:access"');
  return `Bearer ${parts.join(', ')}`;
}

const SCOPE_ORDER = ['mcp:access', 'offline_access'];

/**
 * @param {string | undefined} scope
 * @returns {{ ok: true, scopes: string[] } | { ok: false }}
 */
export function parseScope(scope) {
  if (typeof scope !== 'string' || scope.length === 0 || scope.length > 128) return { ok: false };
  if (scope !== scope.trim() || scope.includes('  ') || /[\u0000-\u001F\u007F]/.test(scope)) return { ok: false };
  const parts = scope.split(' ');
  if (new Set(parts).size !== parts.length) return { ok: false };
  if (!parts.every((part) => SCOPE_ORDER.includes(part))) return { ok: false };
  if (!parts.includes('mcp:access')) return { ok: false };
  return { ok: true, scopes: SCOPE_ORDER.filter((part) => parts.includes(part)) };
}
