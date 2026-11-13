# 05 — Authoritative sources checked 2026-11-12

These URLs are reference material and are **not** runtime package dependencies. Verify them again before implementing a future protocol upgrade; do not rely on memory or guesses for incompatible changes.

1. **OpenAI plugin authentication** (official): https://developers.openai.com/plugins/build/auth — OAuth 2.1; Protected Resource Metadata; Authorization Server Metadata; PKCE S256; CIMD and DCR; client callback and `iss`; `resource` parameter; ChatGPT CIMD supports `none` and `private_key_jwt`; per-tool `securitySchemes` and `mcp/www_authenticate`.
2. **OpenAI connecting custom MCP servers** (official, frequently updated): https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt — custom MCP plan availability, Plugins setup, public HTTPS requirement, OAuth refresh requirements, mobile limits.
3. **OpenAI custom MCP setup** (official): https://developers.openai.com/api/docs/guides/custom-mcp-server — endpoint transport options, OAuth vs no auth, plugin connection.
4. **Live ChatGPT CIMD document** (OpenAI endpoint): https://chatgpt.com/oauth/client.json — as checked, publishes `client_id` matching URL, `redirect_uris` including `https://chatgpt.com/connector_platform_oauth_redirect`, and `token_endpoint_auth_methods_supported:["none","private_key_jwt"]` with legacy preference `private_key_jwt`. Query via native HTTPS when authorization actually happens, not hardcoded as a security bypass.
5. **WAHA MCP official**: https://waha.devlike.pro/docs/apps/mcp/ — one MCP App per WAHA session; scoped MCP App key recommended; `http://localhost:3000/mcp` and `X-Api-Key`, `WAHA_APPS_ENABLED=True`.
6. **MCP authorization specification 2025-11-25**: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization — resource and issuer, OAuth discovery, code verifier, token audience, WWW-Authenticate.
7. **MCP Streamable HTTP specification 2025-11-25**: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports — POST/GET/DELETE, SSE, `Mcp-Session-Id`, version headers, Origin validation.
8. **Cursor rules** (official): https://docs.cursor.com/context/rules-for-ai — `.cursor/rules/*.mdc` and root `AGENTS.md` recognized as project rules.
9. **Node.js release schedule**: https://nodejs.org/en/about/previous-releases — Node.js 26 active LTS as of this research date.
10. **OAuth RFCs (primary standards)**: RFC 8414 https://www.rfc-editor.org/rfc/rfc8414 ; RFC 8707 https://www.rfc-editor.org/rfc/rfc8707 ; RFC 9728 https://www.rfc-editor.org/rfc/rfc9728 ; RFC 9207 https://www.rfc-editor.org/rfc/rfc9207 ; RFC 7636 https://www.rfc-editor.org/rfc/rfc7636 ; RFC 6750 https://www.rfc-editor.org/rfc/rfc6750 .

## Explicit decisions and alternatives

| Topic | P0 decision | Why / tradeoff |
|---|---|---|
| Runtime | Node.js 18 or newer, native JS/ESM | No npm dependencies/compiler. The original pin was Node 26; the floor is now 18 so current and previous LTS lines can run the same built-in code. |
| Public auth | OAuth authorization code + PKCE S256 + issuer `iss` | Current ChatGPT/MCP contract. |
| Client registration | CIMD allowlisted ChatGPT client only | No DCR endpoint, smaller attack surface; supported by ChatGPT, but needs actual ChatGPT validation. |
| Client authentication | `none` public-client + PKCE | ChatGPT CIMD advertises `none`; optional `private_key_jwt` deferred, not falsely advertised. |
| Tokens | Opaque hashed-at-rest bearer and rotating refresh | Avoid separate JWT signing/JWKS implementation; same process is AS and resource server. |
| Refresh | Issued to explicitly approved ChatGPT grant even if `offline_access` absent | Avoid repeated login when only `mcp:access` requested; consent discloses persistent access. |
| Scope | One `mcp:access`; WAHA App key determines read/send/control | No false promises of per-tool OAuth access control where tool permission mapping is unknown. |
| Upstream transport | Fixed private Streamable HTTP WAHA endpoint | No WAHA modification, preserves evolving tool set. |
| Tool metadata | Only `tools/list` OAuth security enrichment | Helps OpenAI link flow while preserving upstream tools. |
| State | Single-writer durable atomic JSON | No database dependency; suitable only for single instance and modest token count. |
| HTTPS | Built-in Node HTTPS; manually provision trusted cert | No hosted proxy or ACME dependency built into application. |
| Deployment | Single process/systemd suggested | Simple ops; no horizontal scaling in P0. |
| ChatGPT entitlement | External/manual acceptance gate | Plan cannot alter account eligibility. |

## Compatibility caution: draft MCP protocol

The site's *draft* transports may diverge from the published 2025-11-25 spec (e.g. changes to session headers). Build for documented WAHA's actual installed protocol version and the published transport; preserve requested `Mcp-Protocol-Version`, and don't automatically implement draft breaking changes. During real WAHA integration, record actual initialize negotiation and adjust compatibility only with tests.

## Security and reliability caveat

No software specification can guarantee a mistake-free security implementation or assure ChatGPT behavior without live testing. The definition of done is precise automated local passing evidence **plus** explicitly outstanding live integration checks; make no false blanket 100%-verified claims.

11. **Cursor Plan Mode** (official): https://prod.cursor.com/docs/agent/plan-mode — Build is an action on a plan registered by Cursor Plan Mode; standalone Markdown isn't guaranteed to activate the UI.
12. **Cursor help on how Plan Mode works** (official): https://prod.cursor.com/help/ai-features/plan-mode — switch Shift+Tab, review the generated plan, click Build.
