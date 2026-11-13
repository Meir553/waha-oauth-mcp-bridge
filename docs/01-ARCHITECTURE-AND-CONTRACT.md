# 01 — Architecture, user contract, boundaries (P0)

## 1. Purpose and exact user-visible behavior

Make an independently hosted OAuth-to-MCP bridge that accepts remote ChatGPT-style MCP Streamable HTTP connections protected by a local authorization server and forwards each authorized MCP request to one operator-configured WAHA MCP endpoint with that WAHA's scoped `X-Api-Key`. The bridge must not modify WAHA's API or reimplement WAHA's tools. WAHA's tool list, input schemas, results, resources, and prompts remain discoverable. A successful authorized message receives the upstream response (except tightly defined security metadata enrichment in `tools/list`).

One operator and one Node process can register multiple WAHA endpoints. Each ChatGPT authorization is one grant bound to exactly one of those endpoints. The operator chooses the binding by giving that ChatGPT the endpoint's URL and approving the named WAHA on the consent screen. A token for one WAHA is rejected on every other WAHA. Do not build a generic multi-tenant SaaS, OAuth federation, remote admin dashboard, or a router that accepts an upstream URL from the client.

### ASCII flow

```
ChatGPT (OAuth client)
    | HTTPS: GET /.well-known/*; GET /oauth/authorize; POST /oauth/token
    | HTTPS: POST/GET/DELETE /mcp  Authorization: Bearer <opaque-access-token>
    v
Node 18+ native HTTPS server (same public origin)
    |- OAuth resource metadata + authorization-server metadata
    |- password-protected operator login and consent
    |- Authorization Code + PKCE S256 + CIMD identity
    |- opaque access/refresh token issuer, revocation and encrypted-at-rest? NO: hashed-at-rest
    |- enforce resource, scope, origin, session/grant and headers
    |- fixed upstream stream proxy; inject X-Api-Key privately
    v
WAHA MCP App at fixed private URL (e.g. http://127.0.0.1:3000/mcp)
```

## 2. Assumptions and non-goals

- Node.js **18 or newer**; use ESM `.mjs` or `type:module` `.js` consistently. Startup refuses a major version below 18. The original contract named Node 26 only; that floor was lowered so the same built-in-module program runs on current and previous LTS lines.
- Zero external **npm** packages, remote hosted auth services, CDNs, GUI frameworks, caches, background workers, relational databases, or hosted logging. Built-in Node modules and the host OS are allowed.
- ChatGPT itself and (when using CIMD) its published HTTPS client metadata endpoint are necessary external parties in this integration; no runtime dependency on a *separate* third-party provider.
- The operator must separately supply a DNS name, public IP/port reachability, production CA-trusted TLS certificate, and a dedicated scoped WAHA MCP App API key. Do **not** silently generate a production self-signed certificate or pretend DNS/certificate issuance can be done without outside infrastructure.
- No guarantee that a particular ChatGPT account has custom MCP entitlement. Current OpenAI docs limit full functionality to Business and Enterprise/Edu; Pro read/fetch only and Plus not included. Real end-to-end test cannot be claimed without an authorized ChatGPT workspace.
- No unrestricted `WAHA_API_KEY` master key by default. Dedicated MCP App per WhatsApp session, minimal permissions chosen in WAHA; initial suggested read-only, optionally send after intentional admin enablement.
- Existing WAHA process, port, data, and docker compose must not be changed by build tool.
- Direct Node HTTPS preferred; optional cohosting behind an already-installed *self-hosted* reverse proxy is outside P0. If 443 is occupied, document a different port or existing proxy option; do not kill services or assume special port support in ChatGPT without testing.
- This project is **not** an end-user WhatsApp client or a message database. Never cache WhatsApp message bodies as application state.

## 3. Public surface / exact routes

| Method | Path | Access | Exact function |
|---|---|---|---|
| GET | `/.well-known/oauth-protected-resource` | Public | RFC 9728 metadata; `resource` is exact public MCP URI. |
| GET | `/.well-known/oauth-protected-resource/mcp` | Public | Return same metadata, for resource-path discovery. |
| GET | `/.well-known/oauth-authorization-server` | Public | RFC 8414 authorization server metadata with stable issuer. |
| GET | `/oauth/authorize` | Browser | Parse/validate and persist authorization request; require login + consent. |
| GET | `/login` | Browser | Short, safe form; no reflected query strings or secrets. |
| POST | `/login` | Browser | CSRF-protected password authentication; rate-limited. |
| GET | `/oauth/consent` | Browser-auth | Show registered client name, fixed scopes, upstream action warning. |
| POST | `/oauth/consent` | Browser-auth | CSRF check, approve or deny; issue single-use authorization code only upon approval. |
| POST | `/oauth/token` | OAuth client | JSON `application/json` success; form body for grants; auth-code and refresh grants. |
| POST | `/logout` | Browser-auth | CSRF check and erase cookie session. |
| POST | `/mcp` | Bearer required | Streamable HTTP messages. |
| GET | `/mcp` | Bearer required | Upstream optional SSE or upstream 405. |
| DELETE | `/mcp` | Bearer required | Forward session close or upstream 405. |
| GET | `/health/live` | Public | Minimal response; no upstream host, keys, status details. |
| any | other paths | None | 404 / 405; do not serve `.env` or `data/`. |

If resource metadata path includes another base path, implement equivalently with path-based metadata discovery. No support for multiple upstreams in P0.

## 4. OAuth / MCP identifiers and metadata (fixed rule)

Choose the public canonical origin `O = https://mcp.example.com` and MCP resource `R = O + '/mcp'`. **This is an implementation choice.** Store `R` as an exact configured constant; do not compute it from untrusted HTTP `Host`, proxy headers, request parameters, or mutable origins. Set authorization-server issuer `ISS = O` (no trailing slash). Validate exact `resource = R` for authorization code and token requests; record `R` as access token audience; reject missing/wrong resources rather than mint an overbroad token. In real integration confirm ChatGPT's requested `resource` matches the advertised metadata and fix only if authoritative spec permits it.

Protected resource JSON (example with placeholder origin):

```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://mcp.example.com"],
  "scopes_supported": ["mcp:access"]
}
```

Authorization metadata (exact discovery keys, adjust URLs from `PUBLIC_ORIGIN`; no trailing slash for issuer):

```json
{
  "issuer": "https://mcp.example.com",
  "authorization_endpoint": "https://mcp.example.com/oauth/authorize",
  "token_endpoint": "https://mcp.example.com/oauth/token",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"],
  "client_id_metadata_document_supported": true,
  "authorization_response_iss_parameter_supported": true,
  "scopes_supported": ["mcp:access", "offline_access"]
}
```

CIMD public-client method `none` is intentionally selected to keep the implementation small. At time of research, ChatGPT's published CIMD advertises both `none` and `private_key_jwt`, with `private_key_jwt` as legacy preference; the intersection with our `none`-only authorization server is `none`. Build tests for this exact negotiation. No `private_key_jwt` claims without actual implementation. `registration_endpoint` must NOT be advertised because Dynamic Client Registration is not supported in P0. Do not silently accept unregistered `client_id` origins. The server must fetch and validate the known client metadata or operate using an explicitly predefined, verified client allowlist; prefer fetching with pinned trusted origin and strict redirect allowlist.

Include `iss=ISS` on all authorization redirect responses **including OAuth errors** when redirects are safe. Never redirect if `client_id` or redirect URI is untrusted; render local error instead.

## 5. Authentication and scope model

- One local administrator/operator account, initialized by private CLI; username optional but password required. Store password with `scrypt` and random salt, using robust parameters; no plaintext passwords or password-derived output in logs.
- Scope exposed to OAuth = `mcp:access` for all MCP tools plus `offline_access` for refresh grant if requested and policy allows. Avoid pretending OAuth `mcp:access` grants read-only or send-only: **WAHA's MCP App key** applies true WhatsApp permissions.
- Require OAuth login for *all* MCP POST/GET/DELETE and all tool discovery. Never include `noauth` in tools metadata. Missing/malformed/expired credentials -> 401 + `WWW-Authenticate: Bearer resource_metadata="<O>/.well-known/oauth-protected-resource", scope="mcp:access"` (with error parameter when appropriate). Valid token without `mcp:access` -> 403 with `insufficient_scope` challenge.
- Access token: cryptographically random opaque bearer value, 32 or more bytes entropy, hash at rest (SHA-256 index) with server-side expiry/issuer/resource/client/grant/scopes. No JWT or JWKS required because resource and authorization server are the same process and can look up opaque tokens securely.
- Refresh token: random opaque value (48 or more bytes entropy), hash at rest, issued only to eligible approved grant with `offline_access` (or equivalent verified semantics). Rotate on every successful refresh; detect replay and revoke the entire token family; token exchange must be atomic and durable. Persist through normal restarts.
- Suggested TTLs: code 120 sec, access 900 sec, refresh absolute 30 days, browser session idle 15 min / absolute 8h, authorization request 10 min. TTLs configurable within safe ranges, never infinite. Clock skew narrowly controlled. Revoke all with local admin CLI.
- An authorization code is used *exactly once*, bound to `client_id`, registered `redirect_uri`, `resource`, `code_challenge`, scope set, user, issuer, and expiry. Code verifier must match S256 exactly; reject `plain`, missing verifier, invalid lengths/characters, wrong/expired/replayed code, wrong resource, wrong client and redirect.
- Token endpoint receives `application/x-www-form-urlencoded`, rejects duplicate security-critical parameters, oversized forms, unsupported grants, invalid content type and invalid client authentication. JSON responses must include no-store headers. Error codes must align with OAuth (`invalid_request`, `invalid_client`, `invalid_grant`, `unsupported_grant_type`, etc.).
- Browser auth cookies: random opaque IDs, Secure, HttpOnly, SameSite=Lax, host-only `__Host-` prefix, Path=/; do not put tokens in browser cookies. CSRF checks on all browser state-changing POSTs. Never include OAuth secret parameters in URL logs.
- Show explicit consent with ChatGPT identity and permitted WAHA actions. Never auto-authorize based on URL alone or a client self-asserted `client_name`.

## 6. Protocol proxy invariants

- Only WAHA endpoints configured at startup are reachable. The default endpoint is `UPSTREAM_MCP_URL` and is published at `/mcp`. Additional endpoints come from `DATA_DIR/upstreams.json` and are published at `/mcp/{id}`. Never route from a request body, query, header, arbitrary URL, or `Host`. Restrict every endpoint to loopback/private network by default; reject a public destination unless the administrator opts in explicitly with proper certificate validation. A grant's resource must match the requested path exactly.
- Upstream is expected Streamable HTTP; bridge must pass through POST/GET/DELETE, status codes, `Content-Type`, MCP version/session/resume-related headers and SSE bytes, with special cases below. Do not parse and reserialize arbitrary tool results.
- Downstream `Authorization`, cookies, browser CSRF/session headers, and upstream API key are **never** forwarded in wrong direction. Build an explicit allowlist of safe forwarded headers, add `X-Api-Key` upstream, strip hop-by-hop headers, set upstream `Host` automatically.
- Do not forward an upstream `Set-Cookie` to ChatGPT. Do not leak upstream WWW-Authenticate or identifying infrastructure/error details in public errors.
- Stream SSE with backpressure, partial-chunk handling and client disconnect cleanup; no blanket buffering. Capture `Mcp-Session-Id` on initialize response and enforce mapping to OAuth authorization grant / session, including after token refresh. Sessions for different grants must not be cross-usable. Handle upstream session 404 as-is and let client reinitialize.
- Preserve `Mcp-Protocol-Version`, `Mcp-Session-Id`, `Last-Event-ID`, `Accept`, `Content-Type`, request `Content-Length` where valid, upstream `Mcp-Session-Id`, response status and content type; strip connection-specific headers. Correctly respect 202 notification responses and 405 GET/DELETE responses.
- `tools/list`: enrich tool metadata with `securitySchemes: [{type:'oauth2',scopes:['mcp:access']}]` in the **correct location required by the current OpenAI MCP tool contract** (docs show `_meta.securitySchemes`, while other examples show tool-level fields). Ensure original name, input/output schema, annotations and metadata are retained, for both JSON and SSE responses. Only transform `tools/list`; preserve all unrelated traffic byte-for-byte whenever possible. Do not corrupt multi-event SSE or hide upstream errors. Test exact metadata format against official docs.
- Do not implement `tools/call` or new WAHA functionality. Do not automatically retry write-capable requests under any failure. Do not confuse network disconnect with an MCP cancellation notification.
- Never log raw MCP request body (may contain private chats), response body, tokens, WAHA key, authorization code, cookies, credential forms, or headers containing secrets.

## 7. Host and transport security

- Production binds HTTPS only, using supplied trusted TLS cert/key loaded securely. Reject startup if cert/key absent, unreadable, mismatched, expired or hostname mismatch (check via appropriate built-in APIs); no silent fallback to HTTP. Local test server may use loopback-only HTTP in explicit test mode, never in production.
- Enforce `Origin` validation as MCP transport spec: if present, reject values outside explicitly configured origin allowlist with 403; missing Origin allowed for server-to-server requests. Do not use wildcard `*`.
- Validate HTTP Host/authority against configured public host; reject header duplicates, CR/LF injection, unusual forwarded headers; don't trust `X-Forwarded-*` unless separately configured trusted reverse proxy mode (out of P0).
- Enforce max request sizes, header sizes, timeouts, concurrency/SSE quotas, IP login throttling, and token endpoint throttling; avoid DoS via unbounded streams or massive stored auth states. Limit rate counters and prune expired records.
- Handle TLS keys and `.env` as private files, non-world-readable; reject obviously unsafe production permissions where possible. Never copy secrets to dist, diagnostics output, README, or test snapshots.
- Admin reset/revoke/status are **CLI only** by default; no unauthenticated admin HTTP APIs.

## 8. Completion definition

Code exists, tests pass, build dist exists, local fake WAHA + simulated OAuth flow pass, no third-party dependency is installed, security gates pass, docs and runbook are accurate, and `BUILD_REPORT.md` explicitly separates *local verified*, *external unverified*, and *blocked by account/hosting prerequisites*. No claim of 100% correctness or ChatGPT compatibility without real-world validation.
