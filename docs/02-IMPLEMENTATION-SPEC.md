# 02 — File-by-file implementation spec (binding P0)

## A. Target source layout

Cursor creates this tree (may add small modules only when justified in BUILD_REPORT):

```
package.json                  # type:module, engines node >=18, zero dependencies
.env.example                 # documented nonsecret settings
src/main.mjs                 # bootstrap + signal/shutdown handling
src/config.mjs               # strict config reader/validator, no dynamic request-derived upstreams
src/server.mjs               # native HTTPS routing, headers, error boundary
src/http.mjs                 # URL/form/json parsing, response, CSP, CSRF helpers
src/log.mjs                  # structured redacted logs
src/store.mjs                # durable single-writer transaction store
src/crypto.mjs               # random, sha256, timingSafeEqual, scrypt, PKCE
src/oauth/metadata.mjs      # PRM/RFC8414 and 401 challenge
src/oauth/cimd.mjs          # restricted ChatGPT CIMD metadata resolver/cache/validator
src/oauth/authorization.mjs # authorization, login, consent, code lifecycle
src/oauth/token.mjs         # code exchange, refresh, revocation
src/oauth/bearer.mjs        # resource server bearer validation
src/mcp/proxy.mjs           # HTTP transport proxy and session binding
src/mcp/tool-metadata.mjs   # tools/list-only JSON and SSE augmentation
src/web/login.mjs           # no-JS accessible login and consent templates
src/web/styles.css         # self-hosted styles, no external fonts/images/assets
scripts/init.mjs            # interactive operator bootstrap
scripts/doctor-local.mjs    # offline simulated diagnostics
scripts/doctor-remote.mjs   # live read-only TLS/discovery/WAHA diagnostics
scripts/build.mjs           # checks/test/copy artifacts -> dist
scripts/security-check.mjs  # security gate, forbidden source patterns/modules/secrets
scripts/admin.mjs           # status / revoke grants / password reset (interactive)
test/helpers.mjs            # ephemeral dirs, test server, fake clock interface
 test/...                   # native node:test suites as 03 describes
systemd/waha-mcp-bridge.service
README.md                   # update after implementation
BUILD_REPORT.md             # generated, test evidence and remaining prerequisites
```

Do not use a third-party `.env` loader. `src/env-file.mjs` reads `.env` with `node:fs` so Node 18, which has no `--env-file`, can start. Existing process environment wins, a missing file is ignored, and a symlink is refused. The private `scripts/init.mjs` may write `.env` with permissions 0600 and `data/` with 0700 on POSIX, using Node fs only; Windows ACL instructions should be documented, not pretended to be implemented with chmod. Private `WAHA` key can live in 0600 `data/upstream-secret.json` or environment injected by the OS. Never include a secret in command-line parameters (shows in process table), repo, `dist/`, or console output. Production `npm start` is `node src/main.mjs` on a local install, and systemd EnvironmentFile from a private path on the host.

Use no `.ts`/TypeScript compiler because that would require a dependency. Write maintainable ESM `.mjs` with JSDoc types and `node --check` syntax verification. No shell scripts required for cross-platform developer operations.

## B. Config and startup contract

Required config: `PUBLIC_ORIGIN` HTTPS URL with no path/query/fragment/trailing slash, `MCP_PATH=/mcp` immutable in P0, `LISTEN_HOST`, `LISTEN_PORT`, `UPSTREAM_MCP_URL`, `UPSTREAM_API_KEY_HEADER` default `X-Api-Key`, `DATA_DIR`, `TLS_CERT_FILE`, `TLS_KEY_FILE`. Private upstream key read from protected secret store / environment. Optional `ALLOW_PUBLIC_UPSTREAM=false`, `ENABLE_LOCAL_TEST_HTTP=false` **strictly test-only**, `LOG_LEVEL`, request/max streams/timeouts with range-limited defaults.

Additional WAHA endpoints are optional objects in `DATA_DIR/upstreams.json`, keyed by a lowercase id. Each object has `url`, `displayName`, and `apiKey`. The file is mode `0600`, is refused when it is a symlink, and is loaded only at startup. Those endpoints are served at `/mcp/{id}` with resource `PUBLIC_ORIGIN/mcp/{id}`. The id `default` is reserved for `UPSTREAM_MCP_URL`. A ChatGPT grant stores `upstreamId` and can be used only on that resource. `npm run admin -- add-upstream ID` and `remove-upstream ID` edit the file; removal also revokes that WAHA's grants. Restart after either command.

Validate before listening: Node.js 18 or newer; URL has HTTPS scheme and valid DNS name (no userinfo); private upstream is exact HTTP/HTTPS URL with path `/mcp`, no query/fragment/userinfo; upstream key nonempty; source path writable, file permissions secure; admin initialized; public port valid 1..65535; no ambiguous origins; TLS cert/key present and valid; all configured limits sane. Disable TLS hostname verification is prohibited for remote HTTPS upstream. For hostname upstream, resolve DNS and refuse nonprivate ranges by default, recheck actual connected address to avoid DNS rebind; localhost and private RFC1918/ULA only by default. For docker networks, require explicit private backend IP or canonical internal hostname.

Do not trust HTTP `Host`, `Forwarded` or `X-Forwarded-*` for constructing `PUBLIC_ORIGIN`. Keep only one process writer to the store and acquire an exclusive lock (atomic `open('wx')`); on stale lock, provide a safe documented recovery procedure rather than deleting someone else's lock blindly. On startup load stored schema version, validate and migrate only with explicit known migration, fail closed on corruption or unexpected version.

TLS: `https.createServer({key,cert,minVersion:'TLSv1.2',...})`; verify leaf cert not expired, matching configured DNS name via `crypto.X509Certificate` and ensure key/cert pair via `tls.createSecureContext` or equivalent. Do not claim local checks establish public CA trust; remote `doctor` makes an ordinary CA-verifying HTTPS call from a second client. Cert reload on SIGHUP is optional P1; restart for certificate rotation P0.

## C. Persistence: durable and safe without a database engine

Single-process design. Implement a durable **atomic JSON snapshot store** with strict schema validation and a *serialized async transaction queue*. If implementation chooses an append-only write-ahead log for improved durability, it must have full tests and documented recovery behavior; simple snapshots are acceptable at small single-user scale.

State schema v1 (fields suggested, never raw token secrets):

```
{
  schemaVersion:1,
  operator:{ username, passwordSalt, passwordVerifier, scryptParams, createdAt, passwordChangedAt },
  browserSessions:{ [sha256(sessionId)]:{createdAt,lastSeenAt,expiresAt,csrfHash,userId} },
  pendingAuthorizations:{ [randomRequestId]:{ clientId,redirectUri,resource,pkceChallenge,requestedScopes,state,expiresAt,sessionBinding,approvedAt?} },
  authorizationCodes:{ [sha256(code)]:{ clientId,redirectUri,resource,pkceChallenge,scope,userId,grantId,expiresAt,usedAt?} },
  grants:{ [grantId]:{clientId,userId,resource,scopes,createdAt,revokedAt,expiresAt?,clientDisplay} },
  accessTokens:{ [sha256(token)]:{grantId,clientId,userId,audience,issuer,scopes,expiresAt,createdAt} },
  refreshTokens:{ [sha256(token)]:{familyId,grantId,clientId,resource,scopes,expiresAt,createdAt,usedAt?} },
  refreshFamilies:{ [familyId]:{grantId,revokedAt,createdAt} },
  mcpSessions:{ [mcpSessionId]:{grantId,createdAt,expiresAt?} },
  updatedAt
}
```

Do not persist `state` if unnecessary; if persisted, treat it as sensitive and never log. Storing session IDs raw in state can be sensitive: store hash as map key and forward original ID only in transit; for session mapping use hashed ID. Do not leave a plaintext session ID in backup logs. Use bounded retention; prune expired state in same transaction opportunistically and periodically, with max active records.

Atomic write algorithm: serialize update in memory -> write JSON into random `data/state.tmp-<random>` via `open` 0600 with `wx` -> `write` -> `fsync(fd)` -> close -> rename within same filesystem over `state.json` -> fsync directory on POSIX if supported. Failure: keep old persisted snapshot, never acknowledge OAuth issuance/rotation before successful durable write. On Windows, provide documented fallback if directory fsync unsupported, and tests for restart persistence. Crash during partially written temp is harmless; startup handles only valid known state, ignores orphan temp with warning. Use `O_NOFOLLOW`/`lstat` protections where supported to reduce symlink attacks.

For replayed refresh token: retain used token hash (tombstone) until absolute family expiry; if presented again, atomically revoke family and its currently valid access/refresh tokens. Reuse detection must not be bypassed by restart; concurrent refresh requests serialize, only one succeeds.

**Critical**: decide and document a safe response to process crash *after* durable refresh rotation but *before* ChatGPT receives new refresh token. It may have to reconnect, not silently reuse a token. Do not leave an old token valid to “help reliability.”

## D. Crypto and password handling

- `crypto.randomBytes(32)` for codes/access/cookie/CSRF; `crypto.randomBytes(48)` for refresh (base64url); cryptographic randomness only.
- `crypto.scrypt` async with unique `randomBytes(16+)` salt per password; recommended N=32768, r=8, p=1, maxmem>=64 MiB, 64-byte derived key. Verify using `timingSafeEqual`; enforce minimum operator password length >=16 and not more than a reasonable UI limit; password reset revokes every grant/session.
- Never use SHA-256 as a password hash; SHA-256 is okay as the index for **high-entropy random opaque tokens**.
- PKCE S256 compare `BASE64URL(SHA256(ASCII(code_verifier)))` with saved code challenge in timing-safe fashion; reject noncanonical verifier length <43 or >128 and non-`[A-Za-z0-9._~-]` characters. Challenge must be exactly valid unpadded base64url of 32-byte hash (43 chars).
- Opaque bearer validation looks up token digest, confirms unrevoked grant/family, not expired, exact issuer `PUBLIC_ORIGIN`, exact audience/resource, scopes and proper grant. No claim-signing or JWT if not implemented.
- Avoid timing channels for bad-user vs bad-password; generic errors. Rate-limit password attempts per IP and globally, with incremental delays/lockout; no unbounded in-memory maps.

## E. CIMD and OAuth client trust

Supported client type P0: **ChatGPT CIMD** public client. Only allow exact client ID URLs that are accepted by the documented policy (initial default `https://chatgpt.com/oauth/client.json`, and optionally an exact per-callback URL matching pattern `https://chatgpt.com/oauth/<validated-callback-id>/client.json` if verified). Do not accept all arbitrary HTTPS client IDs.

For each authorization request:
1. Parse URL with WHATWG `URL`, reject duplicate critical parameters and length violations before rendering any HTML.
2. Require `response_type=code`, known `client_id`, exact `redirect_uri`, `code_challenge_method=S256`, valid challenge, exact `resource=R`, requested scopes drawn from configured allowed set, and state if supplied. Require `state` to be returned byte-for-byte unmodified.
3. Fetch CIMD only from the **strictly allowlisted** `https://chatgpt.com/.../client.json` over default TLS validation; no redirects, no proxying, short timeout, size limit 64 KiB, JSON-only, no credentials, no query params, no host substitution. Cache validated document with bounded TTL, and fail closed if metadata is invalid/stale.
4. Validate fetched `client_id` exactly matches requested URL, document's `redirect_uris` is array of canonical allowed HTTPS URLs, `response_types` supports code, and `token_endpoint_auth_methods_supported` contains `none` (or documented legacy singular fallback). Do not follow arbitrary `jwks_uri` in P0 (we don't support `private_key_jwt`). Verify provided redirect exact string membership **AND** explicit local allowlist of approved ChatGPT callback URIs; no wildcard and no prefix matching.
5. Use stable callback `https://chatgpt.com/connector_platform_oauth_redirect` when using issuer-identified OAuth (metadata `authorization_response_iss_parameter_supported=true`). Accept callback-ID-specific redirect only if live CIMD publishes it **and** it meets an explicit narrowly validated route policy; see actual OpenAI docs. Don't make a blanket arbitrary ChatGPT-host redirect rule.
6. Display exact fetched, sanitized `client_name` and permissions on login/consent; make clear grants permit ongoing WhatsApp access until revoked. Treat client metadata as descriptive, not proof that the caller is genuinely ChatGPT: a public client can claim its ID, and operator approval is required.

Even if `private_key_jwt` is ChatGPT's preferred legacy method, advertising only supported auth methods `none` must be enough because the fetched metadata currently includes `none`. If this expectation fails real ChatGPT integration, do not weaken OAuth. Investigate with actual error and documented protocol before implementing `private_key_jwt` as a separate verified extension.

## F. Browser authorization journey

1. `/oauth/authorize` validates parameters including a live CIMD doc; stores a pending auth request under random ID (not entire user-controlled URL in cookie). Render login if no verified browser session.
2. Login form uses POST with `application/x-www-form-urlencoded`, CSRF double validation (server-stored CSRF token hash tied to browser session or pending auth flow; no reliance on SameSite alone), strict size and count limits, constant-time password hash comparison, and generic failure. Login creates new session cookie (rotate session ID to prevent fixation), bound to pending request ID.
3. Consent page clearly shows “ChatGPT”, requested OAuth scopes, which upstream WAHA session/access that key exposes, and explicit **Approve** / **Deny**. Deny returns OAuth `access_denied` and safe `iss`/`state` if redirect is validated. No prechecked consent, no automatic app-wide approval.
4. Approve atomically creates grant and code (expiration 120s). Redirect using `303 See Other` to *exact* allowed callback URI, with URL-encoded `code`, `state` when provided, `iss`. Include `Referrer-Policy: no-referrer`, no-store, CSP and HSTS.
5. Refresh uses token endpoint server-to-server; no browser interaction, token rotation. Admin CLI revocation cuts off all active tokens immediately.
6. Reject invalid authorization requests locally with safe, minimally descriptive HTML, never redirect to a questionable `redirect_uri`.

HTTP response HTML must escape all untrusted fields (including `client_name`, scopes, state if ever displayed). No CDN, third-party JS, images, external fonts, tracking, inline script or browser API dependency. CSS responsive, polished but minimal, accessible labels/focus/contrast, and semantic `<form>`s. Set CSP `default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, add `img-src 'self'` only if assets. Set `Cache-Control:no-store` on sensitive pages and token responses; `Strict-Transport-Security` only in production HTTPS.

## G. OAuth token endpoint implementation

`POST /oauth/token`: enforce TLS (except explicit loopback test), form content type and <=16KiB body, `Cache-Control:no-store`, `Pragma:no-cache`, reject malformed URL-encoding and duplicate critical fields. Supported `grant_type` values exactly `authorization_code` and `refresh_token`. Require exact client ID, resource R; do not require a client secret for known CIMD public client (method `none`), but still validate its allowed identity and the code's binding to this ID. `client_secret` submitted unexpectedly should not turn an untrusted client into a trusted client. Never accept refresh grants from another client, user or resource.

Auth-code response after successful one-time exchange (actual random values only):

```json
{
  "access_token":"<opaque>",
  "token_type":"Bearer",
  "expires_in":900,
  "refresh_token":"<opaque>",
  "scope":"mcp:access"
}
```

**Refresh interoperability choice:** This is a single-operator explicitly consented integration. Issue refresh tokens to the approved ChatGPT public client by server policy upon initial Authorization Code exchange **even if `offline_access` is not explicitly present**, provided the consent screen clearly discloses persistent access and the user grants it. This is a server authorization policy permitted for OAuth; do not claim it is OIDC `offline_access` behavior. If client explicitly requests `offline_access`, validate and record it and include in scopes. Advertise `offline_access` in authorization-server metadata so clients that do request it can do so. This avoids 15-minute reconnect loops when ChatGPT requests only the challenged `mcp:access` scope. Test with and without `offline_access`.

For `refresh_token` grant, require `resource=R` if provided by the client and reject any resource mismatch; MCP specification expects it. Ensure interoperability with clients that omit the resource on refresh only if verified as allowed by the OAuth 2.1/MCP contract (default strict). New access and refresh tokens returned atomically; invalidate old refresh token. Error body OAuth-conformant and never reveal whether a token belongs to a specific person. No `password` grant and no client credentials grant.

## H. Native Node HTTP proxy details

Use `node:http` / `node:https` request or native streams so **SSE stays streamed**. Map `POST`, `GET`, `DELETE` only. At the route boundary validate OAuth bearer first for all three methods, `Origin`, content type/accept as transport dictates, request length and quota. No redirects from upstream; reject 30x, because redirects could leak the injected upstream key.

Allow request headers (case insensitive, according to method):
`accept`, `content-type`, `mcp-session-id`, `mcp-protocol-version`, `last-event-id`, `accept-language` only if justified, `user-agent` optionally. Set `accept-encoding: identity`. Do not forward `authorization`, `cookie`, `set-cookie`, `host`, `connection`, `proxy-*`, `transfer-encoding`, `x-forwarded-*`, arbitrary `x-api-key`, or `x-mcp-*` without protocol verification. For all methods add only configured upstream key header. Keep outbound API key hidden from all redirects, logs, errors, tracing.

Forward upstream response status and safe headers: `content-type`, `mcp-session-id`, `mcp-protocol-version`, `cache-control` (override no-store), `retry-after` when appropriate, and SSE-specific headers approved by documented protocol; never `set-cookie`, `www-authenticate`, `location`, raw `server`, or any header that contains secrets or exposes internal addresses. For upstream authentication failures 401/403, map to generic **502 Bad Gateway** and server-side redacted error code; never tell ChatGPT to authenticate its WAHA key. Pass legitimate MCP protocol 400/404/405/202 and JSON-RPC errors through as appropriate.

Configure HTTP timeouts: connection <= 5s default, headers <=10s, body timeouts configurable, SSE idle timeout >=120s or controlled no-idle but max concurrent streams and max stream lifetime; heartbeat only if upstream supports it. Use `pipeline` or `stream.pipe` with backpressure for all non-transformed bytes. Abort a hanging upstream read if client permanently closes; do **not** automatically retry or send a cancellation notification to WAHA. On stream disconnect, write diagnostic warning that write completion state may be unknown. JSON and SSE may be split across arbitrary TCP chunks.

**Session mapping:** Capture upstream response `mcp-session-id` after `initialize` (including when response is SSE) and map its digest to the current OAuth grant ID. For all requests with a session ID, verify it maps to the same unrevoked grant before forwarding. On refresh keep grant ID unchanged so session continuity works; on new OAuth grant, refuse other grant session IDs. On DELETE success or upstream 404, drop session mapping. Limit session map and expire stale entries. Do not assume session ID exists; support stateless upstream servers.

**tools/list only:** parse request method from bounded JSON request up to permitted size (single JSON-RPC object; do not change bytes forwarded upstream). Detect exact `method:'tools/list'`. For response JSON decode strict JSON and transform only `result.tools[]` objects, retaining all other fields; add OAuth security scheme for each tool in `_meta.securitySchemes` using OpenAI's current authenticated-tool example, and consider top-level `securitySchemes` if verified by current supported schema, without discarding preexisting unrelated `_meta`. For SSE, build a robust incremental SSE event parser that supports CRLF, `data:` multiple lines, optional event names/IDs/retry, multibyte Unicode across chunks, event boundaries across chunks, and JSON-RPC messages that are not tool lists. For a matching tool-list JSON-RPC event, transform JSON data and re-emit valid SSE with safe line splitting. Preserve event IDs and ordering. Bound single event to 4 MiB, fail with an explicit safe error if oversized rather than corrupting output. Non-`tools/list` responses remain opaque and are piped. If upstream returns compressed bodies despite `accept-encoding:identity`, either correctly decompress built-in or refuse transformation rather than corrupt bytes. JSON-RPC tool-list notification or error must not be misidentified or rewritten.

No hardcoded list of WAHA tools. A WAHA update that adds a tool should automatically appear at next `tools/list`. Keep read/write permission enforcement in WAHA MCP App key, not assumed from name prefixes. For `tools/list` metadata enrichment, do not claim read-only if WAHA permits send/control. If WAHA tool metadata lacks credible annotations, preserve its originals and do not fabricate `readOnlyHint`.

## I. CLI commands / operational implementation

`npm run init`: guided interactive setup, prompt for username (default admin), password twice, upstream private MCP URL, header name (default X-Api-Key), scoped MCP App key (hidden input if terminal supports; never echo; if cannot safely hide, accept secure stdin/secret file rather than visible terminal), public origin and cert paths. Validate options, create private files and refuse to overwrite existing initialized store unless explicit dedicated reset command. Print nonsecret summary and next steps.

`npm start`: fail closed on bad config; structured `ready` log **without** host secrets/key, start native HTTPS listener. Graceful shutdown drains in-flight reads with bounded timeout, handles SIGINT/SIGTERM, flushes store and closes server; no silent token loss.

`npm run dev`: loopback local simulator or test-only mode, never advertise HTTP for public remote clients; communicate clearly that OpenAI won't connect to it.

`npm run doctor:local`: fast offline metadata/authorization/proxy simulation, prints pass/fail redacted; exit nonzero on failure.

`npm run doctor:remote`: optional read-only public HTTPS connectivity, CA-chain/hostname/cert expiry, discovery JSON, 401 WWW-Authenticate, and upstream `initialize` + `tools/list` using scoped key only **if explicitly supplied**. Never call send/delete/modify tools, do not test credentials in stdout, and do not pretend it proves ChatGPT account entitlement. Avoid exposing WAHA key or body.

`npm run admin -- status|revoke-all|revoke-grant|reset-password`: local CLI, must be authenticated via OS file access plus optional password reentry for destructive admin actions; do not expose via network. On password reset/revoke-all, invalidate outstanding codes, sessions and all refresh/access token families. Print only redacted grant summaries.

`npm run build`: Node script checks runtime, runs syntax checks for all `.mjs`, runs `node --test`, security source check, copies production files into `dist/` (exclude data, .env, tests, test cert, reports containing secrets, cache), verifies zero `node_modules`; exits nonzero on any failed gate. Dist can be deployed as local files with installed Node. **Build does not deploy, DNS-provision, issue TLS certs, change WAHA, or connect ChatGPT.**

`npm run lint:security`: built-in AST-free regex scans plus targeted runtime tests (avoid false assurance): reject imports outside `node:` relative local modules, reject `rejectUnauthorized:false`, wildcard redirects, `eval`, `new Function`, hardcoded likely secrets, dangerous proxy-forwarding patterns; report exact file/line. Gate against source only; don't overclaim static analysis security completeness.

## J. Logging and operational safety

Structured JSON logs to stdout/stderr for host service manager. Fields: timestamp, level, requestId random, route, status, latencyMs, event name, upstreamStatus, safe error category, auth reason category. IP can be truncated/hashed for login defense, never store message content. No URL query strings on OAuth endpoints, no full headers. Minimal public 5xx response with requestId for correlation. Password failures aren't distinguished by username. Use high-water marks to prevent memory growth.

Security error policy: fail startup for missing TLS, key, secure state, or invalid backend. Fail request 401/403 for auth; 400 for malformed requests; 413 for over limit; 415 for wrong content type; 429 with Retry-After for rate limit; 502 for unreachable/bad upstream; 503 when store unavailable; never fall back to no-auth or stale refresh state.
