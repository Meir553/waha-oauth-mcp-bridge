# 03 — Automated verification and acceptance gates (P0)

**Do not ship without these tests.** Every test must run without third-party packages, internet, real WhatsApp, real WAHA, real ChatGPT, or privileged ports. Use Node `node:test`, `node:assert/strict`, `node:http`, `node:https`, `node:crypto`, streams and temporary directories. Tests must not mutate actual WAHA. Build local fake WAHA as an ephemeral loopback server implementing Streamable HTTP, and a local simulated OAuth client (not pretending to be a real ChatGPT client). Tests may inject an explicit test-only CIMD fixture resolver in a dependency-injected module; production must fetch and validate live CIMD. Never enable fixture resolver or plain HTTP in production.

Use a controllable clock injected as an argument in services (not global `Date.now` monkeypatch) to deterministically test expiration and expiry races. Use seeded test-only fixtures for reproducible randomness if needed, but always use real `crypto.randomBytes` in production.

## 1. Build/run gates

| ID | Test | Expected |
|---|---|---|
| B-01 | Node 18 or newer `node --version` preflight | Pass on 18+; fail with an informative message on older majors. |
| B-02 | `npm ls --all` / programmatic dependency check | No third-party runtime or dev packages. |
| B-03 | Syntax check every `.mjs` production/test file | Pass without external compiler. |
| B-04 | `npm test` | Every test passes, exit 0, no skipped P0 tests. |
| B-05 | `npm run build` | Reproducibly generates `dist/` and returns 0. |
| B-06 | Inspect `dist/` | Contains source+assets+run instructions, no key/password/.env/data/test fixture keys/node_modules. |
| B-07 | Windows/Linux portability | No unguarded POSIX-only commands in JS scripts; document platform-specific service steps. |
| B-08 | Repeated build | Idempotent; does not change active secrets or data. |

## 2. Metadata / discovery

- M-01: `GET /.well-known/oauth-protected-resource` returns JSON, status 200, exact resource URI ending `/mcp`, issuer origin and `mcp:access`, without secrets.
- M-02: `GET /.well-known/oauth-protected-resource/mcp` yields equivalent JSON.
- M-03: OAuth AS metadata exact issuer, endpoint URLs, `S256`, `authorization_code`, `refresh_token`, `client_id_metadata_document_supported:true`, `token_endpoint_auth_methods_supported:['none']`, `authorization_response_iss_parameter_supported:true`, `offline_access` advertised; NO DCR registration if unimplemented.
- M-04: unauthenticated POST/GET/DELETE `/mcp` returns 401 and valid `WWW-Authenticate` `Bearer resource_metadata="..."` and scope, no upstream call.
- M-05: unknown path and methods return 404/405; sensitive `.env`, `data`, key files never served.
- M-06: metadata uses fixed configured origin even with spoofed `Host`/`X-Forwarded-Host`; unexpected Host rejected.
- M-07: metadata has no CORS wildcard; no secrets via headers.

## 3. CIMD / OAuth authorization input matrix

- C-01: only exact allowlisted CIMD client ID accepted; fetch document with timeout and TLS verification (stub resolver in test), no redirects, size<=64KiB.
- C-02: fetched `client_id` differs from requested -> error, no redirect/code.
- C-03: missing/wrong redirect, redirect not in fetched `redirect_uris`, or not in explicit ChatGPT callback allowlist -> error, no redirect.
- C-04: hostile `redirect_uri=https://evil.example/capture` or similar looking `https://chatgpt.com.evil/..` -> error; never open redirect.
- C-05: missing `response_type`, wrong response type, missing PKCE, `plain` method, invalid S256 challenge, missing resource, wrong resource, invalid scope, duplicate params -> error.
- C-06: only known `none` token endpoint auth supported; test CIMD with `['none','private_key_jwt']`, legacy singular preference `private_key_jwt`; `none` intersection accepted. CIMD without `none` rejected.
- C-07: expired/corrupt/unavailable/stale CIMD metadata fails closed; no unsecured fallback.
- C-08: inject dangerous client name HTML; rendered UI escapes all markup and does not inject JS.
- C-09: successful and error OAuth callback redirects include `iss` exactly matching issuer, preserve `state` unchanged, add no extra URL fragment; never include `iss` in redirect from invalid client/redirect.
- C-10: no cross-flow confusion: two simultaneously pending auth flows cannot trade browser consent/codes.

## 4. Login / consent security

- L-01: interactive CLI initializes securely; password verifier is scrypt, salt unique, plaintext password absent from persisted JSON and stdout.
- L-02: short / weak / mismatched bootstrap passwords rejected; init refuses overwriting existing data.
- L-03: incorrect password fails generically and never issues code/session.
- L-04: login/consent/logout POST without valid CSRF fails; CSRF from unrelated session fails.
- L-05: after successful login cookie has `__Host-` name, Secure, HttpOnly, SameSite=Lax, Path=/, no Domain, random session; session ID rotated after login.
- L-06: login/session idle & absolute expiry, logout, and deleted session are enforced.
- L-07: consent deny returns safe OAuth `access_denied` callback and never issues code; approve works once only.
- L-08: login rate limit: 5+ failures over configured window triggers 429/lock, including across unique usernames/IP variations; track bounded counters; no user enumeration.
- L-09: browser pages use no-store, referrer-policy no-referrer, appropriate CSP/HSTS and no third-party resources; headers tested.
- L-10: POST form duplicate field name, malformed encoding, huge input, non-UTF8/invalid characters rejected; no exception leaks.

## 5. Token code/refresh/bearer lifecycle

- T-01: valid code + exact client ID, redirect URI, PKCE verifier, resource R -> access token and refresh token, both opaque and strong entropy.
- T-02: code replay -> `invalid_grant`; concurrent double code redemption -> only one 200.
- T-03: wrong verifier, missing verifier, expired code, wrong redirect, client, resource -> `invalid_grant` with no tokens created.
- T-04: token response must be JSON with `token_type=Bearer`, `expires_in` positive, no-store/cache headers; raw tokens not persisted or logged.
- T-05: good `Authorization:Bearer token` + correct scopes -> MCP proxy allowed; absent/malformed/invalid/expired/revoked token -> 401; wrong resource or grant client -> 401, insufficient scope -> 403; never forward upstream on failure.
- T-06: valid refresh token -> new access + new refresh and invalidates prior refresh; refresh family stays same; old token reuse -> revoke family and newest access/refresh too.
- T-07: simultaneous refresh -> only one succeeds, replay revokes family (document expected behavior, not a flaky race).
- T-08: process restart preserves active codes/token expiry/revocation/rotations as appropriate; expired state pruned safely; no collision of new tokens.
- T-09: stop during atomic store write/crash recover: old snapshot valid; no partial JSON or accidentally accepted uncommitted token.
- T-10: changing password / admin revoke-all instantly invalidates all sessions, auth codes, grants, refresh/access tokens.
- T-11: refresh with wrong `resource` rejected, invalid client auth rejected, unknown grant `unsupported_grant_type`; invalid form content/duplicates/size rejects.
- T-12: refresh granted even when client initially only requested `mcp:access`, after explicit operator consent disclosing persistent access; also handle explicit `offline_access` when requested.
- T-13: token validation is not merely existence: issuer, exact audience, expiry, scopes, active grant and family checked every time.
- T-14: token strings never in query, logs, URLs, errors, admin display, or `dist`.

## 6. WAHA MCP protocol / streaming integration

Fake WAHA must record incoming headers (test-only), implement `initialize`, `notifications/initialized`, `tools/list`, `tools/call` and long-lived SSE, return `Mcp-Session-Id` on initialize, and support `GET /mcp` with SSE or 405 and `DELETE /mcp` session termination or 405.

- P-01: request to bridge `POST /mcp` with valid bearer forwards to exactly configured upstream URI/method; fake upstream sees `X-Api-Key` and **never** sees ChatGPT Bearer/cookie/host/spoofed API key.
- P-02: initialize JSON response, `Mcp-Session-Id`, version headers and status preserved correctly.
- P-03: `notifications/initialized` -> 202 with no body; no injected unexpected response.
- P-04: `tools/list` returns every upstream tool (preserves name, description, input/output schema, annotations, `_meta`), with a correct OAuth `securitySchemes` declaration for each; new simulated WAHA tool appears automatically.
- P-05: JSON-RPC tool calls return exact upstream response including content arrays, `structuredContent`, tool errors, id types, UTF-8 Hebrew and emoji; no data leaks in logs.
- P-06: large server response >=10MiB (not `tools/list`) is streamed and output byte-equal, not fully buffered; verify bounded memory/backpressure.
- P-07: POST response as SSE, arbitrary chunk boundaries including in UTF-8, JSON escape and event separator; exact content and ordering retained for non-tool requests.
- P-08: `tools/list` response as SSE (one and multi-event) transforms **only** the intended JSON-RPC tool-list event; preserves event id, retry, other event types and payloads; tests Unicode and CRLF and split lines.
- P-09: GET SSE with `Last-Event-ID` passed exactly; response `text/event-stream`; 405 from fake WAHA propagated.
- P-10: DELETE session success and 405 propagated, bound session removed when terminated.
- P-11: fake WAHA `Mcp-Session-Id` belongs to grant A; same grant with refreshed access allowed; grant B with same session rejected before forwarding; no-session stateless works.
- P-12: upstream 401/403 due to wrong WAHA API key yields safe 502, no key, upstream auth instructions or internal host in response; upstream 502/unavailable yields appropriate 502/503.
- P-13: malicious upstream 302 `Location:evil.example` never followed and no upstream API key forwarded to redirect; report safe failure.
- P-14: client tries to set `X-Api-Key`, `Authorization`, `X-Forwarded-*`, `Proxy-Authorization`, `Cookie`, hop-by-hop headers; upstream receives only allowlist plus server-set key.
- P-15: invalid origin -> 403, no upstream call; missing origin for server-to-server request remains allowed; hostile Host rejected.
- P-16: over-limit requests -> 413, too many streams -> 429/503, wrong Accept/method -> clear 4xx and no crash.
- P-17: client disconnect cancels network stream resources without retrying a `tools/call`; fake WAHA counts invocation exactly once, status of write after disconnect marked uncertain.
- P-18: hung upstream, truncated response, malformed tool list, oversized SSE event, mismatched content encoding -> safe deterministic failures, process remains healthy.
- P-19: sensitive phrase inserted in WhatsApp fake response and API key; scan log captures to ensure neither appears.
- P-20: WAHA tool metadata without read-only annotations never gets fictitious `readOnlyHint=true`; no invisible grant escalation.

## 7. Deployment / safety tests

- D-01: production startup with `NODE_ENV=production` and absent TLS cert/key -> refuses to bind, exit nonzero.
- D-02: production startup plain-HTTP test flag -> refuses unless explicit test mode and loopback listener.
- D-03: production upstream URL contains userinfo/query / public host without opt-in / redirect -> reject/fail closed.
- D-04: corrupt persisted JSON, symlinked secret path, unwritable state and concurrent second instance -> refuse startup/issuance, never recreate fresh security state silently.
- D-05: no token, cookie, key, PII, or WAHA message body in logs; no `.env`/private files in generated build.
- D-06: shutdown SIGTERM drains and terminates connections safely, closes lock, no half-written store.
- D-07: `doctor:remote` does read-only network requests only; never calls send/delete/modify tool.
- D-08: `npm run admin -- revoke-all` effective after restart.
- D-09: password changed / WAHA API key rotated requires appropriate restart or reload, and there is no exposure in status endpoint.
- D-10: all public security headers and non-cache responses verified.

## 8. Verification reporting requirements

`BUILD_REPORT.md` must have a table with each ID and status `PASS / FAIL / NOT RUN`, short evidence (exact command, test filename or file/line). Report counts for tests, Node version, total declared external npm dependencies = 0, build path, security caveats, and user-provided requirements remaining. Don't mark P0 as pass because code exists: tests must run. If the interpreter is older than Node 18, mark tests **NOT RUN** and report the blocker rather than claim success.

### Manual acceptance checklist (after software build)

These items cannot be honestly executed without real credentials and host access, so leave as **NOT VERIFIED / REQUIRES OPERATOR** until actually run:

1. Operator supplies production CA-trusted cert, DNS, public reachability on selected port and verifies remote TLS trust.
2. WAHA Apps enabled, dedicated MCP App per intended session, key scoped and tested via read-only MCP initialize/tools/list; no admin key.
3. `npm run doctor:remote` tests discovery and read-only upstream; `curl` missing-auth check returns 401 and correct metadata.
4. User's ChatGPT workspace actually supports custom MCP plugin creation and required tool actions; no code change can bypass entitlement.
5. ChatGPT Plugins > Add custom MCP server, HTTPS MCP endpoint, OAuth; confirm callback matches, complete login and consent, scan tools.
6. Try a **read-only** chat listing first; verify the intended session only. Only after that, optionally enable `send` permission in WAHA and explicitly review agent behavior.
7. Force access-token expiration and verify refresh/no password relogin; disconnect/reconnect, WAHA restart, bridge restart, upstream outage, and cert renewal.
8. Review logs for no sensitive content and test revoke-all immediately cuts access.

## 9. No false claims

`node:test`/mock-client success is not a real ChatGPT integration test; fake WAHA success is not a real WAHA test; a valid TLS file on disk is not proof of public CA trust; existence of a Cursor file is not proof of build. State exactly what passed and what remains unavailable.
