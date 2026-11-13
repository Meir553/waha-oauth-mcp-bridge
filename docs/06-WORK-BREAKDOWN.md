# 06 — Cursor execution checklist; ordered gates

Cursor must implement work packages in order, complete each gate and tests, then mark them in `BUILD_REPORT.md`. `P0` means required for acceptance; `P1` means optional and must not delay completion of P0.

## P0-00 — Environment and source research

- [ ] Read README, AGENTS, all six numbered docs and the published official URLs as available. Respect existing contract if latest sources cannot be accessed; log verification gap.
- [ ] Detect Node 18 or newer; do not install npm packages. Initialize `package.json` with explicit `engines`, `type:module`, scripts and empty dependency fields.
- [ ] Draft a mapping of every HTTP route, state transition, file and test; do not create an extra hosted service.
- [ ] Create `.env.example`, `.gitignore`, private data directory layout (never commit secrets).
- [ ] Ensure all core methods can be dependency-injected for tests: clock, upstream, CIMD fetch, state directory, logger.
**Gate:** syntactic source scaffold and `node --check`; no network-dependent install step.

## P0-01 — Core server and config

- [ ] Strict config validator, private/public URL parsing, allowlisted upstream, TLS check, runtime/version check.
- [ ] `https.createServer` production + isolated test-only loopback HTTP mode; method/path router, unknown-route responses, fixed origin, security headers.
- [ ] `GET /health/live`, graceful shutdown, structured logger with redaction, request limits, generic error boundary.
- [ ] Private upstream auth header name and key handling; no anonymous defaults or hardcoded keys.
**Gate:** M-05..M-07 and D-01..D-03 pass.

## P0-02 — Durable state / crypto

- [ ] Random token helpers, scrypt password hashing and verification, PKCE verifier/challenge calculation, timing-safe digest compare.
- [ ] State schema v1, single-writer lock, bounded in-memory transactional state, atomic/fsync writes and recovery; expired state pruning and schema validation.
- [ ] Interactive `init` and private config bootstrap; safe Windows warnings and POSIX permissions.
- [ ] Admin reset/revoke/status CLI with session/grant/refresh family invalidation.
**Gate:** L-01..L-02, T-08..T-10, D-04 and D-08 pass.

## P0-03 — OAuth metadata and client validation

- [ ] Resource discovery at root and endpoint-specific well-known paths.
- [ ] Authorization server metadata with issuer identification `iss`, S256, client-ID metadata support, accepted token auth methods exactly `none`.
- [ ] 401 Bearer resource metadata challenge, 403 insufficient scope, consistent JSON and cache headers.
- [ ] Strict CIMD resolver with only approved ChatGPT URL(s), current remote metadata validation, exact redirect membership and local callback allowlist, bounded cache and test fixtures.
**Gate:** M-01..M-04 and C-01..C-07 pass.

## P0-04 — Browser login, consent and authorization code

- [ ] Pending authorization parsing/binding, duplicate param handling, CSRF, session cookie fixation protection.
- [ ] HTML login/consent templates with polished self-hosted CSS, escaping, CSP/no-store, accessible controls and explicit WAHA scopes/action notice.
- [ ] Login throttling and generic password failure; interactive consent Approve/Deny; `iss` in success/error redirects when safe; single-use hashed auth codes.
- [ ] No unsafe redirects or user controlled HTML/script; prevent cross-request mix-ups.
**Gate:** C-08..C-10 and L-03..L-10 pass.

## P0-05 — Token grants and bearer enforcement

- [ ] Auth-code exchange strictly bound to all OAuth inputs and PKCE; atomic code consumption and durable token issuance.
- [ ] Refresh grant rotation/reuse detection and grant-family revocation; concurrent request serialization.
- [ ] Hashed access tokens, issuer/audience/scope/expiry checks, revocation and request challenge; include refresh for explicitly approved ChatGPT grant even when only `mcp:access` requested.
- [ ] Token HTTP form validation and OAuth JSON/no-store responses, error codes; do not advertise unsupported client-secret or private-key methods.
**Gate:** T-01..T-14 pass.

## P0-06 — WAHA HTTP/SSE proxy and tools metadata

- [ ] Fixed upstream, server-only API key injection, request and response header allowlists, redirect protection and auth-error mapping.
- [ ] POST/GET/DELETE, JSON/202/405, multiple version headers, GET SSE, SSE streaming, chunk-splitting and backpressure, safe client disconnect without write retries.
- [ ] Initialize upstream session binding to OAuth grant; persist session digest and handle deletion/expiry/refresh continuity.
- [ ] Only `tools/list` tool metadata augmentation for OAuth; support JSON and SSE variants, preserve all fields and event formats; enforce buffer limits for transform.
- [ ] Fake WAHA protocol test server and realistic tool fixtures with both read and send methods; never call real WAHA by default.
**Gate:** P-01..P-20 pass.

## P0-07 — Security / operations / packaging

- [ ] Native `doctor:local` and strictly read-only `doctor:remote`.
- [ ] No npm packages/imports from non-native modules; secret scanning; denial/rate-limit tests; known negative cases.
- [ ] `scripts/build.mjs` packages `dist`, no secret data, test keys or environment file; works without internet.
- [ ] Linux systemd unit hardening and Windows non-destructive local instructions.
- [ ] Update README for real app usage, document production external prerequisites and port conflicts.
- [ ] Run all test IDs; check all security invariants and produce honest BUILD_REPORT with evidence. Fail build if any mandatory automated test fails.
**Gate:** B-01..B-08, D-05..D-10, no P0 failing tests.

## P0-08 — Final validation and handoff

- [ ] Execute `npm test`.
- [ ] Execute `npm run doctor:local`.
- [ ] Execute `npm run lint:security`.
- [ ] Execute `npm run build`.
- [ ] Confirm `dist` is runnable with Node.js 18 or newer plus operator-supplied config/cert, without installation of third-party code.
- [ ] Explicitly mark real ChatGPT auth, real WAHA, live TLS and workspace eligibility **NOT RUN** until independently verified; list exact steps needed, not “looks good”.
- [ ] Report all unimplemented P0 items as **FAIL**, not silently downgrade to P1.

## Optional P1 ideas (ONLY after passing all P0)

- [ ] Direct native ACME renewal module (requires extensive RFC 8555 support and DNS/HTTP challenge; no assumption that all DNS providers can be automated without credentials).
- [ ] `private_key_jwt` client auth with remote JWKS rotation and assertion replay protection.
- [ ] Dynamic client registration for additional clients beyond ChatGPT, with strict operator consent.
- [ ] Multi-user and multi-upstream isolated per-identity credential maps.
- [ ] Secure self-hosted UI to view/revoke OAuth grants (protected by same local login), replacing some CLI commands.
- [ ] Optional trusted local reverse-proxy mode for existing Traefik/Caddy, with explicit trusted-proxy address validation and TLS termination configuration.
- [ ] MCP tools/list metadata caching with expiration/WAHA version detection.

**Do not implement P1 features by weakening or bypassing P0.**
