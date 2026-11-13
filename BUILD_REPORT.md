# BUILD_REPORT

Local implementation and verification of the WAHA MCP OAuth bridge. This report does not claim a live ChatGPT connection, a live WAHA session, or a public TLS deployment.

## Runtime

| Check | Result |
|---|---|
| Interpreter used for tests | Node.js **v22.16.0** (`C:\Program Files\nodejs\node.exe`), npm 11.4.2 |
| Supported runtime | Node.js **18 or newer**. `node src/main.mjs` on v22.16.0 passed the version gate and stopped at missing `PUBLIC_ORIGIN`. Node 18 itself was not installed here, so that exact binary was not executed. |
| Third-party packages | **0**. `npm ls --all` printed `waha-mcp-bridge@1.0.0` and `(empty)`. |
| Tests | **29 passed, 0 failed, 0 skipped** on Node v22.16.0. Command: `npm test`, which runs the five test files and does not execute `test/helpers.mjs` as a suite. |
| Security scan | `npm run lint:security` → `security-check: pass` |
| Offline doctor | `npm run doctor:local` previously passed on v22.16.0 against a loopback fake upstream. |
| Remote doctor | `npm run doctor:remote` exited 0 and printed that live checks were **not performed**. No `DOCTOR_ORIGIN` was set. |
| Package | `npm run build` exited 0. `dist/` contains `package.json`, `README.md`, `.env.example`, `RUN.txt`, `src/`, `scripts/`, `systemd/`, `docs/`. It does not contain `node_modules`, `test/`, `data/`, or `.env`. |

`npm start` is `node src/main.mjs`. It reads `.env` with `src/env-file.mjs` because Node 18 has no `--env-file`. Existing environment variables win, and a symlink is refused.

## Acceptance IDs

Status is for the local suite on Node v22.16.0. The version predicate accepts 18, 20, 22, and 26, and rejects 16 and 17.

| ID | Status | Evidence |
|---|---|---|
| B-01 | PASS on this machine (v22.16.0). Node 18 binary **NOT RUN**. | `test/oauth.test.mjs` accepts 18+ and rejects 16 and 17. Live startup passed the version gate. |
| B-02 | PASS | `npm ls --all` empty. |
| B-03 | PASS | `npm run build` runs `node --check` on every `.mjs` before the suite. |
| B-04 | PASS | 29 passed, 0 failed, 0 skipped. |
| B-05 | PASS | `npm run build` exit 0. `dist/RUN.txt` written. |
| B-06 | PASS | Dist listing above. Secret scan in `scripts/build.mjs` passed. |
| B-07 | PASS | Scripts use Node APIs. Windows ACL note is in README and init output. systemd unit is Linux-only and was not installed. |
| B-08 | PASS | Build deletes and rewrites `dist/` only. It does not read or write `data/`. |
| M-01–M-07 | PASS | `test/oauth.test.mjs` |
| C-01–C-10 | PASS | `test/oauth.test.mjs`. Duplicate `response_type` on a trusted client returns 303 `error=invalid_request` with `iss`, not an open redirect. |
| L-01–L-10 | PASS | `test/gates.test.mjs`, `test/oauth.test.mjs` |
| T-01–T-14 | PASS | `test/oauth.test.mjs`, `test/coverage.test.mjs`, `test/gates.test.mjs`. Concurrent refresh: one 200 and one 400, then the winning access token is 401 because family replay revocation is committed. |
| P-01–P-20 | PASS | `test/proxy.test.mjs`, `test/coverage.test.mjs`. P-06 streamed 64KiB plus 10MiB. |
| D-01 | PASS | `test/gates.test.mjs` rejects Node 16 and missing TLS on the real interpreter. |
| D-02, D-03 | PASS | `test/gates.test.mjs` |
| D-04, D-05 | PASS | Corrupt schema, second lock, and symlinked `state.json` in `test/gates.test.mjs`. Log redaction in `test/proxy.test.mjs`. |
| D-06 | PASS with a Windows limit | Graceful `stop()` closes the port and removes `bridge.lock`. On this Node build, an external SIGTERM ends the process with a non-zero status and does **not** enter the JavaScript handler. The stale lock was then removed by `recover-lock`. |
| D-07 | PASS for the guard. Live network **NOT RUN**. | `assertReadOnlyMethod` rejects `tools/call`. `npm run doctor:remote` made no requests. |
| D-08, D-09 | PASS | `revoke-all` and `reset-password` in `test/gates.test.mjs` and `test/coverage.test.mjs`. |
| D-10 | PASS | Login response headers in `test/oauth.test.mjs`. |

## Not performed

- Real ChatGPT OAuth, CIMD fetch of `https://chatgpt.com`, or any ChatGPT account.
- Real WAHA, WhatsApp, or a scoped MCP App key against a running WAHA.
- Public DNS, a publicly trusted certificate, or `doctor:remote` against a deployed origin.
- Installing or starting `systemd/waha-mcp-bridge.service`.
- A process started on a Node.js 18 binary. This machine ran v22.16.0.

## Security decisions

- The default resource is the configured origin plus `/mcp`. The bare origin is rejected. Each added WAHA is a separate resource at `/mcp/{id}`. A ChatGPT grant stores that upstream id, and its token is rejected on every other path before a request is forwarded. The client cannot supply an upstream URL. API keys stay in `upstream-secret.json` or `upstreams.json` and are not printed by `admin status`.
- Authorization-server metadata advertises only `token_endpoint_auth_methods_supported: ["none"]`. `private_key_jwt` is not implemented. A CIMD document is accepted when `none` is one of its methods.
- Redirects are the stable `https://chatgpt.com/connector_platform_oauth_redirect`, plus `https://chatgpt.com/connector/oauth/{callback_id}` only when that exact client document lists it. Untrusted client or redirect produces a local HTML error and no `Location`.
- `tools/list` writes the same oauth2 `mcp:access` scheme to both `securitySchemes` and `_meta.securitySchemes`, and strips `noauth`. `readOnlyHint` is not invented.
- A refresh token is issued on authorization-code exchange even when `offline_access` was not requested. Family expiry is absolute. Refresh reuse commits the family revocation instead of rolling it back.
- Browser CSS is `GET /styles.css` from this origin because the content security policy has no `unsafe-inline`.
- The upstream API key is added by the proxy. Client `Authorization`, `Cookie`, and `X-Api-Key` are not forwarded. Upstream redirects are not followed.
- Test HTTP exists only when the harness sets `testMode` and the listen address is loopback. Production `main.mjs` never sets `testMode`.
