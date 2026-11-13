# 04 — Deployment, configuration, operations (post-build)

## A. Before deployment: external prerequisites

1. **ChatGPT entitlement:** OpenAI documentation on 2026-11-12 says full write-capable custom MCP on Business / Enterprise / Edu web. ChatGPT Plus isn't documented as eligible; Pro only limited read/fetch. Confirm account/workspace permissions first. This is outside the bridge.
2. **WAHA:** use a version with WAHA Apps and MCP App support. `WAHA_APPS_ENABLED=True`. Create a distinct MCP App for intended WhatsApp session in WAHA Dashboard > Session > Apps; grant only read initially (`read=true,send=false,control=false,setting=false,app=false,delete=false`) and capture its **MCP App key**. Do not use the global `WAHA_API_KEY` unless knowingly accepting unrestricted access (discouraged and blocked by default in this application). Verify WAHA MCP `http://127.0.0.1:3000/mcp` or actual private Docker network endpoint accepts `X-Api-Key` using read-only `initialize`/`tools/list`.
3. **Domain:** public DNS A/AAAA points to the server, e.g. `mcp.example.com`. A publicly trusted TLS certificate for that exact hostname, with PEM fullchain + private key, must be provisioned outside the Node app. HTTPS connectivity must be accessible from OpenAI's servers. No self-signed cert in production.
4. **Port:** direct Node HTTPS on 443 needs a free port/IP. If existing Traefik/Caddy/Nginx owns 443, don't stop it; either provide separate public IP, use the existing self-hosted proxy (optional integration, no *hosted* vendor), or verify ChatGPT accepts a nonstandard TLS port such as 8443. Plan must not assume a port conflict can magically be avoided.
5. **Host security:** Linux non-root account, firewall permits selected public HTTPS port, WAHA is reachable only internally, backup of encrypted protected server state, OS patches and standard process supervision.

## B. Build and local offline checks

On a development machine with Node.js 18 or newer installed:

```sh
node --version
npm test
npm run doctor:local
npm run build
```

No `npm install` needed. No internet needed for mock tests. `dist/` must include a `README` and production Node source/assets, and no secret files. Run all commands from the repo root; `npm run build` packages code but does **not** issue certificates or deploy to the VPS. Windows PowerShell equivalents are the same command names.

## C. Initial private setup (after implementation)

Run the `init` CLI locally on the target host in an access-controlled project directory and provide:

- `PUBLIC_ORIGIN=https://mcp.example.com`, never inferred from inbound requests.
- `LISTEN_HOST=0.0.0.0` (or intended IP), `LISTEN_PORT=443` (or vetted alternate), `MCP_PATH=/mcp`.
- `UPSTREAM_MCP_URL=http://127.0.0.1:3000/mcp` (when bridge and WAHA share host) or private Docker/host network address. For Docker, loopback refers to container itself; don't assume it reaches another container.
- `UPSTREAM_API_KEY_HEADER=X-Api-Key`, `UPSTREAM_API_KEY` set via hidden input or a private secret file and never committed.
- Absolute paths of PEM TLS certificate/fullchain and private key; the bridge must be able to read them, not the whole internet.
- A unique strong operator password of 16+ characters (prompt hidden).

The CLI must support noninteractive config validation without printing the key. No initial temporary password and no default password. Private state must survive restarts; the bridge must not auto-regenerate passwords/tokens at every start.

## D. Direct Node process under systemd (Linux)

Cursor must generate a runnable `systemd/waha-mcp-bridge.service` with placeholders documented, NOT configured with live host-specific paths in repo. Suggested hardening:

```
[Unit]
Description=WAHA MCP OAuth Bridge
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=waha-bridge
Group=waha-bridge
WorkingDirectory=/opt/waha-mcp-bridge
Environment=NODE_ENV=production
EnvironmentFile=/etc/waha-mcp-bridge/bridge.env
ExecStart=/usr/bin/node /opt/waha-mcp-bridge/src/main.mjs
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/waha-mcp-bridge
StateDirectory=waha-mcp-bridge
UMask=0077
# Only when binding :443 as non-root:
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

Adapt Node executable path, certificate permissions/read-only paths, state-directory path and writable files precisely. With `ProtectSystem=strict`, private config and certificate paths must still be readable by service user; data must be in `ReadWritePaths`. Use least capabilities. Do not use `chmod 777`, run as root, or expose state files by web route. On servers with existing reverse proxy and another service on 443, do not install this unit until binding is resolved.

Installation can use `systemctl daemon-reload`, `enable --now` and `journalctl -u` only **after user explicitly authorizes live deployment**. Cursor running Build must not execute these on any real server.

## E. Endpoints and manual checking

With proper DNS and certificate, operator should expect:

```
GET https://mcp.example.com/health/live
GET https://mcp.example.com/.well-known/oauth-protected-resource
GET https://mcp.example.com/.well-known/oauth-authorization-server
POST https://mcp.example.com/mcp    # without token -> HTTP 401, WWW-Authenticate
```

Remote doctor verifies no TLS mismatch, no HTTP redirect to a hosted auth vendor, metadata issuer/resource match, and that 401 advertises metadata URL. Browser authorization is at `/oauth/authorize` (not browsed directly without OAuth parameters). Avoid pasting WAHA key into a shell command or screen share.

## F. ChatGPT connection (only in an eligible workspace)

Open ChatGPT on web > Plugins > Add custom MCP server. Select OAuth for the new connection and use `https://mcp.example.com/mcp`. If prompted for client-registration mode, choose CIMD. The bridge advertises CIMD and accepts ChatGPT's documented public client metadata. If callback differs from registered explicit allowed URI, verify the exact callback shown in ChatGPT's connection management page and the live CIMD, **never** add a wildcard redirect. Link login, explicitly approve scopes, inspect discovered WAHA tools. Begin with read-only WAHA App permissions. Beware tools capable of modifying messages: ask for confirmation and review before allowing send/control.

No truthful claim of successful ChatGPT linkage until this is tested against an eligible account. App write tool confirmation/publishing may be subject to workspace policy.

## G. Security operations and runbook

- **Rotate WAHA MCP App key:** create/rotate scoped key in WAHA dashboard, update protected key file/environment, restart bridge, verify read-only initialize/tools/list, revoke old WAHA key. If leak suspected, revoke old immediately and revoke OAuth grants too.
- **Revoke ChatGPT:** `npm run admin -- revoke-all` (admin CLI) invalidates all bearer and refresh grants immediately, clears auth codes/sessions. Verify known old bearer returns 401 (do not print token).
- **Change password:** `npm run admin -- reset-password`; revoke all grants and browser sessions. Never print new password or store in shell history.
- **TLS renewal:** provision renewed cert files at stable paths, validate chain/hostname remotely, restart bridge gracefully. No self-signed production fallback. Record renewal process with OS scheduler/certificate issuer outside app.
- **Backup:** protect state and password verifier/private config with filesystem encryption and offline backup; backups of token digest store still sensitive. Never back up to world-readable web directory or commit to git. Test restore in isolated environment; restored grants should be revoked if security context changed.
- **Outages:** upstream unreachable -> safe 502, not anonymous mode. On refresh replay detection, operator must reauthorize after family revocation. On state corruption, stop and restore known valid backup; do not erase state to “fix” a start failure.
- **Upgrades:** stop service, back up private data, copy source from new `dist`, run `npm test` on build host, restart and smoke check; rollback code while preserving compatible schema, never overwrite live state with stale file.
- **Audit:** inspect structured redacted logs, login rate limiting, active grants via local CLI, credential file permissions; periodically revoke unused grants.

## H. Threat model summary

- Public internet attacks: brute-force login, OAuth client-ID spoofing, redirect hijack, CSRF, code interception, replay, refresh theft, SSRF, DNS rebinding, oversized streams, DoS.
- Browser attacks: XSS via client metadata, CSRF, clickjacking, cache/referrer exfiltration.
- MCP attacks: malicious tool instructions, tool poisoning, sensitive data exfiltration, unauthorized tool writes, session cross-use, upstream key leakage.
- Operational risks: TLS expiry, lost refresh state, port conflicts, excessive permissions, logs/backups containing secrets.

Mitigations are specified in `01` and `02`, with corresponding negative tests in `03`. Note that a bridge cannot eliminate prompt injection inside WhatsApp messages or protect against legitimate but harmful actions enabled by an overly permissive WAHA key; least-privilege MCP App scopes and explicit user review remain essential.
