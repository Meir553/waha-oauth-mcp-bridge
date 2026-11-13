# WAHA MCP OAuth Bridge

[![CI](https://github.com/Meir553/waha-oauth-mcp-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/Meir553/waha-oauth-mcp-bridge/actions/workflows/ci.yml)

One Node.js process. It is an OAuth authorization server for a single operator and a reverse proxy to one or more WAHA Streamable HTTP MCP endpoints. ChatGPT is the OAuth client. Each approval is bound to one WAHA. The bridge stores opaque access and refresh tokens, shows a browser login and consent screen, and injects that WAHA's MCP App key on the upstream request. It does not reimplement WhatsApp tools.

## Requirements

- Node.js 18 or newer. `src/main.mjs` refuses older major versions. `npm start` reads `.env` itself, so it does not depend on `node --env-file`.
- No npm packages. `npm` is only a script runner.
- A public HTTPS name. Caddy (or another reverse proxy on the same machine) holds the certificate. This process listens on a local port and does not need its own certificate.
- One scoped WAHA MCP App key. Do not use the WAHA master key.
- ChatGPT custom MCP with write-capable tools is documented by OpenAI as a Business, Enterprise, or Edu feature. A successful local build does not prove a particular ChatGPT account can connect.



## Configure

```text
node scripts/init.mjs
```

Init asks for the operator username, a password of at least 16 characters, the public `https://` origin, the WAHA URL, the API key, and a local port. Leave the certificate question empty when Caddy terminates HTTPS. It writes `data/state.json`, `data/upstream-secret.json`, and `.env`. It does not print the password or the key. Run it again only against an empty data directory; it refuses to overwrite an existing store.

On Windows, restrict the ACLs for `.env` and `data/` to the operator account. POSIX modes are recorded as `0600` and `0700`, and Windows does not apply them.

`npm start` reads `.env` from the directory where you start it. A variable already set in the process environment wins over the file. `npm run dev` forces loopback HTTP for that process only.

## Caddy

Pick any free local port, for example `8787`. Point Caddy at it and let Caddy get the certificate:

```text
mcp.example.com {
	reverse_proxy 127.0.0.1:8787
}
```

Leave Caddy's default `Host` header alone. The app checks that header against `PUBLIC_ORIGIN` and ignores `X-Forwarded-*`.

The matching `.env` is:

```text
PUBLIC_ORIGIN=https://mcp.example.com
LISTEN_HOST=127.0.0.1
LISTEN_PORT=8787
```

Do not set `TLS_CERT_FILE` or `TLS_KEY_FILE`. The process then serves plain HTTP on loopback only. ChatGPT still uses `https://mcp.example.com/mcp`. Several apps on one machine each get their own port and their own Caddy site block.

`LISTEN_HOST` must stay `127.0.0.1` or `::1` when this process has no certificate. That keeps the unauthenticated hop on the machine. Set `TLS_CERT_FILE` and `TLS_KEY_FILE` together only when this process itself terminates HTTPS, and then set `LISTEN_HOST=0.0.0.0` and `LISTEN_PORT` to the public port.

## Environment

The operator username and password are not environment variables. You choose them when init asks. The password is 16 to 256 characters. Init stores a hash in `DATA_DIR/state.json`.

### Required

| Variable | Where it comes from |
|---|---|
| `PUBLIC_ORIGIN` | The HTTPS name Caddy serves, with no path and no trailing slash. Example: `https://mcp.example.com`. ChatGPT's connector URL for the first WAHA is this origin plus `/mcp`. |
| `LISTEN_PORT` | The local port you chose for this app. Init asks for it and defaults to `8787`. It does not have to match the public port. |
| `UPSTREAM_MCP_URL` | WAHA's MCP address for the first WhatsApp session. On the same machine this is usually `http://127.0.0.1:3000/mcp`. The path must be `/mcp`. The address must be loopback or another private address unless you set `ALLOW_PUBLIC_UPSTREAM=true`. |
| `DATA_DIR` | The directory for `state.json`, `upstream-secret.json`, and `upstreams.json`. Init creates `./data` and writes its absolute path here. |

The first WAHA's API key is also required. Put it in `DATA_DIR/upstream-secret.json`, which init creates. In WAHA, open the session, open Apps, create an MCP App, and copy that app's key. Use a scoped MCP App key. Leave the global WAHA API key out of this bridge.

`UPSTREAM_API_KEY` is an optional second copy of that same key. Leave it unset when the secret file exists. If both are set, they must be identical.

### Defaults you can leave alone

| Variable | Default | What it is |
|---|---|---|
| `NODE_ENV` | `production` | Production allows loopback HTTP behind a reverse proxy and refuses `ENABLE_LOCAL_TEST_HTTP`. |
| `LISTEN_HOST` | `127.0.0.1` when Caddy terminates HTTPS | Use `0.0.0.0` only when this process terminates TLS itself. |
| `MCP_PATH` | `/mcp` | The only accepted value. The first connector URL is `PUBLIC_ORIGIN/mcp`. |
| `UPSTREAM_API_KEY_HEADER` | `X-Api-Key` | The header WAHA expects for the MCP App key. Change it when that WAHA is configured for a different header name. |
| `UPSTREAM_DISPLAY_NAME` | `connected WhatsApp session` | The name shown on the consent screen for the first WAHA. You choose the words. |
| `ALLOW_PUBLIC_UPSTREAM` | `false` | `true` allows a public WAHA address. TLS verification stays enabled. The value must be `true` or `false`. |
| `ORIGIN_ALLOWLIST` | the public origin and `https://chatgpt.com` | Comma-separated browser origins allowed to call the bridge. No wildcards. |
| `LOG_LEVEL` | `info` | One of `debug`, `info`, `warn`, or `error`. Logs omit tokens, passwords, and the WAHA key. |
| `TLS_CERT_FILE` | unset | PEM certificate chain, only when this process terminates HTTPS. Leave it empty behind Caddy. A regular file, not a symlink. |
| `TLS_KEY_FILE` | unset | PEM private key matching `TLS_CERT_FILE`. Set both or neither. |
| `ENABLE_LOCAL_TEST_HTTP` | `false` | Development-only plain HTTP. Production refuses it. Leave it `false` on a server. |

### More WAHAs

Additional WAHAs are not environment variables. `npm run admin -- add-upstream ID` asks for that WAHA's MCP URL, a display name, and its MCP App key, then writes `DATA_DIR/upstreams.json`. Restart the bridge afterward. That connector URL is `PUBLIC_ORIGIN/mcp/ID`.

### Doctor commands

`npm start` does not read these. Set them in the environment for one `npm run doctor:remote` run.

| Variable | Where it comes from |
|---|---|
| `DOCTOR_ORIGIN` | The public `https://` origin of a bridge that is already running. |
| `DOCTOR_UPSTREAM_URL` | A WAHA MCP URL. The check sends only `initialize` and `tools/list`. |
| `DOCTOR_UPSTREAM_API_KEY` | The MCP App key for that URL. Pass it in the environment, not as a command argument. |

### Optional limits

Leave these unset. Each value is an integer inside the range shown.

| Variable | Default | Allowed range | Meaning |
|---|---|---|---|
| `CODE_TTL_SEC` | 120 | 30–600 | Lifetime of an authorization code. |
| `ACCESS_TTL_SEC` | 900 | 60–3600 | Lifetime of an access token. |
| `REFRESH_TTL_SEC` | 2592000 | 3600–7776000 | Lifetime of a refresh-token family, counted from its creation. |
| `SESSION_IDLE_SEC` | 900 | 60–3600 | Browser login idle timeout. |
| `SESSION_ABSOLUTE_SEC` | 28800 | 300–86400 | Browser login absolute timeout. |
| `AUTH_REQUEST_TTL_SEC` | 600 | 60–1800 | How long the consent request stays valid. |
| `MAX_REQUEST_BYTES` | 1048576 | 1024–8388608 | Largest accepted MCP request body. |
| `MAX_STREAMS` | 8 | 1–64 | Concurrent upstream SSE streams from `GET /mcp`. |
| `STREAM_IDLE_MS` | 120000 | 1000–1800000 | Idle limit for one stream. |
| `STREAM_LIFETIME_MS` | 1800000 | 5000–3600000 | Absolute limit for one stream. |
| `CONNECT_TIMEOUT_MS` | 5000 | 200–10000 | Upstream TCP connection timeout. |
| `HEADER_TIMEOUT_MS` | 10000 | 200–60000 | Upstream response-header timeout. |
| `BODY_TIMEOUT_MS` | 30000 | 200–120000 | Request body read timeout. |
| `LOGIN_MAX_FAILURES` | 5 | 3–20 | Failed logins before a lockout. |
| `LOGIN_WINDOW_SEC` | 900 | 60–3600 | Window that counts those failures. |
| `LOGIN_LOCK_SEC` | 900 | 60–3600 | How long login stays locked. |
| `TOKEN_MAX_PER_WINDOW` | 60 | 5–300 | Token-endpoint requests allowed in one window. |
| `TOKEN_WINDOW_SEC` | 60 | 10–600 | Length of that window. |
| `CIMD_CACHE_SEC` | 300 | 5–3600 | How long a fetched ChatGPT client document is cached. |

## Operate

```text
npm start
npm run admin -- status
npm run admin -- revoke-all
npm run admin -- revoke-grant GRANT_ID
npm run admin -- add-upstream sales
npm run admin -- remove-upstream sales
npm run admin -- reset-password
npm run admin -- recover-lock
npm run doctor:local
```

`status` does not take the process lock. It lists each WAHA id and the grant bound to it. It does not print API keys. Destructive admin commands need the current password and the lock, so stop the server first. `recover-lock` removes `data/bridge.lock` only when the recorded pid is not alive.

## Several WAHAs and several ChatGPT connectors

The WAHA in `UPSTREAM_MCP_URL` is the `default` connection. Its ChatGPT URL is `https://YOUR_ORIGIN/mcp`. Add another WAHA from a terminal:

```text
npm run admin -- add-upstream sales
```

The command asks for that WAHA's MCP URL, a display name, its API key, and the operator password. It writes `data/upstreams.json` and does not print the key. Restart the bridge. The new ChatGPT URL is `https://YOUR_ORIGIN/mcp/sales`.

Give each ChatGPT connector one of those URLs. When that connector signs in, the consent screen names the WAHA and its path. Approve it only if that ChatGPT should use that WAHA. The issued token works on that path alone. A second ChatGPT uses a second connector URL and a second approval. `status` shows the grant id and the WAHA id. `revoke-grant` cuts off one approval. `remove-upstream` revokes every grant for that added WAHA and deletes it from `data/upstreams.json`. Restart after adding or removing a WAHA. The `default` WAHA stays in `.env`.

`doctor:local` is an offline simulation with a fake upstream. `doctor:remote` talks to a deployed origin only when `DOCTOR_ORIGIN` is set. An upstream `initialize` and `tools/list` run only when both `DOCTOR_UPSTREAM_URL` and `DOCTOR_UPSTREAM_API_KEY` are in the environment. It refuses every other JSON-RPC method. Neither doctor proves a ChatGPT login.

The Linux unit `systemd/waha-mcp-bridge.service` is a placeholder. PM2 works as one instance with the project directory as its working directory, so `.env` loads. Do not expose `data/` through a web server.

## Public behavior

The default resource identifier is the public origin plus `/mcp`. Each added WAHA uses the public origin plus `/mcp/{id}`. Unauthenticated `POST` on either path returns 401 and a `WWW-Authenticate` challenge for that resource. The authorization server advertises `token_endpoint_auth_methods_supported: ["none"]`, PKCE S256, and client metadata documents. The only accepted client identifiers are `https://chatgpt.com/oauth/client.json` and `https://chatgpt.com/oauth/{callback_id}/client.json`. Redirects are limited to the stable ChatGPT connector redirect and the callback-specific URI from the fetched document.

Browser pages are served with a locked content security policy. Styles come from `/styles.css` on this origin. The consent screen states that approval issues a refresh token and that WhatsApp read or send permission is enforced by the WAHA key.

## Development checks

```text
npm test
npm run lint:security
npm run doctor:local
npm run build
npm ls --all
```

`npm run build` syntax-checks the source, runs the security scan and the test suite, and writes `dist/` without tests, data, or secrets. The packaged server starts on Node.js 18 or newer.

## License

Required Notice: Copyright Mayer Gottlieb (https://github.com/Meir553/waha-oauth-mcp-bridge)

Personal use is allowed. Use by a charitable, educational, public-research, public-safety, public-health, environmental, or government organization is allowed. Commercial use is not allowed. The full terms are in `LICENSE` under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0).