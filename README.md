# WAHA MCP OAuth Bridge

[![CI](https://github.com/Meir553/waha-oauth-mcp-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/Meir553/waha-oauth-mcp-bridge/actions/workflows/ci.yml)

One Node.js process. It is an OAuth authorization server for a single operator and a reverse proxy to one or more WAHA Streamable HTTP MCP endpoints. ChatGPT is the OAuth client. Each approval is bound to one WAHA. The bridge stores opaque access and refresh tokens, shows a browser login and consent screen, and injects that WAHA's MCP App key on the upstream request. It does not reimplement WhatsApp tools.

This repository is the application. `BUILD_REPORT.md` records which checks ran on this machine and which live checks were not performed.

## Requirements

- Node.js 18 or newer. `src/main.mjs` refuses older major versions. `npm start` reads `.env` itself, so it does not depend on `node --env-file`.
- No npm packages. `npm` is only a script runner.
- A publicly trusted TLS certificate for the public origin. The process terminates HTTPS itself.
- One scoped WAHA MCP App key. Do not use the WAHA master key.
- ChatGPT custom MCP with write-capable tools is documented by OpenAI as a Business, Enterprise, or Edu feature. A successful local build does not prove a particular ChatGPT account can connect.



## Configure

```text
node scripts/init.mjs
```

Init asks for the operator username, a password of at least 16 characters, the public `https://` origin, the upstream `http://127.0.0.1:3000/mcp` style URL, the API key, and the certificate paths. It writes `data/state.json`, `data/upstream-secret.json`, and `.env`. It does not print the password or the key. Run it again only against an empty data directory; it refuses to overwrite an existing store.

On Windows, restrict the ACLs for `.env`, `data/`, and the TLS private key to the operator account. POSIX modes are recorded as `0600` and `0700`, and Windows does not apply them.

`npm run dev` forces loopback HTTP and is only for a local process. Production is `npm start`, which requires Node.js 18 or newer, `NODE_ENV=production`, and the certificate files.

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

The Linux unit `systemd/waha-mcp-bridge.service` is a placeholder. Do not install it until the host, user, certificate, and state directory are chosen. On Windows, run `npm start` under a private account. Do not expose `data/` through a web server.

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