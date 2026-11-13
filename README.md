# WAHA MCP OAuth Bridge

[![CI](https://github.com/Meir553/waha-oauth-mcp-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/Meir553/waha-oauth-mcp-bridge/actions/workflows/ci.yml)

This is a small program that sits between ChatGPT and your WAHA. WAHA is the WhatsApp server. ChatGPT is not allowed to talk to WAHA directly. ChatGPT talks to this program, you approve it in the browser, and this program passes the request on with the right WAHA key.

One running copy can serve several WhatsApp accounts and several ChatGPT connectors. You decide which connector may use which WhatsApp.

## What you need

- Node.js 18 or newer.
- A name on the internet, such as `mcp.example.com`, with Caddy (or another reverse proxy) in front of it. Caddy holds the HTTPS certificate. This program only listens on a port you pick, so several apps can share one machine.
- A WAHA MCP App key for each WhatsApp. In WAHA, open the session, open Apps, and create an MCP App. Copy that app's key. Leave WAHA's master key out of this.
- A ChatGPT account that can add a custom connector. OpenAI currently documents write-capable custom connectors for Business, Enterprise, and Edu accounts.

## First-time setup

From the project folder:

```text
node scripts/init.mjs
```

It asks a few questions:

- A username, and a password of at least 16 characters. These are for the browser login page. They are not ChatGPT's password and not WAHA's key.
- The public address, such as `https://mcp.example.com`. No path, no slash at the end.
- The first WAHA address, usually `http://127.0.0.1:3000/mcp` when WAHA is on the same machine.
- That WAHA's MCP App key.
- A local port. Press Enter to use `8787`, or type another free port.
- A certificate file. Press Enter. Caddy already has the certificate.

It writes `.env`, `data/state.json`, and `data/upstream-secret.json`. The key goes in the secret file. The password is stored as a hash. The command does not print either of them. Run it again only on an empty `data` folder. It will refuse to overwrite one that already exists.

Start it from the same folder, so it finds `.env`:

```text
npm start
```

PM2 is fine. Use one instance, and set the working directory to this project. A second copy will refuse to start because only one process may write `data/`.

## Caddy

```text
mcp.example.com {
	reverse_proxy 127.0.0.1:8787
}
```

Change the name and the port to match yours. Leave Caddy's Host header as it is. ChatGPT uses `https://mcp.example.com/mcp`.

The matching lines in `.env` are:

```text
PUBLIC_ORIGIN=https://mcp.example.com
LISTEN_HOST=127.0.0.1
LISTEN_PORT=8787
```

`LISTEN_HOST` stays `127.0.0.1` so only this machine can reach the program. Caddy is the public door.

## Add a WhatsApp

The WhatsApp you entered during setup is already there. Its ChatGPT address is:

```text
https://mcp.example.com/mcp
```

To add another WhatsApp, pick a short name. Use lowercase letters, numbers, and hyphens, and start with a letter. `sales` is a fine name. `default` is reserved.

```text
npm run admin -- add-upstream sales
```

It asks for that WAHA's address, a name to show on the approval page, its MCP App key, and your password. Then restart the program. The new ChatGPT address is:

```text
https://mcp.example.com/mcp/sales
```

Each WhatsApp gets its own address. The key for an added WhatsApp is stored in `data/upstreams.json`.

## Add a ChatGPT

You add ChatGPT from inside ChatGPT, not from this program. Create a custom connector and paste one address from above.

ChatGPT opens your login page. Sign in with the username and password from setup, read the page, and approve it. The page names the WhatsApp. Approving lets that connector use that WhatsApp until you take it back.

## Who can use what

Each approval is one connector plus one WhatsApp.

**One ChatGPT, two WhatsApps.** In that ChatGPT, create two connectors. Paste `https://mcp.example.com/mcp` into the first and `https://mcp.example.com/mcp/sales` into the second. Approve each one. That ChatGPT then has both WhatsApps, as two separate connectors.

**Two ChatGPTs, one WhatsApp.** Give both of them the same address, for example `https://mcp.example.com/mcp`. Each one logs in, and you approve each one. Both talk to that same WhatsApp. You can cut one off later and leave the other alone.

See who is approved:

```text
npm run admin -- status
```

It prints each WhatsApp and each approval. It does not print keys. To cut off one approval, stop the program, then:

```text
npm run admin -- revoke-grant GRANT_ID
```

`GRANT_ID` is the id from `status`. Start the program again afterward.

To remove an added WhatsApp, stop the program, then:

```text
npm run admin -- remove-upstream sales
```

That deletes `sales` and cuts off every approval for it. The first WhatsApp stays in `.env`. Restart afterward.

Other commands, also with the program stopped:

- `npm run admin -- revoke-all` cuts off every approval.
- `npm run admin -- reset-password` sets a new password and cuts off every approval.
- `npm run admin -- recover-lock` clears `data/bridge.lock` when the program crashed and the old process is gone. If the program is still running, leave the lock alone.

## Settings

Init writes the ones you need. A value already set in the environment wins over `.env`.

| Setting | What to put |
|---|---|
| `PUBLIC_ORIGIN` | The https address Caddy serves, such as `https://mcp.example.com`. |
| `LISTEN_PORT` | The local port you picked. It does not have to be 443. |
| `LISTEN_HOST` | `127.0.0.1` when Caddy is in front. |
| `UPSTREAM_MCP_URL` | The first WAHA, usually `http://127.0.0.1:3000/mcp`. The path is `/mcp`. |
| `DATA_DIR` | Where the password hash, keys, and approvals are stored. Init uses `./data`. |
| `UPSTREAM_DISPLAY_NAME` | The words shown on the approval page for the first WhatsApp. |
| `UPSTREAM_API_KEY_HEADER` | Leave this as `X-Api-Key` unless that WAHA expects a different header. |
| `ALLOW_PUBLIC_UPSTREAM` | Leave `false`. Set `true` only if a WAHA is on a public address. |
| `LOG_LEVEL` | `info` is enough. Logs leave out passwords, keys, and tokens. |
| `ORIGIN_ALLOWLIST` | Browsers allowed to call this program. Init includes your public address and `https://chatgpt.com`. |

`UPSTREAM_API_KEY` is optional. The first key already lives in `data/upstream-secret.json`. Leave the environment variable empty. If you set both, they must be the same key.

`TLS_CERT_FILE` and `TLS_KEY_FILE` stay empty behind Caddy. Fill both in only if this program itself serves HTTPS, and then set `LISTEN_HOST=0.0.0.0` and `LISTEN_PORT` to the public port.

Leave these alone:

- `NODE_ENV=production`
- `MCP_PATH=/mcp`
- `ENABLE_LOCAL_TEST_HTTP=false`

On Windows, limit `.env` and `data/` to your own user account. The program records private file permissions, and Windows does not apply them by itself.

### Knobs you can ignore

Each one is a number. Uncomment it in `.env` only if you want to change the default.

| Setting | Default | What it changes |
|---|---|---|
| `CODE_TTL_SEC` | 120 | How long a login code stays valid. |
| `ACCESS_TTL_SEC` | 900 | How long an access token stays valid. |
| `REFRESH_TTL_SEC` | 2592000 | How long a connector can keep renewing access, from the day you approved it. |
| `SESSION_IDLE_SEC` | 900 | How long you can sit idle on the login page. |
| `SESSION_ABSOLUTE_SEC` | 28800 | How long a browser login lasts in total. |
| `AUTH_REQUEST_TTL_SEC` | 600 | How long ChatGPT's approval request stays valid. |
| `MAX_REQUEST_BYTES` | 1048576 | Largest request this program accepts. |
| `MAX_STREAMS` | 8 | How many live streams it will hold open at once. |
| `STREAM_IDLE_MS` | 120000 | How long a quiet stream may stay open. |
| `STREAM_LIFETIME_MS` | 1800000 | How long any stream may stay open. |
| `CONNECT_TIMEOUT_MS` | 5000 | How long to wait while connecting to WAHA. |
| `HEADER_TIMEOUT_MS` | 10000 | How long to wait for WAHA to start answering. |
| `BODY_TIMEOUT_MS` | 30000 | How long to wait while reading a request. |
| `LOGIN_MAX_FAILURES` | 5 | Wrong passwords before the login page locks. |
| `LOGIN_WINDOW_SEC` | 900 | The period those wrong passwords are counted in. |
| `LOGIN_LOCK_SEC` | 900 | How long the lock lasts. |
| `TOKEN_MAX_PER_WINDOW` | 60 | How many token requests are allowed in one window. |
| `TOKEN_WINDOW_SEC` | 60 | The length of that window. |
| `CIMD_CACHE_SEC` | 300 | How long ChatGPT's client description is remembered. |

## Checkups

You can skip these. The program runs without them.

`npm run doctor:local` rehearses a login on this computer with a fake WAHA. It never calls ChatGPT, your real WAHA, or the internet. `pass` means the program can complete its own steps. It says nothing about your server.

`npm run doctor:remote` checks a copy that is already running. For one run, set `DOCTOR_ORIGIN` to your public address, such as `https://mcp.example.com`. It checks that the public description pages answer, and that a visitor with no approval is turned away. It does not log into ChatGPT.

If you also set `DOCTOR_UPSTREAM_URL` and `DOCTOR_UPSTREAM_API_KEY` for that same run, it asks that WAHA which tools it has. It does not send a WhatsApp message. Put the key in the environment, not in the command line.

## If you are changing the code

```text
npm test
npm run lint:security
npm run doctor:local
npm run build
```

`npm run build` checks the source and writes `dist/` without tests, data, or secrets.

## License

Required Notice: Copyright Mayer Gottlieb (https://github.com/Meir553/waha-oauth-mcp-bridge)

Personal use is allowed. Use by a charitable, educational, public-research, public-safety, public-health, environmental, or government organization is allowed. Commercial use is not allowed. The full terms are in `LICENSE` under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0).
