# Cursor Agent — binding project instructions

You are the lead implementation and verification engineer for a zero-dependency, self-hosted OAuth-to-MCP gateway. Read this whole file and every document in `docs/` before editing source.

1. Treat `docs/01-ARCHITECTURE-AND-CONTRACT.md` and `docs/02-IMPLEMENTATION-SPEC.md` as binding requirements, with security and protocol correctness above convenience. Implement every P0 item in `docs/06-WORK-BREAKDOWN.md`; do not substitute demos or skeletons.
2. Use **Node.js 18 or newer, ESM JavaScript** and **only built-in `node:` modules**. No `npm install`, `npx`, network fetched JS, external auth provider, ORM, framework, database package, frontend framework, CDN asset, Docker image dependency, or third-party JS. `npm` may run scripts. Do not use `node --env-file`; `src/main.mjs` loads `.env` with the built-in loader so Node 18 can start.
3. Every public route, OAuth state transition, persistent schema, HTTP header, timeout, file permission, and credential check must have a corresponding test. Tests use only `node:test`, `node:assert`, and built-in tools.
4. Do not add shortcuts: API-key-in-URL, disabled TLS checks, wildcard redirects, arbitrary client-ID URLs, anonymous MCP, raw secrets in logs, unverified JWTs, static authorization codes, or blind proxying of client-supplied `Authorization` headers upstream.
5. Treat all inputs and output from ChatGPT, WAHA, browsers, and filesystem as untrusted. Always fail closed. No automatic retries of a tool write operation.
6. Make implementation and tests runnable on Windows and Linux; systemd unit may be Linux-specific. Do not assume user has bash on Windows.
7. No direct live server changes, DNS changes, certificate changes, GitHub pushes, or WAHA configuration changes without explicit authorization. Local source and test fixture creation is allowed.
8. Keep a `BUILD_REPORT.md` with an itemized checklist, exact commands/results, security decisions, issues, and live tests **not performed**. Never claim real ChatGPT or real WAHA verification without performing it.
9. Before declaring complete, self-review against every acceptance item, run all tests, repair failures, check `npm ls --all` for no third-party packages, ensure generated `dist/` contains no secrets and gitignore is correct.
10. If a requirement conflicts with a newer verified upstream standard, note the evidence and make the smallest secure compatible correction; document it in `BUILD_REPORT.md`. Never silently relax security or skip a difficult feature.

First action: read all docs, prepare internal plan, then implement and test autonomously. Do not ask for domain, WAHA credentials, or a deployment target during development: use local fake WAHA and placeholders until deployment.
