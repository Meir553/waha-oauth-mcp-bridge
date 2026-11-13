# Cursor Agent — EXECUTE THIS BUILD

You are working in the root of a new project. **Implement the complete production-oriented WAHA MCP OAuth Bridge from scratch, with no npm dependencies.** This is an implementation request, not a request for another plan. Work autonomously through implementation, automated testing, fixes, build, and final review.

## Do first

Read, in order:
1. `AGENTS.md`
2. `docs/01-ARCHITECTURE-AND-CONTRACT.md`
3. `docs/02-IMPLEMENTATION-SPEC.md`
4. `docs/03-TEST-AND-ACCEPTANCE.md`
5. `docs/04-DEPLOYMENT.md`
6. `docs/05-SOURCES-AND-DESIGN-DECISIONS.md`
7. `docs/06-WORK-BREAKDOWN.md`

Use the docs as the contract. Do not drop requirements for token security, OAuth discovery, CIMD, SSE streaming, session continuity, persistence, or negative tests.

## Deliverables

- Actual runnable implementation in `src/`, not a mock or an architecture diagram.
- Secure one-time setup CLI, dependency-free configuration handling, startup checks, local doctor, remote doctor (read-only), and deterministic `npm run build` that packages `dist/`.
- All specified `node:test` contract, integration, adversarial, streaming, recovery, and configuration tests with a built-in fake WAHA and simulated OAuth client.
- `package.json` scripts: `start`, `dev`, `init`, `test`, `test:integration`, `build`, `doctor:local`, `doctor:remote`, `lint:security` (a custom check with only Node built-ins).
- `.env.example`, `.gitignore`, `systemd/waha-mcp-bridge.service`, `README.md` updated for the finished app, and `BUILD_REPORT.md`.
- No `node_modules`, no external imports, no install steps, and no real credentials anywhere.

## Build procedure

1. Inspect Node version and existing project. If Node 26 is missing, implement to Node 26 APIs but state that execution requires Node 26; do not silently install or use external tooling.
2. Implement work packages in `docs/06-WORK-BREAKDOWN.md` in order.
3. Test each package; fix failures before the next.
4. Run complete test suite and negative/security test suite.
5. Run `npm run build` and verify a deployable `dist/` with no secret files or test keys.
6. Review all routes and invariants against spec. Run `npm run doctor:local` against a test server.
7. Update `BUILD_REPORT.md` with exact pass counts, environment, remaining deployment-only prerequisites, and explicit status for real ChatGPT and real WAHA testing.

## Security stop conditions

If you cannot securely implement or test a P0 security component, do not claim project completion. Record the failing item and why; keep the gateway fail-closed. Do not add anonymous MCP, ignore certificate errors, disable PKCE, or skip redirect validation as a workaround.

## Final Cursor answer

Return a concise final summary: files created, commands executed and test results, how to run local simulation, exact production prerequisites, important security choices, and any unverified real-world integration. The end-user wants this app to be ready to configure after Build; do not ask for credentials until local build/test is complete.

**BEGIN IMPLEMENTATION NOW.**
