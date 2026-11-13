import { escapeHtml } from '../http.mjs';

/**
 * @param {{ title: string, body: string }} page
 */
export function layout(page) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(page.title)}</title>
<link rel="stylesheet" href="/styles.css">
</head>
<body>
<main class="card">
${page.body}
</main>
</body>
</html>
`;
}

/**
 * @param {{ csrf: string, error: string }} view
 */
export function renderLogin(view) {
  const alert = view.error ? `<p class="alert" role="alert">${escapeHtml(view.error)}</p>` : '';
  return layout({
    title: 'Sign in',
    body: `<h1>Sign in</h1>
<p>This sign-in is only for the operator of this WhatsApp bridge.</p>
${alert}
<form method="post" action="/login" accept-charset="utf-8">
<label for="username">Username</label>
<input id="username" name="username" type="text" autocomplete="username" required maxlength="64">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required minlength="16" maxlength="256">
<input type="hidden" name="csrf" value="${escapeHtml(view.csrf)}">
<input type="hidden" name="request_id" value="">
<button type="submit">Continue</button>
</form>`,
  });
}

/**
 * The login form's request id is filled from the pending cookie by the server
 * response rewriter below. Keeping it out of the query string avoids reflecting
 * untrusted URLs. The handler passes the id explicitly.
 * @param {{ csrf: string, requestId: string, error: string }} view
 */
export function renderLoginForm(view) {
  const alert = view.error ? `<p class="alert" role="alert">${escapeHtml(view.error)}</p>` : '';
  return layout({
    title: 'Sign in',
    body: `<h1>Sign in</h1>
<p>This sign-in is only for the operator of this WhatsApp bridge.</p>
${alert}
<form method="post" action="/login" accept-charset="utf-8">
<label for="username">Username</label>
<input id="username" name="username" type="text" autocomplete="username" required maxlength="64">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required minlength="16" maxlength="256">
<input type="hidden" name="csrf" value="${escapeHtml(view.csrf)}">
<input type="hidden" name="request_id" value="${escapeHtml(view.requestId)}">
<button type="submit">Continue</button>
</form>`,
  });
}

/**
 * @param {{ csrf: string, clientName: string, clientId: string, scopes: string[], upstreamName: string }} view
 */
export function renderConsent(view) {
  const scopes = view.scopes.map((scope) => `<li><code>${escapeHtml(scope)}</code></li>`).join('');
  return layout({
    title: 'Approve connection',
    body: `<h1>Approve connection</h1>
<p>A client identifying itself as <strong>${escapeHtml(view.clientName)}</strong> is asking to use this bridge.</p>
<p>Client identifier: <code>${escapeHtml(view.clientId)}</code></p>
<p>Approving lets this client reach only ${escapeHtml(view.upstreamName)} at <code>${escapeHtml(view.upstreamPath || '')}</code>. Other WAHA connections on this bridge stay closed to this client. WhatsApp read or send permission is enforced by that WAHA MCP App key. Approval also issues a refresh token so the client can reconnect to this WAHA until you revoke the grant. Nothing is approved automatically.</p>
<h2>Requested access</h2>
<ul>${scopes}</ul>
<form method="post" action="/oauth/consent" accept-charset="utf-8">
<input type="hidden" name="csrf" value="${escapeHtml(view.csrf)}">
<input type="hidden" name="request_id" value="">
<button type="submit" name="decision" value="approve">Approve</button>
<button type="submit" class="secondary" name="decision" value="deny">Deny</button>
</form>
<form method="post" action="/logout" accept-charset="utf-8" class="inline">
<input type="hidden" name="csrf" value="${escapeHtml(view.csrf)}">
<button type="submit" class="secondary">Sign out</button>
</form>`,
  });
}

/**
 * @param {{ csrf: string, requestId: string, clientName: string, clientId: string, scopes: string[], upstreamName: string }} view
 */
export function renderConsentForm(view) {
  const scopes = view.scopes.map((scope) => `<li><code>${escapeHtml(scope)}</code></li>`).join('');
  return layout({
    title: 'Approve connection',
    body: `<h1>Approve connection</h1>
<p>A client identifying itself as <strong>${escapeHtml(view.clientName)}</strong> is asking to use this bridge.</p>
<p>Client identifier: <code>${escapeHtml(view.clientId)}</code></p>
<p>Approving lets this client reach only ${escapeHtml(view.upstreamName)} at <code>${escapeHtml(view.upstreamPath || '')}</code>. Other WAHA connections on this bridge stay closed to this client. WhatsApp read or send permission is enforced by that WAHA MCP App key. Approval also issues a refresh token so the client can reconnect to this WAHA until you revoke the grant. Nothing is approved automatically.</p>
<h2>Requested access</h2>
<ul>${scopes}</ul>
<form method="post" action="/oauth/consent" accept-charset="utf-8">
<input type="hidden" name="csrf" value="${escapeHtml(view.csrf)}">
<input type="hidden" name="request_id" value="${escapeHtml(view.requestId)}">
<button type="submit" name="decision" value="approve">Approve</button>
<button type="submit" class="secondary" name="decision" value="deny">Deny</button>
</form>
<form method="post" action="/logout" accept-charset="utf-8" class="inline">
<input type="hidden" name="csrf" value="${escapeHtml(view.csrf)}">
<button type="submit" class="secondary">Sign out</button>
</form>`,
  });
}

export function renderLocalErrorPage() {
  return layout({
    title: 'Request blocked',
    body: `<h1>Request blocked</h1>
<p>This authorization request cannot continue. Start again from the client that sent you here. No code was issued.</p>`,
  });
}
