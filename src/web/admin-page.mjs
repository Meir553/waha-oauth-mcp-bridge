import { escapeHtml } from '../http.mjs';
import { layout } from './login.mjs';

/**
 * @param {{ csrf: string, error: string }} view
 */
export function renderAdminLogin(view) {
  const alert = view.error ? `<p class="alert" role="alert">${escapeHtml(view.error)}</p>` : '';
  return layout({
    title: 'Admin',
    body: `<h1>Admin</h1>
<p>Sign in with the username and password from setup. This is the control panel for your WhatsApps and the ChatGPT approvals.</p>
${alert}
<form method="post" action="/admin/login" accept-charset="utf-8">
<label for="username">Username</label>
<input id="username" name="username" type="text" autocomplete="username" required maxlength="64">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required minlength="16" maxlength="256">
<input type="hidden" name="csrf" value="${escapeHtml(view.csrf)}">
<button type="submit">Sign in</button>
</form>`,
  });
}

/**
 * The shell stays on screen. Lists and the activity log are filled by /admin.js.
 * @param {{ csrf: string, username: string }} view
 */
export function renderAdminApp(view) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf" content="${escapeHtml(view.csrf)}">
<title>Admin</title>
<link rel="stylesheet" href="/styles.css">
</head>
<body class="app">
<header class="top">
<div>
<p class="eyebrow">WhatsApp bridge</p>
<h1>Admin</h1>
</div>
<div class="who">
<p>Signed in as <strong>${escapeHtml(view.username)}</strong></p>
<button type="button" class="secondary" id="sign-out">Sign out</button>
</div>
</header>
<p id="notice" class="notice" role="status"></p>
<div class="workspace">
<section class="sheet" aria-labelledby="accounts-title">
<h2 id="accounts-title">WhatsApps</h2>
<p>Each one has its own ChatGPT address. The first one comes from setup. Extra ones you add here are ready as soon as you save them.</p>
<div id="accounts"></div>
<h2>Add a WhatsApp</h2>
<form id="add-form">
<label for="short-name">Short name</label>
<input id="short-name" name="id" required maxlength="32" autocomplete="off" placeholder="sales">
<p class="hint">Lowercase letters, numbers, and hyphens. It becomes part of the address, such as /mcp/sales.</p>
<label for="display-name">Name on the approval page</label>
<input id="display-name" name="displayName" required maxlength="80" autocomplete="off" placeholder="Sales WhatsApp">
<label for="waha-url">WAHA address</label>
<input id="waha-url" name="url" required maxlength="512" autocomplete="off" placeholder="http://127.0.0.1:3000/mcp" spellcheck="false">
<label for="api-key">MCP App key</label>
<input id="api-key" name="apiKey" type="password" required minlength="8" maxlength="512" autocomplete="off">
<button type="submit">Add WhatsApp</button>
</form>
</section>
<section class="sheet" aria-labelledby="approvals-title">
<h2 id="approvals-title">ChatGPT approvals</h2>
<p>Each approval is one ChatGPT connector plus one WhatsApp. Cutting one off leaves the others alone.</p>
<div id="approvals"></div>
<button type="button" class="secondary" id="revoke-all">Cut off every approval</button>
<details>
<summary>Change password</summary>
<form id="password-form">
<label for="current-password">Current password</label>
<input id="current-password" name="current" type="password" required minlength="16" maxlength="256" autocomplete="current-password">
<label for="next-password">New password</label>
<input id="next-password" name="next" type="password" required minlength="16" maxlength="256" autocomplete="new-password">
<label for="confirm-password">New password again</label>
<input id="confirm-password" name="confirm" type="password" required minlength="16" maxlength="256" autocomplete="new-password">
<button type="submit">Change password</button>
</form>
</details>
</section>
<section class="activity" aria-labelledby="activity-title">
<div class="activity-head">
<div>
<h2 id="activity-title">Assistant activity</h2>
<p>Live. This list does not reload the page.</p>
</div>
<p class="live" id="live"><span class="dot"></span><span id="live-label">Connecting</span></p>
</div>
<ol id="log" class="log">
<li class="muted" id="log-empty">Nothing yet. When a connected ChatGPT uses a WhatsApp, it shows up here. Message text and keys stay off this screen.</li>
</ol>
</section>
</div>
<script src="/admin.js"></script>
</body>
</html>
`;
}
