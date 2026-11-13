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
<p>Sign in to manage your WhatsApps and the ChatGPTs allowed to use them.</p>
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
<p>Each WhatsApp has one address. Paste that address into a ChatGPT connector.</p>
<div id="accounts"></div>
<h3>Add a WhatsApp</h3>
<form id="add-form">
<label for="short-name">Short name</label>
<input id="short-name" name="id" required maxlength="32" autocomplete="off" placeholder="sales">
<p class="hint">Letters, numbers, and hyphens. Shows up in the address as /mcp/sales.</p>
<label for="display-name">Name people see when they approve</label>
<input id="display-name" name="displayName" required maxlength="80" autocomplete="off" placeholder="Sales WhatsApp">
<label for="waha-url">WAHA address</label>
<input id="waha-url" name="url" required maxlength="512" autocomplete="off" placeholder="http://127.0.0.1:3000/mcp" spellcheck="false">
<label for="api-key">MCP App key</label>
<input id="api-key" name="apiKey" type="password" required minlength="8" maxlength="512" autocomplete="off">
<button type="submit">Add WhatsApp</button>
</form>
</section>
<section class="sheet" aria-labelledby="approvals-title">
<h2 id="approvals-title">ChatGPTs</h2>
<p>Each row is one ChatGPT that you allowed to use one WhatsApp. Rename it here if you need to.</p>
<div id="approvals"></div>
<details>
<summary>Password and access</summary>
<form id="password-form">
<label for="current-password">Current password</label>
<input id="current-password" name="current" type="password" required minlength="16" maxlength="256" autocomplete="current-password">
<label for="next-password">New password</label>
<input id="next-password" name="next" type="password" required minlength="16" maxlength="256" autocomplete="new-password">
<label for="confirm-password">New password again</label>
<input id="confirm-password" name="confirm" type="password" required minlength="16" maxlength="256" autocomplete="new-password">
<button type="submit">Change password</button>
</form>
<button type="button" class="secondary" id="revoke-all">Remove every ChatGPT</button>
</details>
</section>
<section class="activity" aria-labelledby="activity-title">
<div class="activity-head">
<div>
<h2 id="activity-title">Activity</h2>
<p>Updates as ChatGPT works. The page stays put.</p>
</div>
<p class="live" id="live"><span class="dot"></span><span id="live-label">Connecting</span></p>
</div>
<ol id="log" class="log">
<li class="muted" id="log-empty">No activity yet. Message text and keys are not shown.</li>
</ol>
</section>
</div>
<script src="/admin.js"></script>
</body>
</html>
`;
}
