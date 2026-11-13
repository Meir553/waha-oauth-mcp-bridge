(function () {
  const csrf = document.querySelector('meta[name="csrf"]').content;
  const notice = document.getElementById('notice');
  const accounts = document.getElementById('accounts');
  const approvals = document.getElementById('approvals');
  const log = document.getElementById('log');
  const liveLabel = document.getElementById('live-label');
  const names = new Map();

  function say(text, bad) {
    notice.textContent = text || '';
    notice.classList.toggle('alert', Boolean(bad));
  }

  function field(form, name) {
    const input = form.elements[name];
    return input ? String(input.value || '') : '';
  }

  async function post(path, body) {
    const response = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
      body: JSON.stringify(body),
    });
    let payload = {};
    try { payload = await response.json(); } catch { payload = {}; }
    if (response.status === 401) {
      location.assign('/admin');
      return null;
    }
    if (!response.ok) throw new Error(payload.error || 'That did not work.');
    return payload;
  }

  function renderAccounts(items) {
    accounts.replaceChildren();
    names.clear();
    for (const item of items) {
      names.set(item.id, item.name);
      const card = document.createElement('article');
      card.className = 'entry';
      const title = document.createElement('h3');
      title.textContent = item.name;
      const address = document.createElement('p');
      const label = document.createElement('span');
      label.textContent = 'ChatGPT address ';
      const code = document.createElement('code');
      code.textContent = item.url;
      address.append(label, code);
      card.append(title, address);
      if (item.id !== 'default') {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'secondary';
        button.textContent = 'Remove';
        button.addEventListener('click', async () => {
          if (!window.confirm('Remove ' + item.name + ' and cut off its approvals?')) return;
          try {
            const payload = await post('/admin/api/upstream/remove', { id: item.id });
            if (payload) {
              renderState(payload.state);
              say(item.name + ' was removed.');
            }
          } catch (err) {
            say(err.message, true);
          }
        });
        card.append(button);
      } else {
        const note = document.createElement('p');
        note.className = 'hint';
        note.textContent = 'This is the WhatsApp from setup. Its address and key stay in the server settings.';
        card.append(note);
      }
      accounts.append(card);
    }
  }

  function renderApprovals(items) {
    approvals.replaceChildren();
    const active = items.filter((item) => !item.revoked);
    if (!active.length) {
      const empty = document.createElement('p');
      empty.className = 'hint';
      empty.textContent = 'No approvals yet. Add a connector in ChatGPT, paste one of the addresses above, and approve it when the login page opens.';
      approvals.append(empty);
      return;
    }
    for (const item of active) {
      const card = document.createElement('article');
      card.className = 'entry';
      const title = document.createElement('h3');
      title.textContent = item.client || 'ChatGPT';
      const line = document.createElement('p');
      line.textContent = 'Can use ' + (names.get(item.upstreamId) || item.upstreamId || 'a WhatsApp') + '.';
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'secondary';
      button.textContent = 'Cut off';
      button.addEventListener('click', async () => {
        try {
          const payload = await post('/admin/api/revoke', { grantId: item.grantId });
          if (payload) {
            renderState(payload.state);
            say('That approval was cut off.');
          }
        } catch (err) {
          say(err.message, true);
        }
      });
      card.append(title, line, button);
      approvals.append(card);
    }
  }

  function renderState(state) {
    renderAccounts(state.upstreams || []);
    renderApprovals(state.grants || []);
  }

  function pinned() {
    return log.scrollHeight - log.scrollTop - log.clientHeight < 48;
  }

  function addLine(event) {
    const empty = document.getElementById('log-empty');
    if (empty) empty.remove();
    const stick = pinned();
    const row = document.createElement('li');
    const when = document.createElement('time');
    when.dateTime = event.ts;
    when.textContent = String(event.ts || '').slice(11, 19);
    const where = document.createElement('span');
    where.textContent = names.get(event.upstreamId) || event.upstreamId || 'WhatsApp';
    const what = document.createElement('span');
    what.textContent = event.tool || event.method || 'request';
    const result = document.createElement('span');
    const ok = event.status >= 200 && event.status < 300;
    result.className = ok ? 'ok' : 'bad';
    result.textContent = ok ? 'ok' : 'failed';
    row.append(when, where, what, result);
    log.append(row);
    while (log.children.length > 400) log.removeChild(log.firstChild);
    if (stick) log.scrollTop = log.scrollHeight;
  }

  function connect() {
    const source = new EventSource('/admin/events');
    source.onopen = function () {
      liveLabel.textContent = 'Live';
    };
    source.onerror = function () {
      liveLabel.textContent = 'Reconnecting';
    };
    source.onmessage = function (message) {
      let event;
      try { event = JSON.parse(message.data); } catch { return; }
      if (!event || typeof event !== 'object') return;
      addLine(event);
    };
  }

  document.getElementById('add-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      const payload = await post('/admin/api/upstream', {
        id: field(form, 'id'),
        displayName: field(form, 'displayName'),
        url: field(form, 'url'),
        apiKey: field(form, 'apiKey'),
      });
      if (!payload) return;
      form.reset();
      renderState(payload.state);
      say('WhatsApp added. Use its ChatGPT address in a new connector.');
    } catch (err) {
      say(err.message, true);
    }
  });

  document.getElementById('revoke-all').addEventListener('click', async () => {
    if (!window.confirm('Cut off every ChatGPT approval?')) return;
    try {
      const payload = await post('/admin/api/revoke-all', {});
      if (payload) {
        renderState(payload.state);
        say('Every approval was cut off.');
      }
    } catch (err) {
      say(err.message, true);
    }
  });

  document.getElementById('password-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      const payload = await post('/admin/api/password', {
        current: field(form, 'current'),
        next: field(form, 'next'),
        confirm: field(form, 'confirm'),
      });
      if (payload && payload.signedOut) location.assign('/admin');
    } catch (err) {
      say(err.message, true);
    }
  });

  document.getElementById('sign-out').addEventListener('click', async () => {
    try { await post('/admin/logout', {}); } catch { /* the next page is the login form */ }
    location.assign('/admin');
  });

  fetch('/admin/api/state').then(async (response) => {
    if (response.status === 401) {
      location.assign('/admin');
      return;
    }
    const state = await response.json();
    renderState(state);
    connect();
  }).catch(() => {
    say('The panel could not load. Refresh this page.', true);
  });
}());
