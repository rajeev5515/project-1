// TrustVault UI. Plain JS, no framework, no inline scripts (CSP: script-src 'self').
// All text is inserted with textContent via h(); nothing from the server is
// ever parsed as HTML. The UI hides buttons the user cannot use, but that is a
// convenience only: the server checks every request again.
'use strict';

const state = { user: null, categories: [] };

// ------------------------------------------------------------------ helpers
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const $ = (sel) => document.querySelector(sel);
const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : '');
const bytes = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);

function flash(msg, kind = 'ok') {
  const f = $('#flash');
  f.textContent = msg;
  f.className = `flash ${kind}`;
  f.hidden = false;
  clearTimeout(flash.t);
  flash.t = setTimeout(() => (f.hidden = true), 6000);
}

async function api(method, url, body) {
  const opts = { method, headers: { 'X-TrustVault-CSRF': '1' }, credentials: 'same-origin' };
  if (body instanceof FormData) opts.body = body;
  else if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(url, opts);
  let data = null;
  if ((res.headers.get('content-type') || '').includes('application/json')) data = await res.json();
  if (res.status === 401 && url !== '/api/auth/login') {
    state.user = null;
    location.hash = '#/login';
    render();
    throw new Error('Your session has ended. Please sign in again.');
  }
  if (res.status === 403 && data && data.error === 'password_change_required') {
    location.hash = '#/password';
  }
  if (!res.ok) throw new Error((data && data.message) || `Request failed (${res.status})`);
  return data;
}

const guard = (fn) => async (ev) => {
  if (ev && ev.preventDefault) ev.preventDefault();
  try {
    await fn(ev);
  } catch (e) {
    flash(e.message, 'error');
  }
};

function setView(...nodes) {
  const v = $('#view');
  v.replaceChildren(...nodes);
}

// --------------------------------------------------------------------- auth
async function loadMe() {
  try {
    const r = await fetch('/api/auth/me', { credentials: 'same-origin' });
    state.user = r.ok ? (await r.json()).user : null;
  } catch {
    state.user = null;
  }
}

function renderChrome() {
  const u = state.user;
  $('#nav').hidden = !u;
  $('#whoami').hidden = !u;
  if (!u) return;
  $('#whoami-name').textContent = u.name;
  $('#whoami-role').textContent = u.role;
  for (const a of document.querySelectorAll('#nav a')) {
    const role = a.getAttribute('data-role');
    a.hidden = role ? role !== u.role : false;
    a.classList.toggle('active', location.hash.startsWith(`#/${a.getAttribute('data-nav')}`));
  }
}

function viewLogin() {
  const email = h('input', { type: 'email', name: 'email', autocomplete: 'username', required: true });
  const password = h('input', { type: 'password', name: 'password', autocomplete: 'current-password', required: true });
  setView(
    h('div', { class: 'panel login' },
      h('h1', {}, 'Sign in'),
      h('form', { onsubmit: guard(async () => {
        const r = await api('POST', '/api/auth/login', { email: email.value, password: password.value });
        state.user = r.user;
        location.hash = r.user.mustChangePassword ? '#/password' : '#/documents';
      }) },
        h('label', {}, 'Email', email),
        h('label', {}, 'Password', password),
        h('button', { type: 'submit' }, 'Sign in')),
      h('p', { class: 'muted' }, 'Demo accounts are listed in the README.')),
  );
}

function viewPassword() {
  const cur = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const nw = h('input', { type: 'password', autocomplete: 'new-password', minlength: 12, required: true });
  setView(
    h('div', { class: 'panel login' },
      h('h1', {}, 'Change password'),
      state.user && state.user.mustChangePassword ? h('p', {}, 'An administrator set a temporary password. Choose your own to continue.') : null,
      h('form', { onsubmit: guard(async () => {
        await api('POST', '/api/auth/password', { currentPassword: cur.value, newPassword: nw.value });
        await loadMe();
        flash('Password changed. Your other sessions were signed out.');
        location.hash = '#/documents';
      }) },
        h('label', {}, 'Current password', cur),
        h('label', {}, 'New password (12+ characters)', nw),
        h('button', { type: 'submit' }, 'Change password'))),
  );
}

// ---------------------------------------------------------------- documents
function categorySelect(value, { any = false } = {}) {
  return h('select', { name: 'category' },
    any ? h('option', { value: '' }, 'Any category') : null,
    state.categories.map((c) => h('option', { value: c, selected: c === value }, c)));
}

async function viewDocuments() {
  const params = new URLSearchParams(location.hash.split('?')[1] || '');
  const q = h('input', { name: 'q', placeholder: 'Title or description', value: params.get('q') || '' });
  const owner = h('input', { name: 'owner', placeholder: 'Owner name or email', value: params.get('owner') || '' });
  const cat = categorySelect(params.get('category') || '', { any: true });
  const from = h('input', { type: 'date', name: 'from', value: params.get('from') || '' });
  const to = h('input', { type: 'date', name: 'to', value: params.get('to') || '' });
  const scope = h('select', { name: 'scope' },
    [['all', 'All I can access'], ['mine', 'Owned by me'], ['shared', 'Shared with me']].map(([v, l]) => h('option', { value: v, selected: v === (params.get('scope') || 'all') }, l)));
  const form = h('form', { class: 'grid', onsubmit: guard(() => {
    const p = new URLSearchParams();
    for (const [k, el] of Object.entries({ q, owner, category: cat, from, to, scope })) if (el.value) p.set(k, el.value);
    location.hash = `#/documents?${p}`;
  }) },
    h('label', {}, 'Search', q), h('label', {}, 'Owner', owner), h('label', {}, 'Category', cat),
    h('label', {}, 'Updated from', from), h('label', {}, 'Updated to', to), h('label', {}, 'Show', scope),
    h('button', { type: 'submit' }, 'Search'));

  const data = await api('GET', `/api/documents?${params}`);
  const rows = data.documents.map((d) =>
    h('tr', {},
      h('td', { class: 'wrap' }, h('a', { href: `#/doc/${d.id}` }, d.title)),
      h('td', {}, d.category),
      h('td', {}, d.owner.name),
      h('td', {}, h('span', { class: `pill ${d.access}` }, d.access)),
      h('td', {}, fmt(d.updatedAt))));
  setView(
    h('div', { class: 'panel' }, h('h1', {}, 'Documents'), form),
    h('div', { class: 'panel table-wrap' },
      rows.length
        ? h('table', {}, h('thead', {}, h('tr', {}, ['Title', 'Category', 'Owner', 'Your access', 'Updated'].map((t) => h('th', {}, t)))), h('tbody', {}, rows))
        : h('p', { class: 'muted' }, 'No documents match. You only see documents you own or that were shared with you.')),
  );
}

function viewUpload() {
  const title = h('input', { name: 'title', required: true, maxlength: 200 });
  const description = h('textarea', { name: 'description', rows: 3, maxlength: 2000 });
  const cat = categorySelect('Other');
  const file = h('input', { type: 'file', name: 'file', required: true, accept: '.pdf,.png,.jpg,.jpeg,.docx,.xlsx,.pptx,.txt,.csv' });
  setView(h('div', { class: 'panel' },
    h('h1', {}, 'Upload a document'),
    h('p', { class: 'muted' }, 'Allowed: PDF, PNG, JPEG, DOCX, XLSX, PPTX, TXT, CSV. The file type is checked from its content, not its name. Only you can see it until you share it.'),
    h('form', { class: 'grid', onsubmit: guard(async () => {
      const fd = new FormData();
      fd.append('title', title.value);
      fd.append('category', cat.value);
      fd.append('description', description.value);
      if (file.files[0]) fd.append('file', file.files[0]);
      const r = await api('POST', '/api/documents', fd);
      flash('Uploaded.');
      location.hash = `#/doc/${r.document.id}`;
    }) },
      h('label', {}, 'Title', title), h('label', {}, 'Category', cat), h('label', {}, 'File', file),
      h('label', {}, 'Description', description), h('button', { type: 'submit' }, 'Upload'))));
}

async function viewDoc(id) {
  const { document: d } = await api('GET', `/api/documents/${id}`);
  const can = (a) => d.allowedActions.includes(a);
  const sections = [];

  sections.push(h('div', { class: 'panel' },
    h('div', { class: 'row' }, h('h1', {}, d.title), h('span', { class: `pill ${d.access}` }, `your access: ${d.access}`)),
    h('dl', { class: 'kv' },
      h('dt', {}, 'Owner'), h('dd', {}, `${d.owner.name} <${d.owner.email}>`),
      h('dt', {}, 'Category'), h('dd', {}, d.category),
      h('dt', {}, 'Description'), h('dd', {}, d.description || '—'),
      h('dt', {}, 'Current file'), h('dd', {}, d.currentVersion ? `${d.currentVersion.filename} (v${d.currentVersion.versionNo}, ${bytes(d.currentVersion.sizeBytes)})` : '—'),
      h('dt', {}, 'SHA-256'), h('dd', { class: 'mono' }, d.currentVersion ? d.currentVersion.sha256 : ''),
      h('dt', {}, 'Updated'), h('dd', {}, fmt(d.updatedAt))),
    h('div', { class: 'row' },
      can('download') ? h('a', { href: `/api/documents/${d.id}/download` }, h('button', { type: 'button' }, 'Download')) : null,
      can('delete') ? h('button', { type: 'button', class: 'danger', onclick: guard(async () => {
        if (!confirm('Move this document to the trash? Everyone you shared it with loses access immediately.')) return;
        await api('DELETE', `/api/documents/${d.id}`);
        flash('Moved to trash.');
        location.hash = '#/documents';
      }) }, 'Delete') : null)));

  if (can('update_metadata')) {
    const title = h('input', { value: d.title, maxlength: 200 });
    const desc = h('textarea', { rows: 2, maxlength: 2000 }, d.description);
    const cat = categorySelect(d.category);
    const file = h('input', { type: 'file' });
    sections.push(h('div', { class: 'panel' },
      h('h2', {}, 'Edit'),
      h('form', { class: 'grid', onsubmit: guard(async () => {
        await api('PATCH', `/api/documents/${d.id}`, { title: title.value, category: cat.value, description: desc.value });
        flash('Saved.');
        render();
      }) }, h('label', {}, 'Title', title), h('label', {}, 'Category', cat), h('label', {}, 'Description', desc), h('button', { type: 'submit' }, 'Save details')),
      h('form', { class: 'grid', onsubmit: guard(async () => {
        if (!file.files[0]) throw new Error('Choose a file first');
        const fd = new FormData();
        fd.append('file', file.files[0]);
        await api('POST', `/api/documents/${d.id}/versions`, fd);
        flash('New version uploaded.');
        render();
      }) }, h('label', {}, 'Upload a new version', file), h('button', { type: 'submit' }, 'Upload version'))));
  }

  if (can('list_versions')) {
    const { versions } = await api('GET', `/api/documents/${d.id}/versions`);
    sections.push(h('div', { class: 'panel table-wrap' }, h('h2', {}, 'Versions'),
      h('table', {}, h('thead', {}, h('tr', {}, ['#', 'File', 'Size', 'Uploaded by', 'When', ''].map((t) => h('th', {}, t)))),
        h('tbody', {}, versions.map((v) => h('tr', {},
          h('td', {}, `v${v.versionNo}${v.current ? ' (current)' : ''}`), h('td', { class: 'wrap' }, v.filename), h('td', {}, bytes(v.sizeBytes)),
          h('td', {}, v.uploadedBy), h('td', {}, fmt(v.createdAt)),
          h('td', {}, h('a', { href: `/api/documents/${d.id}/versions/${v.id}/download` }, 'Download'))))))));
  }

  if (can('share')) sections.push(await sharingPanel(d));
  if (can('view_activity')) sections.push(await activityPanel(d));
  setView(...sections);
}

async function sharingPanel(d) {
  const { grants } = await api('GET', `/api/documents/${d.id}/grants`);
  const panel = h('div', { class: 'panel' });
  const who = h('input', { placeholder: 'Type a name or email', autocomplete: 'off', list: 'dir-list' });
  const list = h('datalist', { id: 'dir-list' });
  const perm = h('select', {}, h('option', { value: 'read' }, 'Read'), h('option', { value: 'edit' }, 'Edit'));
  const exp = h('input', { type: 'datetime-local' });
  let lookup = [];
  who.addEventListener('input', guard(async () => {
    if (who.value.length < 2) return;
    lookup = (await api('GET', `/api/users/directory?q=${encodeURIComponent(who.value)}`)).users;
    list.replaceChildren(...lookup.map((u) => h('option', { value: u.email }, `${u.name} (${u.role})`)));
  }));
  const grant = async (body) => {
    await api('POST', `/api/documents/${d.id}/grants`, body);
    flash('Access granted. It works from their next request.');
    render();
  };
  const suggestions = h('div');
  panel.append(
    h('h2', {}, 'Who has access'),
    h('p', { class: 'muted' }, 'Read: view and download the current version. Edit: also change details and upload new versions. Only you can share, revoke or delete.'),
    h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, ['Person', 'Access', 'Expires', 'Granted', ''].map((t) => h('th', {}, t)))),
      h('tbody', {},
        h('tr', {}, h('td', {}, `${d.owner.name} (owner)`), h('td', {}, h('span', { class: 'pill owner' }, 'owner')), h('td', {}, '—'), h('td', {}, ''), h('td', {}, '')),
        grants.map((g) => h('tr', {},
          h('td', { class: 'wrap' }, `${g.user.name} <${g.user.email}>`, g.user.active ? '' : ' — deactivated'),
          h('td', {}, h('span', { class: `pill ${g.permission}` }, g.permission)),
          h('td', {}, g.expiresAt ? `${fmt(g.expiresAt)}${g.expired ? ' (expired)' : ''}` : 'never'),
          h('td', {}, `${fmt(g.createdAt)} by ${g.grantedBy}`),
          h('td', {}, h('button', { type: 'button', class: 'secondary', onclick: guard(async () => {
            await api('DELETE', `/api/documents/${d.id}/grants/${g.id}`);
            flash(`Access removed for ${g.user.name}. It stopped working immediately.`);
            render();
          }) }, 'Revoke'))))))),
    h('h2', {}, 'Share with someone'),
    h('form', { class: 'grid', onsubmit: guard(() => grant({ email: who.value.trim(), permission: perm.value, expiresAt: exp.value ? new Date(exp.value).toISOString() : undefined })) },
      h('label', {}, 'Person', who, list), h('label', {}, 'Access', perm), h('label', {}, 'Expires (optional)', exp), h('button', { type: 'submit' }, 'Grant access')),
    h('h2', {}, 'Suggestions'),
    h('p', { class: 'muted' }, 'Ask for suggestions based on who you usually share this kind of document with. Nothing is shared until you confirm. Suggestions and your decisions are recorded.'),
    h('button', { type: 'button', class: 'secondary', onclick: guard(async () => {
      const s = await api('POST', `/api/documents/${d.id}/suggestions`);
      if (!s.suggestions.length) {
        suggestions.replaceChildren(h('p', { class: 'muted' }, 'No suggestions.'));
        return;
      }
      suggestions.replaceChildren(
        h('p', { class: 'muted' }, `Source: ${s.source}${s.note ? ' — ' + s.note : ''}`),
        ...s.suggestions.map((x) => h('div', { class: 'row panel' },
          h('strong', {}, x.name), h('span', { class: 'muted' }, x.email), h('span', { class: `pill ${x.permission}` }, x.permission), h('span', {}, x.reason),
          h('button', { type: 'button', onclick: guard(() => grant({ userId: x.userId, permission: x.permission, suggestionId: s.suggestionId })) }, 'Confirm'),
          h('button', { type: 'button', class: 'secondary', onclick: guard(async (ev) => {
            await api('POST', `/api/documents/${d.id}/suggestions/${s.suggestionId}/dismiss`, { userId: x.userId });
            ev.target.closest('.row').remove();
          }) }, 'Dismiss'))));
    }) }, 'Suggest people'),
    suggestions);
  return panel;
}

function eventsTable(events, { showDoc = false } = {}) {
  return h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ['#', 'When', 'Who', 'Action', 'Outcome', showDoc ? 'Document' : null, 'Details'].filter(Boolean).map((t) => h('th', {}, t)))),
    h('tbody', {}, events.map((e) => h('tr', {},
      h('td', { class: 'mono' }, e.seq), h('td', {}, fmt(e.ts)), h('td', { class: 'wrap' }, e.actor_email || '—'), h('td', {}, e.action),
      h('td', {}, h('span', { class: `pill ${e.outcome}` }, e.outcome)),
      showDoc ? h('td', { class: 'mono' }, e.document_id ? e.document_id.slice(0, 8) : '') : null,
      h('td', { class: 'wrap mono' }, JSON.stringify(e.details)))))));
}

async function activityPanel(d) {
  const { events } = await api('GET', `/api/documents/${d.id}/activity`);
  return h('div', { class: 'panel' }, h('h2', {}, 'Who reached this document'),
    h('p', { class: 'muted' }, 'Every view, download, change, permission change and refused attempt.'), eventsTable(events));
}

async function viewTrash() {
  const { documents } = await api('GET', '/api/documents/trash');
  setView(h('div', { class: 'panel table-wrap' }, h('h1', {}, 'Trash'),
    h('p', { class: 'muted' }, 'Deleted documents are unreachable by everyone you shared them with. Restore brings existing grants back; purge destroys the file permanently (the audit history stays).'),
    documents.length ? h('table', {}, h('tbody', {}, documents.map((d) => h('tr', {},
      h('td', { class: 'wrap' }, d.title), h('td', {}, d.category), h('td', {}, `deleted ${fmt(d.deletedAt)}`),
      h('td', {}, h('div', { class: 'row' },
        h('button', { type: 'button', onclick: guard(async () => { await api('POST', `/api/documents/${d.id}/restore`); flash('Restored.'); render(); }) }, 'Restore'),
        h('button', { type: 'button', class: 'danger', onclick: guard(async () => {
          if (!confirm('Permanently destroy this document and all its versions?')) return;
          await api('DELETE', `/api/documents/${d.id}/purge`);
          flash('Purged.');
          render();
        }) }, 'Purge')))))))
      : h('p', { class: 'muted' }, 'Trash is empty.')));
}

// -------------------------------------------------------------------- admin
async function viewAdmin(tab) {
  tab = tab || 'alerts';
  const tabs = h('div', { class: 'tabs' }, ['alerts', 'audit', 'permissions', 'users'].map((t) =>
    h('button', { type: 'button', class: t === tab ? 'active' : '', onclick: () => (location.hash = `#/admin/${t}`) }, t)));
  const body = h('div');
  setView(h('div', { class: 'panel' }, h('h1', {}, 'Administration'), tabs, body));

  if (tab === 'alerts') {
    const [{ alerts }, stats, verify] = await Promise.all([api('GET', '/api/admin/alerts'), api('GET', '/api/admin/stats'), api('GET', '/api/admin/audit/verify')]);
    body.append(
      h('dl', { class: 'kv' },
        h('dt', {}, 'Audit chain'), h('dd', {}, verify.ok ? `intact (${verify.checked} entries, head ${verify.head.hash.slice(0, 16)}…)` : `BROKEN at #${verify.firstBadSeq}: ${verify.reason}`),
        h('dt', {}, 'Active users'), h('dd', {}, stats.users), h('dt', {}, 'Documents'), h('dd', {}, `${stats.documents} (+${stats.inTrash} in trash)`),
        h('dt', {}, 'Grants'), h('dd', {}, stats.grants)),
      h('h2', {}, 'Worth noticing'),
      alerts.length ? h('div', { class: 'table-wrap' }, h('table', {}, h('tbody', {}, alerts.map((a) => h('tr', {},
        h('td', {}, h('span', { class: `pill ${a.severity}` }, a.severity)), h('td', {}, a.kind), h('td', { class: 'wrap' }, a.message), h('td', {}, fmt(a.lastSeen)))))))
        : h('p', { class: 'muted' }, 'Nothing unusual.'));
  }

  if (tab === 'audit') {
    const actor = h('input', { placeholder: 'actor email' });
    const action = h('input', { placeholder: 'action prefix e.g. grant. or document.download' });
    const outcome = h('select', {}, ['', 'success', 'denied', 'failure'].map((o) => h('option', { value: o }, o || 'any outcome')));
    const out = h('div');
    const load = guard(async () => {
      const p = new URLSearchParams();
      if (actor.value) p.set('actor', actor.value);
      if (action.value) p.set('action', action.value);
      if (outcome.value) p.set('outcome', outcome.value);
      const { events } = await api('GET', `/api/admin/audit?${p}`);
      out.replaceChildren(eventsTable(events, { showDoc: true }));
    });
    body.append(h('form', { class: 'grid', onsubmit: load }, h('label', {}, 'Actor', actor), h('label', {}, 'Action', action), h('label', {}, 'Outcome', outcome), h('button', { type: 'submit' }, 'Filter')), out);
    await load();
  }

  if (tab === 'permissions') {
    const { grants } = await api('GET', '/api/admin/grants');
    const { events } = await api('GET', '/api/admin/audit?action=grant.&limit=200');
    body.append(
      h('h2', {}, 'Current grants'),
      h('div', { class: 'table-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Document', 'Owner', 'Grantee', 'Access', 'Expires'].map((t) => h('th', {}, t)))),
        h('tbody', {}, grants.map((g) => h('tr', {}, h('td', { class: 'wrap' }, g.title), h('td', {}, g.owner_email),
          h('td', {}, `${g.user_email}${g.user_active ? '' : ' (deactivated)'}`), h('td', {}, h('span', { class: `pill ${g.permission}` }, g.permission)), h('td', {}, g.expires_at ? fmt(g.expires_at) : 'never')))))),
      h('h2', {}, 'Permission changes'), eventsTable(events, { showDoc: true }));
  }

  if (tab === 'users') {
    const { users } = await api('GET', '/api/admin/users');
    const email = h('input', { type: 'email', required: true });
    const name = h('input', { required: true });
    const role = h('select', {}, ['viewer', 'owner', 'admin'].map((r) => h('option', { value: r }, r)));
    const pw = h('input', { type: 'password', minlength: 12, required: true, autocomplete: 'new-password' });
    const secret = h('div');
    const owners = users.filter((u) => u.role === 'owner' && u.active);
    body.append(
      secret,
      h('div', { class: 'table-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Name', 'Email', 'Role', 'Status', 'Docs', 'Actions'].map((t) => h('th', {}, t)))),
        h('tbody', {}, users.map((u) => {
          const roleSel = h('select', { onchange: guard(async (ev) => { await api('PATCH', `/api/admin/users/${u.id}`, { role: ev.target.value }); flash('Role changed; their sessions were ended.'); render(); }) },
            ['viewer', 'owner', 'admin'].map((r) => h('option', { value: r, selected: r === u.role }, r)));
          const transferTo = h('select', {}, h('option', { value: '' }, 'transfer docs to…'), owners.filter((o) => o.id !== u.id).map((o) => h('option', { value: o.id }, o.name)));
          return h('tr', {},
            h('td', {}, u.name), h('td', { class: 'wrap' }, u.email), h('td', {}, roleSel),
            h('td', {}, u.active ? 'active' : 'deactivated', u.lockedUntil ? ' · locked' : '', u.mustChangePassword ? ' · must change pw' : ''),
            h('td', {}, u.documentsOwned),
            h('td', {}, h('div', { class: 'row' },
              h('button', { type: 'button', class: 'secondary', onclick: guard(async () => { await api('PATCH', `/api/admin/users/${u.id}`, { active: !u.active }); flash(u.active ? 'Deactivated; all sessions ended.' : 'Reactivated.'); render(); }) }, u.active ? 'Deactivate' : 'Reactivate'),
              h('button', { type: 'button', class: 'secondary', onclick: guard(async () => {
                const r = await api('POST', `/api/admin/users/${u.id}/reset-password`);
                secret.replaceChildren(h('div', { class: 'secret' }, `Temporary password for ${u.email} (shown once, give it to them out of band): `, h('code', {}, r.temporaryPassword)));
              }) }, 'Reset password'),
              h('button', { type: 'button', class: 'secondary', onclick: guard(async () => { const r = await api('POST', `/api/admin/users/${u.id}/revoke-sessions`); flash(`${r.sessionsRevoked} session(s) ended.`); }) }, 'End sessions'),
              u.documentsOwned ? transferTo : null,
              u.documentsOwned ? h('button', { type: 'button', class: 'secondary', onclick: guard(async () => {
                if (!transferTo.value) throw new Error('Pick a recipient');
                const r = await api('POST', `/api/admin/users/${u.id}/transfer-documents`, { toUserId: transferTo.value });
                flash(`${r.transferred} document(s) transferred.`);
                render();
              }) }, 'Transfer') : null)));
        })))),
      h('h2', {}, 'Create user'),
      h('form', { class: 'grid', onsubmit: guard(async () => {
        await api('POST', '/api/admin/users', { email: email.value, name: name.value, role: role.value, password: pw.value });
        flash('User created. They must change the password at first sign-in.');
        render();
      }) }, h('label', {}, 'Email', email), h('label', {}, 'Name', name), h('label', {}, 'Role', role), h('label', {}, 'Initial password', pw), h('button', { type: 'submit' }, 'Create')));
  }
}

// ------------------------------------------------------------------- router
async function render() {
  renderChrome();
  const hash = location.hash || '#/documents';
  const [path] = hash.slice(2).split('?');
  const parts = path.split('/');
  try {
    if (!state.user) return viewLogin();
    if (state.user.mustChangePassword && parts[0] !== 'password') {
      location.hash = '#/password';
      return;
    }
    if (!state.categories.length) state.categories = (await api('GET', '/api/documents/categories')).categories;
    switch (parts[0]) {
      case 'password': return viewPassword();
      case 'upload': return viewUpload();
      case 'trash': return await viewTrash();
      case 'admin': return await viewAdmin(parts[1]);
      case 'doc': return await viewDoc(parts[1]);
      case 'login': location.hash = '#/documents'; return;
      default: return await viewDocuments();
    }
  } catch (e) {
    setView(h('div', { class: 'panel' }, h('p', {}, e.message)));
  }
}

window.addEventListener('hashchange', render);
document.addEventListener('DOMContentLoaded', async () => {
  $('#logout').addEventListener('click', guard(async () => {
    await api('POST', '/api/auth/logout');
    state.user = null;
    location.hash = '#/login';
    render();
  }));
  await loadMe();
  render();
});
