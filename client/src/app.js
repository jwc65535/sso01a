// app.js — SSO dashboard SPA
//
// State machine:
//   INIT      checking auth status (spinner)
//   UNAUTHED  no session; shows login button
//   AUTHED    has JWT session; shows dashboard
//
// Auth flow (same-origin, sp.sso.local):
//   1. GET /api/userinfo — if 200: AUTHED (existing JWT cookie)
//   2. POST /api/token   — exchange active Shibboleth session for JWT cookie
//                          if 200: retry userinfo → AUTHED
//   3. Show login button → redirect to /Shibboleth.sso/Login
//
// Tab navigation:
//   Button clicks set window.location.hash.
//   hashchange event is the single driver of tab activation.
//   activateTab() never mutates location.hash (prevents double-render loop).

(function () {
  'use strict';

  const CFG = window.APP_CONFIG;

  // ── API client ──────────────────────────────────────────────────────────────

  const api = {
    _token() {
      return CFG.cookieAuth ? null : sessionStorage.getItem(CFG.tokenKey);
    },

    async _fetch(method, path, body) {
      const headers = { 'Content-Type': 'application/json' };
      const tok = this._token();
      if (tok) headers['Authorization'] = 'Bearer ' + tok;

      const opts = { method, headers, credentials: 'include' };
      if (body !== undefined) opts.body = JSON.stringify(body);

      return fetch(CFG.apiBase + path, opts);
    },

    get:  (path)       => api._fetch('GET',    path),
    post: (path, body) => api._fetch('POST',   path, body),
    del:  (path)       => api._fetch('DELETE', path),

    async json(resp) {
      if (!resp.ok) return null;
      try { return await resp.json(); } catch { return null; }
    },
  };

  // ── Auth ────────────────────────────────────────────────────────────────────

  async function checkAuth() {
    const resp = await api.get('/userinfo');
    if (resp.ok) return api.json(resp);
    return null;
  }

  async function acquireToken(visitorId) {
    try {
      const resp = await api.post('/token', { fingerprint: visitorId });
      if (!resp.ok) return false;

      if (!CFG.cookieAuth) {
        const data = await resp.json();
        if (data?.token) sessionStorage.setItem(CFG.tokenKey, data.token);
      }
      return true;
    } catch {
      return false;
    }
  }

  function logout() {
    sessionStorage.removeItem(CFG.tokenKey);
    sessionStorage.removeItem(CFG.certSerialKey);
    window.Fingerprint.clear();
    window.location.href = '/Shibboleth.sso/Logout?return=' +
      encodeURIComponent(window.location.origin + '/');
  }

  function login() {
    window.location.href = CFG.loginUrl +
      '?target=' + encodeURIComponent(window.location.pathname);
  }

  // ── Certificate auto-enrolment ───────────────────────────────────────────────

  async function ensureCert() {
    try {
      const resp = await api.post('/cert/issue', {});
      if (resp.ok) {
        const data = await resp.json().catch(() => null);
        if (data?.serial_number) {
          sessionStorage.setItem(CFG.certSerialKey, data.serial_number);
        }
      }
    } catch { /* swallowed — cert tab shows status on demand */ }
  }

  // ── Init ─────────────────────────────────────────────────────────────────────

  async function init() {
    showScreen('loading');

    try {
      const [fpResult, userInfo] = await Promise.all([
        window.Fingerprint.get().catch(() => ({ visitorId: 'unknown' })),
        checkAuth().catch(() => null),
      ]);

      if (userInfo) {
        enterAuthed(userInfo, fpResult.visitorId);
        return;
      }

      const tokenOk = await acquireToken(fpResult.visitorId);
      if (tokenOk) {
        const userInfo2 = await checkAuth().catch(() => null);
        if (userInfo2) {
          enterAuthed(userInfo2, fpResult.visitorId);
          return;
        }
      }

      enterUnauthed(fpResult.visitorId);
    } catch (err) {
      console.error('init failed:', err);
      enterUnauthed('unknown');
    }
  }

  // ── States ───────────────────────────────────────────────────────────────────

  function enterUnauthed(visitorId) {
    showScreen('login');
    el('fp-display').textContent = visitorId || '—';
    el('login-btn').onclick = login;
  }

  function enterAuthed(userInfo, visitorId) {
    showScreen('dashboard');
    populateHeader(userInfo);
    ensureCert(); // fire-and-forget; populates server cert cache for /api/sessions

    el('logout-btn').onclick = logout;

    // Tab buttons set the hash; the hashchange event drives activation.
    // This breaks the activateTab → location.hash → hashchange → activateTab loop.
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.onclick = () => { window.location.hash = btn.dataset.tab; };
    });

    window.addEventListener('hashchange', () => activateTab(currentTab(), userInfo));

    // Activate the initial tab without mutating the hash.
    activateTab(currentTab(), userInfo);
  }

  function currentTab() {
    const hash = window.location.hash.replace('#', '');
    return ['userinfo', 'sessions', 'audit', 'cert'].includes(hash) ? hash : 'userinfo';
  }

  // ── Dashboard ────────────────────────────────────────────────────────────────

  function populateHeader(u) {
    el('user-uid').textContent  = u.uid  || u.sub || '—';
    el('user-mail').textContent = u.mail || '—';
  }

  function activateTab(tab, userInfo) {
    // Update tab button states.
    document.querySelectorAll('.tab-btn').forEach(b => {
      const active = b.dataset.tab === tab;
      b.classList.toggle('active', active);
      b.setAttribute('aria-selected', active);
    });

    // Show the matching panel; hide the rest.
    document.querySelectorAll('.tab-panel').forEach(p => {
      p.hidden = p.dataset.tab !== tab;
    });

    // Load content for the activated tab.
    switch (tab) {
      case 'userinfo': renderUserInfo(userInfo); break;
      case 'sessions': loadSessions();           break;
      case 'audit':    loadAudit();              break;
      case 'cert':     renderCertPanel();        break;
    }
  }

  // ── Tab: Identity ────────────────────────────────────────────────────────────

  function renderUserInfo(u) {
    const rows = [
      ['Subject (uid)',  u.uid       || u.sub || '—'],
      ['Email',         u.mail      || '—'],
      ['Enrolled at',   u.enrolled_at ? new Date(u.enrolled_at * 1000).toLocaleString() : '—'],
      ['Cert bound',    u.cnf?.['x5t#S256'] ? '✓ ' + truncate(u.cnf['x5t#S256'], 20) : '✗ none'],
      ['Device bound',  u.device_fingerprint ? '✓ ' + truncate(u.device_fingerprint, 16) : '✗ none'],
      ['Token expires', u.exp ? new Date(u.exp * 1000).toLocaleString() : '—'],
    ];
    el('panel-userinfo').innerHTML =
      '<table class="info-table">' +
      rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join('') +
      '</table>';
  }

  // ── Tab: Sessions ─────────────────────────────────────────────────────────────

  async function loadSessions() {
    const panel = el('panel-sessions');
    panel.innerHTML = '<p class="muted">Loading…</p>';

    let resp = await api.get('/sessions');
    if (resp.status === 403) {
      // ensureCert() runs in the background after login; wait briefly then retry.
      await wait(1500);
      resp = await api.get('/sessions');
    }
    if (resp.status === 403) {
      panel.innerHTML = noCertMsg('cert');
      return;
    }

    const sessions = await api.json(resp);
    if (!sessions) {
      panel.innerHTML = errorMsg('Failed to load sessions.') + refreshBtn('loadSessions');
      return;
    }
    if (sessions.length === 0) {
      panel.innerHTML = '<p class="muted">No active sessions.</p>' + refreshBtn('loadSessions');
      return;
    }

    panel.innerHTML =
      '<table class="data-table">' +
      '<thead><tr><th>JTI</th><th>Cert serial</th><th>Issued</th><th>Expires</th><th></th></tr></thead>' +
      '<tbody>' +
      sessions.map(s => `
        <tr>
          <td class="mono">${esc(truncate(s.jti || s.JTI, 12))}…</td>
          <td class="mono">${esc(truncate(s.cert_serial || s.CertSerial, 14))}…</td>
          <td>${esc(fmtTime(s.issued_at  || s.IssuedAt))}</td>
          <td>${esc(fmtTime(s.expires_at || s.ExpiresAt))}</td>
          <td><button class="btn btn-danger btn-sm" data-jti="${esc(s.jti || s.JTI)}">Revoke</button></td>
        </tr>`).join('') +
      '</tbody></table>' +
      '<div style="margin-top:1rem">' + refreshBtn('loadSessions') + '</div>';

    panel.querySelectorAll('[data-jti]').forEach(btn => {
      btn.onclick = () => revokeSession(btn.dataset.jti);
    });
  }

  async function revokeSession(jti) {
    if (!confirm('Revoke this session?')) return;
    const resp = await api.del('/sessions/' + encodeURIComponent(jti));
    if (resp.ok || resp.status === 204) {
      loadSessions();
    } else {
      alert('Revoke failed: ' + resp.status);
    }
  }

  // ── Tab: Audit log ───────────────────────────────────────────────────────────

  async function loadAudit() {
    const panel = el('panel-audit');
    panel.innerHTML = '<p class="muted">Loading…</p>';

    let resp = await api.get('/audit?limit=50');
    if (resp.status === 403) {
      await wait(1500);
      resp = await api.get('/audit?limit=50');
    }
    if (resp.status === 403) {
      panel.innerHTML = noCertMsg('cert');
      return;
    }

    const entries = await api.json(resp);
    if (!entries) {
      panel.innerHTML = errorMsg('Failed to load audit log.') + refreshBtn('loadAudit');
      return;
    }
    if (entries.length === 0) {
      panel.innerHTML = '<p class="muted">No audit entries.</p>' + refreshBtn('loadAudit');
      return;
    }

    panel.innerHTML =
      '<table class="data-table">' +
      '<thead><tr><th>Time</th><th>Action</th><th>Detail</th></tr></thead>' +
      '<tbody>' +
      entries.map(e => `
        <tr>
          <td>${esc(fmtTime(e.created_at || e.CreatedAt))}</td>
          <td>${esc(e.action  || e.Action  || '—')}</td>
          <td class="muted">${esc(e.detail || e.Detail || '')}</td>
        </tr>`).join('') +
      '</tbody></table>' +
      '<div style="margin-top:1rem">' + refreshBtn('loadAudit') + '</div>';
  }

  // ── Tab: Certificate ──────────────────────────────────────────────────────────

  function renderCertPanel() {
    // Only build the static structure once; preserve any issued-cert result.
    const panel = el('panel-cert');
    if (panel.dataset.rendered) return;
    panel.dataset.rendered = '1';

    const lastSerial = sessionStorage.getItem(CFG.certSerialKey);
    const statusHtml = lastSerial
      ? `<p class="cert-status">Last issued this session — serial: <code>${esc(lastSerial)}</code></p>`
      : '';

    panel.innerHTML = `
      <p>Issue a new ECDSA P-256 client certificate signed by the Vault PKI.
         The private key is generated server-side and sealed in a memguard
         enclave — it never leaves the server.</p>
      ${statusHtml}
      <button class="btn btn-primary" id="issue-cert-btn" style="margin-top:1rem">Issue Certificate</button>
      <div id="cert-result" class="cert-output hidden"></div>
    `;

    el('issue-cert-btn').onclick = issueCert;
  }

  async function issueCert() {
    const btn = el('issue-cert-btn');
    const out = el('cert-result');
    btn.disabled = true;
    btn.textContent = 'Requesting…';
    out.className = 'cert-output hidden';

    try {
      const resp = await api.post('/cert/issue', {});
      const data = await resp.json();

      if (!resp.ok) {
        out.className = 'cert-output error';
        out.textContent = 'Error ' + resp.status + ': ' + (data?.error || 'unknown');
        return;
      }

      const serial = data.serial_number || data.SerialNumber || '—';
      sessionStorage.setItem(CFG.certSerialKey, serial);

      out.className = 'cert-output success';
      out.innerHTML =
        `<p><strong>Certificate issued.</strong></p>` +
        `<p>Serial: <code>${esc(serial)}</code></p>` +
        `<p>Expires: ${esc(fmtTime(data.expiration || data.Expiration))}</p>` +
        `<details><summary>PEM Certificate</summary>` +
        `<pre>${esc(data.certificate || data.Certificate || '')}</pre></details>` +
        `<details><summary>CA Chain</summary>` +
        `<pre>${esc((data.ca_chain || data.CAChain || []).join('\n'))}</pre></details>`;
    } catch (err) {
      out.className = 'cert-output error';
      out.textContent = 'Request failed: ' + err.message;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Issue Certificate';
      out.classList.remove('hidden');
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────

  function el(id) { return document.getElementById(id); }

  function showScreen(name) {
    document.querySelectorAll('.screen').forEach(s => { s.hidden = s.id !== name; });
  }

  function esc(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function truncate(str, n) {
    if (!str) return '';
    return str.length > n ? str.slice(0, n) : str;
  }

  function fmtTime(val) {
    if (!val) return '—';
    const d = typeof val === 'number' ? new Date(val * 1000) : new Date(val);
    return isNaN(d) ? String(val) : d.toLocaleString();
  }

  function wait(ms) { return new Promise(r => setTimeout(r, ms)); }

  function noCertMsg(certTab) {
    return `<p class="error">No certificate enrolled. ` +
      `<a href="#${certTab}">Go to the Certificate tab</a> to issue one.</p>`;
  }

  function errorMsg(msg) {
    return `<p class="error">${esc(msg)}</p>`;
  }

  function refreshBtn(fnName) {
    // Rendered as a plain button; click handler attached after insertion.
    return `<button class="btn btn-ghost btn-sm" data-refresh="${esc(fnName)}">Refresh</button>`;
  }

  // Delegate refresh button clicks within tab panels.
  document.addEventListener('click', e => {
    const btn = e.target.closest('[data-refresh]');
    if (!btn) return;
    const fn = btn.dataset.refresh;
    if (fn === 'loadSessions') loadSessions();
    else if (fn === 'loadAudit') loadAudit();
  });

  // ── Boot ─────────────────────────────────────────────────────────────────────

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
