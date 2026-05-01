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
// Auth flow (cross-origin, localhost:3000 dev only):
//   Steps 1-3 the same, but the Bearer token from the /api/token response
//   body is stored in sessionStorage and sent via Authorization header.
//   Cookie auth is not available cross-origin (SameSite=Strict).

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

      const opts = {
        method,
        headers,
        credentials: 'include', // send cookies when same-origin
      };
      if (body !== undefined) opts.body = JSON.stringify(body);

      return fetch(CFG.apiBase + path, opts);
    },

    get: (path) => api._fetch('GET', path),
    post: (path, body) => api._fetch('POST', path, body),
    del: (path) => api._fetch('DELETE', path),

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

      // In cross-origin dev mode, extract the Bearer token from the body
      // and store it in sessionStorage (cookie auth won't work cross-origin).
      if (!CFG.cookieAuth) {
        const data = await resp.json();
        if (data?.token) {
          sessionStorage.setItem(CFG.tokenKey, data.token);
        }
      }
      return true;
    } catch {
      return false;
    }
  }

  function logout() {
    sessionStorage.removeItem(CFG.tokenKey);
    window.Fingerprint.clear();
    // Destroy the Shibboleth session and redirect to login.
    window.location.href = '/Shibboleth.sso/Logout?return=' +
      encodeURIComponent(window.location.origin + '/');
  }

  function login(visitorId) {
    const target = encodeURIComponent(window.location.href);
    window.location.href = CFG.loginUrl +
      '?target=' + encodeURIComponent(window.location.pathname);
  }

  // ── Init ─────────────────────────────────────────────────────────────────────

  async function init() {
    showScreen('loading');

    // Collect fingerprint in parallel with the auth check.
    const [fpResult, userInfo] = await Promise.all([
      window.Fingerprint.get().catch(() => ({ visitorId: 'unknown' })),
      checkAuth(),
    ]);

    if (userInfo) {
      enterAuthed(userInfo, fpResult.visitorId);
      return;
    }

    // No JWT cookie — try to exchange an active Shibboleth session for one.
    const tokenOk = await acquireToken(fpResult.visitorId);
    if (tokenOk) {
      const userInfo2 = await checkAuth();
      if (userInfo2) {
        enterAuthed(userInfo2, fpResult.visitorId);
        return;
      }
    }

    enterUnauthed(fpResult.visitorId);
  }

  // ── States ───────────────────────────────────────────────────────────────────

  function enterUnauthed(visitorId) {
    showScreen('login');
    el('fp-display').textContent = visitorId || '—';
    el('login-btn').onclick = () => login(visitorId);
  }

  function enterAuthed(userInfo, visitorId) {
    showScreen('dashboard');
    populateHeader(userInfo);

    el('logout-btn').onclick = logout;

    // Tabs
    const tabs = document.querySelectorAll('.tab-btn');
    tabs.forEach(btn => {
      btn.onclick = () => activateTab(btn.dataset.tab, userInfo);
    });

    // Activate initial tab from URL hash or default.
    const hash = window.location.hash.replace('#', '') || 'userinfo';
    activateTab(hash, userInfo);
    window.onhashchange = () => {
      const h = window.location.hash.replace('#', '') || 'userinfo';
      activateTab(h, userInfo);
    };
  }

  // ── Dashboard ────────────────────────────────────────────────────────────────

  function populateHeader(u) {
    el('user-uid').textContent  = u.uid  || u.sub || '—';
    el('user-mail').textContent = u.mail || '—';
  }

  function activateTab(tab, userInfo) {
    window.location.hash = tab;
    document.querySelectorAll('.tab-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.tab === tab);
    });
    document.querySelectorAll('.tab-panel').forEach(p => {
      p.hidden = p.dataset.tab !== tab;
    });

    switch (tab) {
      case 'userinfo':  renderUserInfo(userInfo); break;
      case 'sessions':  loadSessions();           break;
      case 'audit':     loadAudit();              break;
      case 'cert':      renderCertPanel();        break;
    }
  }

  // ── Tab: User Info ───────────────────────────────────────────────────────────

  function renderUserInfo(u) {
    const panel = el('panel-userinfo');
    const rows = [
      ['Subject (uid)',  u.uid       || u.sub || '—'],
      ['Email',         u.mail      || '—'],
      ['Enrolled at',   u.enrolled_at ? new Date(u.enrolled_at * 1000).toLocaleString() : '—'],
      ['Cert bound',    u.cnf?.['x5t#S256'] ? '✓ ' + truncate(u.cnf['x5t#S256'], 20) : '✗ none'],
      ['Device bound',  u.device_fingerprint ? '✓ ' + truncate(u.device_fingerprint, 16) : '✗ none'],
      ['Token expires', u.exp ? new Date(u.exp * 1000).toLocaleString() : '—'],
    ];
    panel.innerHTML = '<table class="info-table">' +
      rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join('') +
      '</table>';
  }

  // ── Tab: Sessions ────────────────────────────────────────────────────────────

  async function loadSessions() {
    const panel = el('panel-sessions');
    panel.innerHTML = '<p class="muted">Loading…</p>';

    const resp = await api.get('/sessions');
    const sessions = await api.json(resp);

    if (!sessions) {
      panel.innerHTML = '<p class="error">Failed to load sessions.</p>';
      return;
    }
    if (sessions.length === 0) {
      panel.innerHTML = '<p class="muted">No active sessions.</p>';
      return;
    }

    panel.innerHTML = '<table class="data-table">' +
      '<thead><tr><th>JTI</th><th>Cert serial</th><th>Issued</th><th>Expires</th><th></th></tr></thead>' +
      '<tbody>' +
      sessions.map(s => `
        <tr>
          <td class="mono">${esc(truncate(s.jti || s.JTI, 12))}…</td>
          <td class="mono">${esc(truncate(s.cert_serial || s.CertSerial, 14))}…</td>
          <td>${esc(fmtTime(s.issued_at || s.IssuedAt))}</td>
          <td>${esc(fmtTime(s.expires_at || s.ExpiresAt))}</td>
          <td><button class="btn btn-danger btn-sm"
                data-jti="${esc(s.jti || s.JTI)}">Revoke</button></td>
        </tr>
      `).join('') +
      '</tbody></table>';

    panel.querySelectorAll('[data-jti]').forEach(btn => {
      btn.onclick = () => revokeSession(btn.dataset.jti, panel);
    });
  }

  async function revokeSession(jti, panel) {
    if (!confirm('Revoke this session?')) return;
    const resp = await api.del('/sessions/' + encodeURIComponent(jti));
    if (resp.ok || resp.status === 204) {
      loadSessions();
    } else {
      alert('Revoke failed: ' + resp.status);
    }
  }

  // ── Tab: Audit Log ───────────────────────────────────────────────────────────

  async function loadAudit() {
    const panel = el('panel-audit');
    panel.innerHTML = '<p class="muted">Loading…</p>';

    const resp = await api.get('/audit?limit=50');
    const entries = await api.json(resp);

    if (!entries) {
      panel.innerHTML = '<p class="error">Failed to load audit log.</p>';
      return;
    }
    if (entries.length === 0) {
      panel.innerHTML = '<p class="muted">No audit entries.</p>';
      return;
    }

    panel.innerHTML = '<table class="data-table">' +
      '<thead><tr><th>Time</th><th>Action</th><th>Detail</th></tr></thead>' +
      '<tbody>' +
      entries.map(e => `
        <tr>
          <td>${esc(fmtTime(e.created_at || e.CreatedAt))}</td>
          <td>${esc(e.action || e.Action || '—')}</td>
          <td class="muted">${esc(e.detail || e.Detail || '')}</td>
        </tr>
      `).join('') +
      '</tbody></table>';
  }

  // ── Tab: Certificate ─────────────────────────────────────────────────────────

  function renderCertPanel() {
    const panel = el('panel-cert');
    panel.innerHTML = `
      <p>Issue a new ECDSA P-256 certificate signed by the Vault PKI.
         The private key is generated in the server process and sealed in
         a memguard Enclave — it never leaves the server.</p>
      <button class="btn btn-primary" id="issue-cert-btn">Issue Certificate</button>
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
        out.textContent = 'Error: ' + (data?.error || resp.status);
        return;
      }

      out.className = 'cert-output success';
      out.innerHTML =
        `<p><strong>Certificate issued successfully.</strong></p>` +
        `<p>Serial: <code>${esc(data.serial_number || data.SerialNumber || '—')}</code></p>` +
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
    document.querySelectorAll('.screen').forEach(s => {
      s.hidden = s.id !== name;
    });
  }

  function esc(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function truncate(str, n) {
    if (!str) return '';
    return str.length > n ? str.slice(0, n) : str;
  }

  function fmtTime(val) {
    if (!val) return '—';
    // Accept both ISO strings and Unix epoch numbers.
    const d = typeof val === 'number' ? new Date(val * 1000) : new Date(val);
    return isNaN(d) ? String(val) : d.toLocaleString();
  }

  // ── Boot ─────────────────────────────────────────────────────────────────────

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
