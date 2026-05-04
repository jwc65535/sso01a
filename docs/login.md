# How to Log In

This guide walks through the complete login sequence for the sso01a dev stack,
from browser to authenticated JWT session.

---

## Prerequisites

### 1. Stack must be running

```bash
  make _gen-secrets                                                                                                                 
  make up  
```

All services must reach `healthy` before attempting a login.  Check with:

```bash
docker compose -p sso01a ps
```

### 2. `/etc/hosts` entries

The SP and IdP use name-based virtual hosting.  Add these to `/etc/hosts` if
they are not already present:

```
127.0.0.1  sp.sso.local
127.0.0.1  idp.sso.local
```

### 3. Accept the self-signed TLS certificate (dev only)

The Apache SP serves HTTPS on port 443 with the Debian snakeoil certificate.
Browsers will show a security warning on first visit.

In **Chrome / Edge**: click "Advanced" → "Proceed to sp.sso.local (unsafe)".  
In **Firefox**: click "Advanced…" → "Accept the Risk and Continue".

> In production this certificate is replaced with a Vault-issued cert signed by
> the internal CA.  The warning does not appear in production.

---

## Logging In

### Step 1 — Open the application

Navigate to:

```
https://sp.sso.local
```

The single-page application (SPA) loads from the Apache SP's `DocumentRoot`.
No Shibboleth session exists yet, so the SPA shows a **Login** button and the
`/api/userinfo` call returns `401`.

### Step 2 — Start the SAML login

Click **Login**.  The browser is redirected to:

```
GET /Shibboleth.sso/Login?target=/
```

Shibboleth constructs a SAML 2.0 `AuthnRequest` and redirects the browser to
the SimpleSAMLphp IdP:

```
http://idp.sso.local:8880/simplesaml/saml2/idp/SSOService.php?SAMLRequest=…
```

### Step 3 — Enter credentials at the IdP

The SimpleSAMLphp login form appears.  Use one of the dev accounts:

| Username | Password      | Role |
|----------|---------------|------|
| `alice`  | `changeme`    | dev user |
| `bob`    | `changeme`    | dev user |

> The password comes from `DEV_USER_PASSWORD` in `.env`.  Change it there
> before first boot; the value is written to LDAP at container init time.

The IdP binds to OpenLDAP to verify the password, reads `ssoCertThumbprint`
and `ssoEnrolledAt`, signs a SAML assertion (RSA-3072, SHA-256), and posts it
back to the SP's ACS URL.

### Step 4 — SAML assertion consumed by the SP

The browser auto-POSTs the `SAMLResponse` to:

```
POST /Shibboleth.sso/SAML2/POST
```

`mod_shib` validates the assertion signature against the IdP metadata, creates
a Shibboleth session, sets a session cookie, and redirects to the original
target (`/`).

### Step 5 — JWT cookie issued

The SPA detects the page reload and calls:

```
POST /api/token   {fingerprint: "<FingerprintJS visitor ID>"}
```

Because a Shibboleth session now exists, `mod_shib` injects the SAML
attributes as request headers (`uid`, `mail`, `ssoCertThumbprint`, etc.)
before the request reaches the Go backend.

The Go backend:

1. Verifies the `uid` header is present (Shibboleth guard).
2. Issues an ES256 JWT containing `sub`, `cnf.x5t#S256` (cert thumbprint),
   `device_fingerprint`, `iss`, `aud`, `exp`, and `jti`.
3. Returns the token in a `Set-Cookie: sso_session=…` response
   (`HttpOnly`, `Secure`, `SameSite=Strict`).

The SPA cannot read the cookie value (HttpOnly).  Subsequent API calls send it
automatically.

### Step 6 — Authenticated

The SPA calls `GET /api/userinfo` and receives the authenticated user's
profile.  The dashboard shows the logged-in user.

---

## After Login — Key API Endpoints

All endpoints below require the `sso_session` JWT cookie (set automatically
by the browser after Step 5).

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/userinfo` | Authenticated user profile (sub, mail, cert thumbprint, exp) |
| `POST` | `/api/cert/issue` | Issue a Vault-signed x509 certificate for this user |
| `POST` | `/api/sign` | Sign an arbitrary payload with the user's sealed private key |
| `GET`  | `/api/sessions` | List all active JWT sessions for this user |
| `GET`  | `/api/sessions/{jti}` | Get details of a specific session |
| `DELETE` | `/api/sessions/{jti}` | Revoke a specific session |
| `GET`  | `/api/audit` | Per-user audit log (database-backed, row-level security) |
| `GET`  | `/api/.well-known/jwks.json` | Public JWKS endpoint (no auth required) |

---

## Certificate Enrollment

After login, the SPA's **Certificate** tab calls `POST /api/cert/issue`.

What happens server-side:

1. The Go backend generates an ECDSA P-256 key pair in memory.
2. The private key is immediately sealed into a `memguard` Enclave (AES-256-GCM,
   mlock'd, never written to disk).
3. A CSR is sent to Vault; Vault signs it and returns a certificate.
4. The signed certificate PEM is returned to the browser.

The private key **never leaves the Go process**.  The browser receives only the
public certificate.

---

## Signing Out

There is no explicit logout endpoint in this dev build.  To end a session:

- Close the browser tab (the `HttpOnly` cookie is cleared on browser exit for
  session cookies) or
- Delete the `sso_session` cookie in browser DevTools, or
- Revoke the specific JWT via `DELETE /api/sessions/{jti}`.

The JWT has a configurable TTL (default 3600 s, set by `JWT_TTL` in `.env`).
It expires automatically.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `https://sp.sso.local` times out | SP container not running | `make up`; check `docker compose -p sso01a ps` |
| TLS certificate error loops | Self-signed cert not accepted | Accept the browser exception once per session |
| IdP login form never appears | `/etc/hosts` missing `idp.sso.local` | Add the hosts entry above |
| SAML error: "no metadata found" | SP cert not registered in IdP | Run `make sp-cert-extract` and paste into `idp/metadata/saml20-sp-remote.php`, then restart IdP |
| `POST /api/token` returns `401 ShibbolethRequired` | No Shibboleth session on this path | Ensure you clicked Login and completed the IdP form before hitting `/api/token` |
| `POST /api/token` returns `403` | User has no enrolled certificate (`ssoCertThumbprint` empty) | Call `POST /api/cert/issue` first, then re-try token issuance |
| `POST /api/cert/issue` returns `401` | No `sso_session` cookie | Complete login (Steps 1–5) before requesting a cert |
