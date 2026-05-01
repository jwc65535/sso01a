# sso01a — End-to-End Authentication Flow

This document describes the complete flow of the system using Mermaid sequence
diagrams.  Each section covers one phase of the lifecycle.

---

## 1. System Startup & Dependency Order

Services must reach `healthy` before dependents start.  The bootstrap script
(`scripts/bootstrap-all.sh`) enforces this order and runs one-time init steps
between container starts.

```mermaid
sequenceDiagram
    autonumber
    participant Host
    participant Vault
    participant VaultAgent as Vault Agent
    participant ConsulTmpl as Consul Template
    participant LDAP
    participant Postgres
    participant IdP
    participant App as Go App
    participant SP as Apache SP

    Host->>Vault: docker compose up vault
    Vault-->>Host: healthy (dev mode, HTTP :8200)
    Note over Host,Vault: make vault-init → bootstrap-vault.sh<br/>Phases: root CA → intermediate CA →<br/>roles → policies → AppRole

    Host->>LDAP: docker compose up ldap
    LDAP-->>Host: healthy (entrypoint.sh first-run init complete)
    Note over Host,LDAP: Schema loaded, cert-writer account created,<br/>ACLs applied, dev users alice/bob seeded

    Host->>Postgres: docker compose up postgres
    Postgres-->>Host: healthy (pg_isready passes)
    Note over Host,Postgres: pg_hba.conf, schema, roles, RLS policies<br/>applied by init/*.sql at initdb time

    Host->>VaultAgent: docker compose up vault-agent
    VaultAgent->>Vault: authenticate (token_file / AppRole)
    Vault-->>VaultAgent: renewable token
    VaultAgent->>VaultAgent: render ca-chain.pem, crl.pem, ldap-cert-push.sh
    VaultAgent-->>Host: healthy (agent.token written)

    Host->>Host: make postgres-bootstrap<br/>(set sso_app password, copy CA chain)

    Host->>ConsulTmpl: docker compose up consul-template
    ConsulTmpl->>Vault: read PKI (agent token)
    ConsulTmpl->>LDAP: push userCertificate attributes
    ConsulTmpl-->>Host: healthy

    Host->>IdP: docker compose up idp
    IdP->>LDAP: verify LDAP connectivity
    IdP-->>Host: healthy (SimpleSAMLphp welcome page)

    Host->>App: docker compose up app
    App->>Vault: Ping (VAULT_TOKEN)
    App->>Postgres: pgxpool.Connect (sso_app, scram-sha-256)
    App->>App: Generate ephemeral ECDSA key (memguard KeyStore)
    App->>App: Load TOTP master secret → PassphraseGen ready
    App-->>Host: healthy (/healthz 200)

    Host->>SP: docker compose up sp
    SP->>SP: init.sh — envsubst shibboleth2.xml
    SP->>SP: Generate SP signing/encrypt keys (first boot)
    SP->>IdP: Fetch IdP metadata (IDP_METADATA_URL)
    SP-->>Host: healthy (/healthz via port 80)

    Note over Host: make sp-cert-extract → paste into<br/>idp/metadata/saml20-sp-remote.php<br/>docker compose restart idp
```

---

## 2. Full Login Flow (SAML 2.0 → JWT Cookie)

The SPA is served from the Apache SP at `https://sp.sso.local`.  Shibboleth
is only required on `POST /api/token`; all other paths use JWT auth.

```mermaid
sequenceDiagram
    autonumber
    participant Browser
    participant SP as Apache SP<br/>(Shibboleth)
    participant IdP as SimpleSAMLphp IdP
    participant LDAP
    participant App as Go Backend

    Browser->>SP: GET https://sp.sso.local/ (first visit)
    SP-->>Browser: 200 index.html (from DocumentRoot, no Shibboleth required)
    Note over Browser: SPA loads, FingerprintJS collects visitor ID

    Browser->>SP: GET /api/userinfo (credentials: include)
    SP->>App: proxy (no sso_session cookie yet)
    App-->>SP: 401 Unauthorized
    SP-->>Browser: 401

    Browser->>SP: POST /api/token (uid header absent — no Shibboleth session)
    App-->>SP: 401 (ShibbolethRequired: uid header missing)
    SP-->>Browser: 401

    Note over Browser: SPA shows Login button.<br/>User clicks → redirect to Shibboleth
    Browser->>SP: GET /Shibboleth.sso/Login?target=/
    SP->>Browser: 302 → IdP SSO URL (AuthnRequest in query string)

    Browser->>IdP: GET /simplesaml/saml2/idp/SSOService.php?SAMLRequest=...
    IdP-->>Browser: 200 Login form

    Browser->>IdP: POST credentials (username=alice, password=...)
    IdP->>LDAP: ldap_bind(cn=alice,ou=people,..., password)
    LDAP-->>IdP: bind success
    IdP->>LDAP: ldap_search (uid, mail, ssoCertThumbprint, ssoEnrolledAt)
    LDAP-->>IdP: alice's attributes
    IdP->>IdP: Sign SAML assertion (RSA-3072, SHA-256)
    IdP-->>Browser: 200 Auto-POST form (SAMLResponse → SP ACS URL)

    Browser->>SP: POST /Shibboleth.sso/SAML2/POST (SAMLResponse)
    SP->>SP: mod_shib validates signature, maps attributes
    SP->>SP: Create Shibboleth session, set SP session cookie
    SP-->>Browser: 302 → target (/)

    Browser->>SP: GET / (now has Shibboleth session cookie)
    SP-->>Browser: 200 index.html

    Note over Browser: SPA detects page reload,<br/>retries auth sequence with FingerprintJS visitor ID ready

    Browser->>SP: POST /api/token {fingerprint: "fp-visitor-id"}
    Note over SP: <Location /api/token> requireSession 1<br/>mod_shib injects: uid, mail, ssoCertThumbprint,<br/>ssoDeviceFingerprint, ssoEnrolledAt headers
    SP->>App: POST /api/token (with Shibboleth headers + fingerprint body)
    App->>App: ShibbolethRequired: uid header present ✓
    App->>App: thumbprint present ✓ (or 403 if not enrolled)
    App->>App: Issue JWT: sub=alice, cnf.x5t#S256=thumbprint,<br/>device_fingerprint=fp-visitor-id, iss, aud, exp, jti
    App->>App: Sign JWT (ECDSA P-256, ES256, kid from memguard KeyStore)
    App-->>SP: 200 {token, token_type, expires_in}<br/>Set-Cookie: sso_session=<jwt>; HttpOnly; Secure; SameSite=Strict
    SP-->>Browser: 200 + Set-Cookie (sso_session forwarded from App)

    Note over Browser: JWT cookie set (HttpOnly — JS cannot read it)<br/>SPA retries GET /api/userinfo

    Browser->>SP: GET /api/userinfo (sso_session cookie sent automatically)
    SP->>App: proxy (cookie forwarded)
    App->>App: BearerAuth: no Authorization header → check sso_session cookie ✓
    App->>App: Validate JWT signature, exp, iss, aud, cnf ✓
    App-->>SP: 200 {sub, uid, mail, cert_thumbprint, exp, ...}
    SP-->>Browser: 200 userinfo JSON
    Note over Browser: SPA shows authenticated dashboard
```

---

## 3. x509 Certificate Enrollment

Called by the SPA's Certificate tab after the user is authenticated.  The
private key is generated server-side, sealed in memguard, and never transmitted.

```mermaid
sequenceDiagram
    autonumber
    participant Browser
    participant SP as Apache SP
    participant App as Go Backend
    participant KeyMgr as KeyManager<br/>(memguard)
    participant Vault

    Browser->>SP: POST /api/cert/issue {} (sso_session cookie)
    SP->>App: proxy

    App->>App: BearerAuth: sso_session cookie → validate JWT → uid=alice ✓

    App->>KeyMgr: GenerateKeyAndCSR("alice")
    KeyMgr->>KeyMgr: ecdsa.GenerateKey(P-256, rand)
    KeyMgr->>KeyMgr: x509.MarshalPKCS8PrivateKey → privKeyDER
    KeyMgr->>KeyMgr: x509.CreateCertificateRequest(CN=alice)
    KeyMgr-->>App: (privKeyDER, csrPEM)

    App->>KeyMgr: Seal("alice", privKeyDER)
    Note over KeyMgr: passGen.codeAt("alice", now/period)<br/>→ HMAC-SHA256(masterSecret, alice) → TOTP code<br/>→ Argon2id(code, alice) → AES-256 key<br/>→ AES-GCM encrypt: [counter||nonce||ciphertext]<br/>→ memguard.NewEnclave(sealed)
    KeyMgr->>KeyMgr: wipe(privKeyDER)
    KeyMgr-->>App: sealed in Enclave ✓

    App->>Vault: SignCSR(ctx, csrPEM, cn="alice")
    Note over Vault: Policy: pki_int/sign/user-cert [create,update]<br/>Policy DENIES pki_int/issue/* (no server-side key gen)
    Vault->>Vault: Validate CSR, sign with intermediate CA
    Vault-->>App: SignedCert{Certificate, IssuingCA, CAChain, SerialNumber, Expiration}

    App->>App: connFactory.StoreCert("alice", cert.PEM)
    Note over App: In-process cert cache for later UserConnFactory.Conn()

    App-->>SP: 200 {certificate, issuing_ca, ca_chain, serial_number, expiration}
    SP-->>Browser: 200 signed certificate PEM

    Note over Browser: SPA displays cert serial, expiry<br/>User stores cert PEM (public data, safe to transmit)
```

---

## 4. Authenticated API Request (JWT Cookie Path)

Any `/api/*` call after login demonstrates the stateless JWT verification.

```mermaid
sequenceDiagram
    autonumber
    participant Browser
    participant SP as Apache SP<br/>(ShibUseHeaders On)
    participant App as Go Backend
    participant KeyStore as memguard<br/>KeyStore

    Browser->>SP: GET /api/sessions (Cookie: sso_session=<jwt>)
    Note over SP: <Location /api/sessions> — no Shibboleth required.<br/>ShibUseHeaders On: if SP session exists, attributes ARE<br/>injected (but sessions handler doesn't read them).

    SP->>App: GET /api/sessions (cookie forwarded, uid header may be present)
    App->>App: BearerAuth middleware:<br/>1. No Authorization header<br/>2. sso_session cookie found → raw = cookie.Value

    App->>KeyStore: Public() → *ecdsa.PublicKey (non-sensitive heap memory)
    App->>App: jwt.ParseWithClaims → ECDSA P-256 signature verify ✓
    App->>App: Check: exp, iss, aud, cnf (x5t#S256 non-empty) ✓
    App->>App: ContextWithClaims(ctx, claims) → claims.UID = "alice"

    App->>App: SessionsHandler.openConn("alice")
    App->>App: UserConnFactory.Conn(ctx, "alice") — see Diagram 5
    App->>App: db.ListSessions(ctx, userConn)
    Note over App: SELECT ... FROM sso.user_sessions WHERE ...<br/>Runs as role "u_alice", RLS: uid = current_user
    App->>App: userConn.Close()

    App-->>SP: 200 [{jti, cert_serial, issued_at, expires_at, ...}, ...]
    SP-->>Browser: 200 sessions JSON
```

---

## 5. Per-User Database Connection (x509 Client Certificate)

Called within each authenticated handler that needs database access.  The
private key exists in plaintext heap memory only for the ~5 ms TLS handshake.

```mermaid
sequenceDiagram
    autonumber
    participant Handler
    participant Factory as UserConnFactory
    participant KeyMgr as KeyManager<br/>(memguard)
    participant Enclave as memguard<br/>Enclave
    participant TLS as crypto/tls
    participant PG as PostgreSQL<br/>(cert auth)

    Handler->>Factory: Conn(ctx, uid="alice")

    Factory->>Factory: certCache["alice"] → certPEM ✓
    Factory->>Factory: pem.Decode → certDER
    Factory->>Factory: x509.ParseCertificate → CN="alice"
    Factory->>Factory: roleForCN("alice") → "u_alice"

    Factory->>KeyMgr: OpenPrivateKey("alice")
    KeyMgr->>KeyMgr: mu.RLock → enclaves["alice"]
    KeyMgr->>Enclave: Open() → *LockedBuffer (mlock'd pages)
    Enclave-->>KeyMgr: raw bytes (AES-GCM decrypted by memguard)
    KeyMgr->>KeyMgr: try counter ± unlockSkew (Argon2id per window)<br/>decryptGCM: verify GCM tag, return plaintext
    KeyMgr->>KeyMgr: x509.ParsePKCS8PrivateKey → *ecdsa.PrivateKey
    KeyMgr-->>Factory: (*ecdsa.PrivateKey, cleanup func)

    Factory->>TLS: tls.Certificate{Certificate: certDER, PrivateKey: priv}
    Note over Factory,TLS: No temp files. Key lives in Go heap only.
    Factory->>TLS: &tls.Config{Certificates:[cert], RootCAs:vaultCAPool,<br/>ServerName:"postgres", MinVersion:TLS13}

    Factory->>PG: pgx.ConnectConfig (TLS handshake)
    Note over Factory,PG: pg_hba.conf: hostssl sso all 0.0.0.0/0 cert<br/>PG verifies client cert chain → issuer = Vault intermediate CA<br/>PG maps cert CN "alice" → login role "alice"
    PG-->>Factory: connection established
    Factory->>Factory: cleanup() → LockedBuffer.Destroy()<br/>(mlock'd pages zeroed + unpinned)<br/>*ecdsa.PrivateKey.D remains in Go heap until GC

    Factory->>PG: SET ROLE "u_alice"
    Note over PG: Session role = u_alice for all subsequent statements.<br/>RLS policies on sso.* tables enforce uid = current_user.
    PG-->>Factory: SET OK

    Factory-->>Handler: *UserConn{conn, uid:"alice", role:"u_alice"}

    Handler->>PG: SELECT/INSERT/UPDATE (via UserConn.Conn())
    Note over PG: Executes as u_alice.<br/>RLS: only alice's rows are visible/writable.
    PG-->>Handler: result rows

    Handler->>Factory: UserConn.Close()
    Factory->>PG: conn.Close() → TCP FIN
```

---

## Security Properties Summary

| Layer | Mechanism | What it prevents |
|-------|-----------|-----------------|
| Transport | TLS 1.3 (SP), mTLS 1.3 (PG) | Network eavesdropping, MITM |
| Identity | SAML 2.0 (signed assertions) | Unauthenticated access, assertion forgery |
| Session binding | JWT cnf/x5t#S256 (RFC 7800) | Token theft without the matching cert |
| Device binding | FingerprintJS visitorId in JWT | Token reuse from a different browser profile |
| Key protection | memguard Enclave (mlock, AES-GCM) | Key exposure from process memory dump |
| Key derivation | TOTP passphrase + Argon2id | Offline brute-force of sealed key blobs |
| Secret separation | Docker secrets (TOTP) ∩ memguard (ciphertext) | Single-secret compromise yielding key material |
| DB isolation | SET ROLE + Row-Level Security | Cross-user data access |
| Audit trail | `current_user` in BEFORE INSERT trigger | Application-level audit log forgery |

**Compromise requires all of:** Docker secret (`TOTP_MASTER_SECRET`) **AND** process memory dump (Enclave ciphertext) **AND** TOTP window timing — all simultaneously.
