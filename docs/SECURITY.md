# SSO — Security Reference
## John W. Carbone
### Quantum Logic Corporation
### May 2026

---

This document is the authoritative security reference for the sso01a zero-trust
authentication stack.  It covers the threat model, single-module compromise
analysis, rotation policies, audit logging, hardening checklist, and production
deployment requirements.

---

## 1. Architecture at a Glance

```
Browser → Apache SP (Shibboleth) → Go App → PostgreSQL (mTLS)
                                        ↕
                                     Vault PKI
                                        ↕
                                     OpenLDAP
```

**Three-secret architecture** — full key compromise requires all three simultaneously:

| Secret | Location | Controlled by |
|--------|----------|---------------|
| A — `TOTP_MASTER_SECRET` | Docker secret file | Orchestrator / operator |
| B — AES-256-GCM sealed blob | memguard Enclave (mlock'd, no swap) | Go process memory |
| C — Vault AppRole secret-id | Docker secret file, rotated per-deploy | Vault |

Owning A alone → cannot decrypt any sealed key (need B).  
Owning B alone → cannot derive the Argon2id key (need A, plus time to brute-force 8-digit TOTP at ~200 ms/attempt ≈ 38 CPU-years).  
Owning C alone → can sign CSRs, but the private key was never sent to Vault.

---

## 2. Single-Module Compromise Analysis

For each component, this table answers: **if an attacker owns it completely, what is the maximum blast radius?**

### 2.1 Secrets & Keys

| Stolen credential | CAN do | CANNOT do | Detection signal |
|-------------------|--------|-----------|-----------------|
| `TOTP_MASTER_SECRET` (Docker secret A) | Derive per-user TOTP seeds offline. With process memory dump (secret B), brute-force the 8-digit TOTP in a narrow time window | Unseal any key without the AES-GCM ciphertext from the running process. Cannot issue certs. Cannot read the database | Docker secret access audit; Vault audit log shows no new CSR signings |
| memguard Enclave ciphertext (secret B) | Feed the encrypted blob to an offline Argon2id cracker | Decrypt without TOTP_MASTER_SECRET. Cannot forge JWTs. Cannot connect to the database without the plaintext private key | No external signal; mitigated by requiring A simultaneously |
| JWT signing key (ephemeral, in-memory) | Sign arbitrary JWTs valid until next service restart | Persist the key (it is generated fresh at every startup and never written to disk or Vault). Cannot access the database or Vault | No existing session → all existing JWTs become invalid on restart |
| Vault root token | Full Vault control: create policies, read any secret engine, revoke certs | Extract the root CA private key (sealed by Vault's barrier/KMS). Cannot read TOTP_MASTER_SECRET (Docker secret, outside Vault) | Vault audit log: `auth/token/create` with `root` display_name |
| golang-app AppRole secret-id | Sign one CSR per token window (`user-cert-signer` role, 1h TTL). Read a cert by serial. Read CA chain/CRL | Generate private keys server-side (explicit DENY on `pki_int/issue/*`). List all cert serials (DENY on `pki_int/certs`). Revoke certs. Modify PKI config. Escalate to broader policies | Vault audit log: `pki_int/sign/user-cert` without a matching Go app request ID |
| vault-agent AppRole secret-id | Renew agent's own token. Read public PKI cert data (already public) | Sign or issue certs. Write anything to Vault. Escalate token TTL beyond ceiling | Vault audit log: any write operation from vault-agent token |
| consul-template AppRole secret-id | Read public cert data for LDAP template rendering | Issue, sign, or revoke certs. Write to LDAP (uses a separate LDAP credential). Escalate | Vault audit log: any write operation from consul-template token |

### 2.2 Infrastructure Credentials

| Stolen credential | CAN do | CANNOT do | Detection signal |
|-------------------|--------|-----------|-----------------|
| LDAP admin password | Full LDAP write: add/remove users, modify `ssoCertThumbprint` | Sign JWTs (no access to Go app or JWT signing key). Connect to PostgreSQL (no cert). Read TOTP_MASTER_SECRET | LDAP access log; Vault consul-template would detect cert attribute change |
| LDAP cert-writer password | Write `userCertificate` and `ssoCertThumbprint` attributes only (ACL-restricted) | Read user passwords or other attributes. Authenticate to any other system | LDAP ACL audit; ldap_cert_writer only has write on specific attrs |
| PostgreSQL `sso_admin` password | Full DB admin: create roles, drop tables, disable RLS | Read TOTP_MASTER_SECRET or sealed keys (outside DB). Forge JWTs. Sign certs | PostgreSQL log: `log_connections=on`, superuser login alert |
| PostgreSQL `sso_app` password | Run queries as `sso_app` (bypasses RLS — can read all users' data) | Modify schema (no DDL grants). Read private keys. Access Vault | PostgreSQL log: `sso_app` login from unexpected IP |
| PostgreSQL per-user role (e.g., `u_alice`) | Read/write alice's own sessions and enrolled_certs (RLS-filtered) | See other users' rows (RLS blocks). Modify audit log (no INSERT/UPDATE/DELETE grants on `audit_log`). Connect without a valid client cert | PostgreSQL log: cert auth failure for CN mismatch |

### 2.3 Application Layer

| Stolen credential | CAN do | CANNOT do | Detection signal |
|-------------------|--------|-----------|-----------------|
| User's JWT cookie (stolen from browser) | Call authenticated API endpoints as the user until JWT expiry (1h) | Issue a new JWT (requires SAML session). Connect to PostgreSQL (no cert, no private key). Decrypt sealed key | JWT expiry self-limits blast radius. `jti` revocation in DB cuts it immediately |
| User's x509 client certificate (stolen) | Authenticate to PostgreSQL as the user's role after cert expiry would be stopped. Within TTL: read/write own rows | Forge JWTs (no signing key). Issue new certs (no Vault access). Unlock the sealed private key (no TOTP_MASTER_SECRET) | PostgreSQL cert auth log; Vault revocation via pki-admin-policy |
| User's x509 private key (hypothetically leaked from memory) | Sign TLS handshakes for PostgreSQL mTLS | Issue new certs. Forge JWTs. Read other users' data (RLS). Persist across restart (key is ephemeral; destroyed by memguard.Purge() on shutdown) | memguard mlock audit; this path requires process memory dump AND TOTP_MASTER_SECRET |
| Shibboleth SP process (Apache) | Inject arbitrary Shibboleth headers to the Go backend. Bypass the SAML flow for `/api/token` | Forge JWTs (no JWT signing key). Read TOTP_MASTER_SECRET. Access Vault or PostgreSQL directly | Shibboleth access log; new JWTs from unexpected IPs/users |
| SimpleSAMLphp IdP | Forge SAML assertions for any user known to LDAP | Issue JWTs directly (IdP has no JWT signing key). Read private keys. Access Vault | Shibboleth SP signature validation; LDAP access log for unexpected authentications |

---

## 3. Certificate TTL Rotation Policy

### 3.1 TTL Targets

| Certificate | Default TTL | Rotation trigger | Enforcement |
|-------------|-------------|-----------------|-------------|
| User x509 (DB mTLS) | **1 hour** | JWT expiry; `POST /api/cert/issue` re-issues | Vault PKI role `max_ttl=4h`; cert expires with session |
| SP TLS (HTTPS) | **90 days** | 80% of TTL (72 days) via consul-template | Vault PKI intermediate CA; auto-renewed |
| Vault intermediate CA | 5 years | Manual rotation with 6-month overlap | `make vault-init` with new intermediate |
| Vault root CA | 10 years | Manual rotation with 1-year overlap | Offline process; requires root CA material |
| IdP SAML signing cert | 1 year | Manual rotation + SP metadata update | `make sp-cert-extract` + IdP restart |
| JWT signing key | **Per-restart** | Service restart rotates automatically | Ephemeral in-memory `KeyStore`; no persistence |

### 3.2 Automated Rotation

User certificates are short-lived by design: each `POST /api/cert/issue` call
generates a fresh ECDSA P-256 key and certificate.  No background rotation job
is needed for user certs.

For SP TLS cert renewal (production), add a consul-template stanza:

```hcl
# consul-template/templates/sp-cert.ctmpl
{{ with secret "pki_int/issue/sp-server" "common_name=sp.sso.local"
     "ttl=2160h" "alt_names=sp.sso.local" }}
{{ .Data.certificate }}
{{ end }}
```

Run `apachectl graceful` (not restart) after cert renewal to avoid connection drops.

### 3.3 Certificate Revocation

Revoke a user certificate immediately:

```bash
# Find serial in PostgreSQL
serial=$(psql -U sso_admin -d sso -At -c \
  "SELECT cert_serial FROM sso.enrolled_certs WHERE uid='alice' ORDER BY enrolled_at DESC LIMIT 1")

# Revoke in Vault (requires pki-admin-policy token)
VAULT_TOKEN=<admin-token> vault write pki_int/revoke serial_number="$serial"

# Revoke session in PostgreSQL
psql -U sso_app -d sso -c "UPDATE sso.user_sessions SET revoked=true WHERE uid='alice'"

# Force CRL refresh in PostgreSQL
make postgres-crl-update
```

---

## 4. Audit Logging

All security-relevant events are logged at four independent layers.  An attacker
who compromises any one layer cannot erase traces at the other three.

### 4.1 Vault Audit Log

Vault logs **every API call** including the caller token's display name, request
path, and response code.  Enable during bootstrap:

```bash
vault audit enable file \
  path=/vault/logs/audit.log \
  log_raw=false \
  hmac_accessor=true
```

Critical events to alert on:
- Any `pki_int/issue/*` call (explicit deny — means policy violation)
- Any `auth/token/create` not from `user-cert-signer` or `vault-agent` roles
- Any `sys/policy/write` (policy modification)
- Failed auth attempts (`errors` field non-empty)

Ship logs with: `filebeat`, `fluentd`, or `vector` → SIEM.

### 4.2 PostgreSQL Audit Log

`postgresql.conf` (applied via `postgres/init/00-hba.sh`):

```
log_connections      = on
log_disconnections   = on
log_statement        = 'ddl'        # dev; set 'all' for sso_auditor role
log_duration         = on
log_line_prefix      = '%m [%p] %u@%d %r '
log_min_duration_statement = 500   # slow query alert (ms)
```

For compliance, enable per-role statement logging:

```sql
ALTER ROLE sso_auditor SET log_statement = 'all';
ALTER ROLE sso_app      SET log_min_duration_statement = 100;
```

The `sso.audit_log` table provides application-level audit trail separate from
PostgreSQL's own logs — neither alone is sufficient; both together are required.

### 4.3 Go Application Audit Log

Every authenticated request logs a structured JSON record to stdout via `slog`:

```json
{
  "time": "2026-05-01T12:00:00Z",
  "level": "INFO",
  "msg": "request",
  "request_id": "abc123",
  "method": "POST",
  "path": "/api/cert/issue",
  "status": 200,
  "uid": "alice",
  "duration_ms": 342,
  "remote_ip": "10.0.0.1"
}
```

Events written to `sso.audit_log` (PostgreSQL) in addition to stdout:
- `token.issued` — JWT issued (includes `jti`, `cert_thumbprint`, `device_fingerprint`)
- `cert.issued` — x509 cert issued (includes `serial_number`)
- `session.revoked` — session revoked (includes `jti`)

### 4.4 Shibboleth / Apache Access Log

The SP logs every request with SAML attributes injected:

```apache
CustomLog ${APACHE_LOG_DIR}/sp-access.log \
  "%h %l %u %t \"%r\" %>s %b uid=%{uid}e cert=%{ssoCertThumbprint}e"
```

All accesses to `/api/token` with `uid` and `ssoCertThumbprint` values are
recorded, providing an IdP-independent authentication audit trail.

Alert on:
- POST `/api/token` with status 200 from unexpected source IPs
- POST `/api/token` with status 403 (enrolled user without cert thumbprint)
- Any request to `/api/token` that bypasses Shibboleth (status 401 from Go backend)

---

## 5. Rate Limiting & WAF Rules

### 5.1 Apache Layer (see `sp/apache/vhosts/sso.conf`)

Applied via `mod_ratelimit` + `mod_reqtimeout` + `mod_rewrite` WAF rules:

| Endpoint | Rate limit | Burst | Rationale |
|----------|-----------|-------|-----------|
| `POST /api/token` | 5 req/min per IP | 3 | SAML callback; browser makes at most 1–2 per login |
| `POST /api/cert/issue` | 2 req/5min per IP | 1 | Key generation is expensive; more = DoS |
| `POST /api/sign` | 10 req/min per IP | 5 | Signing is cheap but rate-limit for abuse |
| All other `/api/*` | 60 req/min per IP | 10 | General API protection |

WAF rules block:
- Path traversal (`../`, `%2e%2e`)
- Null byte injection (`%00`)
- Request body > 100 KB on non-upload paths
- Slow read attacks (timeout: header 5s, body 10s + 500 bytes/s)

### 5.2 Go Application Layer (see `app/internal/auth/ratelimit.go`)

Per-IP token bucket rate limiter applied to sensitive endpoints before the JWT
middleware.  Uses `golang.org/x/time/rate` (already in go.mod).

Limits (separate from Apache; defense-in-depth if Apache is bypassed):
- `/api/token`: 5 tokens/minute, burst 3
- `/api/cert/issue`: 2 tokens/5min, burst 1

---

## 6. Memguard Destruction Guarantees

### 6.1 Normal Request Path

```
Request arrives
  → OpenPrivateKey("alice")
      → enclave.Open()  → LockedBuffer (mlock'd pages)
      → decrypt GCM     → plaintext DER
      → parse PKCS8     → *ecdsa.PrivateKey
      → return (priv, cleanup)
  → TLS handshake (priv used as crypto.Signer)
  → cleanup()           → LockedBuffer.Destroy() — pages zeroed, unpinned
  → handler completes
  → *ecdsa.PrivateKey.D scalar in Go heap → GC-collected (no guarantee of timing)
```

The private key scalar `D` exists on the Go heap for the duration of the TLS
handshake only.  To eliminate this window entirely would require a custom
`crypto.Signer` that performs scalar multiplication inside the mlock'd buffer
(a significant complexity trade-off deferred to production hardening if required).

### 6.2 Shutdown Path

```go
// In main.go, on SIGTERM / graceful shutdown:
srv.Shutdown(ctx)           // stop accepting new requests
keyManager.Purge()          // zero all Enclaves, call memguard.Purge()
memguard.Purge()            // belt-and-suspenders: zero all LockedBuffers
```

`memguard.Purge()` is idempotent.  The kernel also zero-fills mlock'd pages on
process exit (Linux `MADV_FREE` / `MADV_WIPEONFORK` is set by memguard).

### 6.3 OOM / Kill Path

If the process is killed with SIGKILL, graceful cleanup does not run.  Mitigations:
- mlock'd pages are not swapped; they do not appear in a core dump by default
  (`RLIMIT_CORE=0` is set by memguard)
- The Enclave ciphertext on the heap is useless without `TOTP_MASTER_SECRET`
- Docker containers have `--security-opt=no-new-privileges` set (enforce below)

---

## 7. Production Deployment Hardening

### 7.1 Remove Vault Dev Mode

Vault dev mode (`-dev` flag) stores all data in memory and auto-unseals with
a fixed key.  **Do not use in production.**

```bash
# Production Vault configuration (vault/config/vault.hcl):
storage "raft" {
  path    = "/vault/data"
  node_id = "vault-01"
}

listener "tcp" {
  address            = "0.0.0.0:8200"
  tls_cert_file      = "/vault/tls/server.crt"
  tls_key_file       = "/vault/tls/server.key"
  tls_min_version    = "tls13"
  tls_client_ca_file = "/vault/tls/ca-chain.pem"
}

seal "awskms" {         # or gcpckms, azurekeyvault, transit
  region     = "us-east-1"
  kms_key_id = "arn:aws:kms:..."
}

ui         = false      # disable Vault UI in production
api_addr   = "https://vault.internal:8200"
cluster_addr = "https://vault.internal:8201"
```

### 7.2 Replace Self-Signed SP Certificate

```bash
# Generate via Vault PKI (requires pki-admin-policy token):
vault write -format=json pki_int/issue/sp-server \
  common_name=sp.sso.local \
  alt_names=sp.sso.local \
  ttl=2160h \
  | jq -r '{cert: .data.certificate, key: .data.private_key, ca: .data.ca_chain}'

# Mount in SP container:
# sp/apache/vhosts/sso.conf:
#   SSLCertificateFile    /etc/ssl/vault/sp.crt
#   SSLCertificateKeyFile /etc/ssl/vault/sp.key
#   SSLCACertificateFile  /etc/ssl/vault/ca-chain.pem
```

Also enforce TLS 1.3 only in production:

```apache
SSLProtocol           TLSv1.3
SSLCipherSuite        TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
```

### 7.3 AppRole Secret-ID Rotation

```bash
# Rotate golang-app secret-id:
vault write -f auth/approle/role/golang-app/secret-id \
  | jq -r '.data.secret_id' \
  > secrets/golang-app-secret-id.txt

# Rotate vault-agent secret-id (update docker-compose.yml to mount new file):
vault write -f auth/approle/role/vault-agent/secret-id \
  | jq -r '.data.secret_id' \
  > secrets/vault-agent-secret-id.txt
```

Automate via CI/CD pipeline on a weekly schedule.

### 7.4 Docker Security Hardening

Add to every service in `docker-compose.yml`:

```yaml
security_opt:
  - no-new-privileges:true
read_only: true                      # wherever possible
tmpfs:
  - /tmp:size=64m,noexec,nosuid
cap_drop:
  - ALL
cap_add:
  - IPC_LOCK                         # app only — needed for memguard mlock()
```

For the app service specifically:
```yaml
ulimits:
  core: 0                           # no core dumps
  memlock: -1                       # unlimited mlock for memguard
```

### 7.5 Network Segmentation

All internal networks already use `internal: true` in docker-compose.yml.  In
Kubernetes, enforce via NetworkPolicy:

```yaml
# Allow only SP → App on port 8080
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-ingress
spec:
  podSelector:
    matchLabels: {app: sso-app}
  ingress:
    - from:
        - podSelector:
            matchLabels: {app: sso-sp}
      ports:
        - port: 8080
```

### 7.6 TOTP Master Secret Minimum Requirements

The `TOTP_MASTER_SECRET` must be:
- At least 32 bytes of cryptographically random data (generated by `openssl rand -base64 48`)
- Stored only in Docker secrets / Kubernetes secrets (never in `.env` or environment)
- Rotated by re-sealing all user keys (requires `make cert-rotate` for all users)
- Never logged, printed, or transmitted over the network

### 7.7 PostgreSQL TLS Enforcement

In `postgresql.conf`:
```
ssl                     = on
ssl_min_protocol_version = TLSv1.3
ssl_cert_file           = '/var/lib/postgresql/ssl/server.crt'
ssl_key_file            = '/var/lib/postgresql/ssl/server.key'
ssl_ca_file             = '/var/lib/postgresql/ssl/ca-chain.pem'
ssl_crl_file            = '/var/lib/postgresql/ssl/crl.pem'
ssl_ciphers             = 'HIGH:!aNULL'
```

Verify all connections use TLS:
```sql
SELECT pg_ssl FROM pg_stat_ssl JOIN pg_stat_activity USING (pid)
WHERE datname = 'sso' AND pg_ssl IS NOT TRUE;
-- Must return 0 rows.
```

### 7.8 Shibboleth SP Production Settings

In `shibboleth2.xml`:
```xml
<!-- Sign all AuthnRequests -->
<SSO signing="true" encryptRequests="true">

<!-- Enforce strict NameID format -->
<NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>

<!-- Validate InResponseTo to prevent replay attacks -->
<Sessions checkAddress="true" handlerSSL="true" cookieProps="https" />
```

---

## 8. Hardening Checklist

### Pre-Production (Required)

- [ ] Replace Vault dev mode with Vault Raft + KMS auto-unseal
- [ ] Replace snakeoil SP TLS cert with Vault-issued cert (CN=sp.sso.local)
- [ ] Set `VAULT_DEV_ROOT_TOKEN_ID` to a randomly generated 32-byte hex value
- [ ] Rotate all AppRole secret-ids from bootstrap defaults
- [ ] Enable Vault audit backend: `vault audit enable file path=/vault/logs/audit.log`
- [ ] Remove `DEV_USER_PASSWORD` from `.env` and from ldap entrypoint
- [ ] Set `SSP_SECRET_SALT` to a random 32-char string
- [ ] Configure `ssl_crl_file` in PostgreSQL; run `make postgres-crl-update` after any revocation
- [ ] Add `security_opt: [no-new-privileges:true]` to all Docker services
- [ ] Set `ulimits.core: 0` on the app service (no core dumps)
- [ ] Set `cap_drop: [ALL]` on all services; `cap_add: [IPC_LOCK]` on app only
- [ ] Configure TLS 1.3 only on Apache SP (`SSLProtocol TLSv1.3`)
- [ ] Remove port 8880 (IdP) from docker-compose.yml ports (internal only)
- [ ] Set `ui = false` in Vault production config
- [ ] Configure SIEM ingestion for Vault audit log and PostgreSQL log
- [ ] Verify `TOTP_MASTER_SECRET` is ≥32 bytes of random data
- [ ] Verify `POSTGRES_APP_PASSWORD_FILE` is read from Docker secret, not env var
- [ ] Set `APP_ENV=production` in `.env`

### Security Posture Verification

- [ ] `vault policy list` — confirms only the four expected policies exist
- [ ] `vault auth list` — confirms only `approle` auth method is enabled (no token or userpass)
- [ ] `vault secrets list` — confirms only `pki` and `pki_int` engines exist
- [ ] `psql -c "\dp sso.*"` — confirms per-user roles have SELECT/INSERT only on their own tables
- [ ] `psql -c "SELECT * FROM pg_hba_file_rules"` — confirms `cert` auth for all non-admin users
- [ ] Apache: `curl -I https://sp.sso.local/` — verify all security headers present
- [ ] Apache: `nmap --script ssl-enum-ciphers sp.sso.local` — verify TLS 1.3 only
- [ ] Go app: `GET /api/userinfo` without auth → must return 401
- [ ] Go app: `POST /api/token` without Shibboleth headers → must return 401
- [ ] Go app: `POST /api/token` without `ssoCertThumbprint` → must return 403

### Ongoing Operations

- [ ] Weekly: check Vault cert expiry (`make cert-status`)
- [ ] Weekly: rotate AppRole secret-ids via CI/CD
- [ ] Monthly: review Vault audit log for anomalous sign requests
- [ ] Monthly: review PostgreSQL `sso.audit_log` for revoked session access attempts
- [ ] 90 days: rotate SP TLS cert (or automate via consul-template)
- [ ] 1 year: rotate IdP SAML signing cert + update SP metadata
- [ ] Before any: rotate `TOTP_MASTER_SECRET` when re-sealing all user keys

---

## 9. Incident Response

### 9.1 Compromised JWT

1. Identify `jti` from the stolen JWT (base64-decode the payload)
2. Revoke: `DELETE /api/sessions/{jti}` with an admin Bearer token
3. The Go app will return 403 on all subsequent requests using that JWT once the DB check is wired
4. Force re-authentication: `LDAP: lockout alice` or `vault write auth/approle/role/golang-app/secret-id` rotation

### 9.2 Compromised x509 Certificate

1. Identify the serial number from `sso.enrolled_certs` or the cert file
2. Revoke in Vault: `vault write pki_int/revoke serial_number=<serial>`
3. Update CRL in PostgreSQL: `make postgres-crl-update`
4. PostgreSQL will reject the next connection attempt from that cert within seconds (CRL check at handshake)

### 9.3 Compromised TOTP_MASTER_SECRET

1. **Immediately restart the app service** — this generates a new JWT signing key (invalidating all existing sessions) and allows re-sealing to start
2. **Change the Docker secret** — generate new: `openssl rand -base64 48 > secrets/totp_master_secret.txt`, redeploy app
3. **All users must re-enroll** — their sealed keys are now encrypted with the old TOTP master and cannot be unlocked; `POST /api/cert/issue` re-issues a fresh key sealed with the new master
4. **Rotate all JWT signing keys** — done automatically by step 1

### 9.4 Compromised Vault AppRole Secret-ID

1. Rotate immediately: `vault write -f auth/approle/role/golang-app/secret-id`
2. Update Docker secret file, restart app service
3. Review Vault audit log for all API calls made with the stolen secret-id's token
4. Revoke any suspicious CSR signatures (check `sso.enrolled_certs` for unexpected CNs)
