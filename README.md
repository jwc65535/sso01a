# SSO — Zero-Trust Kerberos-Style Authentication System
## John W. Carbone
### Quantum Logic Corporation
### May 2026

---

## Overview

This monorepo implements a production-grade, multi-layer authentication system
inspired by Kerberos's ticket-granting model but built on modern open standards:
SAML 2.0, mTLS x509 client certificates, JWT Proof-of-Possession (RFC 7800),
HashiCorp Vault PKI, and PostgreSQL per-user certificate authentication.

The cardinal design rule: **no single compromised component yields a workable
attack surface**. Each layer of trust is independently enforced by a different
component using a different cryptographic primitive.

---

## Threat Model

### Components and What They Hold

| Component        | Holds                                              | Does NOT hold                          |
|------------------|----------------------------------------------------|----------------------------------------|
| SimpleSAMLphp IdP | SAML identity assertions, IdP signing key         | x509 private keys, DB credentials     |
| Shibboleth SP    | SP signing key, SAML session state                | x509 user private keys, DB passwords  |
| HashiCorp Vault  | Root CA, intermediate CA, PKI policy              | x509 private keys (generated client-side), DB passwords |
| OpenLDAP         | Public certificate only (`userCertificate`)       | Private keys, passwords                |
| Golang app       | Encrypted private key in `memguard` arena (RAM only) | Vault root token, LDAP admin creds  |
| PostgreSQL       | Schema, data, per-user roles                      | Any usable secret (cert-auth only)     |
| Client browser   | x509 private key (generated on-device), TOTP seed | Vault token, DB creds, IdP signing key |

### Attack Scenarios

#### Scenario 1 — Vault is fully compromised
An attacker with the Vault root token can:
- Issue new certificates from the intermediate CA
- Read existing PKI configuration

They **cannot**:
- Recover any user's x509 private key (keys are generated on the client, never
  transmitted to Vault; only the public cert CSR is signed)
- Access PostgreSQL without a valid client certificate that matches a per-user role
- Forge a SAML assertion (that key lives only in the IdP)

**Result:** New certs can be issued but the attacker has no existing identity to
steal. Short TTLs (≤4 h) bound the window even for freshly-issued rogue certs.

#### Scenario 2 — OpenLDAP is fully compromised
LDAP holds only `userCertificate` (public key). An attacker learns:
- Which users exist and what their public certificates look like

They **cannot**:
- Reconstruct private keys from public certificates (elliptic-curve hardness)
- Log into PostgreSQL (client-cert auth requires the private key)
- Forge a JWT cnf claim that passes x5t#S256 verification

**Result:** Read-only public-key directory. Zero cryptographic value to an attacker.

#### Scenario 3 — PostgreSQL is compromised
Postgres holds rows, schema, and per-user roles. `pg_hba.conf` enforces
`cert` auth with `clientcert=verify-full`; there are no password entries.
An attacker who can connect to the Postgres port (5432) without a valid client
certificate gets:
- `FATAL: certificate authentication failed`

Even with `pg_hba.conf` in hand an attacker learns only the list of role names.
No credential exists to steal.

**Result:** Data breach risk only if attacker also has valid user x509 private key
AND the matching TOTP passphrase window has not expired.

#### Scenario 4 — The Golang application server is compromised (running process)
The app loads the encrypted private key into a `memguard.LockedBuffer`. An
attacker who can attach a debugger or dump `/proc/<pid>/mem` needs both:
1. The in-memory decrypted key bytes (memguard canaries and mlock attempt to
   prevent paging to disk)
2. The current TOTP-derived passphrase (valid for at most 30 s)

They **cannot**:
- Impersonate another user (each user has an independent key)
- Read other users' PostgreSQL data (per-user roles, row-level security)
- Forge SAML assertions (IdP key is in a separate container)

**Result:** Blast radius is limited to one user for the duration of the TOTP
window.

#### Scenario 5 — Client device is compromised
Attacker has the encrypted private-key file on disk. Decryption requires:
- The TOTP seed (stored separately, never written to the key file)
- The correct 30-second TOTP window

FingerprintJS device binding means the server also checks that the incoming
request matches the enrolled device fingerprint. A cloned key on a different
device fails the device-binding check.

**Result:** Time-bounded window (one TOTP period) on a single device identity.

#### Scenario 6 — IdP (SimpleSAMLphp) is fully compromised
Attacker can forge arbitrary SAML assertions and claim any identity.

They **cannot**:
- Produce a valid x509 client certificate for that claimed identity without also
  compromising Vault AND the user's private key
- Authenticate to PostgreSQL (cert-auth, independent of SAML)
- Pass the JWT cnf / x5t#S256 binding check without the matching private key

**Result:** SAML forgery allows session establishment at the SP layer only.
Every downstream check (mTLS to Postgres, JWT PoP) independently rejects the
forged identity.

---

## Trust Boundaries

```
[Browser / Client]
      │  HTTPS + SAML POST
      ▼
[Shibboleth SP / Apache]  ── validates SAML assertion ──▶ [SimpleSAMLphp IdP]
      │  reverse-proxy (internal network only)
      ▼
[Golang App Server]
      │  mTLS client cert              │  LDAP lookup (public cert only)
      ▼                                ▼
[PostgreSQL]                      [OpenLDAP]
 cert-auth only                    read-only public certs
      ▲
      │ Vault Agent pushes short-lived certs
[HashiCorp Vault PKI]
      │ Consul Template
      ▼
[OpenLDAP]  ← public cert pushed here automatically
```

Every arrow that crosses a trust boundary uses mutual TLS with certificates
issued by Vault's intermediate CA (except the IdP↔SP SAML POST, which uses
XML signatures with independently managed keys).

---

## Component Responsibilities

| Component           | Role                                                  |
|---------------------|-------------------------------------------------------|
| `idp/`              | SimpleSAMLphp — SAML 2.0 identity assertions          |
| `sp/`               | Shibboleth SP + Apache — SAML assertion validation, reverse proxy |
| `vault/`            | Vault PKI — short-lived x509 cert issuance (≤4 h TTL) |
| `ldap/`             | OpenLDAP — public-cert directory, no secrets          |
| `app/`              | Golang server — JWT PoP issuance, memguard key store  |
| `postgres/`         | PostgreSQL — per-user roles, cert-auth only           |
| `client/`           | Browser SPA — FingerprintJS device binding, key gen   |
| `consul-template/`  | Vault Agent + Consul Template — LDAP cert sync        |
| `pki/`              | Bootstrap scripts for root CA initialisation          |

---

## Quick Start

```bash
# Bootstrap the full stack (first run)
make bootstrap

# Bring all services up
make up

# Tail logs
make logs

# Rotate all user certificates
make cert-rotate

# Run integration tests
make test

# Tear down (preserves volumes)
make down

# Full clean (destroys volumes and generated certs)
make clean
```

---

## Key Design Decisions

1. **TOTP-derived passphrase (independent of Vault):** The x509 private key is
   encrypted with `PBKDF2(TOTP(seed, t), salt)`. Vault compromise does not
   reveal this passphrase; it is derived from a seed that never leaves the
   client.

2. **Short cert TTLs (≤4 h):** Vault's PKI engine issues certificates with a
   4-hour maximum TTL. A stolen certificate is self-expiring.

3. **Per-user PostgreSQL roles:** Each user maps to a dedicated `ROLE` in
   Postgres. `pg_hba.conf` contains `cert` auth with `map=ssl`. An attacker
   compromising one user's cert cannot read another user's data.

4. **JWT cnf / x5t#S256 (RFC 7800):** JWTs carry a `cnf` claim binding them to
   a specific certificate thumbprint. A JWT stolen without its matching private
   key is unusable.

5. **FingerprintJS device binding:** The browser fingerprint is enrolled during
   initial certificate generation. The Golang app rejects tokens from
   unrecognised device fingerprints even with a valid cert.

6. **memguard in the Golang app:** Private key bytes are held in a locked,
   canary-guarded memory buffer (`EnclaveBuf`). On process exit the buffer is
   zeroed. Key material never touches disk in the app container.

---

## Infrastructure Setup (Prompt 2)

### Service images

| Service          | Base image                    | Custom? |
|------------------|-------------------------------|---------|
| `vault`          | `hashicorp/vault:1.17`        | No      |
| `vault-agent`    | `hashicorp/vault:1.17`        | No      |
| `ldap`           | `bitnami/openldap:2`          | Yes     |
| `idp`            | `php:8.2-apache`              | Yes     |
| `sp`             | `ubuntu:22.04`                | Yes     |
| `app`            | `golang:1.24-alpine` → `alpine:3.20` | Yes (multi-stage) |
| `postgres`       | `postgres:16-alpine`          | Yes     |
| `consul-template`| `hashicorp/consul-template:0.39` → `alpine:3.20` | Yes |
| `client`         | `nginx:1.27-alpine`           | Yes     |

### First-run bootstrap order

Services have hard dependency chains enforced by `depends_on` + healthchecks.
The startup order is:

```
1. vault          — dev mode, HTTP, no TLS
2. vault-agent    — writes root token to shared volume (waits: vault healthy)
3. ldap           — bitnami OpenLDAP, loads bootstrap LDIF
4. consul-template— watches Vault PKI, pushes public certs to LDAP (waits: vault + ldap healthy)
5. postgres       — runs init scripts: schema, roles, RLS, pg_hba
6. idp            — SimpleSAMLphp, generates IdP signing cert on first boot
7. app            — Golang server (waits: postgres + vault healthy)
8. sp             — Shibboleth SP + Apache (waits: idp + app healthy)
9. client         — nginx SPA (independent)
```

### Bootstrap commands

```bash
# 1. Copy and edit the environment file
cp .env.example .env
# Edit .env: set FPJS_API_KEY, SSP_SECRET_SALT, and domain names

# 2. Run full bootstrap (generates secrets, initialises Vault PKI, seeds LDAP/Postgres)
make bootstrap

# 3. Bring the stack up
make up

# 4. Verify all services are healthy
docker compose ps

# 5. Configure Vault PKI engine (run once after vault is healthy)
make vault-init

# 6. Tail logs for the full stack
make logs

# 7. Run smoke tests
make test-saml
make test-mtls
```

### Network topology

```
Internet
    │ :80/:443
    ▼
[sso-sp]  (frontend network)
    │  proxy-backend (internal)
    ▼
[sso-app]
    ├── db (internal) ──────────────────▶ [sso-postgres]
    ├── ldap-net (internal) ────────────▶ [sso-ldap]
    └── vault-net (internal) ───────────▶ [sso-vault]
                                              ▲
[sso-vault-agent] ────────────────────────────┤ vault-net
[sso-consul-template] ─────────────────────────┘
    │  ldap-net
    └──────────────────────────────────▶ [sso-ldap]

[sso-idp] (saml-net + frontend)
    ▲  saml-net
    └── [sso-sp]

[sso-client] (frontend, port 3000)
```

### Exposed ports

| Host port | Container | Purpose                        |
|-----------|-----------|--------------------------------|
| 80        | sso-sp    | HTTP → HTTPS redirect          |
| 443       | sso-sp    | HTTPS (Shibboleth + proxy)     |
| 8200      | sso-vault | Vault API (localhost only)     |
| 3000      | sso-client| Dev SPA server (localhost only)|

No other ports are exposed. All inter-service communication uses Docker
internal networks.

### Secrets

Docker secrets are used for all sensitive values. The `make bootstrap` target
generates them into `secrets/` (git-ignored) and writes them as files mounted
at `/run/secrets/<name>` inside containers:

| Secret file                  | Used by                        |
|------------------------------|--------------------------------|
| `ldap_admin_password.txt`    | ldap, idp, sp, consul-template |
| `postgres_admin_password.txt`| postgres                       |
| `ssp_admin_password.txt`     | idp                            |

The Vault dev root token is written to `.env` and into the `vault-agent-token`
named volume (never into a Docker secret — it is ephemeral in dev mode).
