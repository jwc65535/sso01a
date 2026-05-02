#!/usr/bin/env bash
# =============================================================================
# pki/scripts/bootstrap-ca.sh
#
# DEV-ONLY: Generates a self-signed root CA and a PostgreSQL server certificate
# using OpenSSL.  Run this BEFORE `docker compose up postgres` so that
# postgres/init/00-hba.sh finds the cert files and enables TLS.
#
# In production, Vault PKI issues ALL certificates.  This script's output is
# replaced by vault-agent's rendered output after `make vault-init` runs.
# The postgres-bootstrap Makefile target copies the Vault CA chain over the
# self-signed one written here.
#
# OUTPUT
# ──────
#   postgres/ssl/server.crt   — PostgreSQL server cert (CN=postgres, dev CA)
#   postgres/ssl/server.key   — PostgreSQL server private key (EC P-256)
#   postgres/ssl/ca-chain.pem — Dev root CA cert (trusted by clients in dev)
#   pki/certs/ca.crt          — Dev root CA cert (kept for reference)
#   pki/certs/ca.key          — Dev root CA private key (never leaves this host)
#
# IDEMPOTENT: skips generation if postgres/ssl/server.crt already exists.
#
# SINGLE-MODULE COMPROMISE NOTE
# ──────────────────────────────
# The dev CA key (pki/certs/ca.key) is generated locally and is only used to
# sign the PostgreSQL server cert.  It is NOT the Vault root CA.  If this key
# is stolen, an attacker can forge TLS server certs that will be trusted by
# clients that have the dev CA chain — but they still cannot:
#   • Forge JWTs (no JWT signing key here)
#   • Unseal user private keys (no TOTP_MASTER_SECRET here)
#   • Sign user CSRs via Vault (no AppRole credential here)
#
# For production: delete pki/certs/ca.key after vault-agent renders the real
# Vault CA chain to postgres/ssl/.  The `make postgres-bootstrap` target
# overwrites postgres/ssl/ca-chain.pem with the Vault intermediate CA chain.
# =============================================================================

set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[pki-bootstrap]${RESET} $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}           $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}         $*"; }
die()   { echo -e "${RED}[FATAL]${RESET}        $*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || die "openssl not found — install it first"

# ── Configuration ─────────────────────────────────────────────────────────────
DOMAIN="${DOMAIN:-sso.local}"
CA_DIR="pki/certs"
SSL_DIR="postgres/ssl"
CA_KEY="${CA_DIR}/ca.key"
CA_CERT="${CA_DIR}/ca.crt"
SERVER_KEY="${SSL_DIR}/server.key"
SERVER_CERT="${SSL_DIR}/server.crt"
CA_CHAIN="${SSL_DIR}/ca-chain.pem"
DAYS_CA=3650       # 10 years for dev CA
DAYS_SERVER=365    # 1 year for postgres server cert (replace with Vault cert in prod)

mkdir -p "${CA_DIR}" "${SSL_DIR}"

# ── Idempotency check ─────────────────────────────────────────────────────────
if [ -f "${SERVER_CERT}" ] && [ -f "${SERVER_KEY}" ] && [ -f "${CA_CHAIN}" ]; then
    expiry=$(openssl x509 -noout -enddate -in "${SERVER_CERT}" 2>/dev/null \
        | cut -d= -f2 || echo "unknown")
    ok "postgres/ssl/ already populated (expires: ${expiry}) — skipping."
    ok "Run 'make postgres-bootstrap' to replace with Vault-issued certs."
    exit 0
fi

info "Generating dev PKI for PostgreSQL TLS (domain=${DOMAIN})"
warn "These certs are for DEVELOPMENT ONLY."
warn "Run 'make vault-init && make postgres-bootstrap' to replace with Vault certs."
echo ""

# ── Step 1: Dev root CA ───────────────────────────────────────────────────────
if [ -f "${CA_KEY}" ] && [ -f "${CA_CERT}" ]; then
    info "Reusing existing dev CA (${CA_CERT})"
else
    info "Generating dev root CA…"
    openssl ecparam -name prime256v1 -genkey -noout -out "${CA_KEY}" 2>/dev/null
    chmod 600 "${CA_KEY}"

    openssl req -new -x509 \
        -key "${CA_KEY}" \
        -out "${CA_CERT}" \
        -days "${DAYS_CA}" \
        -subj "/C=US/O=sso01a Dev/CN=sso01a Dev Root CA (${DOMAIN})" \
        -extensions v3_ca \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        2>/dev/null
    ok "Dev root CA: ${CA_CERT}"
fi

# ── Step 2: PostgreSQL server key and CSR ─────────────────────────────────────
info "Generating PostgreSQL server key (EC P-256)…"
openssl ecparam -name prime256v1 -genkey -noout -out "${SERVER_KEY}" 2>/dev/null
chmod 600 "${SERVER_KEY}"
ok "Server key: ${SERVER_KEY}"

info "Generating PostgreSQL server CSR (CN=postgres)…"
CSR_TMP="$(mktemp /tmp/postgres-csr.XXXXXX.pem)"
# SAN covers both the Docker hostname ('postgres') and localhost.
EXT_TMP="$(mktemp /tmp/openssl-ext.XXXXXX.cnf)"
cat > "${EXT_TMP}" << EOF
[req]
distinguished_name = dn
req_extensions     = v3_req
prompt             = no

[dn]
C  = US
O  = sso01a Dev
CN = postgres

[v3_req]
subjectAltName = @alt_names
keyUsage       = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = postgres
DNS.2 = sso-postgres
DNS.3 = localhost
IP.1  = 127.0.0.1
EOF

openssl req -new \
    -key "${SERVER_KEY}" \
    -out "${CSR_TMP}" \
    -config "${EXT_TMP}" \
    2>/dev/null

# ── Step 3: Sign the server cert with the dev CA ──────────────────────────────
info "Signing PostgreSQL server cert with dev CA (TTL=${DAYS_SERVER} days)…"
EXT_SIGN_TMP="$(mktemp /tmp/openssl-sign.XXXXXX.cnf)"
cat > "${EXT_SIGN_TMP}" << EOF
[v3_server]
subjectAltName = @alt_names
keyUsage       = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
basicConstraints = CA:FALSE

[alt_names]
DNS.1 = postgres
DNS.2 = sso-postgres
DNS.3 = localhost
IP.1  = 127.0.0.1
EOF

openssl x509 -req \
    -in "${CSR_TMP}" \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -out "${SERVER_CERT}" \
    -days "${DAYS_SERVER}" \
    -extfile "${EXT_SIGN_TMP}" \
    -extensions v3_server \
    2>/dev/null

rm -f "${CSR_TMP}" "${EXT_TMP}" "${EXT_SIGN_TMP}"
ok "Server cert: ${SERVER_CERT}"

# ── Step 4: Write CA chain ────────────────────────────────────────────────────
# In dev: the chain is just the root CA cert.
# After `make postgres-bootstrap`, this file is replaced by the Vault intermediate
# CA chain (the chain that Vault uses to sign user client certs).
cp "${CA_CERT}" "${CA_CHAIN}"
ok "CA chain: ${CA_CHAIN}"

# ── Verification ──────────────────────────────────────────────────────────────
info "Verifying server cert against CA chain…"
if openssl verify -CAfile "${CA_CHAIN}" "${SERVER_CERT}" 2>/dev/null | grep -q "OK"; then
    ok "Cert chain verification passed."
else
    warn "Cert chain verification failed — check the CA and server cert files."
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}Dev PKI bootstrap complete.${RESET}"
echo ""
echo "  ${CA_CHAIN}   ← trusted by clients connecting to PostgreSQL"
echo "  ${SERVER_CERT}   ← PostgreSQL TLS server cert"
echo "  ${SERVER_KEY}   ← PostgreSQL TLS server key (keep secret)"
echo ""
echo -e "${YELLOW}IMPORTANT:${RESET} After running 'make vault-init' + 'make postgres-bootstrap',"
echo "postgres/ssl/ca-chain.pem will be replaced with the Vault intermediate CA"
echo "chain. User x509 client certs will then be validated against that chain."
echo ""
echo -e "${YELLOW}To inspect the generated cert:${RESET}"
echo "  openssl x509 -noout -text -in ${SERVER_CERT} | grep -A3 'Validity\|Subject\|Issuer\|Alt'"
