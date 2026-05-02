#!/bin/bash
# =============================================================================
# ldap/scripts/entrypoint.sh
#
# Custom entrypoint for the debian:bookworm-slim + slapd-based OpenLDAP image.
# Replaces the previous bitnami/openldap:2 wrapper (removed from Docker Hub).
#
# STARTUP FLOW
# ────────────
# First run (SENTINEL absent):
#   1.  Run dpkg-reconfigure slapd with the real admin password from the Docker
#       secret to create /etc/ldap/slapd.d and /var/lib/ldap from scratch.
#   2.  Start slapd temporarily AS ROOT so SASL EXTERNAL has cn=config rootDN
#       authority over ldapi://.
#   3.  Load sso.ldif schema into cn=config via SASL EXTERNAL.
#   4.  Apply ACL LDIF via apply-acl.sh (SASL EXTERNAL, cn=config).
#   5.  Load bootstrap LDIFs (OUs, service accounts, sample users) via admin bind.
#   6.  Set cert-writer service account password.
#   7.  Generate self-signed sample certs for dev users and write to LDAP.
#   8.  Set dev user passwords so the IdP can perform LDAP bind-for-auth.
#   9.  Kill temporary slapd; create sentinel.
#  10.  exec slapd as the openldap user (unprivileged, persistent).
#
# Subsequent runs (SENTINEL present):
#   exec slapd as openldap directly (no re-initialization).
#
# SINGLE-MODULE COMPROMISE NOTE
# ──────────────────────────────
# An attacker who fully owns this container can read public certs and cause
# denial-of-service by deleting entries, but CANNOT retrieve private keys,
# forge JWTs, or authenticate to PostgreSQL or Vault without additional
# credentials.  See Dockerfile header for full blast-radius table.
# =============================================================================

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────
SENTINEL="/var/lib/ldap-sentinel/.sso-configured"
SLAPD_CONF="/etc/ldap/slapd.d"
SLAPD_BIN="/usr/sbin/slapd"
LDAPI_SOCK="/var/run/slapd/ldapi"
LDAPI_URL="ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi"
BOOTSTRAP_DIR="/etc/ldap/bootstrap"
OPENLDAP_USER="openldap"
LDAP_PORT="1389"

LDAP_ROOT="${LDAP_ROOT:-${LDAP_BASE_DN:-dc=sso,dc=local}}"
LDAP_ADMIN_USERNAME="${LDAP_ADMIN_USERNAME:-admin}"
LDAP_ADMIN_DN="cn=${LDAP_ADMIN_USERNAME},${LDAP_ROOT}"
LDAP_LOGLEVEL="${LDAP_LOGLEVEL:-256}"
LDAP_DOMAIN="${LDAP_DOMAIN:-sso.local}"
LDAP_ORGANISATION="${LDAP_ORGANISATION:-sso01a}"

red()   { printf '\033[0;31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[0;32m%s\033[0m\n' "$*" >&2; }
cyan()  { printf '\033[0;36m%s\033[0m\n' "$*" >&2; }
info()  { cyan  "[ldap/init] $*"; }
ok()    { green "[ldap/init] ✓ $*"; }
die()   { red   "[ldap/init] ✗ $*"; exit 1; }

# ── Ensure ldapi socket dir exists (tmpfs is reset on each container start) ───
mkdir -p "${LDAPI_SOCK%/*}"
chown "${OPENLDAP_USER}:${OPENLDAP_USER}" "${LDAPI_SOCK%/*}" 2>/dev/null || true

# ── Helper: wait for slapd to accept connections ──────────────────────────────
wait_for_slapd() {
    local max="${1:-30}"
    for i in $(seq 1 "${max}"); do
        if ldapsearch -x -H "ldap://127.0.0.1:${LDAP_PORT}" \
                -b "" -s base "(objectClass=*)" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    die "slapd did not start within ${max} seconds."
}

# ── Read the admin password ───────────────────────────────────────────────────
if [ -f /run/secrets/ldap_admin_password ]; then
    LDAP_ADMIN_PASSWORD=$(cat /run/secrets/ldap_admin_password)
    export LDAP_ADMIN_PASSWORD
fi
[ -n "${LDAP_ADMIN_PASSWORD:-}" ] || die "LDAP_ADMIN_PASSWORD not set and secret not found."

# ── Read the cert-writer password ─────────────────────────────────────────────
if [ -f /run/secrets/ldap_cert_writer_password ]; then
    LDAP_CERT_WRITER_PASSWORD=$(cat /run/secrets/ldap_cert_writer_password)
    export LDAP_CERT_WRITER_PASSWORD
fi

# ── Fast path: already configured ─────────────────────────────────────────────
if [ -f "${SENTINEL}" ]; then
    info "Already configured (sentinel found). Starting slapd as ${OPENLDAP_USER}..."
    exec gosu "${OPENLDAP_USER}" "${SLAPD_BIN}" \
        -F "${SLAPD_CONF}" \
        -h "ldap://0.0.0.0:${LDAP_PORT}/ ${LDAPI_URL}" \
        -d "${LDAP_LOGLEVEL}"
fi

# =============================================================================
# FIRST RUN
# =============================================================================
info "First-run initialization starting (domain=${LDAP_DOMAIN}, base=${LDAP_ROOT})..."

# ── Step 1: dpkg-reconfigure slapd ────────────────────────────────────────────
# Creates /etc/ldap/slapd.d (OLC config) and /var/lib/ldap (MDB data) with:
#   - base DN: dc=sso,dc=local (from domain sso.local)
#   - admin DN: cn=admin,dc=sso,dc=local
#   - admin password: from Docker secret
# The volumes for slapd.d and var/lib/ldap must be writable (and empty on first run).
info "Step 1: Initializing slapd via dpkg-reconfigure..."
mkdir -p "${SLAPD_CONF}" /var/lib/ldap

# Pre-seed debconf with real admin password from Docker secret.
echo "slapd slapd/no_configuration boolean false" | debconf-set-selections
echo "slapd slapd/domain string ${LDAP_DOMAIN}" | debconf-set-selections
echo "slapd slapd/organization string ${LDAP_ORGANISATION}" | debconf-set-selections
echo "slapd slapd/password1 password ${LDAP_ADMIN_PASSWORD}" | debconf-set-selections
echo "slapd slapd/password2 password ${LDAP_ADMIN_PASSWORD}" | debconf-set-selections
echo "slapd slapd/backend select MDB" | debconf-set-selections
echo "slapd slapd/purge_database boolean true" | debconf-set-selections
echo "slapd slapd/move_old_database boolean true" | debconf-set-selections
echo "slapd slapd/allow_ldap_v2 boolean false" | debconf-set-selections

DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive slapd
ok "dpkg-reconfigure slapd complete."

# Ensure openldap owns its directories after dpkg-reconfigure.
chown -R "${OPENLDAP_USER}:${OPENLDAP_USER}" "${SLAPD_CONF}" /var/lib/ldap 2>/dev/null || true

# ── Step 2: Start slapd as root for cn=config modifications ──────────────────
info "Step 2: Starting temporary slapd as root for cn=config access..."

"${SLAPD_BIN}" \
    -F "${SLAPD_CONF}" \
    -h "ldap://0.0.0.0:${LDAP_PORT}/ ${LDAPI_URL}" \
    -d 0 &
SLAPD_PID=$!

wait_for_slapd 30
ok "Temporary slapd (PID ${SLAPD_PID}) ready."

# ── Step 3: Load sso schema into cn=config ────────────────────────────────────
info "Step 3: Loading custom sso schema into cn=config..."
if ldapsearch -Y EXTERNAL -H "${LDAPI_URL}" \
        -b "cn=schema,cn=config" "(cn=sso)" dn 2>/dev/null | grep -q "^dn:"; then
    info "  sso schema already present."
else
    ldapadd -Y EXTERNAL -H "${LDAPI_URL}" \
        -f /etc/ldap/schema/sso.ldif 2>/dev/null \
    && ok "  sso schema loaded." \
    || die "sso schema load failed — check /etc/ldap/schema/sso.ldif"
fi

# ── Step 4: Apply ACLs to cn=config ──────────────────────────────────────────
info "Step 4: Applying ACL configuration to cn=config..."
bash /etc/ldap/scripts/apply-acl.sh "${LDAPI_URL}" "${LDAP_ROOT}"
ok "ACLs applied."

# ── Step 5: Load bootstrap LDIF (DIT structure + service accounts + users) ────
info "Step 5: Loading bootstrap LDIF files..."
for _ldif in $(ls -1 "${BOOTSTRAP_DIR}"/*.ldif 2>/dev/null | sort); do
    _name=$(basename "${_ldif}")
    if ldapadd -x -H "ldap://127.0.0.1:${LDAP_PORT}" \
            -D "${LDAP_ADMIN_DN}" -w "${LDAP_ADMIN_PASSWORD}" \
            -f "${_ldif}" 2>/dev/null; then
        ok "  Loaded: ${_name}"
    else
        info "  ${_name} returned non-zero (may already exist — continuing)."
    fi
done

# ── Step 6: Set cert-writer password ─────────────────────────────────────────
info "Step 6: Setting cert-writer service account password..."
if [ -n "${LDAP_CERT_WRITER_PASSWORD:-}" ]; then
    CERT_WRITER_HASH=$(slappasswd -s "${LDAP_CERT_WRITER_PASSWORD}")
    CERT_WRITER_DN="cn=cert-writer,ou=service-accounts,${LDAP_ROOT}"
    ldapmodify -x -H "ldap://127.0.0.1:${LDAP_PORT}" \
        -D "${LDAP_ADMIN_DN}" -w "${LDAP_ADMIN_PASSWORD}" <<LDIF
dn: ${CERT_WRITER_DN}
changetype: modify
replace: userPassword
userPassword: ${CERT_WRITER_HASH}
LDIF
    ok "cert-writer password set."
else
    info "LDAP_CERT_WRITER_PASSWORD not set; cert-writer uses placeholder password."
fi

# ── Step 7: Generate sample development certificates ─────────────────────────
info "Step 7: Generating sample x509 certificates for dev users..."
bash /etc/ldap/scripts/gen-sample-certs.sh \
    "${LDAP_ADMIN_DN}" "${LDAP_ADMIN_PASSWORD}" "${LDAP_ROOT}" \
    || info "Sample cert generation failed (non-fatal in dev)."
ok "Sample certs done."

# ── Step 8: Set dev user passwords for IdP LDAP bind-for-auth ────────────────
# SimpleSAMLphp IdP authenticates users by binding to LDAP as the user
# (uid=alice,ou=users,...) with the password from the login form.
# DEV_USER_PASSWORD applies to all sample users; production never uses this.
DEV_USER_PASSWORD="${DEV_USER_PASSWORD:-changeme}"
info "Step 8: Setting dev user passwords (DEV_USER_PASSWORD)..."
for _dev_user in alice bob; do
    if ldapsearch -x -H "ldap://127.0.0.1:${LDAP_PORT}" \
            -D "${LDAP_ADMIN_DN}" -w "${LDAP_ADMIN_PASSWORD}" \
            -b "uid=${_dev_user},ou=users,${LDAP_ROOT}" \
            -s base "(objectClass=*)" dn 2>/dev/null | grep -q "^dn:"; then
        _hash=$(slappasswd -s "${DEV_USER_PASSWORD}")
        ldapmodify -x -H "ldap://127.0.0.1:${LDAP_PORT}" \
            -D "${LDAP_ADMIN_DN}" -w "${LDAP_ADMIN_PASSWORD}" << LDIF
dn: uid=${_dev_user},ou=users,${LDAP_ROOT}
changetype: modify
replace: userPassword
userPassword: ${_hash}
LDIF
        ok "  Dev password set for ${_dev_user}."
    else
        info "  ${_dev_user} not found — skipping."
    fi
done

# ── Step 9: Stop temporary slapd, create sentinel ────────────────────────────
info "Step 9: Stopping temporary slapd..."
kill "${SLAPD_PID}" 2>/dev/null || true
wait "${SLAPD_PID}" 2>/dev/null || true
rm -f "${LDAPI_SOCK}"
ok "Temporary slapd stopped."

# Re-chown after schema/ACL writes: the root-owned slapd creates new
# LDIF files in slapd.d (schema, config) as root; fix ownership so the
# persistent openldap-user slapd can read them.
chown -R "${OPENLDAP_USER}:${OPENLDAP_USER}" "${SLAPD_CONF}" /var/lib/ldap 2>/dev/null || true
mkdir -p "$(dirname "${SENTINEL}")"
touch "${SENTINEL}"
ok "First-run complete. Sentinel created at ${SENTINEL}."

# ── Hand off to slapd as openldap user ────────────────────────────────────────
info "Starting slapd as ${OPENLDAP_USER} (persistent)..."
exec gosu "${OPENLDAP_USER}" "${SLAPD_BIN}" \
    -F "${SLAPD_CONF}" \
    -h "ldap://0.0.0.0:${LDAP_PORT}/ ${LDAPI_URL}" \
    -d "${LDAP_LOGLEVEL}"
