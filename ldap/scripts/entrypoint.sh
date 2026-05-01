#!/bin/bash
# =============================================================================
# ldap/scripts/entrypoint.sh
#
# Custom entrypoint wrapping bitnami/openldap's initialization.
#
# STARTUP FLOW
# ────────────
# First run (SENTINEL absent):
#   1.  Run bitnami's setup.sh to create the data directory, slapd.d config,
#       and load /docker-entrypoint-initdb.d/ LDIF files (OUs, sample users).
#   2.  Start slapd temporarily AS ROOT so SASL EXTERNAL has cn=config rootDN
#       authority.
#   3.  Load sso.ldif schema into cn=config via ldapi SASL EXTERNAL.
#   4.  Apply ACL LDIF (00-global-acl.ldif) to olcDatabase={2}mdb,cn=config.
#   5.  Create the cert-writer service account password hash and update entry.
#   6.  Generate self-signed sample certs for dev users and write to LDAP.
#   7.  Kill temporary slapd; create sentinel; exec bitnami's run.sh.
#
# Subsequent runs (SENTINEL present):
#   Exec bitnami's run.sh directly.
# =============================================================================

set -euo pipefail

SENTINEL="/bitnami/openldap/.sso-configured"
LDAP_ROOT="${LDAP_ROOT:-dc=sso,dc=local}"
LDAP_ADMIN_USERNAME="${LDAP_ADMIN_USERNAME:-admin}"
LDAP_ADMIN_DN="cn=${LDAP_ADMIN_USERNAME},${LDAP_ROOT}"

BITNAMI_LDAPI="/opt/bitnami/openldap/var/run/ldapi"
LDAPI_URL="ldapi://$(printf '%s' "${BITNAMI_LDAPI}" | sed 's|/|%2F|g')"

red()   { printf '\033[0;31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[0;32m%s\033[0m\n' "$*" >&2; }
cyan()  { printf '\033[0;36m%s\033[0m\n' "$*" >&2; }
info()  { cyan  "[ldap/init] $*"; }
ok()    { green "[ldap/init] ✓ $*"; }
die()   { red   "[ldap/init] ✗ $*"; exit 1; }

# ── Helper: wait for slapd to be accepting connections ───────────────────────
wait_for_slapd() {
    local max="${1:-30}"
    for i in $(seq 1 "${max}"); do
        if ldapsearch -x -H ldap://127.0.0.1:1389 \
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
    info "Already configured. Starting slapd via bitnami's run.sh..."
    exec gosu 1001 /opt/bitnami/scripts/openldap/run.sh
fi

# =============================================================================
# FIRST RUN
# =============================================================================
info "First-run initialization starting..."

# ── Step 1: bitnami setup (data dir, cn=config, load bootstrap LDIF) ─────────
info "Step 1: Running bitnami's setup.sh..."
# bitnami's setup.sh handles: data dir creation, initial slapd.d config,
# loading docker-entrypoint-initdb.d/ LDIF, and stopping slapd.
BITNAMI_DEBUG="${BITNAMI_DEBUG:-false}" \
    /opt/bitnami/scripts/openldap/setup.sh
ok "Bitnami setup.sh complete."

# ── Step 2: Start slapd as root for cn=config modifications ──────────────────
info "Step 2: Starting slapd as root for cn=config configuration..."
mkdir -p "$(dirname "${BITNAMI_LDAPI}")"

/opt/bitnami/slapd/sbin/slapd \
    -F /opt/bitnami/openldap/etc/openldap/slapd.d \
    -h "ldap://0.0.0.0:1389/ ldapi://${BITNAMI_LDAPI}" \
    -u root -g root \
    -d 0 &
SLAPD_PID=$!

wait_for_slapd 30
ok "Temporary slapd (PID ${SLAPD_PID}) is ready."

# ── Step 3: Load sso schema into cn=config ────────────────────────────────────
info "Step 3: Loading custom sso schema..."
if ldapsearch -Y EXTERNAL -H "${LDAPI_URL}" \
        -b "cn=schema,cn=config" "(cn=sso)" dn 2>/dev/null | grep -q "^dn:"; then
    info "  sso schema already loaded."
else
    ldapadd -Y EXTERNAL -H "${LDAPI_URL}" \
        -f /etc/ldap/schema/sso.ldif 2>/dev/null \
    && ok "  sso schema loaded." \
    || { info "  Schema load via ldapi failed; trying admin bind..."; \
         ldapadd -x -H ldap://127.0.0.1:1389 \
             -D "cn=config" -w "${LDAP_ADMIN_PASSWORD}" \
             -f /etc/ldap/schema/sso.ldif 2>/dev/null || true; }
fi

# ── Step 4: Apply ACLs ────────────────────────────────────────────────────────
info "Step 4: Applying ACL configuration to cn=config..."
bash /etc/ldap/scripts/apply-acl.sh "${LDAPI_URL}" "${LDAP_ROOT}"
ok "ACLs applied."

# ── Step 5: Set cert-writer password ─────────────────────────────────────────
info "Step 5: Setting cert-writer service account password..."
if [ -n "${LDAP_CERT_WRITER_PASSWORD:-}" ]; then
    CERT_WRITER_HASH=$(slappasswd -s "${LDAP_CERT_WRITER_PASSWORD}")
    CERT_WRITER_DN="cn=cert-writer,ou=service-accounts,${LDAP_ROOT}"

    # Update password (entry was created by bitnami from 01-service-accounts.ldif)
    ldapmodify -x -H ldap://127.0.0.1:1389 \
        -D "${LDAP_ADMIN_DN}" -w "${LDAP_ADMIN_PASSWORD}" <<LDIF
dn: ${CERT_WRITER_DN}
changetype: modify
replace: userPassword
userPassword: ${CERT_WRITER_HASH}
LDIF
    ok "cert-writer password set."
else
    info "LDAP_CERT_WRITER_PASSWORD not set; cert-writer will use placeholder password."
fi

# ── Step 6: Generate sample development certificates ─────────────────────────
info "Step 6: Generating sample x509 certificates for dev users..."
bash /etc/ldap/scripts/gen-sample-certs.sh \
    "${LDAP_ADMIN_DN}" "${LDAP_ADMIN_PASSWORD}" "${LDAP_ROOT}" \
    || info "Sample cert generation failed (non-fatal in dev)."
ok "Sample certs done."

# ── Step 6.5: Set dev user passwords for IdP LDAP authentication ─────────────
# The SimpleSAMLphp IdP authenticates users by binding to LDAP as the user
# (uid=alice,ou=users,...) with the password they supply on the login form.
# For that bind to succeed, alice and bob need a userPassword in LDAP.
#
# DEV_USER_PASSWORD defaults to "changeme" and applies to all sample users.
# This is a development convenience — production users are provisioned with
# strong passwords through the IAM/enrolment process, never through this script.
#
# userPassword is stored as SSHA (salted SHA-1) by slappasswd.  The ACL
# (by anonymous auth) permits the IdP's LDAP bind-for-auth without disclosing
# the hash to any other connection.
DEV_USER_PASSWORD="${DEV_USER_PASSWORD:-changeme}"
info "Step 6.5: Setting dev user passwords (DEV_USER_PASSWORD)..."
for _dev_user in alice bob; do
    if ldapsearch -x -H ldap://127.0.0.1:1389 \
            -D "${LDAP_ADMIN_DN}" -w "${LDAP_ADMIN_PASSWORD}" \
            -b "uid=${_dev_user},ou=users,${LDAP_ROOT}" \
            -s base "(objectClass=*)" dn 2>/dev/null | grep -q "^dn:"; then
        _hash=$(slappasswd -s "${DEV_USER_PASSWORD}")
        ldapmodify -x -H ldap://127.0.0.1:1389 \
            -D "${LDAP_ADMIN_DN}" -w "${LDAP_ADMIN_PASSWORD}" << LDIF
dn: uid=${_dev_user},ou=users,${LDAP_ROOT}
changetype: modify
replace: userPassword
userPassword: ${_hash}
LDIF
        ok "  Dev password set for ${_dev_user}."
    else
        info "  ${_dev_user} not found — skipping password set."
    fi
done

# ── Step 7: Stop temporary slapd, create sentinel ────────────────────────────
info "Step 7: Stopping temporary slapd..."
kill "${SLAPD_PID}" 2>/dev/null || true
wait "${SLAPD_PID}" 2>/dev/null || true
rm -f "${BITNAMI_LDAPI}"
ok "Temporary slapd stopped."

touch "${SENTINEL}"
ok "First-run complete. Sentinel created."

# ── Hand off to bitnami's run.sh (drops to user 1001) ────────────────────────
info "Starting slapd via bitnami's run.sh (user 1001)..."
exec gosu 1001 /opt/bitnami/scripts/openldap/run.sh
