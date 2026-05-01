#!/bin/bash
# ldap/scripts/gen-sample-certs.sh
#
# Generates self-signed EC P-256 client certificates for dev sample users
# and writes ONLY the DER-encoded public cert to their LDAP userCertificate
# attribute. The private key is written to /tmp (deleted immediately after
# the DER encoding step) and is NEVER stored in LDAP or on persistent disk.
#
# This script runs ONLY during first-time container initialization (dev mode).
# In production, certificates are issued by Vault PKI and pushed by
# consul-template; this script is never invoked.
#
# Usage: gen-sample-certs.sh <admin-dn> <admin-password> <base-dn>
set -euo pipefail

ADMIN_DN="${1:-cn=admin,dc=sso,dc=local}"
ADMIN_PASSWORD="${2:-}"
BASE_DN="${3:-dc=sso,dc=local}"
LDAP_HOST="127.0.0.1"
LDAP_PORT="1389"
CERT_DIR="/tmp/sample-certs"
DOMAIN="${DOMAIN:-sso.local}"

mkdir -p "${CERT_DIR}"

# ── Helper: generate cert for a user and push to LDAP ─────────────────────────
enrol_sample_user() {
    local uid="$1"
    local email="${uid}@${DOMAIN}"
    local user_dn="uid=${uid},ou=users,${BASE_DN}"
    local key_file="${CERT_DIR}/${uid}.key"
    local cert_file="${CERT_DIR}/${uid}.crt"
    local der_file="${CERT_DIR}/${uid}.der"

    echo "[gen-certs] Generating x509 client cert for ${uid}..."

    # Generate EC P-256 private key (temp, never stored in LDAP)
    openssl genpkey \
        -algorithm EC \
        -pkeyopt ec_paramgen_curve:P-256 \
        -out "${key_file}" 2>/dev/null

    # Generate self-signed cert (90 days — dev only; Vault issues 1h TTL certs in prod)
    openssl req -new -x509 \
        -key "${key_file}" \
        -out "${cert_file}" \
        -days 90 \
        -subj "/CN=${uid}/emailAddress=${email}/O=sso01a Dev/C=US" \
        -addext "keyUsage=digitalSignature" \
        -addext "extendedKeyUsage=clientAuth" \
        -addext "subjectAltName=email:${email}" \
        2>/dev/null

    # Convert to DER for LDAP binary attribute
    openssl x509 -in "${cert_file}" -outform DER -out "${der_file}" 2>/dev/null

    # Compute SHA-256 thumbprint (x5t#S256 per RFC 7638)
    THUMBPRINT=$(openssl dgst -sha256 -binary "${der_file}" | base64 | tr '+/' '-_' | tr -d '=')

    # Base64-encode DER for ldapmodify ;binary: syntax
    CERT_B64=$(base64 -w0 "${der_file}")

    # Push to LDAP — only the PUBLIC cert (DER bytes)
    ldapmodify -x \
        -H ldap://${LDAP_HOST}:${LDAP_PORT} \
        -D "${ADMIN_DN}" -w "${ADMIN_PASSWORD}" <<LDIF
dn: ${user_dn}
changetype: modify
replace: userCertificate;binary
userCertificate;binary:: ${CERT_B64}
-
replace: ssoCertThumbprint
ssoCertThumbprint: ${THUMBPRINT}
LDIF

    echo "[gen-certs] ✓ ${uid}: cert written to LDAP (thumbprint: ${THUMBPRINT:0:16}...)"
    echo "[gen-certs]   Public cert: ${cert_file}"

    # Delete the private key immediately — dev cert private key is disposable
    rm -f "${key_file}"
    echo "[gen-certs]   Private key deleted from /tmp."
}

# ── Process sample users listed in /etc/ldap/scripts/sample-users.txt ─────────
SAMPLE_USERS_FILE="/etc/ldap/scripts/sample-users.txt"
if [ -f "${SAMPLE_USERS_FILE}" ]; then
    while IFS= read -r uid; do
        [ -n "${uid}" ] && [ "${uid}" != "${uid#\#}" ] && continue  # skip comments
        [ -n "${uid}" ] && enrol_sample_user "${uid}" || true
    done < "${SAMPLE_USERS_FILE}"
else
    # Default sample users if no file present
    for uid in alice bob; do
        enrol_sample_user "${uid}" || true
    done
fi

# Remove temp directory (no private keys should remain, but belt-and-suspenders)
rm -rf "${CERT_DIR}"
echo "[gen-certs] Temporary cert directory cleaned up."
