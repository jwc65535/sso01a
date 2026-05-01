#!/bin/bash
# ldap/scripts/apply-acl.sh
#
# Finds the correct olcDatabase DN for our suffix and applies ACL LDIF.
# Uses SASL EXTERNAL via ldapi (requires root caller for cn=config authority).
#
# Usage: apply-acl.sh <ldapi-url> <ldap-base-dn>
set -euo pipefail

LDAPI_URL="${1:-ldapi:///opt%2Fbitnami%2Fopenldap%2Fvar%2Frun%2Fldapi}"
LDAP_ROOT="${2:-dc=sso,dc=local}"
ACL_DIR="/etc/ldap/acl"

# ── Find the olcDatabase DN for our suffix ────────────────────────────────────
DB_DN=$(ldapsearch -Y EXTERNAL -H "${LDAPI_URL}" \
    -b "cn=config" -LLL \
    "(&(objectClass=olcMdbConfig)(olcSuffix=${LDAP_ROOT}))" dn 2>/dev/null \
    | grep -i "^dn:" | sed 's/^[Dd][Nn]: //')

if [ -z "${DB_DN}" ]; then
    # Fallback: try mdb or bdb without the suffix filter
    DB_DN=$(ldapsearch -Y EXTERNAL -H "${LDAPI_URL}" \
        -b "cn=config" -LLL \
        "(objectClass=olcMdbConfig)" dn 2>/dev/null \
        | grep -i "^dn:" | head -1 | sed 's/^[Dd][Nn]: //')
fi

[ -n "${DB_DN}" ] || { echo "[apply-acl] ERROR: Could not find olcDatabase DN."; exit 1; }
echo "[apply-acl] Target database DN: ${DB_DN}"

# ── Generate and apply the ACL LDIF ──────────────────────────────────────────
# We use sed to substitute the real DB_DN and LDAP_ROOT into the template.
CERT_WRITER_DN="cn=cert-writer,ou=service-accounts,${LDAP_ROOT}"
ADMIN_DN="cn=admin,${LDAP_ROOT}"

for acl_file in $(ls -1 "${ACL_DIR}"/*.ldif 2>/dev/null | sort); do
    echo "[apply-acl] Applying ${acl_file}..."
    sed \
        -e "s|__DB_DN__|${DB_DN}|g" \
        -e "s|__LDAP_ROOT__|${LDAP_ROOT}|g" \
        -e "s|__CERT_WRITER_DN__|${CERT_WRITER_DN}|g" \
        -e "s|__ADMIN_DN__|${ADMIN_DN}|g" \
        "${acl_file}" \
    | ldapmodify -Y EXTERNAL -H "${LDAPI_URL}" 2>&1 \
    && echo "[apply-acl] ${acl_file} applied." \
    || echo "[apply-acl] WARNING: ${acl_file} returned non-zero (may already be set)."
done
