#!/bin/bash
# ldap/tests/verify-acl.sh
# Smoke-tests that ACL rules are enforced as expected.
# Run with: make test-ldap-acl (after `make up`)
set -euo pipefail

LDAP_HOST="${LDAP_HOST:-localhost}"
LDAP_PORT="${LDAP_PORT:-1389}"
BASE_DN="${LDAP_BASE_DN:-dc=sso,dc=local}"
ADMIN_DN="cn=admin,${BASE_DN}"
ADMIN_PASSWORD="${LDAP_ADMIN_PASSWORD:-}"
CERT_WRITER_DN="cn=cert-writer,ou=service-accounts,${BASE_DN}"
CERT_WRITER_PASSWORD="${LDAP_CERT_WRITER_PASSWORD:-}"
H="ldap://${LDAP_HOST}:${LDAP_PORT}"

pass() { printf '\033[0;32m[PASS]\033[0m %s\n' "$1"; }
fail() { printf '\033[0;31m[FAIL]\033[0m %s\n' "$1"; FAILURES=$((FAILURES+1)); }
FAILURES=0

echo "=== LDAP ACL verification against ${H} ==="
echo ""

# ── Test 1: Anonymous can read userCertificate ───────────────────────────────
echo "Test 1: Anonymous read of userCertificate"
RESULT=$(ldapsearch -x -H "${H}" -b "uid=alice,ou=users,${BASE_DN}" \
    -s base "(objectClass=*)" userCertificate 2>/dev/null | grep -c "userCertificate" || true)
[ "${RESULT}" -ge 1 ] \
    && pass "Anonymous can read userCertificate" \
    || fail "Anonymous CANNOT read userCertificate (check ACL rule 1)"

# ── Test 2: Anonymous CANNOT read userPassword ────────────────────────────────
echo "Test 2: Anonymous cannot read userPassword"
RESULT=$(ldapsearch -x -H "${H}" -b "uid=alice,ou=users,${BASE_DN}" \
    -s base "(objectClass=*)" userPassword 2>/dev/null | grep -c "userPassword" || true)
[ "${RESULT}" -eq 0 ] \
    && pass "Anonymous cannot read userPassword" \
    || fail "Anonymous CAN read userPassword (ACL rule 0 broken!)"

# ── Test 3: Anonymous CANNOT search ou=service-accounts ──────────────────────
echo "Test 3: Anonymous cannot read service accounts"
RESULT=$(ldapsearch -x -H "${H}" -b "ou=service-accounts,${BASE_DN}" \
    -s one "(objectClass=*)" dn 2>/dev/null | grep -c "^dn:" || true)
[ "${RESULT}" -eq 0 ] \
    && pass "Anonymous cannot enumerate service accounts" \
    || fail "Anonymous CAN see service accounts (ACL rule 2 broken!)"

# ── Test 4: cert-writer can update userCertificate ────────────────────────────
if [ -n "${CERT_WRITER_PASSWORD}" ]; then
    echo "Test 4: cert-writer can write userCertificate"
    # Generate a throwaway cert for the test
    TMPDIR=$(mktemp -d)
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -x509 \
        -days 1 -subj "/CN=test-acl" -keyout "${TMPDIR}/k.pem" \
        -out "${TMPDIR}/c.pem" 2>/dev/null
    openssl x509 -in "${TMPDIR}/c.pem" -outform DER -out "${TMPDIR}/c.der" 2>/dev/null
    CERT_B64=$(base64 -w0 "${TMPDIR}/c.der")
    RESULT=$(ldapmodify -x -H "${H}" \
        -D "${CERT_WRITER_DN}" -w "${CERT_WRITER_PASSWORD}" <<LDIF 2>&1
dn: uid=alice,ou=users,${BASE_DN}
changetype: modify
replace: userCertificate;binary
userCertificate;binary:: ${CERT_B64}
LDIF
    )
    echo "${RESULT}" | grep -q "modifying entry" \
        && pass "cert-writer can update userCertificate" \
        || fail "cert-writer CANNOT update userCertificate (ACL rule 1 broken!)"
    rm -rf "${TMPDIR}"
else
    echo "Test 4: SKIPPED (LDAP_CERT_WRITER_PASSWORD not set)"
fi

# ── Test 5: cert-writer CANNOT modify cn (not a cert attribute) ───────────────
if [ -n "${CERT_WRITER_PASSWORD}" ]; then
    echo "Test 5: cert-writer cannot modify cn"
    RESULT=$(ldapmodify -x -H "${H}" \
        -D "${CERT_WRITER_DN}" -w "${CERT_WRITER_PASSWORD}" <<LDIF 2>&1
dn: uid=alice,ou=users,${BASE_DN}
changetype: modify
replace: cn
cn: Alice Hacked
LDIF
    )
    echo "${RESULT}" | grep -qiE "insufficient|access|denied" \
        && pass "cert-writer cannot modify cn" \
        || fail "cert-writer CAN modify cn (ACL rules too permissive!)"
fi

# ── Test 6: Anonymous CANNOT modify anything ──────────────────────────────────
echo "Test 6: Anonymous cannot write any attribute"
RESULT=$(ldapmodify -x -H "${H}" <<LDIF 2>&1
dn: uid=alice,ou=users,${BASE_DN}
changetype: modify
replace: description
description: hacked
LDIF
)
echo "${RESULT}" | grep -qiE "auth|anon|insufficient|access|denied" \
    && pass "Anonymous cannot write attributes" \
    || fail "Anonymous CAN write attributes (ACL broken!)"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
if [ "${FAILURES}" -eq 0 ]; then
    echo -e "\033[0;32m=== All ACL tests passed ===\033[0m"
    exit 0
else
    echo -e "\033[0;31m=== ${FAILURES} test(s) FAILED ===\033[0m"
    exit 1
fi
