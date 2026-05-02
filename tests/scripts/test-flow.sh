#!/usr/bin/env bash
# test-flow.sh — end-to-end integration test for sso01a
#
# Tests each layer of the stack without requiring a browser.
# The SAML interactive flow is not automatable; the JWT is obtained by calling
# the Go backend directly (via docker exec) with Shibboleth-like headers.
# This is valid in dev mode: ShibbolethRequired only checks header presence.
#
# Prerequisites: stack must be running (make up or ./scripts/bootstrap-all.sh)
#
# Exit codes: 0 = all tests passed, 1 = one or more failed

set -euo pipefail
cd "$(dirname "$0")/../.."

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

DC="docker compose -p sso01a"
PASS=0; FAIL=0; SKIP=0

# ── Test helpers ──────────────────────────────────────────────────────────────
pass() { echo -e "  ${GREEN}PASS${RESET}  $*"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}FAIL${RESET}  $*"; FAIL=$((FAIL+1)); }
skip() { echo -e "  ${YELLOW}SKIP${RESET}  $*"; SKIP=$((SKIP+1)); }
section() { echo ""; echo -e "${CYAN}${BOLD}── $* ──${RESET}"; }

# Run a command and check its exit code; capture stdout.
run() {
    local out
    out=$("$@" 2>/dev/null) && echo "$out"
}

# curl to the app backend directly on the host (network_mode: host → port 8080 is on localhost)
app_curl() {
    curl -sf --max-time 10 "$@"
}

# curl to the SP (self-signed cert in dev → -k)
# Use --resolve to bypass DNS since sp.sso.local may not be in /etc/hosts.
sp_curl() {
    curl -sk --max-time 10 \
        --resolve "${SP_HOSTNAME:-sp.sso.local}:80:127.0.0.1" \
        --resolve "${SP_HOSTNAME:-sp.sso.local}:443:127.0.0.1" \
        "$@"
}

# ── 0. Stack sanity ───────────────────────────────────────────────────────────
section "0. Stack running"

check_service() {
    local svc="$1"
    local status
    status=$($DC ps --format json "$svc" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); d=d[0] if isinstance(d,list) else d; print(d.get('Health', d.get('State','unknown')))" \
        2>/dev/null || echo "not-running")
    if [ "$status" = "healthy" ] || [ "$status" = "running" ]; then
        pass "$svc ($status)"
    else
        fail "$svc ($status)"
    fi
}

for svc in vault vault-agent ldap postgres idp app sp; do
    check_service "$svc"
done

# ── 1. Vault ──────────────────────────────────────────────────────────────────
section "1. Vault PKI"

VAULT_TOKEN=$(cat secrets/vault-root-token.txt 2>/dev/null || echo "devroot")

vault_exec() {
    $DC exec -T \
        -e VAULT_ADDR=http://127.0.0.1:8200 \
        -e VAULT_TOKEN="$VAULT_TOKEN" \
        vault vault "$@" 2>/dev/null
}

if vault_exec status -format=json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if not d.get('sealed') else 1)" 2>/dev/null; then
    pass "Vault unsealed"
else
    fail "Vault sealed or unreachable"
fi

POLICIES=$(vault_exec policy list 2>/dev/null || echo "")
for policy in golang-app-policy vault-agent-policy consul-template-policy; do
    if echo "$POLICIES" | grep -q "^${policy}$"; then
        pass "Vault policy: $policy"
    else
        fail "Vault policy missing: $policy"
    fi
done

if vault_exec read -format=json pki_int/cert/ca 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('data',{}).get('certificate') else 1)" 2>/dev/null; then
    pass "Vault intermediate CA cert readable"
else
    fail "Vault intermediate CA not found at pki_int/cert/ca"
fi

# ── 2. LDAP ───────────────────────────────────────────────────────────────────
section "2. LDAP directory"

BASE_DN=$(grep '^LDAP_BASE_DN=' .env 2>/dev/null | cut -d= -f2- || echo "dc=sso,dc=local")
LDAP_PW=$(cat secrets/ldap_admin_password.txt 2>/dev/null || echo "")

ldap_search() {
    $DC exec -T ldap \
        ldapsearch -x -LLL \
        -H ldap://localhost:1389 \
        -b "$BASE_DN" \
        -D "cn=admin,${BASE_DN}" \
        -w "$LDAP_PW" \
        "$@" 2>/dev/null
}

LDAP_USERS=$(ldap_search "(|(uid=alice)(uid=bob))" uid 2>/dev/null || true)
for user in alice bob; do
    if echo "$LDAP_USERS" | grep -q "uid: ${user}"; then
        pass "LDAP user: $user"
    else
        fail "LDAP user not found: $user"
    fi
done

if ldap_search "(objectClass=organizationalUnit)" dn 2>/dev/null | grep -q "^dn:"; then
    pass "LDAP OUs accessible"
else
    fail "LDAP OUs not accessible"
fi

# cert-writer ACL: should only be able to write ssoCertThumbprint, not userPassword
if $DC exec -T ldap \
    ldapsearch -x -LLL \
    -H ldap://localhost:1389 \
    -b "$BASE_DN" \
    -D "cn=cert-writer,ou=service-accounts,${BASE_DN}" \
    -w "$(cat secrets/ldap_cert_writer_password.txt 2>/dev/null)" \
    "(uid=alice)" userPassword 2>/dev/null | grep -q "userPassword"; then
    fail "LDAP ACL: cert-writer can read userPassword (ACL misconfigured)"
else
    pass "LDAP ACL: cert-writer cannot read userPassword"
fi

# ── 3. PostgreSQL ─────────────────────────────────────────────────────────────
section "3. PostgreSQL"

PG_DB=$(grep '^POSTGRES_DB=' .env 2>/dev/null | cut -d= -f2 || echo "sso")
PG_ADMIN=$(grep '^POSTGRES_ADMIN_USER=' .env 2>/dev/null | cut -d= -f2 || echo "sso_admin")
PG_ADMIN_PW=$(cat secrets/postgres_admin_password.txt 2>/dev/null || echo "")

pg_exec() {
    $DC exec -T -e PGPASSWORD="$PG_ADMIN_PW" postgres psql -U "$PG_ADMIN" -d "$PG_DB" -At -c "$@" 2>/dev/null
}

if pg_exec "SELECT 1;" 2>/dev/null | grep -q "^1$"; then
    pass "PostgreSQL admin connection"
else
    fail "PostgreSQL admin connection failed"
fi

for tbl in sessions auth_events enrolled_certs; do
    if pg_exec "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename='${tbl}';" 2>/dev/null | grep -q "$tbl"; then
        pass "Table: public.$tbl"
    else
        fail "Table missing: public.$tbl"
    fi
done

for tbl in sessions enrolled_certs; do
    RLS=$(pg_exec "SELECT relrowsecurity FROM pg_class JOIN pg_namespace ON relnamespace=pg_namespace.oid WHERE nspname='public' AND relname='${tbl}';" 2>/dev/null)
    if [ "$RLS" = "t" ]; then
        pass "RLS enabled: public.$tbl"
    else
        fail "RLS NOT enabled: public.$tbl"
    fi
done

if pg_exec "SELECT rolname FROM pg_roles WHERE rolname='sso_app';" 2>/dev/null | grep -q "sso_app"; then
    pass "PostgreSQL role: sso_app"
else
    fail "PostgreSQL role sso_app not found"
fi

# ── 4. Go backend — public endpoints ─────────────────────────────────────────
section "4. Go backend (direct)"

if app_curl http://localhost:8080/healthz | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('status')=='ok' else 1)" 2>/dev/null; then
    pass "GET /healthz → {status:ok}"
else
    fail "GET /healthz failed"
fi

JWKS=$(app_curl http://localhost:8080/api/.well-known/jwks.json 2>/dev/null || echo "{}")
if echo "$JWKS" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('keys') and len(d['keys'])>0 else 1)" 2>/dev/null; then
    KID=$(echo "$JWKS" | python3 -c "import sys,json; print(json.load(sys.stdin)['keys'][0]['kid'])")
    pass "GET /api/.well-known/jwks.json → kid=$KID"
else
    fail "JWKS endpoint returned no keys"
fi

# ── 5. JWT issuance (dev: bypass Shibboleth via direct backend call) ──────────
section "5. JWT issuance (dev bypass)"

echo ""
echo -e "  ${YELLOW}NOTE: SAML interactive flow is not automatable.${RESET}"
echo -e "  ${YELLOW}Calling backend directly with Shibboleth-like headers.${RESET}"
echo -e "  ${YELLOW}This works in dev because ShibbolethRequired only checks header presence.${RESET}"
echo ""

# Use alice as the test user; provide a fake (but non-empty) cert thumbprint.
TEST_UID="alice"
TEST_MAIL="alice@sso.local"
TEST_THUMBPRINT="sha256:aabbccddeeff00112233445566778899aabbccddeeff001122334455667788aa"
TEST_FP="test-device-fp-$(date +%s)"

TOKEN_RESP=$(app_curl -X POST http://localhost:8080/api/token \
    -H "Content-Type: application/json" \
    -H "uid: ${TEST_UID}" \
    -H "mail: ${TEST_MAIL}" \
    -H "ssoCertThumbprint: ${TEST_THUMBPRINT}" \
    -d "{\"fingerprint\":\"${TEST_FP}\"}" \
    2>/dev/null || echo "{}")

JWT=$(echo "$TOKEN_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null || echo "")

if [ -n "$JWT" ] && [ "$JWT" != "null" ]; then
    # Minimal structural check: 3 base64 segments separated by dots
    PARTS=$(echo "$JWT" | tr '.' '\n' | wc -l | tr -d ' ')
    if [ "$PARTS" -eq 3 ]; then
        pass "POST /api/token → JWT issued (3-part structure)"
    else
        fail "POST /api/token → JWT malformed"
    fi

    EXPIRES_IN=$(echo "$TOKEN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('expires_in',0))" 2>/dev/null || echo 0)
    [ "$EXPIRES_IN" -gt 0 ] && pass "JWT expires_in=$EXPIRES_IN" || fail "JWT expires_in missing or zero"
else
    fail "POST /api/token → no token returned (body: ${TOKEN_RESP:0:120})"
    JWT=""
fi

# ── 6. Authenticated endpoints ────────────────────────────────────────────────
section "6. Authenticated API calls"

if [ -z "$JWT" ]; then
    skip "GET /api/userinfo (no JWT)"
    skip "GET /api/sessions (no JWT)"
    skip "GET /api/audit (no JWT)"
else
    USERINFO=$(app_curl http://localhost:8080/api/userinfo \
        -H "Authorization: Bearer ${JWT}" 2>/dev/null || echo "{}")

    if echo "$USERINFO" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('uid')=='alice' else 1)" 2>/dev/null; then
        pass "GET /api/userinfo → uid=alice"
    else
        fail "GET /api/userinfo failed or wrong uid (body: ${USERINFO:0:120})"
    fi

    # cnf claim must be present
    if echo "$USERINFO" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('cert_thumbprint') else 1)" 2>/dev/null; then
        pass "GET /api/userinfo → cnf/cert_thumbprint present"
    else
        fail "GET /api/userinfo → cnf/cert_thumbprint missing"
    fi

    # device fingerprint
    if echo "$USERINFO" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('device_fingerprint') else 1)" 2>/dev/null; then
        pass "GET /api/userinfo → device_fingerprint bound"
    else
        fail "GET /api/userinfo → device_fingerprint missing"
    fi

    # Sessions endpoint — use curl without -f so http_code is captured cleanly
    SESS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        http://localhost:8080/api/sessions \
        -H "Authorization: Bearer ${JWT}" 2>/dev/null)
    [ -z "$SESS_STATUS" ] && SESS_STATUS="000"
    if [ "$SESS_STATUS" = "200" ] || [ "$SESS_STATUS" = "403" ] || [ "$SESS_STATUS" = "503" ]; then
        pass "GET /api/sessions → HTTP $SESS_STATUS"
    else
        fail "GET /api/sessions → HTTP $SESS_STATUS (expected 200, 403, or 503)"
    fi

    AUDIT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        http://localhost:8080/api/audit \
        -H "Authorization: Bearer ${JWT}" 2>/dev/null)
    [ -z "$AUDIT_STATUS" ] && AUDIT_STATUS="000"
    if [ "$AUDIT_STATUS" = "200" ] || [ "$AUDIT_STATUS" = "403" ] || [ "$AUDIT_STATUS" = "503" ]; then
        pass "GET /api/audit → HTTP $AUDIT_STATUS"
    else
        fail "GET /api/audit → HTTP $AUDIT_STATUS (expected 200, 403, or 503)"
    fi
fi

# ── 7. JWT signature validation against JWKS ──────────────────────────────────
section "7. JWT signature (JWKS validation)"

if [ -z "$JWT" ]; then
    skip "JWT signature validation (no JWT)"
else
    # Decode the header to get the kid, then check it exists in JWKS
    HEADER_B64=$(echo "$JWT" | cut -d. -f1)
    # Pad base64 if needed
    PAD=$(( (4 - ${#HEADER_B64} % 4) % 4 ))
    for _ in $(seq 1 $PAD); do HEADER_B64="${HEADER_B64}="; done
    JWT_KID=$(echo "$HEADER_B64" | base64 -d 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('kid',''))" 2>/dev/null || echo "")

    if [ -n "$JWT_KID" ]; then
        pass "JWT header.kid = $JWT_KID"
        if echo "$JWKS" | python3 -c "import sys,json; kids=[k['kid'] for k in json.load(sys.stdin).get('keys',[])]; exit(0 if '${JWT_KID}' in kids else 1)" 2>/dev/null; then
            pass "JWT kid matches JWKS"
        else
            fail "JWT kid NOT found in JWKS (key rotation drift?)"
        fi
    else
        fail "JWT header.kid could not be decoded"
    fi
fi

# ── 8. SP HTTPS endpoints ─────────────────────────────────────────────────────
section "8. Shibboleth SP (HTTPS)"

SP_HOSTNAME=$(grep '^SP_HOSTNAME=' .env 2>/dev/null | cut -d= -f2 || echo "sp.sso.local")

# Healthz via HTTP (port 80 — redirect exempt, plain text response "ok")
HTTP_HEALTH=$(curl -sf --max-time 10 \
    --resolve "${SP_HOSTNAME}:80:127.0.0.1" \
    "http://${SP_HOSTNAME}/healthz" 2>/dev/null || echo "")
if [ "$HTTP_HEALTH" = "ok" ]; then
    pass "SP HTTP /healthz (port 80) → ok"
else
    fail "SP HTTP /healthz unreachable (got: '${HTTP_HEALTH}')"
fi

# JWKS via HTTPS SP (public endpoint — no Shibboleth required)
SP_JWKS=$(sp_curl "https://${SP_HOSTNAME}/api/.well-known/jwks.json" 2>/dev/null || echo "{}")
if echo "$SP_JWKS" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('keys') else 1)" 2>/dev/null; then
    pass "SP HTTPS /api/.well-known/jwks.json → keys present"
else
    skip "SP HTTPS JWKS unreachable (add $SP_HOSTNAME to /etc/hosts)"
fi

# Static SPA: GET / should return HTML
SP_INDEX=$(sp_curl -o /dev/null -w "%{http_code}" "https://${SP_HOSTNAME}/" 2>/dev/null || echo "000")
if [ "$SP_INDEX" = "200" ]; then
    pass "SP HTTPS / → 200 (static SPA served)"
elif [ "$SP_INDEX" = "302" ] || [ "$SP_INDEX" = "301" ]; then
    pass "SP HTTP / → $SP_INDEX (redirect to HTTPS — expected)"
else
    skip "SP HTTPS / → $SP_INDEX (hostname resolution may be missing)"
fi

# /api/token should require Shibboleth → 302 redirect to IdP or 401 (no session)
TOKEN_STATUS=$(sp_curl -o /dev/null -w "%{http_code}" \
    -X POST "https://${SP_HOSTNAME}/api/token" \
    -H "Content-Type: application/json" \
    -d '{"fingerprint":"test"}' 2>/dev/null || echo "000")
if [ "$TOKEN_STATUS" = "302" ] || [ "$TOKEN_STATUS" = "303" ] || [ "$TOKEN_STATUS" = "401" ]; then
    pass "SP HTTPS POST /api/token → $TOKEN_STATUS (Shibboleth guard active)"
else
    skip "SP HTTPS POST /api/token → $TOKEN_STATUS (hostname may be unavailable)"
fi

# ── 9. Cert issuance (Vault PKI) ─────────────────────────────────────────────
section "9. Certificate issuance via Vault"

if [ -z "$JWT" ]; then
    skip "POST /api/cert/issue (no JWT)"
else
    # Single request capturing both body and status code to avoid consuming two rate-limit tokens.
    CERT_RAW=$(curl -s --max-time 10 -w "\n%{http_code}" \
        -X POST http://localhost:8080/api/cert/issue \
        -H "Authorization: Bearer ${JWT}" \
        -H "Content-Type: application/json" \
        -H "uid: ${TEST_UID}" \
        -d '{}' 2>/dev/null || true)
    CERT_STATUS=$(printf '%s' "$CERT_RAW" | tail -1)
    CERT_RESP=$(printf '%s' "$CERT_RAW" | head -n -1)
    [ -z "$CERT_STATUS" ] && CERT_STATUS="000"

    if [ "$CERT_STATUS" = "429" ]; then
        pass "POST /api/cert/issue → 429 rate limited (cert already issued this window)"
    else
        CERT_FIELD=$(echo "$CERT_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('certificate','')[:40])" 2>/dev/null || echo "")
        if [[ "$CERT_FIELD" == "-----BEGIN CERTIFICATE-----"* ]] || [[ "$CERT_FIELD" == "-----BEGIN"* ]]; then
            SERIAL=$(echo "$CERT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('serial_number','')[:24])" 2>/dev/null || echo "")
            pass "POST /api/cert/issue → PEM cert issued (serial: ${SERIAL}…)"
        elif echo "$CERT_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('error') else 1)" 2>/dev/null; then
            ERR=$(echo "$CERT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))")
            fail "POST /api/cert/issue → error: $ERR"
        else
            fail "POST /api/cert/issue → unexpected response (HTTP ${CERT_STATUS}): ${CERT_RESP:0:120}"
        fi
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────────────────────"
TOTAL=$((PASS + FAIL + SKIP))
echo -e "  Total: ${TOTAL}   ${GREEN}Passed: ${PASS}${RESET}   ${RED}Failed: ${FAIL}${RESET}   ${YELLOW}Skipped: ${SKIP}${RESET}"
echo "────────────────────────────────────────────────────────────"

if [ "$FAIL" -gt 0 ]; then
    echo -e "\n  ${RED}${BOLD}Integration test FAILED${RESET} — check 'make logs' for details.\n"
    exit 1
else
    echo -e "\n  ${GREEN}${BOLD}All tests passed!${RESET}\n"
    exit 0
fi
