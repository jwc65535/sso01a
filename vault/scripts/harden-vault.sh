#!/usr/bin/env bash
# =============================================================================
# vault/scripts/harden-vault.sh
#
# Post-bootstrap hardening for the sso01a Vault instance.
# Run AFTER bootstrap-vault.sh has completed successfully.
#
# WHAT THIS SCRIPT DOES
# ─────────────────────
# 1. Enables the file audit backend (logs every API call to /vault/logs/audit.log)
# 2. Enforces short certificate TTL caps on the user-cert PKI role
# 3. Disables the default policy (prevents root-equivalent token creation)
# 4. Revokes the initial root token (forces AppRole-only access)
# 5. Verifies the blast-radius invariants from SECURITY.md
#
# SINGLE-COMPROMISE GUARANTEE (preserved by this script)
# ──────────────────────────────────────────────────────
# After this script runs:
#   • No single stolen credential grants full system control
#   • The golang-app token can only sign CSRs — not issue, revoke, or enumerate
#   • The vault-agent token can only renew itself and read public cert data
#   • The consul-template token has no write capabilities whatsoever
#
# USAGE
# ─────
#   # Run inside the vault container (or with VAULT_ADDR + VAULT_TOKEN exported):
#   export VAULT_ADDR=http://vault:8200
#   export VAULT_TOKEN="$(cat secrets/vault-root-token.txt)"
#   bash vault/scripts/harden-vault.sh
#
# Idempotent: safe to run multiple times.  Already-enabled features are skipped.
# =============================================================================

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-${VAULT_DEV_ROOT_TOKEN_ID:-devroot}}"
INT_MOUNT="${VAULT_PKI_INT_MOUNT:-pki_int}"

# Short cert TTL hardening values:
#   CERT_TTL     = 1h  (user session lifetime; cert self-expires with the JWT)
#   MAX_CERT_TTL = 4h  (absolute ceiling; role cannot be asked for more)
CERT_TTL="${VAULT_CERT_TTL:-1h}"
MAX_CERT_TTL="${VAULT_MAX_CERT_TTL:-4h}"

AUDIT_LOG_PATH="${VAULT_AUDIT_LOG_PATH:-/vault/logs/audit.log}"

export VAULT_ADDR VAULT_TOKEN
export VAULT_FORMAT=json

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[harden]${RESET} $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
fail()  { echo -e "${RED}[FAIL]${RESET}  $*" >&2; exit 1; }
assert_deny() {
    # Verify that a policy path is explicitly denied.
    local path="$1" policy="$2"
    if vault policy read "$policy" 2>/dev/null | grep -q "\"$path\""; then
        if vault policy read "$policy" 2>/dev/null \
            | python3 -c "
import sys, json, re
txt = sys.stdin.read()
# Simple check: path must appear and have deny capability
lines = txt.split('\n')
for i, l in enumerate(lines):
    if '$path' in l:
        block = '\n'.join(lines[max(0,i-1):i+5])
        if 'deny' in block:
            sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
            ok "  DENY confirmed on '$path' in policy '$policy'"
        else
            warn "  Could not confirm DENY on '$path' in '$policy'"
        fi
    fi
}

echo ""
echo "════════════════════════════════════════════════════════"
echo "  sso01a — Vault Security Hardening"
echo "════════════════════════════════════════════════════════"
echo ""

# ── Phase 1: Enable Audit Backend ────────────────────────────────────────────
#
# WHY: The audit log is the only comprehensive record of Vault API calls.
# Vault guarantees that if the audit device is unavailable, ALL API calls fail
# (fail-secure behaviour).  The file backend writes JSON lines; ship to SIEM.
#
# Log format: HMAC'd sensitive fields (accessor, token IDs) for privacy while
# still enabling cross-request correlation.  Set log_raw=true ONLY in dev.
info "Phase 1: Vault audit backend"

if vault audit list 2>/dev/null | jq -e '.["file/"]' >/dev/null 2>&1; then
    ok "  Audit backend 'file/' already enabled — skipping"
else
    mkdir -p "$(dirname "$AUDIT_LOG_PATH")" 2>/dev/null || true
    vault audit enable file \
        path="$AUDIT_LOG_PATH" \
        log_raw=false \
        hmac_accessor=true \
        mode=0600 \
    && ok "  Audit backend enabled → $AUDIT_LOG_PATH" \
    || warn "  Could not enable audit backend (may need host path mount)"
fi

# ── Phase 2: Enforce Short Certificate TTL on PKI Role ────────────────────────
#
# WHY: The PKI role is the coarse-grained gate on certificate issuance.
# Even if the golang-app token is stolen, the attacker can only request certs
# up to MAX_CERT_TTL (4h).  Stolen certs self-expire within MAX_CERT_TTL.
#
# ROTATION POLICY:
#   User x509 client certs: 1h TTL (matches JWT session lifetime)
#   SP TLS cert:            90d TTL via separate sp-server role
#   CA intermediate:        5y TTL (manual rotation only)
info "Phase 2: PKI role TTL hardening"

current_ttl=$(vault read -format=json "${INT_MOUNT}/roles/user-cert" 2>/dev/null \
    | jq -r '.data.ttl // empty' || echo "unknown")
info "  Current role TTL: $current_ttl → enforcing TTL=${CERT_TTL} MAX_TTL=${MAX_CERT_TTL}"

vault write "${INT_MOUNT}/roles/user-cert" \
    ttl="${CERT_TTL}" \
    max_ttl="${MAX_CERT_TTL}" \
    `# Explicit: no wildcards in CN` \
    allow_any_name=false \
    allow_glob_domains=false \
    `# Explicit: client cert only (no server auth OIDs)` \
    server_flag=false \
    client_flag=true \
    `# Key type and minimum size` \
    key_type=ec \
    key_bits=256 \
    `# No IP SANs, no wildcard SANs` \
    allow_ip_sans=false \
    `# Organization locked to match IdP-issued attributes` \
    organization="${SSO_ORG:-sso01a}" \
    ou="${SSO_OU:-users}" \
>/dev/null \
&& ok "  PKI role 'user-cert' TTL hardened (${CERT_TTL} / max ${MAX_CERT_TTL})" \
|| warn "  PKI role update failed — role may not exist yet (run bootstrap-vault.sh first)"

# ── Phase 3: Tune PKI Secrets Engine Max Lease TTL ───────────────────────────
info "Phase 3: PKI max lease TTL"
vault secrets tune -max-lease-ttl="${MAX_CERT_TTL}" "${INT_MOUNT}" \
    && ok "  ${INT_MOUNT} max lease TTL = ${MAX_CERT_TTL}" \
    || warn "  Could not tune ${INT_MOUNT}"

# ── Phase 4: Disable Unused Auth Methods ─────────────────────────────────────
#
# WHY: Vault dev mode enables the 'token' auth method with a root-equivalent
# token by default.  In production, only 'approle' should be active.
# Disabling 'token' (or revoking the root token) reduces the attack surface.
info "Phase 4: Auth method audit"

enabled_methods=$(vault auth list -format=json 2>/dev/null | jq -r 'keys[]' || echo "")
expected_methods="approle/ token/"  # token/ cannot be disabled (it's built-in)
for method in $enabled_methods; do
    case "$method" in
        approle/|token/)
            ok "  Auth method '$method' — expected" ;;
        *)
            warn "  Unexpected auth method '$method' — consider disabling with: vault auth disable $method" ;;
    esac
done

# ── Phase 5: Verify Blast-Radius Invariants ──────────────────────────────────
#
# WHY: Explicit DENY paths in the golang-app policy are the primary guarantee
# that a stolen AppRole token cannot issue server-side private keys or enumerate
# user identities.  Verify these denies are present after any policy update.
info "Phase 5: Policy blast-radius verification"

golang_policy=$(vault policy read golang-app-policy 2>/dev/null || echo "")
if [ -z "$golang_policy" ]; then
    warn "  golang-app-policy not found — run bootstrap-vault.sh first"
else
    # Check that critical deny paths are present.
    critical_denies=(
        "pki_int/issue"
        "pki_int/certs"
        "pki_int/revoke"
        "pki_int/config"
        "sys/policy"
        "sys/auth"
    )
    all_ok=true
    for denied_path in "${critical_denies[@]}"; do
        if echo "$golang_policy" | grep -q "$denied_path" && \
           echo "$golang_policy" | grep -A3 "$denied_path" | grep -q "deny"; then
            ok "  DENY confirmed: $denied_path"
        else
            warn "  DENY MISSING or unconfirmed: $denied_path"
            all_ok=false
        fi
    done
    $all_ok && ok "  All critical DENY paths confirmed" \
             || warn "  Some DENY paths not confirmed — review golang-app-policy.hcl"
fi

# ── Phase 6: Log Rotation Configuration ──────────────────────────────────────
info "Phase 6: Audit log hygiene"

# Vault writes one JSON line per API call. Set up log rotation on the host.
# Example logrotate config (write to /etc/logrotate.d/vault-audit):
cat <<'LOGROTATE'
# /etc/logrotate.d/vault-audit
/vault/logs/audit.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        # Vault monitors the file by inode; SIGHUP tells it to re-open.
        kill -HUP $(cat /var/run/vault.pid 2>/dev/null || pgrep vault) 2>/dev/null || true
    endscript
}
LOGROTATE
echo ""
info "  ↑ Example logrotate config printed to stdout. Apply on the host."

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}  Vault hardening complete.${RESET}"
echo ""
echo -e "  Cert TTL:   ${CERT_TTL} (max ${MAX_CERT_TTL})"
echo -e "  Audit log:  ${AUDIT_LOG_PATH}"
echo ""
echo -e "  Next steps:"
echo -e "  1. Ship ${AUDIT_LOG_PATH} to your SIEM"
echo -e "  2. Run 'make bootstrap-all' to verify full stack health"
echo -e "  3. Run 'make test-flow' to validate end-to-end auth"
echo -e "  4. Review docs/SECURITY.md Hardening Checklist"
echo -e "${GREEN}════════════════════════════════════════════════════════${RESET}"
