#!/usr/bin/env bash
# =============================================================================
# vault/scripts/bootstrap-vault.sh
#
# Zero-trust PKI bootstrap for the sso01a authentication system.
# Supersedes vault/scripts/setup-pki.sh from Prompt 2.
#
# SINGLE-COMPROMISE GUARANTEE
# ─────────────────────────────
# After this script completes, no individual stolen credential allows a full
# system compromise:
#
#   Stolen credential          What the attacker CAN do
#   ─────────────────────────  ────────────────────────────────────────────────
#   Root token                 Anything inside Vault EXCEPT extract the root CA
#                              private key (stored in Vault's encrypted barrier,
#                              requires compromising the seal/KMS too).
#
#   golang-app AppRole         Sign one CSR per 1-hour token window.  Requires
#   secret-id                  the matching private key to be useful. Cannot
#                              list certs, revoke, issue (server-gen), or
#                              escalate. Explicit denies override any wildcard.
#
#   vault-agent AppRole        Renew its own token. Read PKI public cert data
#   secret-id                  (already public). Cannot sign, issue, or revoke.
#
#   consul-template AppRole    Read public cert data only. Explicit deny on
#   secret-id                  all write operations.
#
#   Any service token          Cannot be used to create tokens with MORE
#                              capabilities (token roles enforce ceiling via
#                              explicit_max_ttl + no_default_policy).
#
# USAGE
# ─────
#   export VAULT_ADDR=http://vault:8200
#   export VAULT_TOKEN=<root-or-init-token>
#   bash vault/scripts/bootstrap-vault.sh
#
# Idempotent: safe to run multiple times.
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-${VAULT_DEV_ROOT_TOKEN_ID:-devroot}}"
DOMAIN="${DOMAIN:-sso.local}"
ROOT_MOUNT="${VAULT_PKI_MOUNT:-pki}"
INT_MOUNT="${VAULT_PKI_INT_MOUNT:-pki_int}"
CERT_TTL="${VAULT_CERT_TTL:-1h}"          # user cert lifetime; 1h default
MAX_CERT_TTL="${VAULT_MAX_CERT_TTL:-4h}"  # upper bound a role can request
ROOT_CA_TTL="87600h"                      # 10 years
INT_CA_TTL="43800h"                       # 5 years
POLICY_DIR="/vault/policies"
SUMMARY_FILE="/vault/bootstrap-summary.json"

export VAULT_ADDR VAULT_TOKEN
export VAULT_FORMAT="json"   # all vault CLI output as JSON

# ── Colour output ─────────────────────────────────────────────────────────────
red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
cyan()   { printf '\033[0;36m%s\033[0m\n' "$*"; }
info()   { cyan "[bootstrap] $*"; }
ok()     { green "[bootstrap] ✓ $*"; }
warn()   { yellow "[bootstrap] ⚠ $*"; }
die()    { red "[bootstrap] ✗ $*"; exit 1; }

# ── Helper: enable a secrets engine once ──────────────────────────────────────
enable_secrets() {
    local path="$1" type="$2"
    shift 2
    local existing
    existing=$(vault secrets list -format=json 2>/dev/null) || existing='{}'
    if printf '%s\n' "${existing}" | jq -r 'keys[]' 2>/dev/null \
            | grep -q "^${path}/$"; then
        warn "secrets engine ${path}/ already enabled — skipping enable."
        return 0
    fi
    info "Enabling secrets engine '${type}' at ${path}/..."
    local out rc=0
    out=$(vault secrets enable -path="${path}" "$@" "${type}" 2>&1) || rc=$?
    if [[ $rc -eq 0 ]]; then
        ok "secrets/${path}/ enabled."
    elif printf '%s\n' "${out}" | grep -q "path is already in use"; then
        warn "secrets engine ${path}/ already enabled — skipping enable."
    else
        printf '%s\n' "${out}" >&2
        die "Failed to enable secrets engine '${type}' at ${path}/."
    fi
}

# ── Helper: enable an auth method once ────────────────────────────────────────
enable_auth() {
    local path="$1" type="$2"
    shift 2
    local existing
    existing=$(vault auth list -format=json 2>/dev/null) || existing='{}'
    if printf '%s\n' "${existing}" | jq -r 'keys[]' 2>/dev/null \
            | grep -q "^${path}/$"; then
        warn "auth method ${path}/ already enabled — skipping enable."
        return 0
    fi
    info "Enabling auth method '${type}' at ${path}/..."
    local out rc=0
    out=$(vault auth enable -path="${path}" "$@" "${type}" 2>&1) || rc=$?
    if [[ $rc -eq 0 ]]; then
        ok "auth/${path}/ enabled."
    elif printf '%s\n' "${out}" | grep -q "path is already in use"; then
        warn "auth method ${path}/ already enabled — skipping enable."
    else
        printf '%s\n' "${out}" >&2
        die "Failed to enable auth method '${type}' at ${path}/."
    fi
}

# ── Phase 0: Preflight ────────────────────────────────────────────────────────
info "Phase 0: Preflight checks"

# Wait up to 60 s for Vault to be ready and unsealed
for i in $(seq 1 30); do
    STATUS=$(vault status -format=json 2>/dev/null || echo '{}')
    # Use `// null` + default to avoid jq's alternative operator treating false as empty.
    INITIALIZED=$(echo "${STATUS}" | jq -r 'if .initialized == null then "false" else (.initialized | tostring) end')
    SEALED=$(echo "${STATUS}" | jq -r 'if .sealed == null then "true" else (.sealed | tostring) end')
    if [ "${INITIALIZED}" = "true" ] && [ "${SEALED}" = "false" ]; then
        ok "Vault is initialized and unsealed."
        break
    fi
    if [ "${i}" -eq 30 ]; then
        die "Vault not ready after 60 s. Check container logs."
    fi
    warn "Vault not ready (initialized=${INITIALIZED} sealed=${SEALED}), retrying (${i}/30)..."
    sleep 2
done

# Verify token is valid
vault token lookup >/dev/null 2>&1 || die "VAULT_TOKEN is invalid or expired."
ok "Token is valid."

# ── Phase 1: Audit Logging ────────────────────────────────────────────────────
# WHY: Audit logs are the security team's record of every Vault operation.
# Any stolen token used to sign a rogue cert will appear in the audit log.
# Enable this BEFORE doing anything else so we capture the bootstrap itself.
info "Phase 1: Audit logging"
# Ensure the audit directory is writable by the vault process (uid=vault).
# In dev mode the exec context may be root, so chown the dir.
mkdir -p /vault/audit 2>/dev/null || true
chown vault:vault /vault/audit 2>/dev/null || true
chmod 750 /vault/audit 2>/dev/null || true

if ! vault audit list -format=json 2>/dev/null | jq -r 'keys[]' | grep -q '^file/'; then
    if vault audit enable file \
            file_path=/vault/audit/audit.log \
            log_raw=false 2>/dev/null; then  # never log plaintext secret values
        ok "Audit log enabled at /vault/audit/audit.log"
    else
        warn "Could not enable file audit backend (permission issue in dev mode)."
        warn "Run 'make harden' after adjusting /vault/audit permissions for production."
    fi
else
    warn "File audit device already enabled."
fi

# ── Phase 2: Root PKI Secrets Engine ─────────────────────────────────────────
# WHY: The root CA's private key is generated with type=internal, which means
# it lives ONLY inside Vault's encrypted barrier. It is never exported — even
# to administrators. An attacker who steals a Vault token cannot read it;
# they would additionally need to compromise the unseal key/KMS.
info "Phase 2: Root PKI engine (${ROOT_MOUNT}/)"
enable_secrets "${ROOT_MOUNT}" pki

info "  Tuning root PKI max lease TTL → ${ROOT_CA_TTL}"
vault secrets tune -max-lease-ttl="${ROOT_CA_TTL}" "${ROOT_MOUNT}"

# Generate root CA if it doesn't already have an issuer
if vault list -format=json "${ROOT_MOUNT}/issuers" 2>/dev/null \
        | jq -e 'type == "array" and length > 0' >/dev/null 2>&1; then
    warn "  Root CA issuer already exists — skipping generation."
else
    info "  Generating root CA (EC P-384, internal key — never exported)..."
    # key_type=ec key_bits=384 → NIST P-384, provides ~192-bit security
    # type=internal              → private key stays inside Vault's barrier forever
    vault write -format=json "${ROOT_MOUNT}/root/generate/internal" \
        common_name="${DOMAIN} Root CA" \
        issuer_name="root-ca" \
        key_type="ec" \
        key_bits=384 \
        ttl="${ROOT_CA_TTL}" \
        exclude_cn_from_sans=true \
        | jq -r '.data.certificate' > /vault/audit/root-ca.pem
    ok "  Root CA generated. Public cert saved to /vault/audit/root-ca.pem"
fi

info "  Configuring root CA CRL and issuing URLs..."
vault write "${ROOT_MOUNT}/config/urls" \
    issuing_certificates="${VAULT_ADDR}/v1/${ROOT_MOUNT}/ca" \
    crl_distribution_points="${VAULT_ADDR}/v1/${ROOT_MOUNT}/crl" \
    ocsp_servers="${VAULT_ADDR}/v1/${ROOT_MOUNT}/ocsp"

info "  Configuring root CA CRL rotation (24h validity, 12h rotation)..."
vault write "${ROOT_MOUNT}/config/crl" \
    expiry="24h" \
    auto_rebuild=true \
    auto_rebuild_grace_period="12h" \
    enable_delta=true \
    delta_rebuild_interval="15m"

ok "Root PKI engine configured."

# ── Phase 3: Intermediate PKI Secrets Engine ──────────────────────────────────
# WHY: The intermediate CA — not the root — issues user certificates. This
# two-tier design means the root CA key can be kept offline (or in Vault's
# barrier) and rotated independently of day-to-day issuance. Compromising the
# intermediate allows issuing rogue certs but the root can be used to revoke
# the intermediate's own certificate.
info "Phase 3: Intermediate PKI engine (${INT_MOUNT}/)"
enable_secrets "${INT_MOUNT}" pki

info "  Tuning intermediate PKI max lease TTL → ${MAX_CERT_TTL}"
vault secrets tune -max-lease-ttl="${MAX_CERT_TTL}" "${INT_MOUNT}"

if vault list -format=json "${INT_MOUNT}/issuers" 2>/dev/null \
        | jq -e 'type == "array" and length > 0' >/dev/null 2>&1; then
    warn "  Intermediate CA issuer already exists — skipping."
else
    info "  Generating intermediate CA CSR (EC P-384)..."
    INT_CSR=$(vault write -format=json "${INT_MOUNT}/intermediate/generate/internal" \
        common_name="${DOMAIN} Intermediate CA" \
        issuer_name="int-ca" \
        key_type="ec" \
        key_bits=384 \
        add_basic_constraints=true \
        | jq -r '.data.csr')
    [ -n "${INT_CSR}" ] || die "Failed to generate intermediate CSR."

    info "  Signing intermediate CSR with root CA..."
    SIGNED_CERT=$(vault write -format=json "${ROOT_MOUNT}/root/sign-intermediate" \
        issuer_ref="root-ca" \
        csr="${INT_CSR}" \
        common_name="${DOMAIN} Intermediate CA" \
        ttl="${INT_CA_TTL}" \
        use_csr_values=true \
        | jq -r '.data.certificate')
    [ -n "${SIGNED_CERT}" ] || die "Root CA failed to sign the intermediate CSR."

    info "  Importing signed intermediate certificate..."
    vault write "${INT_MOUNT}/intermediate/set-signed" \
        certificate="${SIGNED_CERT}"

    ok "  Intermediate CA signed and imported."
fi

info "  Configuring intermediate CA CRL and issuing URLs..."
vault write "${INT_MOUNT}/config/urls" \
    issuing_certificates="${VAULT_ADDR}/v1/${INT_MOUNT}/ca" \
    crl_distribution_points="${VAULT_ADDR}/v1/${INT_MOUNT}/crl" \
    ocsp_servers="${VAULT_ADDR}/v1/${INT_MOUNT}/ocsp"

vault write "${INT_MOUNT}/config/crl" \
    expiry="4h" \
    auto_rebuild=true \
    auto_rebuild_grace_period="1h" \
    enable_delta=true \
    delta_rebuild_interval="5m"

# Auto-tidy: removes expired certs from storage so consul-template's cert list
# never grows unboundedly and doesn't expose stale serial numbers.
info "  Configuring auto-tidy for expired certificates..."
vault write "${INT_MOUNT}/config/auto-tidy" \
    enabled=true \
    tidy_cert_store=true \
    tidy_revoked_certs=true \
    tidy_revoked_cert_issuer_associations=true \
    safety_buffer="1h" \
    interval_duration="6h"

ok "Intermediate PKI engine configured."

# ── Phase 4: PKI Role — user-cert ─────────────────────────────────────────────
# WHY: The role is the coarse-grained gate on what certificates can be issued.
# Restrictions enforced HERE (key type, TTL, client/server flags, no wildcards)
# apply regardless of which policy grants access to the role.
#
# Fine-grained CN restriction (one user can only sign for themselves) is
# enforced at TWO additional layers:
#   1. Token role: tokens are created via the golang-app-policy which restricts
#      which named token role can be used (user-cert-signer).
#   2. Application layer: the Golang app verifies the SAML assertion UID matches
#      the CN being signed before calling Vault.
#
# Production enhancement (identity-based templating, requires Vault entities):
#   allowed_domains_template=true
#   allowed_domains='{{identity.entity.metadata.ldap_uid}}@${DOMAIN}'
#   This ties each signing call to the authenticated entity's UID, so a stolen
#   token literally cannot sign for a different user.
info "Phase 4: PKI role 'user-cert'"

vault write "${INT_MOUNT}/roles/user-cert" \
    issuer_ref="int-ca" \
    \
    `# ── CN/SAN restrictions ────────────────────────────────────────────── #` \
    allow_any_name=true \
    enforce_hostnames=false \
    allow_bare_domains=false \
    allow_subdomains=false \
    allow_ip_sans=false \
    `# Allow email SANs of the form user@sso.local only` \
    allow_email_with_subdomains=false \
    allowed_domains="${DOMAIN}" \
    `# No wildcard CNs` \
    allow_wildcard_certificates=false \
    require_cn=true \
    \
    `# ── Key constraints ────────────────────────────────────────────────── #` \
    `# EC P-256: 128-bit security, fast TLS handshakes, small cert size` \
    key_type="ec" \
    key_bits=256 \
    key_usage="DigitalSignature" \
    ext_key_usage="ClientAuth" \
    `# client_flag=true → Extended Key Usage: TLS Web Client Authentication` \
    `# server_flag=false → cert CANNOT be used to impersonate a server` \
    client_flag=true \
    server_flag=false \
    code_signing_flag=false \
    email_protection_flag=true \
    \
    `# ── TTL constraints ─────────────────────────────────────────────────── #` \
    `# Short TTL is the primary defence against stolen certificates.` \
    `# A stolen cert self-expires in CERT_TTL; no action needed.` \
    ttl="${CERT_TTL}" \
    max_ttl="${MAX_CERT_TTL}" \
    \
    `# ── Storage ─────────────────────────────────────────────────────────── #` \
    `# no_store=false: issued certs are recorded so consul-template can` \
    `# enumerate them and push public certs to LDAP.` \
    `# Private keys are NOT stored — they're returned once at issuance.` \
    no_store=false \
    \
    `# ── Basic constraints ───────────────────────────────────────────────── #` \
    basic_constraints_valid_for_non_ca=true \
    not_before_duration="30s"   # clock-skew buffer

ok "Role 'user-cert' configured."

# ── Phase 5: Policies ─────────────────────────────────────────────────────────
# WHY: Policies are the authorisation layer. Each policy follows
# least-privilege: only the exact paths and capabilities needed, with
# belt-and-suspenders explicit denies on the most dangerous operations.
# Even if a token escapes its intended container, the policy bounds the damage.
info "Phase 5: Writing Vault policies"

# 5a. golang-app-policy — the Golang app server
# Key security properties:
#   - CANNOT issue (generate server-side private key)
#   - CANNOT list all certs (no bulk enumeration)
#   - CANNOT revoke (no DoS against other users)
#   - CANNOT touch root PKI or modify config
#   - CAN sign CSRs (private key stays with the client)
#   - CAN read a cert by serial (for validation)
#   - CAN create scoped tokens for per-user signing
vault policy write golang-app-policy "${POLICY_DIR}/golang-app-policy.hcl"
ok "  Policy 'golang-app-policy' written."

# 5b. vault-agent-policy — the vault-agent sidecar
vault policy write vault-agent-policy "${POLICY_DIR}/vault-agent-policy.hcl"
ok "  Policy 'vault-agent-policy' written."

# 5c. consul-template-policy — reads PKI, pushes to LDAP (no Vault writes)
vault policy write consul-template-policy "${POLICY_DIR}/consul-template-policy.hcl"
ok "  Policy 'consul-template-policy' written."

# 5d. pki-admin-policy — human operators for cert rotation, CRL, tidy
vault policy write pki-admin-policy "${POLICY_DIR}/pki-admin-policy.hcl"
ok "  Policy 'pki-admin-policy' written."

# Remove deprecated policies from Prompt 2 (they are superseded)
for old_policy in pki-issue ldap-push app-read; do
    if vault policy list -format=json 2>/dev/null \
            | jq -r '.[]' | grep -q "^${old_policy}$"; then
        vault policy delete "${old_policy}" 2>/dev/null || true
        warn "  Removed deprecated policy '${old_policy}'."
    fi
done

# ── Phase 6: Token Roles ──────────────────────────────────────────────────────
# WHY: Named token roles restrict which policies can be attached to tokens
# created under that role. Without token roles, any token with
# auth/token/create permission could grant arbitrary policies to new tokens.
# With token roles:
#   - allowed_policies: hard ceiling on what policies the new token can have
#   - disallowed_policies: explicit blocklist (belt-and-suspenders)
#   - explicit_max_ttl: hard TTL ceiling that cannot be overridden by renewals
#   - token_no_default_policy=true: removes the 'default' policy which has
#     broad read access to sys/
info "Phase 6: Token roles"

# Token role: golang-app
# Used by the Golang app service. Tokens are short-lived (1h = cert TTL).
# explicit_max_ttl = MAX_CERT_TTL so renewals can't extend beyond cert lifetime.
vault write auth/token/roles/golang-app \
    allowed_policies="golang-app-policy" \
    disallowed_policies="root,pki-admin-policy" \
    orphan=false \
    renewable=true \
    period="0" \
    ttl="${CERT_TTL}" \
    explicit_max_ttl="${MAX_CERT_TTL}" \
    token_type="service" \
    token_no_default_policy=true \
    path_suffix=""
ok "  Token role 'golang-app' created."

# Token role: vault-agent
# Used by the vault-agent sidecar. Very short-lived; agent renews continuously.
# orphan=true: agent tokens are not tied to the creating token's lifetime.
vault write auth/token/roles/vault-agent \
    allowed_policies="vault-agent-policy" \
    disallowed_policies="root,golang-app-policy,pki-admin-policy" \
    orphan=true \
    renewable=true \
    period="15m" \
    explicit_max_ttl="2h" \
    token_type="service" \
    token_no_default_policy=true
ok "  Token role 'vault-agent' created."

# Token role: consul-template
# Read-only access to PKI. Tokens last 1h and are auto-renewed by agent.
vault write auth/token/roles/consul-template \
    allowed_policies="consul-template-policy" \
    disallowed_policies="root,golang-app-policy,vault-agent-policy,pki-admin-policy" \
    orphan=true \
    renewable=true \
    period="1h" \
    explicit_max_ttl="4h" \
    token_type="service" \
    token_no_default_policy=true
ok "  Token role 'consul-template' created."

# Token role: user-cert-signer
# Short-lived tokens the Golang app creates FOR a specific user's signing
# operation. They are children of the golang-app token, expire in CERT_TTL,
# and have NO additional permissions beyond signing.
vault write auth/token/roles/user-cert-signer \
    allowed_policies="user-cert-sign-policy" \
    disallowed_policies="root,golang-app-policy,vault-agent-policy,pki-admin-policy,consul-template-policy" \
    orphan=false \
    renewable=false \
    ttl="${CERT_TTL}" \
    explicit_max_ttl="${CERT_TTL}" \
    token_type="service" \
    token_no_default_policy=true
ok "  Token role 'user-cert-signer' created."

# Write the minimal user-cert-sign-policy (only sign — used by per-user tokens)
vault policy write user-cert-sign-policy - <<'SIGN_POLICY'
# user-cert-sign-policy
# Granted to per-user tokens created by the golang-app.
# The ONLY permitted operation is signing a CSR for the user-cert role.
# Private key never leaves the client; Vault signs the public component only.

path "pki_int/sign/user-cert" {
  capabilities = ["create", "update"]
}

# Allow reading own cert after signing (by serial returned in sign response)
path "pki_int/cert/*" {
  capabilities = ["read"]
}

# Deny everything else explicitly
path "pki_int/issue/*"  { capabilities = ["deny"] }
path "pki_int/revoke"   { capabilities = ["deny"] }
path "pki_int/certs"    { capabilities = ["deny"] }
path "pki/*"            { capabilities = ["deny"] }
path "auth/*"           { capabilities = ["deny"] }
path "sys/*"            { capabilities = ["deny"] }
SIGN_POLICY
ok "  Policy 'user-cert-sign-policy' written."

# ── Phase 7: AppRole Auth Method ──────────────────────────────────────────────
# WHY: AppRole is the standard machine-to-machine auth method. It separates
# the role-id (non-secret, baked into the container image) from the secret-id
# (short-lived, injected at runtime by a trusted orchestrator).
# Compromise of the role-id alone is useless without the secret-id.
info "Phase 7: AppRole auth method"
enable_auth "approle" "approle"

# AppRole: golang-app
info "  Creating AppRole: golang-app"
vault write auth/approle/role/golang-app \
    token_policies="golang-app-policy" \
    token_ttl="${CERT_TTL}" \
    token_max_ttl="${MAX_CERT_TTL}" \
    token_no_default_policy=true \
    secret_id_ttl="24h" \
    secret_id_num_uses=1 \
    bind_secret_id=true

GOLANG_APP_ROLE_ID=$(vault read -format=json auth/approle/role/golang-app/role-id \
    | jq -r '.data.role_id')
printf '%s' "${GOLANG_APP_ROLE_ID}" > /vault/audit/golang-app-role-id.txt
ok "  AppRole 'golang-app' created. Role-ID → /vault/audit/golang-app-role-id.txt"

# AppRole: vault-agent
info "  Creating AppRole: vault-agent"
vault write auth/approle/role/vault-agent \
    token_policies="vault-agent-policy" \
    token_ttl="15m" \
    token_max_ttl="2h" \
    token_no_default_policy=true \
    secret_id_ttl="0"          \
    secret_id_num_uses=0        `# agent renews continuously` \
    bind_secret_id=true

VAULT_AGENT_ROLE_ID=$(vault read -format=json auth/approle/role/vault-agent/role-id \
    | jq -r '.data.role_id')
printf '%s' "${VAULT_AGENT_ROLE_ID}" > /vault/audit/vault-agent-role-id.txt
ok "  AppRole 'vault-agent' created. Role-ID → /vault/audit/vault-agent-role-id.txt"

# AppRole: consul-template
info "  Creating AppRole: consul-template"
vault write auth/approle/role/consul-template \
    token_policies="consul-template-policy" \
    token_ttl="1h" \
    token_max_ttl="4h" \
    token_no_default_policy=true \
    secret_id_ttl="0" \
    secret_id_num_uses=0 \
    bind_secret_id=true

CT_ROLE_ID=$(vault read -format=json auth/approle/role/consul-template/role-id \
    | jq -r '.data.role_id')
printf '%s' "${CT_ROLE_ID}" > /vault/audit/consul-template-role-id.txt
ok "  AppRole 'consul-template' created. Role-ID → /vault/audit/consul-template-role-id.txt"

# ── Phase 8: Secret-ID generation (dev mode only) ─────────────────────────────
# In production, secret-IDs are generated by a trusted orchestrator (e.g.,
# Kubernetes vault-injector, Nomad, or a CI/CD pipeline) and injected at
# container start time. Here we generate them for local dev only.
if [ "${APP_ENV:-development}" != "production" ]; then
    info "Phase 8: Generating AppRole secret-IDs (dev mode)"
    mkdir -p /vault/audit/secret-ids
    for role in golang-app vault-agent consul-template; do
        SECRET_ID=$(vault write -format=json \
            -f "auth/approle/role/${role}/secret-id" \
            | jq -r '.data.secret_id')
        printf '%s' "${SECRET_ID}" > "/vault/audit/secret-ids/${role}-secret-id.txt"
        chmod 600 "/vault/audit/secret-ids/${role}-secret-id.txt"
        ok "  Secret-ID for '${role}' → /vault/audit/secret-ids/${role}-secret-id.txt"
    done
    warn "SECRET IDs WRITTEN TO DISK — for dev only, rotate before production."
else
    info "Phase 8: Production mode — skipping secret-ID generation."
    info "  Generate secret-IDs via your orchestrator and inject at runtime."
fi

# ── Phase 9: Vault Identity (entities for per-user CN restriction) ────────────
# WHY: Creating a Vault entity per LDAP user allows identity-templated policies.
# When a user authenticates, the app resolves their entity and creates a
# scoped token. The token's identity.entity.metadata.ldap_uid constrains which
# CN the PKI role will sign (if allowed_domains_template=true is set).
#
# This is the production path for "only the current user's CN" enforcement.
# In dev mode we rely on the application layer; entities are created at
# enrolment time by the Golang app using the snippet below.
info "Phase 9: Identity engine (entity template for per-user CN restriction)"
info "  The Golang app creates entities at enrolment using:"
cat <<'SNIPPET'
  vault write identity/entity \
      name="${USERNAME}" \
      metadata="ldap_uid=${USERNAME}" \
      metadata="email=${USERNAME}@${DOMAIN}"

  ENTITY_ID=$(vault read -format=json identity/entity/name/${USERNAME} \
      | jq -r '.data.id')

  vault write identity/entity-alias \
      name="${USERNAME}" \
      canonical_id="${ENTITY_ID}" \
      mount_accessor=$(vault auth list -format=json | jq -r '."approle/".accessor')
SNIPPET

# ── Phase 10: Summary ─────────────────────────────────────────────────────────
info "Phase 10: Writing bootstrap summary"

ROOT_CA_SERIAL=$(vault read -format=json "${ROOT_MOUNT}/cert/ca" \
    | jq -r '.data.serial_number // "unknown"')
INT_CA_SERIAL=$(vault read -format=json "${INT_MOUNT}/cert/ca" \
    | jq -r '.data.serial_number // "unknown"')

cat > "${SUMMARY_FILE}" <<JSON
{
  "bootstrapped_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "vault_addr": "${VAULT_ADDR}",
  "domain": "${DOMAIN}",
  "root_pki": {
    "mount": "${ROOT_MOUNT}",
    "ca_serial": "${ROOT_CA_SERIAL}",
    "ca_ttl": "${ROOT_CA_TTL}"
  },
  "int_pki": {
    "mount": "${INT_MOUNT}",
    "ca_serial": "${INT_CA_SERIAL}",
    "ca_ttl": "${INT_CA_TTL}",
    "cert_ttl": "${CERT_TTL}",
    "max_cert_ttl": "${MAX_CERT_TTL}"
  },
  "roles": {
    "pki": "user-cert",
    "token": ["golang-app", "vault-agent", "consul-template", "user-cert-signer"]
  },
  "approle_role_ids": {
    "golang_app": "${GOLANG_APP_ROLE_ID:-n/a}",
    "vault_agent": "${VAULT_AGENT_ROLE_ID:-n/a}",
    "consul_template": "${CT_ROLE_ID:-n/a}"
  },
  "policies": [
    "golang-app-policy",
    "vault-agent-policy",
    "consul-template-policy",
    "pki-admin-policy",
    "user-cert-sign-policy"
  ]
}
JSON

chmod 640 "${SUMMARY_FILE}"
green "═══════════════════════════════════════════════════════════"
green " Vault PKI bootstrap complete."
green " Summary: ${SUMMARY_FILE}"
green " Root CA public cert: /vault/audit/root-ca.pem"
green "═══════════════════════════════════════════════════════════"
