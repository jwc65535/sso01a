#!/usr/bin/env bash
# bootstrap-all.sh — ordered first-run initialisation for sso01a
#
# Usage:
#   ./scripts/bootstrap-all.sh            # full bootstrap
#   ./scripts/bootstrap-all.sh --resume   # skip already-healthy services
#
# Run this ONCE after cloning.  Subsequent starts just need `make up`.
# The script is idempotent: services already running or secrets already
# generated are skipped safely.
#
# Prerequisites: docker, docker compose v2, openssl, jq, curl, envsubst

set -euo pipefail
cd "$(dirname "$0")/.."

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
fatal() { echo -e "${RED}[FATAL]${RESET} $*" >&2; exit 1; }

COMPOSE="docker compose"
PROJECT="sso01a"
DC="$COMPOSE -p $PROJECT"
RESUME="${1:-}"

# ── Prerequisite check ────────────────────────────────────────────────────────
check_deps() {
    local missing=0
    for cmd in docker openssl jq curl envsubst; do
        command -v "$cmd" &>/dev/null || { warn "Missing: $cmd"; missing=1; }
    done
    docker compose version &>/dev/null || { warn "docker compose v2 not found"; missing=1; }
    [ $missing -eq 0 ] || fatal "Install missing prerequisites and retry."
    ok "Prerequisites satisfied"
}

# ── Wait for a service to pass its healthcheck ────────────────────────────────
wait_healthy() {
    local svc="$1" timeout="${2:-120}" interval=5 elapsed=0
    info "Waiting for $svc to be healthy (timeout ${timeout}s)…"
    while true; do
        local status
        status=$($DC ps --format json "$svc" 2>/dev/null \
            | jq -r 'if type=="array" then .[0].Health else .Health end' 2>/dev/null \
            || echo "unknown")
        if [ "$status" = "healthy" ]; then
            ok "$svc is healthy"
            return 0
        fi
        if [ "$elapsed" -ge "$timeout" ]; then
            fatal "$svc did not become healthy within ${timeout}s (last status: $status)"
        fi
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done
}

# ── Ensure .env exists ────────────────────────────────────────────────────────
setup_env() {
    if [ ! -f .env ]; then
        info "Creating .env from .env.example"
        cp .env.example .env
        warn ".env created — review and set real values before production use."
        warn "At minimum, change: SSP_SECRET_SALT, VAULT_DEV_ROOT_TOKEN_ID, DEV_USER_PASSWORD"
    else
        ok ".env already exists"
    fi
}

# ── Generate Docker secret files ──────────────────────────────────────────────
gen_secrets() {
    info "Generating secret files (skipping any that already exist)…"
    mkdir -p secrets
    local secrets=(
        ldap_admin_password
        ldap_cert_writer_password
        postgres_admin_password
        postgres_app_password
        ssp_admin_password
    )
    for s in "${secrets[@]}"; do
        [ -f "secrets/${s}.txt" ] || openssl rand -base64 32 > "secrets/${s}.txt"
    done

    # TOTP master secret — longer (48 bytes → 64 base64 chars) for Argon2id input
    [ -f secrets/totp_master_secret.txt ] || openssl rand -base64 48 > secrets/totp_master_secret.txt

    # Vault dev root token — sync into .env
    if [ ! -f secrets/vault-root-token.txt ]; then
        openssl rand -hex 16 > secrets/vault-root-token.txt
    fi
    local tok
    tok=$(cat secrets/vault-root-token.txt)
    if grep -q '^VAULT_DEV_ROOT_TOKEN_ID=' .env 2>/dev/null; then
        sed -i "s|^VAULT_DEV_ROOT_TOKEN_ID=.*|VAULT_DEV_ROOT_TOKEN_ID=${tok}|" .env
    fi

    chmod 600 secrets/*.txt
    ok "Secret files ready ($(ls secrets/*.txt | wc -l | tr -d ' ') files)"
}

# ── Start a service (with its compose-defined dependencies) ───────────────────
start_svc() {
    local svc="$1"
    info "Starting $svc…"
    $DC up -d "$svc"
}

# ── Vault PKI bootstrap ───────────────────────────────────────────────────────
vault_bootstrap() {
    info "Running Vault PKI bootstrap (bootstrap-vault.sh)…"
    local token
    token=$(cat secrets/vault-root-token.txt 2>/dev/null || echo "devroot")
    $DC exec -T \
        -e VAULT_ADDR=http://vault:8200 \
        -e VAULT_TOKEN="$token" \
        vault sh /vault/scripts/bootstrap-vault.sh \
    && ok "Vault PKI bootstrap complete" \
    || { warn "Vault bootstrap returned non-zero; may already be initialised."; }
}

# ── LDAP bootstrap gate ───────────────────────────────────────────────────────
ldap_bootstrap() {
    info "Verifying LDAP first-run init…"
    local base_dn
    base_dn=$(grep '^LDAP_BASE_DN=' .env 2>/dev/null | cut -d= -f2 || echo "dc=sso,dc=local")
    local pw
    pw=$(cat secrets/ldap_admin_password.txt 2>/dev/null)
    local tries=0
    until $DC exec -T ldap \
            ldapsearch -x -H ldap://localhost:1389 \
            -b "$base_dn" \
            -D "cn=admin,${base_dn}" \
            -w "$pw" \
            '(objectClass=organizationalUnit)' dn 2>/dev/null | grep -q '^dn:'; do
        tries=$((tries + 1))
        [ $tries -ge 24 ] && fatal "LDAP init did not complete within 120s"
        sleep 5
    done
    ok "LDAP first-run init complete"
}

# ── PostgreSQL bootstrap ──────────────────────────────────────────────────────
postgres_bootstrap() {
    info "Setting sso_app password in PostgreSQL…"
    local app_pw db admin
    app_pw=$(cat secrets/postgres_app_password.txt)
    db=$(grep '^POSTGRES_DB=' .env 2>/dev/null | cut -d= -f2 || echo "sso")
    admin=$(grep '^POSTGRES_ADMIN_USER=' .env 2>/dev/null | cut -d= -f2 || echo "sso_admin")

    $DC exec -T postgres \
        psql -U "$admin" -d "$db" \
        -c "ALTER ROLE sso_app PASSWORD '${app_pw}';" \
    && ok "sso_app password set" \
    || warn "Could not set sso_app password (may already be set)"

    info "Copying Vault CA chain to postgres/ssl/…"
    mkdir -p postgres/ssl
    if $DC exec -T vault-agent test -f /vault/rendered/ca-chain.pem 2>/dev/null; then
        $DC exec -T vault-agent cat /vault/rendered/ca-chain.pem > postgres/ssl/ca-chain.pem
        ok "CA chain written to postgres/ssl/ca-chain.pem"
    else
        warn "vault-agent has not yet rendered ca-chain.pem — skipping."
        warn "Run 'make postgres-bootstrap' again after consul-template is healthy."
    fi
}

# ── Health summary ────────────────────────────────────────────────────────────
health_summary() {
    info "Service health summary:"
    local svcs=(vault vault-agent consul-template ldap postgres idp app sp client)
    local all_ok=0
    for svc in "${svcs[@]}"; do
        local status
        status=$($DC ps --format json "$svc" 2>/dev/null \
            | jq -r 'if type=="array" then .[0].Health else .Health end' 2>/dev/null \
            || echo "not running")
        if [ "$status" = "healthy" ] || [ "$status" = "running" ]; then
            echo -e "  ${GREEN}✓${RESET} $svc ($status)"
        else
            echo -e "  ${RED}✗${RESET} $svc ($status)"
            all_ok=1
        fi
    done
    return $all_ok
}

# ── Next-steps hint ───────────────────────────────────────────────────────────
print_next_steps() {
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
    echo -e "${GREEN}${BOLD}  Bootstrap complete!${RESET}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e "  ${CYAN}Next steps:${RESET}"
    echo ""
    echo -e "  1. Add to /etc/hosts (browser access):"
    echo -e "     ${YELLOW}127.0.0.1  sp.sso.local  idp.sso.local${RESET}"
    echo ""
    echo -e "  2. Extract the SP signing cert and register it with the IdP:"
    echo -e "     ${YELLOW}make sp-cert-extract${RESET}"
    echo -e "     Paste the output as 'certData' in idp/metadata/saml20-sp-remote.php"
    echo -e "     then: ${YELLOW}docker compose -p sso01a restart idp${RESET}"
    echo ""
    echo -e "  3. Open the SPA:"
    echo -e "     ${YELLOW}https://sp.sso.local/${RESET}  (accept the self-signed cert in dev)"
    echo ""
    echo -e "  4. Run the integration test suite:"
    echo -e "     ${YELLOW}make test-flow${RESET}"
    echo ""
    echo -e "  5. Tail all logs:"
    echo -e "     ${YELLOW}make logs${RESET}"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    echo -e "${BOLD}sso01a — Bootstrap All${RESET}"
    echo "────────────────────────────────────────────────────────"

    check_deps
    setup_env
    gen_secrets

    # ── Phase 1: Infrastructure ───────────────────────────────────────────────
    echo ""
    info "Phase 1: Starting infrastructure services…"

    start_svc vault
    wait_healthy vault 90

    start_svc ldap
    wait_healthy ldap 120

    start_svc postgres
    wait_healthy postgres 90

    # ── Phase 2: Vault PKI initialisation ─────────────────────────────────────
    echo ""
    info "Phase 2: Vault PKI bootstrap…"
    vault_bootstrap

    # ── Phase 3: Vault Agent + certificate rendering ──────────────────────────
    echo ""
    info "Phase 3: Starting Vault Agent…"
    start_svc vault-agent
    wait_healthy vault-agent 60

    # ── Phase 4: PostgreSQL initialisation ────────────────────────────────────
    echo ""
    info "Phase 4: PostgreSQL bootstrap (passwords + CA chain)…"
    postgres_bootstrap

    # ── Phase 5: Application services ────────────────────────────────────────
    echo ""
    info "Phase 5: Starting application services…"

    start_svc consul-template
    wait_healthy consul-template 90

    ldap_bootstrap

    start_svc idp
    wait_healthy idp 90

    start_svc app
    wait_healthy app 60

    # ── Phase 6: Front door ───────────────────────────────────────────────────
    echo ""
    info "Phase 6: Starting Shibboleth SP + client…"
    start_svc sp
    wait_healthy sp 120

    start_svc client

    # ── Final checks ──────────────────────────────────────────────────────────
    echo ""
    info "Phase 7: Health check all services…"
    health_summary && ok "All services healthy" || warn "Some services not healthy — check 'make logs'"

    print_next_steps
}

main "$@"
