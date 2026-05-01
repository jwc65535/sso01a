#!/bin/bash
# =============================================================================
# sp/scripts/init.sh — Shibboleth SP + Apache container entrypoint
#
# STARTUP FLOW
# ────────────
# 1. Generate SP signing and encryption key pairs (RSA-3072, 10 years) if
#    not already present in the shib-keys named volume.
# 2. Process shibboleth2.xml template via envsubst (substitutes SP_ENTITY_ID,
#    IDP_ENTITY_ID, IDP_METADATA_URL) and install to /etc/shibboleth/.
#    Copy attribute-map.xml and attribute-policy.xml from the source dir.
# 3. Start shibd and wait until its Unix socket is ready.
# 4. Start Apache in the foreground; forward SIGTERM/SIGINT to both daemons.
#
# VOLUME LAYOUT
# ─────────────
# /etc/shibboleth-src/   bind-mount (ro) of ./sp/shibboleth/ on the host;
#                        contains shibboleth2.xml template + attribute files
# /etc/shibboleth/       Shibboleth package defaults + files installed in step 2
# /etc/shibboleth/keys/  named volume (shib-keys); key pairs generated in step 1
#
# FIRST-RUN CERT EXTRACTION (populate IdP trust)
# ─────────────────────────────────────────────────
# After the first boot, extract the SP signing cert and paste it into
# idp/metadata/saml20-sp-remote.php 'certData':
#   make sp-cert-extract
# Then restart the IdP: docker compose restart idp
# =============================================================================
set -euo pipefail

KEY_DIR="/etc/shibboleth/keys"
SRC_DIR="/etc/shibboleth-src"
SHIB_DIR="/etc/shibboleth"
SP_HOSTNAME="${SP_HOSTNAME:-sp.sso.local}"

info() { printf '\033[0;36m[sp/init] %s\033[0m\n' "$*" >&2; }
ok()   { printf '\033[0;32m[sp/init] ✓ %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[0;31m[sp/init] ✗ %s\033[0m\n' "$*" >&2; exit 1; }

# ── Step 1: Generate SP key pairs ────────────────────────────────────────────
mkdir -p "${KEY_DIR}"
chmod 700 "${KEY_DIR}"

for purpose in sp-signing sp-encrypt; do
    if [ ! -f "${KEY_DIR}/${purpose}.key" ] || [ ! -f "${KEY_DIR}/${purpose}.crt" ]; then
        info "Generating Shibboleth SP key pair: ${purpose} (RSA-3072, 10 years)..."
        if command -v shib-keygen >/dev/null 2>&1; then
            shib-keygen \
                -n "${purpose}" \
                -o "${KEY_DIR}" \
                -h "${SP_HOSTNAME}" \
                -y 10 \
                -f 2>/dev/null
        else
            openssl req -newkey rsa:3072 -nodes -x509 -days 3650 \
                -subj "/CN=${SP_HOSTNAME}/O=sso01a SP" \
                -keyout "${KEY_DIR}/${purpose}.key" \
                -out    "${KEY_DIR}/${purpose}.crt"
        fi
        chmod 600 "${KEY_DIR}/${purpose}.key"
        chmod 644 "${KEY_DIR}/${purpose}.crt"
        ok "Generated ${purpose} key pair."
    else
        ok "${purpose} key pair already exists — skipping."
    fi
done

# ── Step 2: Install Shibboleth config files ───────────────────────────────────
# shibboleth2.xml contains ${VAR} placeholders; envsubst processes them.
# Only the exact listed variables are substituted — other ${...} patterns
# (none exist in this file) are left untouched.
info "Installing shibboleth2.xml (envsubst)..."
[ -f "${SRC_DIR}/shibboleth2.xml" ] || die "Missing ${SRC_DIR}/shibboleth2.xml"

envsubst '${SP_ENTITY_ID}${IDP_ENTITY_ID}${IDP_METADATA_URL}' \
    < "${SRC_DIR}/shibboleth2.xml" \
    > "${SHIB_DIR}/shibboleth2.xml"
ok "shibboleth2.xml installed."

for f in attribute-map.xml attribute-policy.xml; do
    if [ -f "${SRC_DIR}/${f}" ]; then
        cp "${SRC_DIR}/${f}" "${SHIB_DIR}/${f}"
        ok "${f} installed."
    else
        info "${f} not in ${SRC_DIR} — using package default."
    fi
done

# ── Step 3: Start shibd ───────────────────────────────────────────────────────
info "Starting shibd..."
mkdir -p /var/run/shibboleth /var/log/shibboleth /var/cache/shibboleth
# -f: foreground-compatible (writes PID file but does not daemonize when given -F)
shibd -f -p /var/run/shibboleth/shibd.pid &
SHIBD_PID=$!

# Wait up to 30 s for the shibd Unix socket
READY=0
for i in $(seq 1 30); do
    if [ -S /var/run/shibboleth/shibd.sock ]; then
        READY=1
        break
    fi
    sleep 1
done
[ "${READY}" -eq 1 ] || die "shibd did not start within 30 seconds."
ok "shibd ready (PID ${SHIBD_PID})."

# ── Step 4: Start Apache ──────────────────────────────────────────────────────
info "Starting Apache..."

# Forward SIGTERM/SIGINT to both daemons so the container stops cleanly.
cleanup() {
    info "Caught signal — stopping Apache and shibd..."
    kill "${APACHE_PID:-}" 2>/dev/null || true
    kill "${SHIBD_PID}"    2>/dev/null || true
    wait "${APACHE_PID:-}" 2>/dev/null || true
    wait "${SHIBD_PID}"    2>/dev/null || true
}
trap cleanup TERM INT

apache2ctl -D FOREGROUND &
APACHE_PID=$!

ok "Apache started (PID ${APACHE_PID}). SP is ready."
wait "${APACHE_PID}"
