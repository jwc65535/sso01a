#!/bin/sh
# postgres/init/00-hba.sh
# Runs inside the postgres container during initdb, before the server starts.
# Installs custom pg_hba.conf, pg_ident.conf ssl map, and SSL settings.
# Executed as the postgres user (uid 70 on alpine).
set -eu

SSL_DIR="/var/lib/postgresql/ssl"

# ── 1. Install custom pg_hba.conf ─────────────────────────────────────────────
cp /etc/postgresql/pg_hba.conf.template "${PGDATA}/pg_hba.conf"
echo "[00-hba] Custom pg_hba.conf installed."

# ── 2. Install pg_ident.conf ssl map ──────────────────────────────────────────
# Map format: MAPNAME  SYSTEM-USERNAME  PG-USERNAME
# "ssl" map: the certificate CN is used verbatim as the PostgreSQL role name.
# PostgreSQL POSIX regex with backreference: /^(.*)$/ captures the full CN.
# This means cert CN "alice" → role "alice" (role must exist; created at enrolment).
#
# SECURITY NOTE: CN validation happens at two layers:
#   1. Vault PKI role restricts which CNs can be issued (allowed_domains).
#   2. provision_user_role() validates the username regex before creating a role.
# pg_ident.conf is a pass-through; the protection is upstream.
cat >> "${PGDATA}/pg_ident.conf" << 'EOF'

# MAPNAME   SYSTEM-USERNAME   PG-USERNAME
# ssl map: cert CN must exactly match the PostgreSQL role name
ssl         /^(.*)$/          \1
EOF
echo "[00-hba] pg_ident.conf ssl map appended."

# ── 3. Apply SSL settings ─────────────────────────────────────────────────────
# Check for server certificate and key.  These are pre-populated by
# `make pki-bootstrap` (which exports them from Vault to postgres/ssl/).
# If absent (first `docker compose up` before bootstrap), TLS is disabled
# and a clear warning is emitted.  In that state:
#   • sso_admin can still connect (scram-sha-256, localhost)
#   • sso_app can still connect (scram-sha-256, any internal IP)
#   • User cert-auth connections will be rejected (no TLS = hostssl unreachable)
if [ -f "${SSL_DIR}/server.crt" ] && [ -f "${SSL_DIR}/server.key" ] \
        && [ -f "${SSL_DIR}/ca-chain.pem" ]; then

    # Enforce 0600 on the key — PostgreSQL refuses to start if the key is
    # world-readable, even in a container.
    chmod 600 "${SSL_DIR}/server.key"

    # Append to postgresql.conf; last occurrence of a setting wins.
    # Using include file avoids conflicts with the auto-generated settings.
    CONF_APPEND="${PGDATA}/postgresql.conf"
    cat >> "${CONF_APPEND}" << EOF

# ── SSL/TLS (added by 00-hba.sh) ──────────────────────────────────────────────
ssl                       = on
ssl_cert_file             = '${SSL_DIR}/server.crt'
ssl_key_file              = '${SSL_DIR}/server.key'
ssl_ca_file               = '${SSL_DIR}/ca-chain.pem'
ssl_min_protocol_version  = 'TLSv1.2'
ssl_prefer_server_ciphers = on
EOF

    # Enable CRL if one has been rendered already (vault-agent may not have run yet).
    if [ -f "${SSL_DIR}/crl.pem" ]; then
        echo "ssl_crl_file = '${SSL_DIR}/crl.pem'" >> "${CONF_APPEND}"
        echo "[00-hba] CRL configured: ${SSL_DIR}/crl.pem"
    else
        echo "[00-hba] Note: ${SSL_DIR}/crl.pem not found — ssl_crl_file not set."
        echo "[00-hba] Run 'make cert-push-now' after vault-agent has started."
    fi

    echo "[00-hba] PostgreSQL TLS configured (server cert + Vault CA chain)."

else
    echo "[00-hba] WARNING: SSL certs missing from ${SSL_DIR}."
    echo "[00-hba] Run 'make pki-bootstrap' to generate and install certs."
    echo "[00-hba] TLS is DISABLED — only sso_admin/sso_app can connect in this state."
    echo "ssl = off" >> "${PGDATA}/postgresql.conf"
fi

# ── 4. Apply remaining custom settings ───────────────────────────────────────
cat >> "${PGDATA}/postgresql.conf" << 'EOF'

# ── Custom settings (added by 00-hba.sh) ──────────────────────────────────────
password_encryption  = scram-sha-256
log_connections      = on
log_disconnections   = on
log_hostname         = off
log_timezone         = 'UTC'
log_line_prefix      = '%t [%p]: user=%u,db=%d,client=%h '
log_statement        = 'ddl'
EOF

echo "[00-hba] Custom postgresql.conf settings applied."
