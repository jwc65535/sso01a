#!/bin/sh
# =============================================================================
# idp/scripts/init.sh — SimpleSAMLphp IdP container entrypoint
#
# RESPONSIBILITIES
# ─────────────────
# 1. Generate the IdP SAML signing/encryption key pair if not already present.
#    The cert is stored in the idp-cert Docker volume (/var/simplesamlphp/cert/)
#    so it persists across container restarts.  Regenerating it would break all
#    SPs that have cached the old cert in their metadata.
#
# 2. Read the SSP admin password from the Docker secret file and export it as
#    SSP_ADMIN_PASSWORD so that config.php can pick it up via getenv().
#    Apache inherits the environment when exec'd at the end of this script.
#
# 3. Pre-create runtime directories that SSP needs write access to.
#
# NOTE ON envsubst
# ─────────────────
# Previous versions of this script used envsubst to process *.php.tmpl files.
# That approach is REMOVED: envsubst mangles PHP variables like $attributes
# and $config.  Config files now use getenv() directly in PHP and are
# bind-mounted read-only at runtime.
#
# PRODUCTION NOTES
# ─────────────────
# • Replace the self-signed cert with one from a trusted CA (external to Vault)
#   after validating the SP trusts it; do not change the cert without updating
#   the SP's metadata simultaneously.
# • Set session.cookie.secure=true in config.php (requires HTTPS).
# =============================================================================
set -eu

SSP_DIR="/var/simplesamlphp"
CERT_DIR="${SSP_DIR}/cert"

# ── 1. Generate IdP signing certificate if not already present ────────────────
# The cert is used to sign SAML assertions and metadata.
# This cert is intentionally self-signed and SEPARATE from Vault PKI:
#   • Vault PKI governs x509 client certificates (mTLS / device identity)
#   • This cert governs SAML assertion integrity (IdP/federation identity)
# Compromise of one does not compromise the other.
mkdir -p "${CERT_DIR}"
chmod 750 "${CERT_DIR}"

if [ ! -f "${CERT_DIR}/idp.crt" ] || [ ! -f "${CERT_DIR}/idp.pem" ]; then
    echo "[idp/init] Generating IdP SAML signing certificate (RSA-3072, 10 years)..."

    # EntityID without the scheme is used as the CN.
    ENTITY_ID="${IDP_ENTITY_ID:-https://idp.sso.local/simplesaml/saml2/idp/metadata.php}"
    CN=$(echo "${ENTITY_ID}" | sed 's|https\?://||' | cut -d'/' -f1)

    openssl req \
        -newkey rsa:3072 \
        -new \
        -x509 \
        -days 3650 \
        -nodes \
        -out  "${CERT_DIR}/idp.crt" \
        -keyout "${CERT_DIR}/idp.pem" \
        -subj "/O=sso01a IdP/CN=${CN}"

    chmod 600 "${CERT_DIR}/idp.pem"
    chmod 644 "${CERT_DIR}/idp.crt"
    chown -R www-data:www-data "${CERT_DIR}"
    echo "[idp/init] IdP certificate generated: CN=${CN}"
else
    echo "[idp/init] IdP certificate already exists — skipping generation."
    # Ensure ownership is correct after a volume mount.
    chown -R www-data:www-data "${CERT_DIR}"
fi

# ── 2. Export SSP admin password from Docker secret ───────────────────────────
# config.php reads SSP_ADMIN_PASSWORD via getenv(), which works because
# Apache is exec'd below and inherits this process's environment.
SECRET_FILE="${SSP_ADMIN_PASSWORD_FILE:-/run/secrets/ssp_admin_password}"
if [ -f "${SECRET_FILE}" ]; then
    SSP_ADMIN_PASSWORD=$(cat "${SECRET_FILE}")
    export SSP_ADMIN_PASSWORD
    echo "[idp/init] SSP admin password loaded from ${SECRET_FILE}."
elif [ -n "${SSP_ADMIN_PASSWORD:-}" ]; then
    echo "[idp/init] SSP admin password from environment variable (dev fallback)."
else
    echo "[idp/init] WARNING: no admin password found — using placeholder." >&2
    SSP_ADMIN_PASSWORD="CHANGE_ME_PLACEHOLDER_$(openssl rand -hex 8)"
    export SSP_ADMIN_PASSWORD
fi

# ── 3. Create runtime directories ────────────────────────────────────────────
# SSP writes session and temporary data here.  These are not persisted (tmpfs
# in prod is fine).
mkdir -p /tmp/simplesamlphp
chmod 770 /tmp/simplesamlphp
chown www-data:www-data /tmp/simplesamlphp

mkdir -p "${SSP_DIR}/data"
chown -R www-data:www-data "${SSP_DIR}/data"

# ── 4. Validate that required config files are mounted ────────────────────────
for required in \
    "${SSP_DIR}/config/config.php" \
    "${SSP_DIR}/config/authsources.php" \
    "${SSP_DIR}/metadata/saml20-idp-hosted.php" \
    "${SSP_DIR}/metadata/saml20-sp-remote.php"; do
    if [ ! -f "${required}" ]; then
        echo "[idp/init] ERROR: required config file missing: ${required}" >&2
        echo "[idp/init] Check that idp/config/ and idp/metadata/ are bind-mounted." >&2
        exit 1
    fi
done
echo "[idp/init] All required config files present."

# ── 5. Start Apache / SimpleSAMLphp ──────────────────────────────────────────
echo "[idp/init] Starting Apache (SimpleSAMLphp IdP)..."
exec apache2-foreground
