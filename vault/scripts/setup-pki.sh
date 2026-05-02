#!/bin/sh
# vault/scripts/setup-pki.sh
# Enables and configures the Vault PKI secrets engine.
# Run once after `make vault-init`. Idempotent.
set -eu

export VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
export VAULT_TOKEN="${VAULT_DEV_ROOT_TOKEN_ID:-devroot}"

ROOT_MOUNT="pki"
INT_MOUNT="pki_int"
DOMAIN="${DOMAIN:-sso.local}"
MAX_TTL="${VAULT_MAX_CERT_TTL:-24h}"
CERT_TTL="${VAULT_CERT_TTL:-4h}"

echo "[setup-pki] Enabling root PKI mount..."
vault secrets enable -path="${ROOT_MOUNT}" pki 2>/dev/null || true
vault secrets tune -max-lease-ttl=87600h "${ROOT_MOUNT}"

echo "[setup-pki] Generating root CA..."
vault write -field=certificate "${ROOT_MOUNT}/root/generate/internal" \
    common_name="${DOMAIN} Root CA" \
    issuer_name="root-ca" \
    ttl=87600h \
    key_type=ec \
    key_bits=384 \
    > /vault/pki-root/ca.pem 2>/dev/null || true

vault write "${ROOT_MOUNT}/config/urls" \
    issuing_certificates="http://vault:8200/v1/${ROOT_MOUNT}/ca" \
    crl_distribution_points="http://vault:8200/v1/${ROOT_MOUNT}/crl"

echo "[setup-pki] Enabling intermediate PKI mount..."
vault secrets enable -path="${INT_MOUNT}" pki 2>/dev/null || true
vault secrets tune -max-lease-ttl="${MAX_TTL}" "${INT_MOUNT}"

echo "[setup-pki] Generating intermediate CA CSR..."
INT_CSR=$(vault write -format=json "${INT_MOUNT}/intermediate/generate/internal" \
    common_name="${DOMAIN} Intermediate CA" \
    issuer_name="int-ca" \
    key_type=ec \
    key_bits=384 \
    | jq -r '.data.csr')

echo "[setup-pki] Signing intermediate CA with root..."
SIGNED=$(vault write -format=json "${ROOT_MOUNT}/root/sign-intermediate" \
    issuer_ref="root-ca" \
    csr="${INT_CSR}" \
    common_name="${DOMAIN} Intermediate CA" \
    ttl=43800h \
    | jq -r '.data.certificate')

vault write "${INT_MOUNT}/intermediate/set-signed" certificate="${SIGNED}"

# Name the imported issuer "int-ca" so the role's issuer_ref can resolve it.
# set-signed imports the cert as the default issuer but drops the name.
INT_ISSUER_ID=$(vault list -format=json "${INT_MOUNT}/issuers" | jq -r '.[0]')
vault write "${INT_MOUNT}/issuer/${INT_ISSUER_ID}" issuer_name=int-ca

# Import the root CA into pki_int and set the manual chain so that
# pki_int/cert/ca_chain returns the full chain (intermediate + root).
# This allows the Go app to verify the PG server cert against the full chain.
ROOT_CA=$(vault read -field=certificate "${ROOT_MOUNT}/cert/ca")
ROOT_IN_INT=$(vault write -format=json "${INT_MOUNT}/issuers/import/cert" \
    pem_bundle="${ROOT_CA}" | jq -r '.data.imported_issuers[0]')
vault write "${INT_MOUNT}/issuer/${INT_ISSUER_ID}" \
    issuer_name=int-ca \
    manual_chain="${INT_ISSUER_ID},${ROOT_IN_INT}"

vault write "${INT_MOUNT}/config/urls" \
    issuing_certificates="http://vault:8200/v1/${INT_MOUNT}/ca" \
    crl_distribution_points="http://vault:8200/v1/${INT_MOUNT}/crl"

echo "[setup-pki] Creating user-cert issuance role..."
vault write "${INT_MOUNT}/roles/user-cert" \
    issuer_ref="int-ca" \
    allowed_domains="${DOMAIN}" \
    allow_subdomains=false \
    allow_bare_domains=false \
    allow_any_name=true \
    enforce_hostnames=false \
    client_flag=true \
    server_flag=false \
    key_type=ec \
    key_bits=256 \
    ttl="${CERT_TTL}" \
    max_ttl="${MAX_TTL}" \
    no_store=false

echo "[setup-pki] Applying policies..."
vault policy write pki-issue  /vault/policies/pki-issue.hcl
vault policy write ldap-push  /vault/policies/ldap-push.hcl
vault policy write app-read   /vault/policies/app-read.hcl

echo "[setup-pki] PKI setup complete."
