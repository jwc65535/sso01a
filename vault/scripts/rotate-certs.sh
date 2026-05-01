#!/bin/sh
# vault/scripts/rotate-certs.sh
# Revokes the current certificate for a user (or all users) and issues a
# replacement. Consul Template detects the new cert and pushes it to LDAP.
set -eu

export VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
export VAULT_TOKEN="${VAULT_DEV_ROOT_TOKEN_ID:-devroot}"

INT_MOUNT="${VAULT_PKI_INT_MOUNT:-pki_int}"
ROLE="user-cert"
USER="${USER:-}"    # set via make cert-rotate-user USER=alice

rotate_user() {
    local cn="$1"
    echo "[rotate-certs] Rotating certificate for ${cn}..."

    # Revoke existing certs for this CN
    vault list "${INT_MOUNT}/certs" 2>/dev/null | tail -n +3 | while read -r serial; do
        info=$(vault read -format=json "${INT_MOUNT}/cert/${serial}" 2>/dev/null) || continue
        cert_cn=$(echo "${info}" | jq -r '.data.certificate' \
            | openssl x509 -noout -subject 2>/dev/null \
            | sed 's/.*CN = //')
        if [ "${cert_cn}" = "${cn}" ]; then
            echo "  Revoking serial ${serial}"
            vault write "${INT_MOUNT}/revoke" serial_number="${serial}" || true
        fi
    done

    # Issue new certificate (CSR generated client-side in prod; here we
    # generate internally to exercise the Vault role)
    vault write -format=json "${INT_MOUNT}/issue/${ROLE}" \
        common_name="${cn}" \
        ttl="${VAULT_CERT_TTL:-4h}" \
        | jq -r '.data.certificate' \
        > "/tmp/${cn}-new.crt"

    echo "[rotate-certs] New certificate for ${cn} written to /tmp/${cn}-new.crt"
}

if [ -n "${USER}" ]; then
    rotate_user "${USER}"
else
    echo "[rotate-certs] No USER specified; rotating all known users..."
    # Enumerate users from LDAP or a local list (placeholder)
    for cn in $(cat /vault/scripts/known-users.txt 2>/dev/null); do
        rotate_user "${cn}"
    done
fi

echo "[rotate-certs] Done. Consul Template will push updated certs to LDAP."
