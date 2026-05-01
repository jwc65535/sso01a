#!/bin/sh
# vault/scripts/init.sh
# Entry point called by `make vault-init`.
# Writes the dev root token to the shared volume then runs bootstrap-vault.sh.
set -eu

TOKEN_FILE="/vault/agent-token/token"
VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
TOKEN="${VAULT_DEV_ROOT_TOKEN_ID:-devroot}"

echo "[vault/init] Waiting for Vault to be ready..."
for i in $(seq 1 30); do
    if VAULT_ADDR="${VAULT_ADDR}" vault status 2>/dev/null \
            | grep -q "Initialized.*true"; then
        echo "[vault/init] Vault is ready."
        break
    fi
    echo "[vault/init] ... retry ${i}/30"
    sleep 2
    [ "${i}" -lt 30 ] || { echo "[vault/init] ERROR: Vault did not become ready."; exit 1; }
done

# Write the root token so vault-agent can use token_file auth in dev mode.
mkdir -p "$(dirname "${TOKEN_FILE}")"
printf '%s' "${TOKEN}" > "${TOKEN_FILE}"
chmod 600 "${TOKEN_FILE}"
echo "[vault/init] Dev root token written to ${TOKEN_FILE}"

# Run the full PKI bootstrap.
export VAULT_ADDR VAULT_TOKEN="${TOKEN}"
echo "[vault/init] Running bootstrap-vault.sh..."
bash /vault/scripts/bootstrap-vault.sh
echo "[vault/init] Bootstrap complete."
