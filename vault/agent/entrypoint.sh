#!/bin/sh
# vault/agent/entrypoint.sh
#
# DEV-MODE BOOTSTRAP: writes the Vault root token (from $VAULT_TOKEN env var)
# to the token_file path that agent.hcl expects, then execs vault agent.
#
# In production, replace this entrypoint with one that delivers the AppRole
# secret-id via a secrets manager injection (e.g., AWS SSM, Kubernetes Secret)
# and remove the token_file auth method from agent.hcl entirely.
set -e

TOKEN_FILE="/vault/agent-token/token"

if [ -z "${VAULT_TOKEN:-}" ]; then
    echo "[vault-agent] FATAL: VAULT_TOKEN env var is not set." >&2
    exit 1
fi

# Write once; skip if already written (idempotent on restart).
if [ ! -f "${TOKEN_FILE}" ]; then
    printf '%s' "${VAULT_TOKEN}" > "${TOKEN_FILE}"
    chmod 600 "${TOKEN_FILE}"
    echo "[vault-agent] Wrote bootstrap token to ${TOKEN_FILE}."
fi

exec vault agent -config=/vault/agent/agent.hcl "$@"
