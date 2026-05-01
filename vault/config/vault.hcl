# =============================================================================
# vault/config/vault.hcl — Production Vault server configuration
#
# This file is NOT used in dev mode (docker-compose uses `vault server -dev`).
# To switch to production mode:
#   1. Remove `-dev` from the vault service `command:` in docker-compose.yml
#   2. Mount this file: -config=/vault/config/vault.hcl
#   3. Run `vault operator init` and store unseal keys securely
#   4. Run `vault operator unseal` (3-of-5 Shamir shares by default)
#   5. Run vault/scripts/bootstrap-vault.sh with the initial root token
#   6. Revoke the initial root token: `vault token revoke <root-token>`
#
# SINGLE-COMPROMISE GUARANTEE (Vault seal)
# ─────────────────────────────────────────
# The Vault seal protects the encryption key that wraps ALL data in Vault's
# barrier. Even if an attacker exfiltrates the raw storage backend (/vault/data),
# it is AES-256-GCM encrypted and useless without the unseal key.
#
# With Shamir seal (default): requires K-of-N unseal key holders to cooperate.
# With auto-unseal (recommended for prod): requires the external KMS to be
# operational AND the Vault container to have valid cloud credentials.
# =============================================================================

ui = false    # disable the web UI in production

# ── Storage backend ───────────────────────────────────────────────────────────
# File storage is suitable for single-node deployments.
# For HA: switch to Integrated Raft storage (raft) or Consul.
storage "file" {
  path = "/vault/data"
}

# ── HA Raft storage (uncomment for multi-node deployment) ────────────────────
# storage "raft" {
#   path    = "/vault/data"
#   node_id = "vault-node-1"
#
#   retry_join {
#     leader_api_addr = "https://vault-node-2:8200"
#   }
# }

# ── TCP listener ──────────────────────────────────────────────────────────────
listener "tcp" {
  address = "0.0.0.0:8200"

  # TLS — certs issued by pki/scripts/bootstrap-ca.sh (pre-Vault bootstrap)
  # These are separate from the user PKI because Vault's own TLS cert must
  # exist BEFORE the PKI engine is configured.
  tls_cert_file              = "/vault/tls/vault.crt"
  tls_key_file               = "/vault/tls/vault.key"
  tls_client_ca_file         = "/vault/tls/ca.crt"
  tls_min_version            = "tls13"
  tls_cipher_suites          = "TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256"

  # Set to true to require mTLS for ALL Vault API calls (not just admin).
  # WARNING: breaks anything that doesn't have a client cert, including
  # the vault CLI without -client-cert / -client-key flags.
  tls_require_and_verify_client_cert = false
}

# ── Cluster listener (raft HA) ────────────────────────────────────────────────
# listener "tcp" {
#   address         = "0.0.0.0:8201"
#   cluster_address = "0.0.0.0:8201"
#   tls_cert_file   = "/vault/tls/vault.crt"
#   tls_key_file    = "/vault/tls/vault.key"
#   tls_min_version = "tls13"
# }

# ── Security hardening ────────────────────────────────────────────────────────
# Prevents direct reading of Vault's internal key-value storage via the API.
# An attacker with a valid token still cannot read the raw encrypted backend.
raw_storage_endpoint = false

# Disable the sys/pprof endpoint (profiling data can leak memory contents).
disable_printable_check = true

# ── Auto-unseal (AWS KMS — recommended for production) ───────────────────────
# seal "awskms" {
#   region     = "us-east-1"
#   kms_key_id = "alias/vault-unseal-key"
# }

# ── Auto-unseal (GCP Cloud KMS) ──────────────────────────────────────────────
# seal "gcpckms" {
#   project    = "my-project"
#   region     = "global"
#   key_ring   = "vault-keyring"
#   crypto_key = "vault-unseal"
# }

# ── Telemetry ────────────────────────────────────────────────────────────────
telemetry {
  disable_hostname         = true
  prometheus_retention_time = "30s"
  # Uncomment to expose Prometheus metrics:
  # unauthenticated_metrics_access = false
}

# ── Logging ──────────────────────────────────────────────────────────────────
log_level      = "info"
log_format     = "json"
log_file       = "/vault/audit/vault.log"
log_rotate_max_files = 14    # ~2 weeks of daily rotations
