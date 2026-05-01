# =============================================================================
# vault/agent/agent.hcl
#
# RESPONSIBILITIES
# ────────────────
# 1. Authenticate to Vault (dev: token_file; prod: AppRole).
# 2. Write a renewable Vault token to the shared vault-agent-token volume so
#    consul-template can query Vault without its own auth credentials.
# 3. Render the PKI CA chain and CRL for consumption by postgres, the Golang
#    app, and the Shibboleth SP.
#
# WHAT THIS AGENT DOES NOT DO
# ────────────────────────────
# • It does NOT issue or sign certificates (no pki_int/issue/* calls).
# • It does NOT push anything to LDAP — that is consul-template's job.
# • It does NOT hold or render private keys.
#
# SECURITY INVARIANT
# ──────────────────
# A fully-compromised vault-agent container yields only:
#   • A token scoped to vault-agent-policy (read-only PKI public data + CRL)
#   • The CA chain and CRL already public to all containers on vault-net
# It cannot sign user certificates, read kv secrets, or modify Vault state.
# =============================================================================

# ── Vault server connection ───────────────────────────────────────────────────
vault {
  address = "http://vault:8200"   # PROD: switch to https:// once TLS is up

  retry {
    num_retries = 10
  }
}

# ── Authentication ─────────────────────────────────────────────────────────────
# DEV: token_file reads the root token written by the container entrypoint
#      (entrypoint.sh writes $VAULT_TOKEN → /vault/agent-token/token).
# PROD: switch to the AppRole block; disable token_file.
auto_auth {
  # ── Dev mode ────────────────────────────────────────────────────────────────
  method "token_file" {
    config = {
      token_file_path = "/vault/agent-token/token"
    }
  }

  # ── Prod: AppRole (uncomment to enable) ─────────────────────────────────────
  # method "approle" {
  #   mount_path = "auth/approle"
  #   config = {
  #     role_id_file_path                   = "/vault/agent/role-id"
  #     secret_id_file_path                 = "/vault/agent/secret-id"
  #     remove_secret_id_file_after_reading = true
  #   }
  # }

  # Sink: write the renewable token to disk so consul-template can read it.
  # Mode 0600 ensures only the vault-agent process (uid=100) can read the file.
  sink "file" {
    config = {
      path = "/vault/agent-token/agent.token"
      mode = 0600
    }
  }
}

# ── Template: CA trust chain ──────────────────────────────────────────────────
# Renders root + intermediate CA cert chain from Vault's PKI engine.
# Consumed by: postgres (ssl_ca_file), Golang app (x509.CertPool), Shib SP.
template {
  source               = "/vault/agent/templates/ca-chain.tmpl"
  destination          = "/vault/rendered/ca-chain.pem"
  perms                = 0644
  error_on_missing_key = true

  wait {
    min = "5s"
    max = "30s"
  }
}

# ── Template: Active cert manifest ───────────────────────────────────────────
# JSON index of all non-revoked user certs in pki_int.
# Consumed by: Golang app (cert validation without live Vault lookup).
# consul-template queries pki_int/certs/ directly for the LDAP push.
template {
  source               = "/vault/agent/templates/cert-manifest.tmpl"
  destination          = "/vault/rendered/cert-manifest.json"
  perms                = 0644
  error_on_missing_key = true

  wait {
    min = "15s"
    max = "90s"
  }
}

# ── Template: CRL ────────────────────────────────────────────────────────────
# Offline certificate revocation list in PEM format.
# Consumed by: Golang app (CRL-based revocation without live Vault OCSP).
# pki_int/cert/crl returns the CRL as .Data.certificate in PEM format.
template {
  contents    = <<-EOT
    {{- with secret "pki_int/cert/crl" -}}
    {{ .Data.certificate }}
    {{- end -}}
  EOT
  destination = "/vault/rendered/crl.pem"
  perms       = 0644

  # CRL rarely changes; check every 5–15 minutes.
  wait {
    min = "5m"
    max = "15m"
  }
}

# ── Template config ───────────────────────────────────────────────────────────
template_config {
  # Re-render the CA chain every 6 h even without a lease event (belt-and-suspenders
  # for the rare intermediate CA rotation).
  static_secret_render_interval = "6h"

  # Never kill the agent on a render failure — log and retry on the next event.
  exit_on_retry_failure = false
}

# ── Logging ───────────────────────────────────────────────────────────────────
log_level = "info"
