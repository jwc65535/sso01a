# =============================================================================
# consul-template/config/consul-template.hcl
#
# IMPORTANT: this file is parsed as plain HCL — NOT as a consul-template
# template.  {{ }} syntax does NOT work here.  Use literal values or rely on
# environment variables that consul-template reads automatically:
#   VAULT_ADDR, VAULT_TOKEN, VAULT_SKIP_VERIFY, etc.
#
# RESPONSIBILITIES
# ─────────────────
# Watch pki_int/certs/ in Vault; whenever a cert is added, rotated, or
# revoked, render ldap-cert-push.sh and execute it to update LDAP.
#
# SECURITY DESIGN
# ────────────────
# • consul-template reads a Vault token from the file written by vault-agent's
#   sink — it never holds the root token directly.
# • The push script authenticates to LDAP as cert-writer (not admin).
# • cert-writer can only replace cert attributes; it cannot add/delete entries.
# =============================================================================

# ── Vault connection ──────────────────────────────────────────────────────────
vault {
  # Vault address is set via VAULT_ADDR environment variable (docker-compose).
  # Hardcoding here as a fallback; VAULT_ADDR env var takes precedence.
  address = "http://vault:8200"

  # Read the renewable token written by vault-agent's auto_auth sink.
  # Avoids passing the root dev token to this container's environment.
  vault_agent_token_file = "/vault/agent-token/agent.token"

  renew_token = true

  retry {
    enabled     = true
    attempts    = 15
    backoff     = "500ms"
    max_backoff = "2m"
  }

  ssl {
    enabled = false   # PROD: set true, configure ca_cert, cert, key
  }
}

log_level = "info"

# ── PKI cert-push template ────────────────────────────────────────────────────
# Triggered when the pki_int/certs/ list changes (new cert issued or revoked).
# The 30-minute periodic re-render is handled by entrypoint.sh (SIGHUP loop).
#
# Wait stanza debounces rapid-fire cert issuances (e.g., bulk enrolment):
# consul-template waits at least 10 s after the last change before rendering.
template {
  source          = "/etc/consul-template/templates/ldap-cert-push.sh.tmpl"
  destination     = "/vault/rendered/ldap-cert-push.sh"
  perms           = 0700
  command         = "bash /vault/rendered/ldap-cert-push.sh"
  command_timeout = "120s"

  wait {
    min = "10s"
    max = "60s"
  }

  # A failed push (LDAP down, network error) logs the error and retries on
  # the next Vault event or the next scheduled SIGHUP — never crashes the daemon.
  error_on_missing_key = false
}
