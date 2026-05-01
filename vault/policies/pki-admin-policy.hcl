# =============================================================================
# vault/policies/pki-admin-policy.hcl
#
# Granted to: human operators and the cert-rotate Makefile target
# NOT granted to any service (no AppRole for this policy)
#
# SINGLE-COMPROMISE GUARANTEE
# ────────────────────────────
# This policy is for break-glass operations: certificate rotation, CRL
# management, PKI tidy, and role tuning. It is intentionally NOT assigned
# to any long-running service. Tokens with this policy should be:
#   - Created via `vault token create -policy=pki-admin-policy -ttl=1h`
#   - Used once for the administrative task
#   - Revoked immediately after: `vault token revoke <token>`
#
# Even this policy CANNOT:
#   - Access the root CA private key (type=internal, never exported)
#   - Unseal/seal Vault (sys/seal requires root or operator policy)
#   - Modify auth methods (intentional separation of duties)
#   - Create tokens with arbitrary policies
# =============================================================================

# ── Intermediate PKI: full lifecycle management ───────────────────────────────

# Issue new certs (for admin-initiated cert generation, e.g., test users)
path "pki_int/issue/user-cert" {
  capabilities = ["create", "update"]
}

# Sign CSRs
path "pki_int/sign/user-cert" {
  capabilities = ["create", "update"]
}

# Revoke individual certificates (serial number required)
path "pki_int/revoke" {
  capabilities = ["create", "update"]
}

# List all issued cert serials
path "pki_int/certs" {
  capabilities = ["list"]
}

# Read any cert by serial
path "pki_int/cert/*" {
  capabilities = ["read"]
}

# Manual CRL rotation
path "pki_int/crl/rotate" {
  capabilities = ["read"]
}

path "pki_int/crl" {
  capabilities = ["read"]
}

path "pki_int/crl/pem" {
  capabilities = ["read"]
}

# Tidy: remove expired/revoked cert records
path "pki_int/tidy" {
  capabilities = ["create", "update"]
}

path "pki_int/tidy-cancel" {
  capabilities = ["create", "update"]
}

path "pki_int/tidy-status" {
  capabilities = ["read"]
}

# Read/update role parameters (e.g., change TTL during an incident)
path "pki_int/roles/*" {
  capabilities = ["read", "create", "update"]
}

# Read/update CRL config
path "pki_int/config/crl" {
  capabilities = ["read", "create", "update"]
}

path "pki_int/config/urls" {
  capabilities = ["read", "create", "update"]
}

path "pki_int/config/auto-tidy" {
  capabilities = ["read", "create", "update"]
}

# ── Root PKI: read-only (rotation requires a separate ceremony) ───────────────
path "pki/cert/ca" {
  capabilities = ["read"]
}

path "pki_int/cert/ca_chain" {
  capabilities = ["read"]
}

path "pki/crl" {
  capabilities = ["read"]
}

path "pki/crl/rotate" {
  capabilities = ["read"]
}

# ── Intermediate CA rotation (rare, ceremonial) ───────────────────────────────
# Generates a new intermediate CSR; root sign is a separate step.
path "pki_int/intermediate/generate/*" {
  capabilities = ["create", "update"]
}

path "pki_int/intermediate/set-signed" {
  capabilities = ["create", "update"]
}

# ── Issuer management (Vault 1.11+ multi-issuer) ─────────────────────────────
path "pki_int/issuers" {
  capabilities = ["list"]
}

path "pki_int/issuer/*" {
  capabilities = ["read", "create", "update"]
}

# ── Token: self-management only ───────────────────────────────────────────────
path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/revoke-self" {
  capabilities = ["update"]
}

# ── Sys: read Vault status ────────────────────────────────────────────────────
path "sys/health" {
  capabilities = ["read"]
}

path "sys/mounts" {
  capabilities = ["read"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}

# ── Audit log: read for forensics ─────────────────────────────────────────────
path "sys/audit" {
  capabilities = ["read", "list"]
}

# =============================================================================
# EXPLICIT DENIES — even the admin policy cannot do these
# =============================================================================

# Root CA private key is internal — no path to export it
path "pki/root/*"        { capabilities = ["deny"] }

# Cannot touch auth configuration (separation of duties)
path "sys/auth/*"        { capabilities = ["deny"] }

# Cannot modify policies (self-escalation prevention)
path "sys/policy/*"      { capabilities = ["deny"] }
path "sys/policies/*"    { capabilities = ["deny"] }

# Cannot seal/unseal (requires separate operator policy)
path "sys/seal"          { capabilities = ["deny"] }
path "sys/unseal"        { capabilities = ["deny"] }
path "sys/step-down"     { capabilities = ["deny"] }

# Cannot read raw storage
path "sys/raw/*"         { capabilities = ["deny"] }

# Cannot generate tokens with arbitrary policies
path "auth/token/create" { capabilities = ["deny"] }
