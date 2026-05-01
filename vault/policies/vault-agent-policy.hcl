# =============================================================================
# vault/policies/vault-agent-policy.hcl
#
# Granted to: vault-agent sidecar process (AppRole: vault-agent)
#
# SINGLE-COMPROMISE GUARANTEE
# ────────────────────────────
# The vault-agent's sole job is token lifecycle management and template
# rendering. Its policy is deliberately narrow:
#
#   CAN DO                        CANNOT DO
#   ───────────────────────────   ────────────────────────────────────────────
#   Renew its own token           Sign or issue any certificate
#   Look up its own token         Revoke any certificate
#   Create consul-template tokens List or enumerate user identities
#   Read PKI public cert data     Modify any Vault configuration
#   Read CA chain / CRL           Access root PKI or other secret engines
#
# WHY can it create consul-template tokens?
#   consul-template needs a Vault token to read PKI data. The vault-agent
#   creates these tokens using the named 'consul-template' token role, which
#   hard-caps the policy to 'consul-template-policy'. Even if the agent is
#   compromised, the child tokens it creates cannot exceed their role ceiling.
#
# WHY read PKI data?
#   The vault-agent renders templates (e.g., the CA chain, active cert list)
#   to disk. These are PUBLIC data — no private keys involved.
# =============================================================================

# ── Token: self-renewal ───────────────────────────────────────────────────────
path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# ── Token: create scoped consul-template tokens ───────────────────────────────
# Only the named role is allowed; child tokens are capped at consul-template-policy.
path "auth/token/create/consul-template" {
  capabilities = ["create", "update"]
}

# ── PKI: read public cert data for template rendering ─────────────────────────
# These paths contain only PUBLIC information (certificates, CA chain, CRL).
# Private keys are never stored here.
path "pki_int/cert/*" {
  capabilities = ["read"]
}

path "pki_int/cert/ca_chain" {
  capabilities = ["read"]
}

path "pki/cert/ca" {
  capabilities = ["read"]
}

path "pki_int/crl" {
  capabilities = ["read"]
}

path "pki_int/crl/pem" {
  capabilities = ["read"]
}

# List of cert serials — needed for consul-template to enumerate active certs.
# The agent can see serial numbers (public metadata) but not the private keys.
path "pki_int/certs" {
  capabilities = ["list"]
}

# ── Sys: lease renewal ────────────────────────────────────────────────────────
path "sys/leases/renew" {
  capabilities = ["update"]
}

# ── AppRole: obtain the consul-template secret-id at startup ──────────────────
# The agent pulls a fresh secret-id on each start so consul-template can
# authenticate independently. secret_id_num_uses=1 means each ID is one-shot.
path "auth/approle/role/consul-template/secret-id" {
  capabilities = ["create", "update"]
}

# =============================================================================
# EXPLICIT DENIES
# =============================================================================

path "pki_int/issue/*"   { capabilities = ["deny"] }
path "pki_int/sign/*"    { capabilities = ["deny"] }
path "pki_int/revoke"    { capabilities = ["deny"] }
path "pki_int/config/*"  { capabilities = ["deny"] }
path "pki_int/root/*"    { capabilities = ["deny"] }
path "pki_int/roles/*"   { capabilities = ["deny"] }
path "pki/root/*"        { capabilities = ["deny"] }

# NEVER create tokens outside the named role
path "auth/token/create" {
  capabilities = ["deny"]
}

path "sys/auth/*"     { capabilities = ["deny"] }
path "sys/policy/*"   { capabilities = ["deny"] }
path "sys/mounts/*"   { capabilities = ["deny"] }
path "sys/raw/*"      { capabilities = ["deny"] }
path "sys/seal"       { capabilities = ["deny"] }
path "sys/unseal"     { capabilities = ["deny"] }
path "secret/*"       { capabilities = ["deny"] }
