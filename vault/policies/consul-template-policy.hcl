# =============================================================================
# vault/policies/consul-template-policy.hcl
#
# Granted to: consul-template process (AppRole: consul-template)
# Supersedes: vault/policies/ldap-push.hcl (Prompt 2)
#
# SINGLE-COMPROMISE GUARANTEE
# ────────────────────────────
# consul-template's ONLY job is to read public certificate data from Vault
# and push it to LDAP. It has NO write access to Vault whatsoever.
#
#   CAN DO                          CANNOT DO
#   ─────────────────────────────   ────────────────────────────────────────
#   List issued cert serials        Issue or sign any certificate
#   Read any cert by serial         Revoke any certificate
#   Read CA chain                   Modify PKI config or roles
#   Read CRL                        Access root CA paths
#   Renew its own token             Create other tokens
#
# WHY is this acceptable?
#   All data accessible via this policy is PUBLIC. The certificate (PEM bytes)
#   and serial number are designed to be shared — that is why we push them to
#   LDAP. The private key is generated client-side and never exists in Vault.
#   An attacker with this token learns: which users have certs, what their
#   certs look like, when they expire. No credential to steal.
# =============================================================================

# ── PKI: enumerate active cert serials ───────────────────────────────────────
path "pki_int/certs" {
  capabilities = ["list"]
}

# ── PKI: read individual cert by serial ──────────────────────────────────────
# Returns: certificate PEM, serial, expiry, revocation time (if revoked).
# Does NOT return the private key (never stored by Vault).
path "pki_int/cert/*" {
  capabilities = ["read"]
}

# ── PKI: CA chain for LDAP trust anchoring ────────────────────────────────────
path "pki_int/cert/ca_chain" {
  capabilities = ["read"]
}

path "pki/cert/ca" {
  capabilities = ["read"]
}

# ── PKI: CRL for revocation awareness ────────────────────────────────────────
path "pki_int/crl" {
  capabilities = ["read"]
}

path "pki_int/crl/pem" {
  capabilities = ["read"]
}

# ── Token: self-renewal only ──────────────────────────────────────────────────
path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# ── Sys: lease renewal ────────────────────────────────────────────────────────
path "sys/leases/renew" {
  capabilities = ["update"]
}

# =============================================================================
# EXPLICIT DENIES — belt-and-suspenders on every write operation
# =============================================================================

path "pki_int/issue/*"    { capabilities = ["deny"] }
path "pki_int/sign/*"     { capabilities = ["deny"] }
path "pki_int/revoke"     { capabilities = ["deny"] }
path "pki_int/tidy"       { capabilities = ["deny"] }
path "pki_int/config/*"   { capabilities = ["deny"] }
path "pki_int/root/*"     { capabilities = ["deny"] }
path "pki_int/roles/*"    { capabilities = ["deny"] }
path "pki/root/*"         { capabilities = ["deny"] }
path "auth/token/create"  { capabilities = ["deny"] }
path "sys/auth/*"         { capabilities = ["deny"] }
path "sys/policy/*"       { capabilities = ["deny"] }
path "sys/mounts/*"       { capabilities = ["deny"] }
path "sys/raw/*"          { capabilities = ["deny"] }
path "sys/seal"           { capabilities = ["deny"] }
path "secret/*"           { capabilities = ["deny"] }
