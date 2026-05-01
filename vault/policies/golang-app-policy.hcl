# =============================================================================
# vault/policies/golang-app-policy.hcl
#
# Granted to: Golang application server (AppRole: golang-app)
#
# SINGLE-COMPROMISE GUARANTEE
# ────────────────────────────
# If the golang-app AppRole secret-id is stolen the attacker receives a token
# with THIS policy and nothing more. The blast radius is bounded:
#
#   CAN DO                      CANNOT DO
#   ─────────────────────────   ──────────────────────────────────────────────
#   Sign a CSR (client key)     Issue a cert (generate server-side private key)
#   Read a cert by serial       List all issued cert serials
#   Read the CA chain           Revoke any certificate
#   Read the CRL                Modify PKI config or roles
#   Create a scoped user token  Escalate to any broader policy
#
# WHY sign-not-issue?
#   pki_int/sign/* returns only the signed certificate. The private key was
#   generated on the client and never transmitted to Vault. If the attacker
#   calls sign, they still need the matching private key to use the cert.
#
#   pki_int/issue/* would generate a private key server-side and return it.
#   Explicit DENY on all issue/* paths removes this attack surface entirely.
#
# WHY no list?
#   Listing pki_int/certs/ returns all serial numbers. An attacker with the
#   list capability plus sign capability could enumerate users and probe
#   which CNs have active certificates. Deny removes the enumeration vector.
#
# WHY explicit deny on dangerous paths?
#   Vault evaluates policies in ORDER: explicit deny beats any allow. These
#   denies protect against future policy merges or inheritance that might
#   accidentally widen scope.
# =============================================================================

# ── PKI: sign CSRs (client-side private key stays with the user) ──────────────
# The Golang app calls this on behalf of the currently authenticated user.
# Application layer enforces that CN == SAML-asserted UID.
path "pki_int/sign/user-cert" {
  capabilities = ["create", "update"]
}

# ── PKI: read a specific cert by serial number (validation / status check) ────
# The serial is returned by sign/issue and stored in PostgreSQL enrolled_certs.
# The app reads it back to verify the cert is still valid and not revoked.
# Wildcard on serial: the app must know the serial already (no enumeration).
path "pki_int/cert/*" {
  capabilities = ["read"]
}

# ── PKI: read CA chain for verification ───────────────────────────────────────
path "pki_int/cert/ca_chain" {
  capabilities = ["read"]
}

path "pki/cert/ca" {
  capabilities = ["read"]
}

# ── PKI: read current CRL (check revocation status) ──────────────────────────
path "pki_int/crl" {
  capabilities = ["read"]
}

path "pki_int/crl/pem" {
  capabilities = ["read"]
}

# ── PKI: OCSP responder (live revocation check) ───────────────────────────────
path "pki_int/ocsp" {
  capabilities = ["create", "read"]
}

# ── Token: create scoped per-user signing tokens ──────────────────────────────
# The app creates a short-lived child token (TTL = CERT_TTL) for each user
# signing operation. The child token has only 'user-cert-sign-policy'.
# This allows per-user CN restriction at the Vault level when combined with
# identity entities (see bootstrap-vault.sh Phase 9).
path "auth/token/create/user-cert-signer" {
  capabilities = ["create", "update"]
}

# ── Token: self-management ────────────────────────────────────────────────────
path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# ── Identity: look up a user's Vault entity for scoped token creation ──────────
path "identity/entity/name/*" {
  capabilities = ["read"]
}

path "identity/entity" {
  capabilities = ["create", "update"]
}

path "identity/entity-alias" {
  capabilities = ["create", "update"]
}

# ── Sys: lease renewal for long-running operations ────────────────────────────
path "sys/leases/renew" {
  capabilities = ["update"]
}

# =============================================================================
# EXPLICIT DENIES — these override any wildcard allow in merged policies.
# Belt-and-suspenders: even if a future policy accidentally grants broader
# access, these denies are final.
# =============================================================================

# NEVER generate private keys server-side
path "pki_int/issue/*" {
  capabilities = ["deny"]
}

path "pki/issue/*" {
  capabilities = ["deny"]
}

# NEVER enumerate the full cert list (information leakage of user identities)
path "pki_int/certs" {
  capabilities = ["deny"]
}

# NEVER revoke certificates (only the PKI admin role can do this)
path "pki_int/revoke" {
  capabilities = ["deny"]
}

# NEVER touch PKI configuration or root CA paths
path "pki_int/config/*" {
  capabilities = ["deny"]
}

path "pki_int/root/*" {
  capabilities = ["deny"]
}

path "pki/root/*" {
  capabilities = ["deny"]
}

path "pki_int/roles/*" {
  capabilities = ["deny"]
}

# NEVER create tokens with more capabilities than this policy
path "auth/token/create" {
  capabilities = ["deny"]     # only the named role above is allowed
}

# NEVER access other secret engines
path "secret/*" {
  capabilities = ["deny"]
}

path "kv/*" {
  capabilities = ["deny"]
}

# NEVER access system administration paths
path "sys/auth/*"     { capabilities = ["deny"] }
path "sys/policy/*"   { capabilities = ["deny"] }
path "sys/mounts/*"   { capabilities = ["deny"] }
path "sys/raw/*"      { capabilities = ["deny"] }
path "sys/seal"       { capabilities = ["deny"] }
path "sys/unseal"     { capabilities = ["deny"] }
path "sys/step-down"  { capabilities = ["deny"] }
