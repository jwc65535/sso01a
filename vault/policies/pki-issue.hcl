# DEPRECATED — superseded by golang-app-policy.hcl (Prompt 3).
# bootstrap-vault.sh removes this policy at startup.
# Kept for reference only; do not grant to any service.
# pki-issue.hcl — allows signing CSRs and reading issued certs
# Granted to: vault-agent sidecar attached to the Golang app

path "pki_int/issue/user-cert" {
  capabilities = ["create", "update"]
}

path "pki_int/sign/user-cert" {
  capabilities = ["create", "update"]
}

path "pki_int/certs" {
  capabilities = ["list"]
}

path "pki_int/cert/*" {
  capabilities = ["read"]
}

path "pki_int/revoke" {
  capabilities = ["create", "update"]
}

path "pki/cert/ca" {
  capabilities = ["read"]
}

path "pki_int/cert/ca" {
  capabilities = ["read"]
}

path "pki_int/cert/ca_chain" {
  capabilities = ["read"]
}
