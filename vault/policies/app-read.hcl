# DEPRECATED — superseded by golang-app-policy.hcl (Prompt 3).
# app-read.hcl — Golang app can verify cert serial numbers, read CRL/CA chain.
# Deliberately cannot issue or revoke certificates.

path "pki_int/cert/*" {
  capabilities = ["read"]
}

path "pki_int/certs" {
  capabilities = ["list"]
}

path "pki/cert/ca" {
  capabilities = ["read"]
}

path "pki_int/cert/ca_chain" {
  capabilities = ["read"]
}

path "pki_int/crl" {
  capabilities = ["read"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}
