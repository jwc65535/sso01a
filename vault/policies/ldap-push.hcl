# DEPRECATED — superseded by consul-template-policy.hcl (Prompt 3).
# ldap-push.hcl — read-only access to PKI; granted to consul-template
# consul-template only needs to read public cert data, never private keys.

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

# Deny any write operations (belt-and-suspenders)
path "pki_int/issue/*" {
  capabilities = ["deny"]
}

path "pki_int/sign/*" {
  capabilities = ["deny"]
}
