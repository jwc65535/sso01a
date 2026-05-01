// Package vault provides a thin client over the HashiCorp Vault API,
// scoped to exactly the capabilities granted by golang-app-policy.hcl.
//
// SEPARATION OF DUTIES — why this client exists as a separate layer
// ──────────────────────────────────────────────────────────────────
// Vault is the CERTIFICATE AUTHORITY only.  It signs CSRs; it never generates
// or stores private keys on behalf of application users.  The policy explicit-
// ly DENYs pki_int/issue/* (which would generate a server-side private key).
//
// Private key lifecycle:
//   1. Generated locally by KeyManager.GenerateKeyAndCSR (never transmitted).
//   2. Immediately sealed into a memguard Enclave by KeyManager.
//   3. The CSR (public data) is sent here for signing.
//   4. The signed certificate is returned; the private key never left this process.
//
// Compromise blast-radius:
//   Vault compromised       → attacker gets SIGNED CERTS only (no private keys).
//   memguard Enclave leaked → attacker gets AES-ENCRYPTED bytes (needs TOTP key).
//   Docker secret leaked    → attacker gets master secret (needs Enclave data).
//   All three required simultaneously for key exposure.
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Config carries the Vault connection parameters for the application.
// In dev mode the Token is the root token; in production replace with an
// AppRole secret-id and set Token = "" (the client will authenticate via AppRole).
type Config struct {
	Addr    string // e.g. "http://vault:8200"
	Token   string // dev: root token; prod: AppRole auth token
	PKIMount string // intermediate CA mount, e.g. "pki_int"
	PKIRole  string // signing role, e.g. "user-cert"
	CertTTL  string // max cert lifetime, e.g. "4h"
}

// Client wraps a Vault API client, exposing only the operations permitted by
// golang-app-policy.hcl.  Methods are intentionally narrow — any attempt to
// call a Vault path not listed in that policy returns a 403 from Vault.
type Client struct {
	vc  *vaultapi.Client
	cfg Config
}

// SignedCert is the result of signing a CSR via Vault PKI.
// It contains NO private key material — the private key was generated locally
// and sealed before this call was made.
type SignedCert struct {
	Certificate  string   // PEM-encoded signed leaf cert
	IssuingCA    string   // PEM-encoded issuing CA cert
	CAChain      []string // PEM-encoded chain: [issuing CA, ..., root]
	SerialNumber string   // hex serial (e.g. "7a:3b:…") for revocation lookup
	Expiration   int64    // Unix epoch; useful for cache TTL
}

// New creates a Vault client.  A connection is not attempted until the first call.
func New(cfg Config) (*Client, error) {
	vcfg := vaultapi.DefaultConfig()
	vcfg.Address = cfg.Addr
	vcfg.Timeout = 10 * time.Second

	vc, err := vaultapi.NewClient(vcfg)
	if err != nil {
		return nil, fmt.Errorf("vault: creating client: %w", err)
	}
	if cfg.Token != "" {
		vc.SetToken(cfg.Token)
	}

	return &Client{vc: vc, cfg: cfg}, nil
}

// SignCSR submits a PEM-encoded Certificate Signing Request to the Vault PKI
// role and returns the signed certificate.
//
// The CN in the CSR MUST match the SAML-asserted UID (enforced at the call
// site; Vault role config may also enforce it via allowed_domains).
//
// Vault policy path: pki_int/sign/user-cert [create, update]
func (c *Client) SignCSR(ctx context.Context, csrPEM, cn string) (*SignedCert, error) {
	path := fmt.Sprintf("%s/sign/%s", c.cfg.PKIMount, c.cfg.PKIRole)

	secret, err := c.vc.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"csr":         csrPEM,
		"common_name": cn,
		"ttl":         c.cfg.CertTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("vault: signing CSR for cn=%s: %w", cn, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: empty response for CSR sign")
	}

	cert := &SignedCert{
		Certificate:  getStr(secret.Data, "certificate"),
		IssuingCA:    getStr(secret.Data, "issuing_ca"),
		SerialNumber: getStr(secret.Data, "serial_number"),
		Expiration:   getInt64(secret.Data, "expiration"),
	}

	if chain, ok := secret.Data["ca_chain"].([]interface{}); ok {
		for _, v := range chain {
			if s, ok := v.(string); ok && s != "" {
				cert.CAChain = append(cert.CAChain, s)
			}
		}
	}

	if cert.Certificate == "" {
		return nil, fmt.Errorf("vault: PKI sign returned no certificate")
	}
	return cert, nil
}

// ReadCACChain returns the full PEM-encoded CA chain from the intermediate PKI mount.
// Safe to cache; the chain changes only on CA rotation.
//
// Vault policy path: pki_int/cert/ca_chain [read]
func (c *Client) ReadCAChain(ctx context.Context) (string, error) {
	path := c.cfg.PKIMount + "/cert/ca_chain"
	secret, err := c.vc.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return "", fmt.Errorf("vault: reading CA chain: %w", err)
	}
	if secret == nil {
		return "", fmt.Errorf("vault: empty CA chain response")
	}
	return getStr(secret.Data, "certificate"), nil
}

// ReadCert fetches a certificate by serial number.  Used to verify a cert's
// revocation status before performing sensitive operations.
//
// Vault policy path: pki_int/cert/* [read]
func (c *Client) ReadCert(ctx context.Context, serial string) (string, error) {
	path := fmt.Sprintf("%s/cert/%s", c.cfg.PKIMount, serial)
	secret, err := c.vc.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return "", fmt.Errorf("vault: reading cert serial=%s: %w", serial, err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault: cert serial=%s not found", serial)
	}
	return getStr(secret.Data, "certificate"), nil
}

// Ping verifies connectivity and that the current token is valid.
// Uses auth/token/lookup-self which is always allowed for valid tokens.
func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := c.vc.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return fmt.Errorf("vault: ping failed: %w", err)
	}
	return nil
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

func getStr(m map[string]interface{}, k string) string {
	v, _ := m[k].(string)
	return v
}

func getInt64(m map[string]interface{}, k string) int64 {
	switch v := m[k].(type) {
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	case int64:
		return v
	}
	return 0
}
