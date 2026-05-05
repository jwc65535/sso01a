package handler

// key.go — certificate issuance and private-key signing endpoints
//
// SECURITY MODEL
//
// POST /api/cert/issue
//   1. Generates a fresh ECDSA P-256 key pair in-process (private key never
//      leaves this process and is never transmitted to Vault).
//   2. Sends ONLY the CSR (public data) to Vault PKI for signing.
//   3. Seals the private key in a memguard Enclave under the current TOTP window.
//   4. Returns the signed certificate + CA chain to the client.
//
// POST /api/sign
//   1. Unlocks the sealed private key for the duration of this request only.
//   2. Signs the caller-supplied payload.
//   3. The cleanup() returned by Unlock() is deferred — the LockedBuffer is
//      destroyed (zeroed and unpinned) before this handler returns.
//
// Neither endpoint logs or echoes private key material.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"

	ssoAuth "github.com/sso01a/app/internal/auth"
	ssoCrypto "github.com/sso01a/app/internal/crypto"
	"github.com/sso01a/app/internal/db"
	"github.com/sso01a/app/internal/vault"
)

// certStorer is the subset of db.UserConnFactory used by KeyHandler.
// Defined as an interface so KeyHandler can be tested without a real factory.
type certStorer interface {
	StoreCert(uid, certPEM string)
}

// KeyHandler handles certificate lifecycle requests.
type KeyHandler struct {
	km          *ssoCrypto.KeyManager
	vaultClient *vault.Client
	connFactory certStorer // optional; nil if Vault CA chain was unavailable at startup
}

// NewKeyHandler wires a KeyHandler to its dependencies.
func NewKeyHandler(km *ssoCrypto.KeyManager, vaultClient *vault.Client) *KeyHandler {
	return &KeyHandler{km: km, vaultClient: vaultClient}
}

// SetConnFactory wires the per-user connection factory so Issue() can cache
// the signed certificate for later use in DB connections.  Called by main()
// after the Vault CA chain has been fetched.
func (h *KeyHandler) SetConnFactory(f *db.UserConnFactory) {
	h.connFactory = f
}

// IssueRequest is the JSON body for POST /api/cert/issue.
// Currently empty — the UID comes from the validated JWT (context) and the
// Shibboleth uid header already verified by upstream middleware.  Reserved
// for future fields (e.g. requested key usage extensions).
type IssueRequest struct{}

// IssueResponse is returned on successful certificate issuance.
type IssueResponse struct {
	Certificate string   `json:"certificate"`           // PEM signed leaf cert
	IssuingCA   string   `json:"issuing_ca"`            // PEM issuing CA
	CAChain     []string `json:"ca_chain"`              // PEM full chain
	SerialNumber string  `json:"serial_number"`         // hex serial for revocation
	Expiration  int64    `json:"expiration"`            // Unix epoch
}

// Issue handles POST /api/cert/issue.
// The caller must be authenticated (JWT middleware already ran).
func (h *KeyHandler) Issue(w http.ResponseWriter, r *http.Request) {
	claims, ok := ssoAuth.ClaimsFromContext(r.Context())
	if !ok || claims.UID == "" {
		jsonError(w, "authentication required", http.StatusUnauthorized)
		return
	}
	uid := claims.UID

	// Generate key + CSR locally.  privKeyDER must be sealed before this
	// function returns; keymanager.Seal() zeroes it after sealing.
	privKeyDER, csrPEM, err := h.km.GenerateKeyAndCSR(uid)
	if err != nil {
		http.Error(w, "failed to generate key pair", http.StatusInternalServerError)
		return
	}

	// Seal the private key immediately — before the network call to Vault.
	// If Vault signing fails, the sealed key remains in memory for future
	// re-seal or explicit Destroy(); no orphan plaintext is left behind.
	if err := h.km.Seal(uid, privKeyDER); err != nil {
		http.Error(w, "failed to seal private key", http.StatusInternalServerError)
		return
	}
	// privKeyDER is zeroed by Seal(); do not use it after this point.

	// Send the CSR (public data only) to Vault for signing.
	ctx, cancel := context.WithTimeout(r.Context(), 30_000_000_000) // 30s
	defer cancel()

	signed, err := h.vaultClient.SignCSR(ctx, string(csrPEM), uid)
	if err != nil {
		h.km.Destroy(uid) // no cert means no use for the sealed key
		http.Error(w, "vault signing failed", http.StatusBadGateway)
		return
	}

	// Cache the signed cert so the per-user DB connection factory can build
	// the TLS client certificate on subsequent requests.
	if h.connFactory != nil {
		h.connFactory.StoreCert(uid, signed.Certificate)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(IssueResponse{
		Certificate:  signed.Certificate,
		IssuingCA:    signed.IssuingCA,
		CAChain:      signed.CAChain,
		SerialNumber: signed.SerialNumber,
		Expiration:   signed.Expiration,
	})
}

// SignRequest is the JSON body for POST /api/sign.
type SignRequest struct {
	// Payload is the base64url-encoded bytes to sign (max 1 MiB).
	Payload string `json:"payload"`
}

// SignResponse is returned on successful signing.
type SignResponse struct {
	// Signature is the base64url-encoded DER-encoded ECDSA signature over
	// SHA-256(payload).
	Signature string `json:"signature"`
}

// Sign handles POST /api/sign.
// Unlocks the sealed private key for uid, signs SHA-256(payload), then
// immediately destroys the LockedBuffer via deferred cleanup.
func (h *KeyHandler) Sign(w http.ResponseWriter, r *http.Request) {
	claims, ok := ssoAuth.ClaimsFromContext(r.Context())
	if !ok || claims.UID == "" {
		jsonError(w, "authentication required", http.StatusUnauthorized)
		return
	}
	uid := claims.UID

	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Payload == "" {
		http.Error(w, "payload required", http.StatusBadRequest)
		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(req.Payload)
	if err != nil {
		http.Error(w, "payload must be base64url-encoded", http.StatusBadRequest)
		return
	}
	if len(payload) > 1<<20 {
		http.Error(w, "payload exceeds 1 MiB limit", http.StatusRequestEntityTooLarge)
		return
	}

	// Unlock the private key — the LockedBuffer is destroyed when cleanup() runs.
	priv, cleanup, err := h.km.OpenPrivateKey(uid)
	if err != nil {
		http.Error(w, "no enrolled key for this user", http.StatusForbidden)
		return
	}
	defer cleanup() // zeroes and unpins LockedBuffer before handler returns

	digest := sha256.Sum256(payload)
	sig, err := priv.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(SignResponse{
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	})
}
