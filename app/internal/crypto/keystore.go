package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/awnumar/memguard"
)

// KeyStore holds a JWT signing key in memory-locked storage via memguard.
//
// The raw PKCS8-encoded private key bytes live exclusively in a
// memguard.Enclave (AES-256-GCM encrypted, pinned to non-swappable pages).
// Opening the enclave yields a LockedBuffer; the caller must Destroy() it
// immediately after use so the plaintext window is as short as possible.
//
// The derived public key is non-sensitive and lives in normal heap memory.
type KeyStore struct {
	enclave *memguard.Enclave
	pub     *ecdsa.PublicKey
	kid     string // SHA-256 (first 16 hex chars) of the SubjectPublicKeyInfo DER
}

// NewEphemeralKeyStore generates a fresh ECDSA P-256 key pair and seals the
// private key into a memguard Enclave.  Call Destroy when the server exits.
func NewEphemeralKeyStore() (*KeyStore, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ECDSA key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshalling PKCS8 key: %w", err)
	}

	// Seal into a memguard Enclave.  The Enclave AES-encrypts the bytes and
	// pins them to non-swappable RAM.  After sealing, zero the plaintext slice.
	enclave := memguard.NewEnclave(der)
	for i := range der {
		der[i] = 0
	}

	kid, err := computeKID(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	return &KeyStore{
		enclave: enclave,
		pub:     &priv.PublicKey,
		kid:     kid,
	}, nil
}

// Open decrypts the private key into a LockedBuffer and returns the parsed
// *ecdsa.PrivateKey together with a cleanup function.
//
// The caller MUST call cleanup() immediately after the signing operation;
// it destroys the LockedBuffer, zeroing and unpinning its memory.
//
//	priv, cleanup, err := ks.Open()
//	if err != nil { ... }
//	defer cleanup()
//	// use priv only within this scope
func (ks *KeyStore) Open() (*ecdsa.PrivateKey, func(), error) {
	buf, err := ks.enclave.Open()
	if err != nil {
		return nil, nil, fmt.Errorf("opening key enclave: %w", err)
	}

	raw, err := x509.ParsePKCS8PrivateKey(buf.Bytes())
	if err != nil {
		buf.Destroy()
		return nil, nil, fmt.Errorf("parsing PKCS8 key: %w", err)
	}

	ecKey, ok := raw.(*ecdsa.PrivateKey)
	if !ok {
		buf.Destroy()
		return nil, nil, fmt.Errorf("key is not ECDSA")
	}

	// Destroy the LockedBuffer after the caller is done with the key.
	// Note: ecKey.D (the private scalar) will still exist in Go heap memory
	// briefly until GC collects it — this is an inherent Go limitation.
	return ecKey, func() { buf.Destroy() }, nil
}

// Public returns the ECDSA public key.  Non-sensitive; safe to hold long-term.
func (ks *KeyStore) Public() *ecdsa.PublicKey { return ks.pub }

// KID returns the key identifier used in JWT headers and JWKS responses.
func (ks *KeyStore) KID() string { return ks.kid }

// Destroy purges all memguard-managed allocations.  Call once on shutdown.
// This zeroes and frees the locked memory pages that back every Enclave and
// LockedBuffer allocated in this process — the Enclave API has no per-object
// destroy, so Purge() is the correct cleanup mechanism.
func (ks *KeyStore) Destroy() {
	ks.enclave = nil // allow GC to collect the Enclave object
	memguard.Purge()
}

// computeKID derives a short, stable key ID from the SubjectPublicKeyInfo DER
// of the public key (first 16 hex chars of SHA-256).
func computeKID(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshalling public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8]), nil
}
