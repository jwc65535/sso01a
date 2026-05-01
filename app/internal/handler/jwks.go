package handler

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"

	ssoappCrypto "github.com/sso01a/app/internal/crypto"
)

// jwkEC is the JWK (JSON Web Key) representation of an EC public key.
// See RFC 7517 §6.2.
type jwkEC struct {
	Kty string `json:"kty"` // "EC"
	Use string `json:"use"` // "sig"
	Alg string `json:"alg"` // "ES256"
	Kid string `json:"kid"`
	Crv string `json:"crv"` // "P-256"
	X   string `json:"x"`   // base64url, no padding
	Y   string `json:"y"`   // base64url, no padding
}

type jwkSet struct {
	Keys []jwkEC `json:"keys"`
}

// JWKS handles GET /api/.well-known/jwks.json.
// Returns the public signing key in JWK Set format for external JWT validators.
// This endpoint is public — it contains no secret material.
func JWKS(ks *ssoappCrypto.KeyStore) http.HandlerFunc {
	// Pre-render the response once at startup; the key is static for the
	// lifetime of the process (ephemeral key), so caching is safe.
	pub := ks.Public()
	body, _ := json.Marshal(jwkSet{
		Keys: []jwkEC{ecPublicKeyToJWK(pub, ks.KID())},
	})

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Allow downstream caching but require revalidation (the kid changes on restart).
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	}
}

func ecPublicKeyToJWK(pub *ecdsa.PublicKey, kid string) jwkEC {
	// Coordinates must be zero-padded to the full curve byte length.
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	return jwkEC{
		Kty: "EC",
		Use: "sig",
		Alg: "ES256",
		Kid: kid,
		Crv: "P-256",
		X:   base64urlEncode(pad(pub.X, byteLen)),
		Y:   base64urlEncode(pad(pub.Y, byteLen)),
	}
}

func base64urlEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func pad(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}
