package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	ssoappCrypto "github.com/sso01a/app/internal/crypto"
)

// Issuer creates and validates JWTs signed with an ECDSA P-256 key stored
// in a memguard KeyStore.  The signing key is decrypted only for the duration
// of each signing call; the public key is held in plaintext for verification.
type Issuer struct {
	ks       *ssoappCrypto.KeyStore
	issuer   string
	audience jwt.ClaimStrings
	ttl      time.Duration
}

// NewIssuer wires an Issuer to the provided KeyStore and configuration values.
func NewIssuer(ks *ssoappCrypto.KeyStore, issuer string, audience []string, ttl time.Duration) *Issuer {
	return &Issuer{
		ks:       ks,
		issuer:   issuer,
		audience: jwt.ClaimStrings(audience),
		ttl:      ttl,
	}
}

// IssueParams carries the SAML-sourced attributes used to populate the JWT.
// All fields are sourced from Shibboleth request headers on the token endpoint.
type IssueParams struct {
	// UID is the LDAP uid (must match subject of the SAML NameID).
	UID string
	// Mail is the email address from the SAML assertion.
	Mail string
	// CertThumbprint is the x5t#S256 value from ssoCertThumbprint header.
	// Required: a user without an enrolled cert cannot obtain a token.
	CertThumbprint string
	// DeviceFingerprint is the FingerprintJS visitor ID POSTed by the client.
	DeviceFingerprint string
	// EnrolledAt is the Unix epoch of cert enrolment (ssoEnrolledAt header).
	EnrolledAt int64
}

// Issue signs and returns a new JWT.  Returns an error if CertThumbprint is
// empty — the caller must enforce cert enrolment before calling this.
func (is *Issuer) Issue(p IssueParams) (string, error) {
	if p.CertThumbprint == "" {
		return "", fmt.Errorf("cert thumbprint is required: user has no enrolled x509 certificate")
	}
	if p.UID == "" {
		return "", fmt.Errorf("uid is required")
	}

	now := time.Now()
	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    is.issuer,
			Subject:   p.UID,
			Audience:  is.audience,
			ExpiresAt: jwt.NewNumericDate(now.Add(is.ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
		CNF:               &CNFClaim{X5TS256: p.CertThumbprint},
		UID:               p.UID,
		Mail:              p.Mail,
		DeviceFingerprint: p.DeviceFingerprint,
		EnrolledAt:        p.EnrolledAt,
	}

	// Decrypt the private key for the duration of the signing call only.
	priv, cleanup, err := is.ks.Open()
	if err != nil {
		return "", fmt.Errorf("opening signing key: %w", err)
	}
	defer cleanup()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = is.ks.KID()

	return token.SignedString(priv)
}

// TTL returns the configured token lifetime.  Exposed so handlers can populate
// the expires_in field of the token response without repeating the config.
func (is *Issuer) TTL() time.Duration { return is.ttl }

// Validate parses and fully validates a JWT string.
// Returns the embedded CustomClaims on success.
// The cnf claim is guaranteed non-nil with a non-empty x5t#S256 field.
func (is *Issuer) Validate(tokenString string) (*CustomClaims, error) {
	var claims CustomClaims
	_, err := jwt.ParseWithClaims(
		tokenString,
		&claims,
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method %q", t.Header["alg"])
			}
			return is.ks.Public(), nil
		},
		jwt.WithIssuedAt(),
		jwt.WithIssuer(is.issuer),
		jwt.WithAudience(string(is.audience[0])),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}

	// Enforce cnf presence — a token without a cert binding is not accepted.
	if claims.CNF == nil || claims.CNF.X5TS256 == "" {
		return nil, fmt.Errorf("token missing required cnf/x5t#S256 claim")
	}

	return &claims, nil
}
