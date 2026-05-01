package auth

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
)

// CustomClaims extends the standard JWT RegisteredClaims with zero-trust
// binding fields (RFC 7800 cnf/x5t#S256) and device fingerprint.
type CustomClaims struct {
	jwt.RegisteredClaims

	// CNF is the Confirmation claim (RFC 7800 §3.1) binding the token to the
	// holder's x509 certificate.  The x5t#S256 field carries the base64url-
	// encoded SHA-256 thumbprint of the DER-encoded certificate.
	//
	// Issuance: populated from the Shibboleth ssoCertThumbprint header.
	// Validation: compared against the user's current LDAP entry when strict
	// mode is enabled (e.g., on sensitive operations).
	CNF *CNFClaim `json:"cnf,omitempty"`

	// DeviceFingerprint is the FingerprintJS Pro visitor ID collected by the
	// client SPA and POSTed to /api/token.  Stored here so each subsequent
	// request can validate device consistency without a round-trip to FingerprintJS.
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`

	// UID is the LDAP uid attribute (redundant with Sub, but explicit and
	// strongly typed for downstream consumers that may not parse Sub).
	UID string `json:"uid,omitempty"`

	// Mail is the user's email address from the SAML assertion.
	Mail string `json:"mail,omitempty"`

	// EnrolledAt is the Unix epoch at which the user enrolled their x509 cert
	// (sourced from the ssoEnrolledAt SAML attribute / LDAP entry).
	// Consumers can enforce maximum cert age relative to this value.
	EnrolledAt int64 `json:"enrolled_at,omitempty"`
}

// CNFClaim is the JWT Confirmation claim structure.
// The JSON key "x5t#S256" contains a # which is valid in both JSON and
// golang struct tags.
type CNFClaim struct {
	X5TS256 string `json:"x5t#S256"`
}

// ───────────────────────────── context helpers ──────────────────────────────

type contextKey int

const contextKeyClaims contextKey = iota

// ContextWithClaims stores validated claims in the request context.
func ContextWithClaims(ctx context.Context, c *CustomClaims) context.Context {
	return context.WithValue(ctx, contextKeyClaims, c)
}

// ClaimsFromContext retrieves validated claims stored by BearerAuth middleware.
// Returns (nil, false) if the context was not populated by the middleware.
func ClaimsFromContext(ctx context.Context) (*CustomClaims, bool) {
	c, ok := ctx.Value(contextKeyClaims).(*CustomClaims)
	return c, ok
}
