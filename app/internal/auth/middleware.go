package auth

import (
	"net/http"
	"strings"
)

// BearerAuth returns an HTTP middleware that validates the JWT from either:
//   1. Authorization: Bearer <token> header  (API clients, dev SPA at localhost:3000)
//   2. sso_session HttpOnly cookie            (SPA served from sp.sso.local)
//
// The Authorization header takes precedence when both are present.
//
// Optionally enforces device fingerprint consistency via X-Device-Fingerprint.
// On failure: 401 JSON.  On success: next is called with claims in context.
func BearerAuth(issuer *Issuer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := extractBearer(r)
			if !ok {
				// No Authorization header — try the HttpOnly session cookie.
				// The cookie is set by the token handler with SameSite=Strict,
				// so it is only sent on same-origin requests from sp.sso.local.
				if c, err := r.Cookie("sso_session"); err == nil && c.Value != "" {
					raw, ok = c.Value, true
				}
			}
			if !ok {
				writeAuthError(w, "authentication required: provide Authorization: Bearer <token> or a valid sso_session cookie")
				return
			}

			claims, err := issuer.Validate(raw)
			if err != nil {
				writeAuthError(w, "invalid token: "+err.Error())
				return
			}

			// Device fingerprint consistency (best-effort, non-blocking).
			if fp := r.Header.Get("X-Device-Fingerprint"); fp != "" &&
				claims.DeviceFingerprint != "" &&
				fp != claims.DeviceFingerprint {
				writeAuthError(w, "device fingerprint mismatch")
				return
			}

			next.ServeHTTP(w, r.WithContext(ContextWithClaims(r.Context(), claims)))
		})
	}
}

// ShibbolethRequired is a lightweight guard for endpoints that MUST be called
// through the Shibboleth SP (i.e., they expect the uid Shibboleth header).
// Requests arriving without the header have somehow bypassed the SP — reject.
func ShibbolethRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("uid") == "" {
			writeAuthError(w, "request must be proxied through the Shibboleth SP")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── helpers ──────────────────────────────────────────────────────────────────

func extractBearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", false
	}
	tok := strings.TrimPrefix(h, "Bearer ")
	if tok == "" {
		return "", false
	}
	return tok, true
}

func writeAuthError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="sso01a"`)
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized","detail":` +
		`"` + strings.ReplaceAll(msg, `"`, `\"`) + `"}`))
}
