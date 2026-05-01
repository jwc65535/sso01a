package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/sso01a/app/internal/auth"
)

// tokenRequest is the optional JSON body the client POSTs to /api/token.
// The fingerprint field carries the FingerprintJS Pro visitor ID collected
// client-side; if omitted, we fall back to the ssoDeviceFingerprint Shibboleth
// header (populated from LDAP at the previous enrolment).
type tokenRequest struct {
	Fingerprint string `json:"fingerprint"`
}

type tokenResponse struct {
	// Token is returned in the body so API clients and the standalone dev SPA
	// (localhost:3000, cross-origin) can use it as a Bearer token.
	// The SPA served from the SP uses the HttpOnly cookie instead and ignores
	// this field.  Never log or echo this value.
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
}

// Token handles POST /api/token.
//
// ROUTE PROTECTION: this endpoint is behind the Shibboleth SP.  The SP
// requires a valid SAML session before proxying the request, and sets the
// sso* headers below.  The auth.ShibbolethRequired middleware (wired in
// main.go) rejects requests that arrive without the uid header, guarding
// against misconfigured proxy setups.
//
// HEADERS read (set by mod_shib via ShibUseHeaders On):
//   uid                — LDAP uid; becomes JWT subject
//   mail               — email address
//   ssoCertThumbprint  — x5t#S256 of the Vault-issued x509 cert (REQUIRED)
//   ssoDeviceFingerprint — FingerprintJS visitor ID from last enrolment
//   ssoEnrolledAt      — Unix epoch of cert enrolment
//
// REQUEST BODY (optional JSON):
//   {"fingerprint": "<fpjs-visitor-id>"}
//
// RESPONSE:
//   {"token": "<jwt>", "token_type": "Bearer", "expires_in": <seconds>}
func Token(issuer *auth.Issuer, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ── Read Shibboleth headers ──────────────────────────────────────────
		uid := strings.TrimSpace(r.Header.Get("uid"))
		mail := strings.TrimSpace(r.Header.Get("mail"))
		thumbprint := strings.TrimSpace(r.Header.Get("ssoCertThumbprint"))
		shibFP := strings.TrimSpace(r.Header.Get("ssoDeviceFingerprint"))
		enrolledAtRaw := strings.TrimSpace(r.Header.Get("ssoEnrolledAt"))

		if uid == "" {
			// Should be caught by ShibbolethRequired middleware, but be explicit.
			writeError(w, http.StatusBadRequest, "missing uid header — request must be proxied through the SP")
			return
		}

		if thumbprint == "" {
			log.Warn("token request without cert thumbprint",
				"uid", uid,
				"remote", r.RemoteAddr,
			)
			writeError(w, http.StatusForbidden,
				"no x509 certificate enrolled; complete device enrolment before requesting a token")
			return
		}

		// ── Device fingerprint: prefer client-supplied, fall back to LDAP-sourced ──
		deviceFP := shibFP
		if r.Body != nil {
			var req tokenRequest
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err == nil {
				if fp := strings.TrimSpace(req.Fingerprint); fp != "" {
					deviceFP = fp
				}
			}
			// Ignore decode errors — body is optional
		}

		var enrolledAt int64
		if enrolledAtRaw != "" {
			if v, err := strconv.ParseInt(enrolledAtRaw, 10, 64); err == nil {
				enrolledAt = v
			}
		}

		// ── Issue JWT ────────────────────────────────────────────────────────
		signed, err := issuer.Issue(auth.IssueParams{
			UID:               uid,
			Mail:              mail,
			CertThumbprint:    thumbprint,
			DeviceFingerprint: deviceFP,
			EnrolledAt:        enrolledAt,
		})
		if err != nil {
			log.Error("JWT issuance failed", "uid", uid, "err", err)
			writeError(w, http.StatusInternalServerError, "token issuance failed")
			return
		}

		log.Info("token issued",
			"uid", uid,
			"thumbprint_prefix", safePrefix(thumbprint, 12),
			"has_device_fp", deviceFP != "",
		)

		ttlSec := int(issuer.TTL().Seconds())

		// Set the JWT as an HttpOnly Secure SameSite=Strict cookie.
		// The SPA served from the same origin (sp.sso.local) uses this cookie
		// transparently — JavaScript never reads the token value.
		//
		// SameSite=Strict: the cookie is not sent on cross-origin requests,
		// preventing CSRF.  API clients and the dev SPA (localhost:3000) should
		// use the Bearer token returned in the response body instead.
		http.SetCookie(w, &http.Cookie{
			Name:     "sso_session",
			Value:    signed,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   ttlSec,
			Path:     "/",
		})

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		_ = json.NewEncoder(w).Encode(tokenResponse{
			Token:     signed,
			TokenType: "Bearer",
			ExpiresIn: ttlSec,
		})
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
