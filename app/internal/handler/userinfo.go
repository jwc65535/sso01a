package handler

import (
	"encoding/json"
	"net/http"

	"github.com/sso01a/app/internal/auth"
)

type userinfoResponse struct {
	Sub               string   `json:"sub"`
	UID               string   `json:"uid"`
	Mail              string   `json:"mail,omitempty"`
	CertThumbprint    string   `json:"cert_thumbprint"`
	DeviceFingerprint string   `json:"device_fingerprint,omitempty"`
	EnrolledAt        int64    `json:"enrolled_at,omitempty"`
	ExpiresAt         int64    `json:"exp"`
	IssuedAt          int64    `json:"iat"`
	TokenID           string   `json:"jti"`
	Audience          []string `json:"aud"`
}

// UserInfo handles GET /api/userinfo.
// Requires: valid JWT Bearer token (enforced by auth.BearerAuth middleware).
// Returns the claims embedded in the token without any further lookups.
func UserInfo(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "claims missing from context")
		return
	}

	resp := userinfoResponse{
		Sub:      claims.Subject,
		UID:      claims.UID,
		Mail:     claims.Mail,
		TokenID:  claims.ID,
		Audience: []string(claims.Audience),
	}
	if claims.CNF != nil {
		resp.CertThumbprint = claims.CNF.X5TS256
	}
	resp.DeviceFingerprint = claims.DeviceFingerprint
	resp.EnrolledAt = claims.EnrolledAt
	if claims.ExpiresAt != nil {
		resp.ExpiresAt = claims.ExpiresAt.Unix()
	}
	if claims.IssuedAt != nil {
		resp.IssuedAt = claims.IssuedAt.Unix()
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}
