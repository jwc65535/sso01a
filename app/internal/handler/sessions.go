package handler

// sessions.go — HTTP handlers for session management and audit log access.
//
// Per-request isolation pattern
// ─────────────────────────────
// Every handler opens a fresh *db.UserConn authenticated with the caller's
// x509 client certificate.  The connection is closed (via deferred Close)
// before the handler returns, so no credentials outlive the request.
//
//   1. Extract uid from JWT claims (placed in context by BearerAuth middleware).
//   2. Open UserConn — TLS handshake with the user's client cert, SET ROLE.
//   3. Run queries — PostgreSQL executes them as the user's role; RLS applies.
//   4. Close UserConn — TCP connection torn down, private key already zeroed.
//
// The pattern is enforced structurally: handlers receive a *db.UserConnFactory
// (not a raw connection) so they must open+close on each request.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	ssoAuth "github.com/sso01a/app/internal/auth"
	"github.com/sso01a/app/internal/db"
)

// SessionsHandler handles session and audit log endpoints.
type SessionsHandler struct {
	factory *db.UserConnFactory
}

// NewSessionsHandler wires a SessionsHandler to the given connection factory.
func NewSessionsHandler(factory *db.UserConnFactory) *SessionsHandler {
	return &SessionsHandler{factory: factory}
}

// ── /api/sessions ─────────────────────────────────────────────────────────────

// ListSessions handles GET /api/sessions.
// Returns the caller's active (non-revoked, non-expired) sessions.
func (h *SessionsHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	uc, cleanup, ok := h.openConn(w, r)
	if !ok {
		return
	}
	defer cleanup()

	sessions, err := db.ListSessions(r.Context(), uc)
	if err != nil {
		jsonError(w, "failed to list sessions", http.StatusInternalServerError)
		return
	}

	writeJSON(w, sessions)
}

// GetSession handles GET /api/sessions/{jti}.
// Returns a single session owned by the caller; 404 if not found or owned by
// another user (RLS makes the rows invisible rather than returning 403).
func (h *SessionsHandler) GetSession(w http.ResponseWriter, r *http.Request) {
	jti := chi.URLParam(r, "jti")
	if jti == "" {
		jsonError(w, "jti parameter required", http.StatusBadRequest)
		return
	}

	uc, cleanup, ok := h.openConn(w, r)
	if !ok {
		return
	}
	defer cleanup()

	session, err := db.GetSession(r.Context(), uc, jti)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "session not found", http.StatusNotFound)
			return
		}
		jsonError(w, "failed to get session", http.StatusInternalServerError)
		return
	}

	writeJSON(w, session)
}

// RevokeSession handles DELETE /api/sessions/{jti}.
// Marks the session revoked.  RLS prevents revoking another user's session.
func (h *SessionsHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	jti := chi.URLParam(r, "jti")
	if jti == "" {
		jsonError(w, "jti parameter required", http.StatusBadRequest)
		return
	}

	uc, cleanup, ok := h.openConn(w, r)
	if !ok {
		return
	}
	defer cleanup()

	if err := db.RevokeSession(r.Context(), uc, jti); err != nil {
		if isNotFound(err) {
			jsonError(w, "session not found", http.StatusNotFound)
			return
		}
		jsonError(w, "failed to revoke session", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ── /api/audit ────────────────────────────────────────────────────────────────

// ListAudit handles GET /api/audit?limit=N.
// Returns recent audit entries for the authenticated user.  limit defaults to
// 20 and is capped at 100 (enforced in the query layer as well).
func (h *SessionsHandler) ListAudit(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			limit = n
		}
	}

	uc, cleanup, ok := h.openConn(w, r)
	if !ok {
		return
	}
	defer cleanup()

	entries, err := db.ListAuditEntries(r.Context(), uc, limit)
	if err != nil {
		jsonError(w, "failed to list audit entries", http.StatusInternalServerError)
		return
	}

	writeJSON(w, entries)
}

// ── private ───────────────────────────────────────────────────────────────────

// openConn extracts the authenticated uid from context, opens a per-user DB
// connection, and returns a cleanup func that closes the connection.
// On any error it writes the HTTP response and returns ok=false.
func (h *SessionsHandler) openConn(w http.ResponseWriter, r *http.Request) (_ *db.UserConn, cleanup func(), ok bool) {
	claims, hasClaims := ssoAuth.ClaimsFromContext(r.Context())
	if !hasClaims || claims.UID == "" {
		jsonError(w, "authentication required", http.StatusUnauthorized)
		return nil, nil, false
	}
	uid := claims.UID

	if !h.factory.HasCert(uid) {
		jsonError(w, "no enrolled certificate for this user — call /api/cert/issue first", http.StatusForbidden)
		return nil, nil, false
	}

	uc, err := h.factory.Conn(r.Context(), uid)
	if err != nil {
		jsonError(w, "database connection failed", http.StatusServiceUnavailable)
		return nil, nil, false
	}

	return uc, func() { _ = uc.Close(r.Context()) }, true
}

func isNotFound(err error) bool {
	return err != nil && (errors.Is(err, pgx.ErrNoRows) ||
		containsStr(err.Error(), "not found"))
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
