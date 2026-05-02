package db

// postgres.go — CRUD operations executed under the authenticated user's role.
//
// ISOLATION GUARANTEE
// ───────────────────
// Every function in this file accepts a *UserConn whose role is already set to
// the caller's PostgreSQL role (e.g. "alice").  Two enforcement layers prevent
// a user from touching another user's rows:
//
//  1. SET ROLE in UserConnFactory.Conn() — queries run as the user's PG role.
//
//  2. Row-Level Security policies on sessions and enrolled_certs — an
//     additional server-side guard keyed on username = CURRENT_USER.

import (
	"context"
	"fmt"
	"time"
)

// ── sessions ──────────────────────────────────────────────────────────────────

// Session represents a row in public.sessions.
type Session struct {
	SessionID  string
	Username   string    // set via RLS (username = CURRENT_USER) — tamper-proof
	Thumbprint string    // x5t#S256 of the bound x509 cert
	DeviceFP   string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Revoked    bool
}

// ListSessions returns active (non-revoked, non-expired) sessions for the
// authenticated user.  RLS on public.sessions enforces username = CURRENT_USER.
func ListSessions(ctx context.Context, uc *UserConn) ([]Session, error) {
	rows, err := uc.Conn().Query(ctx,
		`SELECT session_id, username, thumbprint, device_fp, created_at, expires_at, revoked
		   FROM public.sessions
		  WHERE revoked = false
		    AND expires_at > NOW()
		  ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list sessions: %w", err)
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.SessionID, &s.Username, &s.Thumbprint, &s.DeviceFP,
			&s.CreatedAt, &s.ExpiresAt, &s.Revoked); err != nil {
			return nil, fmt.Errorf("db: scan session: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetSession fetches a single session by session_id.
// RLS on public.sessions ensures only the authenticated user's own session is visible.
func GetSession(ctx context.Context, uc *UserConn, sessionID string) (*Session, error) {
	row := uc.Conn().QueryRow(ctx,
		`SELECT session_id, username, thumbprint, device_fp, created_at, expires_at, revoked
		   FROM public.sessions
		  WHERE session_id = $1`,
		sessionID,
	)
	var s Session
	if err := row.Scan(&s.SessionID, &s.Username, &s.Thumbprint, &s.DeviceFP,
		&s.CreatedAt, &s.ExpiresAt, &s.Revoked); err != nil {
		return nil, fmt.Errorf("db: get session id=%s: %w", sessionID, err)
	}
	return &s, nil
}

// RevokeSession marks a session revoked.
// RLS on public.sessions prevents revoking another user's session.
func RevokeSession(ctx context.Context, uc *UserConn, sessionID string) error {
	tag, err := uc.Conn().Exec(ctx,
		`UPDATE public.sessions SET revoked = true WHERE session_id = $1`,
		sessionID,
	)
	if err != nil {
		return fmt.Errorf("db: revoke session id=%s: %w", sessionID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("db: session id=%s not found (or belongs to a different user)", sessionID)
	}
	return nil
}

// ── auth_events ───────────────────────────────────────────────────────────────

// AuditEntry represents a row in public.auth_events.
type AuditEntry struct {
	ID         string
	EventTime  time.Time
	EventType  string
	Username   string
	Serial     string
	Thumbprint string
	DeviceFP   string
	RemoteAddr string
}

// ListAuditEntries returns recent audit events for the authenticated user.
// limit is clamped to [1, 100].
func ListAuditEntries(ctx context.Context, uc *UserConn, limit int) ([]AuditEntry, error) {
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := uc.Conn().Query(ctx,
		`SELECT id::text, event_time, event_type,
		        COALESCE(username, ''), COALESCE(serial, ''),
		        COALESCE(thumbprint, ''), COALESCE(device_fp, ''), COALESCE(remote_addr, '')
		   FROM public.auth_events
		  WHERE username = current_user
		  ORDER BY event_time DESC
		  LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list audit entries: %w", err)
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.EventTime, &e.EventType,
			&e.Username, &e.Serial, &e.Thumbprint, &e.DeviceFP, &e.RemoteAddr); err != nil {
			return nil, fmt.Errorf("db: scan audit entry: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
